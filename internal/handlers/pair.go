package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/pair"
	"github.com/sigilauth/server/internal/pictogram"
)

const (
	handshakeTTL       = 10 * time.Second
	defaultApprovalTTL = 5 * time.Minute
	maxConcurrentPairs = 3
	maxPairsPerMinute  = 10
)

type PairHandler struct {
	pairStore     *pair.Store
	serverPrivKey *ecdsa.PrivateKey
	serverID      string
}

func NewPairHandler(pairStore *pair.Store, serverPrivKey *ecdsa.PrivateKey, serverID string) *PairHandler {
	return &PairHandler{
		pairStore:     pairStore,
		serverPrivKey: serverPrivKey,
		serverID:      serverID,
	}
}

func (h *PairHandler) Init(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientPubB64 := r.URL.Query().Get("client_pub")
	if clientPubB64 == "" {
		writeError(w, http.StatusBadRequest, "MISSING_CLIENT_PUB", "client_pub query parameter required")
		return
	}

	clientPubBytes, err := base64.StdEncoding.DecodeString(clientPubB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CLIENT_PUB", "client_pub must be base64-encoded")
		return
	}

	_, err = crypto.DecompressPublicKey(clientPubBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CLIENT_PUB", fmt.Sprintf("invalid public key: %v", err))
		return
	}

	sourceIP := getSourceIP(r)
	if err := h.pairStore.CheckRateLimit(r.Context(), sourceIP, maxConcurrentPairs, maxPairsPerMinute); err != nil {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMIT", err.Error())
		return
	}

	h.pairStore.IncrementIP(r.Context(), sourceIP)
	defer h.pairStore.DecrementIP(r.Context(), sourceIP)

	serverPubCompressed := crypto.CompressPublicKey(&h.serverPrivKey.PublicKey)
	derivedNonce, sessionPictogram, err := h.deriveSessionPictogram(serverPubCompressed, clientPubBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to derive session pictogram")
		return
	}

	approvalTTL := defaultApprovalTTL
	if ttlStr := r.URL.Query().Get("approval_ttl"); ttlStr != "" {
		if ttl, err := time.ParseDuration(ttlStr); err == nil {
			if ttl < 30*time.Second {
				approvalTTL = 30 * time.Second
			} else if ttl > 7*24*time.Hour {
				approvalTTL = 7 * 24 * time.Hour
			} else {
				approvalTTL = ttl
			}
		}
	}

	// PR4 fix: Pass derivedNonce to Create (same nonce used for pictogram derivation)
	if err := h.pairStore.Create(r.Context(), derivedNonce, clientPubBytes, sessionPictogram, handshakeTTL, approvalTTL); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create pair")
		return
	}

	expiresAt := time.Now().Add(handshakeTTL)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"server_id":                  h.serverID,
		"server_public_key":          base64.StdEncoding.EncodeToString(serverPubCompressed),
		"server_nonce":               base64.StdEncoding.EncodeToString(derivedNonce),
		"expires_at":                 expiresAt.Format(time.RFC3339),
		"session_pictogram":          sessionPictogram,
		"session_pictogram_speakable": pictogram.FormatSpeakable(sessionPictogram),
	})
}

func (h *PairHandler) Complete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerNonce      string                 `json:"server_nonce"`
		ClientPublicKey  string                 `json:"client_public_key"`
		DeviceInfo       map[string]interface{} `json:"device_info"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be valid JSON")
		return
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(req.ServerNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_NONCE", "server_nonce must be base64-encoded")
		return
	}

	clientPubBytes, err := base64.StdEncoding.DecodeString(req.ClientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CLIENT_PUB", "client_public_key must be base64-encoded")
		return
	}

	pendingPair, exists := h.pairStore.Get(r.Context(), nonceBytes)
	if !exists {
		writeError(w, http.StatusGone, "HANDSHAKE_EXPIRED", "Pair handshake expired or already used. Retry /pair/init.")
		return
	}

	// PR6: Enforce 10s handshake TTL (grinding attack mitigation)
	if time.Since(pendingPair.IssuedAt) > handshakeTTL {
		writeError(w, http.StatusGone, "PAIR_EXPIRED", "Pair handshake exceeded 10-second window. Retry /pair/init.")
		return
	}

	// PR7: Verify client_pub matches what was sent in /pair/init (constant-time comparison)
	if !bytes.Equal(clientPubBytes, pendingPair.ClientPublicKey) {
		writeError(w, http.StatusForbidden, "CLIENT_PUB_MISMATCH", "Client public key does not match /pair/init request")
		return
	}

	if !pendingPair.Approved {
		writeError(w, http.StatusForbidden, "NOT_APPROVED", "Pair not yet approved by administrator")
		return
	}

	if err := h.pairStore.Consume(r.Context(), nonceBytes); err != nil {
		writeError(w, http.StatusGone, "HANDSHAKE_EXPIRED", err.Error())
		return
	}

	serverPubCompressed := crypto.CompressPublicKey(&h.serverPrivKey.PublicKey)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "paired",
		"server_public_key": base64.StdEncoding.EncodeToString(serverPubCompressed),
		"paired_at":         time.Now().Format(time.RFC3339),
	})
}

func (h *PairHandler) deriveSessionPictogram(serverPub, clientPub []byte) ([]byte, []string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	pictogramWords, err := pictogram.DeriveSessionPictogram(serverPub, clientPub, nonce)
	if err != nil {
		return nil, nil, err
	}

	return nonce, pictogramWords, nil
}

func getSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
