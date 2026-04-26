package handlers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/envelope"
	"github.com/sigilauth/server/internal/replay"
)

type EnvelopeHandler struct {
	serverPrivKey *ecdsa.PrivateKey
	nonceStore    *replay.NonceStore
	timestampWindow int64
}

func NewEnvelopeHandler(serverPrivKey *ecdsa.PrivateKey) *EnvelopeHandler {
	return &EnvelopeHandler{
		serverPrivKey:   serverPrivKey,
		nonceStore:      replay.NewNonceStore(5 * time.Minute),
		timestampWindow: 300,
	}
}

func (h *EnvelopeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req envelope.OuterEnvelope
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be valid JSON")
		return
	}

	payload, clientPub, err := envelope.DecryptRequest(h.serverPrivKey, req.Envelope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ENVELOPE_INVALID", "envelope verification failed")
		return
	}

	if !replay.VerifyTimestamp(r.Context(), payload.Timestamp, h.timestampWindow) {
		writeError(w, http.StatusBadRequest, "ENVELOPE_INVALID", "envelope verification failed")
		return
	}

	if !h.nonceStore.Check(payload.Nonce) {
		writeError(w, http.StatusBadRequest, "ENVELOPE_INVALID", "envelope verification failed")
		return
	}

	serverPubCompressed := crypto.CompressPublicKey(&h.serverPrivKey.PublicKey)
	serverFingerprint := crypto.FingerprintFromPublicKey(&h.serverPrivKey.PublicKey)
	expectedAudience := hex.EncodeToString(serverFingerprint)

	if payload.Audience != expectedAudience {
		writeError(w, http.StatusBadRequest, "ENVELOPE_INVALID", "envelope verification failed")
		return
	}
	_ = serverPubCompressed

	nonce, err := generateNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "NONCE_GENERATION_FAILED", "failed to generate nonce")
		return
	}

	respPayload := &envelope.ResponsePayload{
		Status:    "ok",
		Body:      map[string]interface{}{"message": "envelope received"},
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	respEnvelope, err := envelope.EncryptResponse(h.serverPrivKey, clientPub, respPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ENVELOPE_ENCRYPTION_FAILED", "failed to encrypt response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"envelope": respEnvelope,
	})
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
