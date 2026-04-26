package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/sigilauth/server/internal/apikey"
	"github.com/sigilauth/server/internal/session"
)

// ChallengeRequest matches OpenAPI schema
type ChallengeRequest struct {
	Fingerprint     string                 `json:"fingerprint"`
	DevicePublicKey string                 `json:"device_public_key"`
	Action          map[string]interface{} `json:"action"`
}

// ChallengeResponse matches OpenAPI schema
type ChallengeResponse struct {
	ChallengeID        string   `json:"challenge_id"`
	ChallengeBytes     string   `json:"challenge_bytes"`      // base64(32 bytes)
	ServerSignature    string   `json:"server_signature"`     // base64(64 bytes)
	Pictogram          []string `json:"pictogram"`
	PictogramSpeakable string   `json:"pictogram_speakable"`
	ExpiresAt          string   `json:"expires_at"`
	RespondTo          string   `json:"respond_to"`
}

// CreateChallenge handles POST /challenge
func (h *Handler) CreateChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// Validate fingerprint format (64 hex chars)
	if len(req.Fingerprint) != 64 {
		writeError(w, http.StatusBadRequest, "INVALID_FINGERPRINT", "Fingerprint must be 64 hex characters")
		return
	}

	// Decode device public key (base64)
	devicePubKeyBytes, err := base64.StdEncoding.DecodeString(req.DevicePublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PUBLIC_KEY", "Device public key must be base64")
		return
	}

	// INSTRUMENTATION: Log decoded key
	log.Printf("[TRACE] CreateChallenge handler decoded key: len=%d, hex=%x",
		len(devicePubKeyBytes), devicePubKeyBytes)

	// Validate public key format
	if len(devicePubKeyBytes) != 33 {
		writeError(w, http.StatusBadRequest, "INVALID_PUBLIC_KEY", "Device public key must be 33 bytes compressed")
		return
	}

	// Convert action from map to session.Action
	actionType, _ := req.Action["type"].(string)
	actionDesc, _ := req.Action["description"].(string)
	actionParams, _ := req.Action["params"].(map[string]interface{})

	// Create challenge session
	challenge, err := h.sessionStore.CreateChallenge(r.Context(), session.ChallengeRequest{
		Fingerprint:     req.Fingerprint,
		DevicePublicKey: devicePubKeyBytes,
		Action: session.Action{
			Type:        actionType,
			Description: actionDesc,
			Params:      actionParams,
		},
		ServerKey: h.serverKey,
		TTL:       5 * time.Minute,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CHALLENGE_CREATION_FAILED", err.Error())
		return
	}

	resp := ChallengeResponse{
		ChallengeID:        challenge.ChallengeID,
		ChallengeBytes:     base64.StdEncoding.EncodeToString(challenge.ChallengeBytes),
		ServerSignature:    base64.StdEncoding.EncodeToString(challenge.ServerSignature),
		Pictogram:          challenge.Pictogram,
		PictogramSpeakable: challenge.PictogramSpeakable,
		ExpiresAt:          challenge.ExpiresAt.Format(time.RFC3339),
		RespondTo:          "/respond",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// RespondRequest matches OpenAPI schema
type RespondRequest struct {
	ChallengeID string `json:"challenge_id"`
	Fingerprint string `json:"fingerprint"`
	Signature   string `json:"signature"`
}

// RespondResponse matches OpenAPI schema
type RespondResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// Respond handles POST /respond
func (h *Handler) Respond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RespondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// INSTRUMENTATION: Log respond request
	log.Printf("[TRACE] Respond handler called: challenge_id=%s, fingerprint=%s",
		req.ChallengeID, req.Fingerprint)

	// Check if challenge exists and is not expired BEFORE validating signature format
	// This ensures expired challenges return CHALLENGE_EXPIRED, not INVALID_SIGNATURE
	challenge, err := h.sessionStore.GetChallenge(r.Context(), req.ChallengeID)
	if err != nil {
		// GetChallenge returns "challenge not found" or "challenge expired"
		errMsg := err.Error()
		if errMsg == "challenge not found" || errMsg == "challenge expired" {
			writeError(w, http.StatusGone, "CHALLENGE_EXPIRED", errMsg)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", errMsg)
		return
	}

	// INSTRUMENTATION: Log challenge key from GetChallenge
	log.Printf("[TRACE] Respond handler GetChallenge returned: key_len=%d, key_hex=%x",
		len(challenge.DevicePublicKey), challenge.DevicePublicKey)

	// Now validate signature format
	signatureBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SIGNATURE", "Signature must be base64")
		return
	}

	// Validate fingerprint format (64 hex chars)
	if len(req.Fingerprint) != 64 {
		writeError(w, http.StatusBadRequest, "INVALID_FINGERPRINT", "Fingerprint must be 64 hex characters")
		return
	}

	// Verify challenge (expiry already checked, now verify signature)
	err = h.sessionStore.VerifyChallenge(r.Context(), session.VerifyRequest{
		ChallengeID: req.ChallengeID,
		Fingerprint: req.Fingerprint,
		Signature:   signatureBytes,
	})

	if err != nil {
		// Map error to HTTP status
		errMsg := err.Error()
		if errMsg == "challenge not found" || errMsg == "challenge expired" {
			writeError(w, http.StatusGone, "CHALLENGE_EXPIRED", errMsg)
			return
		}
		if errMsg == "challenge already used" {
			writeError(w, http.StatusConflict, "CHALLENGE_ALREADY_USED", errMsg)
			return
		}
		if errMsg == "fingerprint mismatch" {
			writeError(w, http.StatusBadRequest, "FINGERPRINT_MISMATCH", errMsg)
			return
		}
		writeError(w, http.StatusUnauthorized, "SIGNATURE_INVALID", errMsg)
		return
	}

	// Fire challenge.verified webhook (async, don't block response)
	keyID := apikey.GetKeyIDFromContext(r.Context())
	if keyID != "" {
		h.deliverWebhook(keyID, "challenge.verified", map[string]interface{}{
			"event":        "challenge.verified",
			"challenge_id": req.ChallengeID,
			"fingerprint":  req.Fingerprint,
		})
	}

	resp := RespondResponse{
		Status:  "verified",
		Message: "Authentication successful",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   errorCode,
		"message": message,
	})
}
