package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/sigilauth/server/internal/apikey"
	"github.com/sigilauth/server/internal/crypto"
)

// DecryptRequest matches OpenAPI schema for /v1/secure/decrypt
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"` // Base64-encoded ECIES ciphertext
	Salt       string `json:"salt"`       // Base64-encoded salt (e.g., request_id for context binding)
}

// DecryptResponse matches OpenAPI schema
type DecryptResponse struct {
	Plaintext string `json:"plaintext"` // Base64-encoded plaintext
}

// SecureDecrypt handles POST /v1/secure/decrypt
//
// Uses ECIES (Elliptic Curve Integrated Encryption Scheme) to decrypt
// ciphertext encrypted with the server's public key.
func (h *Handler) SecureDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CIPHERTEXT", "Ciphertext must be base64")
		return
	}

	// Decode base64 salt
	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SALT", "Salt must be base64")
		return
	}

	// Decrypt using server's private key
	// Ciphertext format: ephemeral_public_key (33) || nonce (12) || ciphertext || tag (16)
	plaintext, err := crypto.Decrypt(h.serverKey, ciphertext, salt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "DECRYPTION_FAILED", err.Error())
		return
	}

	// Encode plaintext as base64
	plaintextB64 := base64.StdEncoding.EncodeToString(plaintext)

	// Fire decrypt.completed webhook (async, don't block response)
	keyID := apikey.GetKeyIDFromContext(r.Context())
	if keyID != "" {
		h.deliverWebhook(keyID, "decrypt.completed", map[string]interface{}{
			"event": "decrypt.completed",
			"salt":  req.Salt, // Return salt for context correlation
		})
	}

	resp := DecryptResponse{
		Plaintext: plaintextB64,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
