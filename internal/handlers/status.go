package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ChallengeStatusResponse matches OpenAPI schema
type ChallengeStatusResponse struct {
	ChallengeID string `json:"challenge_id"`
	Status      string `json:"status"` // "pending", "verified", "expired", "failed"
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// GetChallengeStatus handles GET /v1/auth/challenge/{id}/status
func (h *Handler) GetChallengeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract challenge ID from path
	// Path format: /v1/auth/challenge/{id}/status
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Challenge ID required")
		return
	}
	challengeID := parts[3]

	// Get challenge from store
	challenge, err := h.sessionStore.GetChallenge(r.Context(), challengeID)
	if err != nil {
		// Challenge not found or expired
		resp := ChallengeStatusResponse{
			ChallengeID: challengeID,
			Status:      "expired",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	status := "pending"
	if challenge.Consumed {
		status = "verified"
	}

	resp := ChallengeStatusResponse{
		ChallengeID: challengeID,
		Status:      status,
		ExpiresAt:   challenge.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DecryptStatusResponse matches OpenAPI schema
type DecryptStatusResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// GetDecryptStatus handles GET /v1/secure/decrypt/{id}/status
func (h *Handler) GetDecryptStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract request ID from path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Request ID required")
		return
	}
	requestID := parts[3]

	// TODO: Implement decrypt status tracking
	// For now, return stub response

	resp := DecryptStatusResponse{
		RequestID: requestID,
		Status:    "completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
