package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sigilauth/server/internal/mpa"
)

// MPARequestBody matches OpenAPI schema
type MPARequestBody struct {
	Fingerprints []string               `json:"fingerprints"`
	Action       map[string]interface{} `json:"action"`
	Required     int                    `json:"required"`
	Groups       []mpa.Group            `json:"groups,omitempty"`
}

// MPARequestResponse matches OpenAPI schema
type MPARequestResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Required  int    `json:"required"`
	Approved  int    `json:"approved"`
}

// CreateMPARequest handles POST /mpa/request
func (h *Handler) CreateMPARequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MPARequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	if len(req.Fingerprints) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "At least one fingerprint required")
		return
	}

	if req.Required < 1 || req.Required > len(req.Fingerprints) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Required must be between 1 and number of fingerprints")
		return
	}

	// Create MPA request
	requestID := "mpa_" + uuid.New().String()

	// Convert action from map to mpa.Action
	actionType, _ := req.Action["type"].(string)
	actionDesc, _ := req.Action["description"].(string)
	actionParams, _ := req.Action["params"].(map[string]interface{})

	mpaReq, err := h.mpaStore.CreateRequest(r.Context(), mpa.CreateRequest{
		RequestID: requestID,
		Action: mpa.Action{
			Type:        actionType,
			Description: actionDesc,
			Params:      actionParams,
		},
		Groups:       req.Groups,
		Required:     req.Required,
		RejectPolicy: "reject_on_quorum_impossible",
		ExpiresIn:    10 * time.Minute,
		ServerKey:    h.serverKey,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MPA_CREATION_FAILED", err.Error())
		return
	}

	resp := MPARequestResponse{
		RequestID: mpaReq.RequestID,
		Status:    mpaReq.Status,
		Required:  mpaReq.Required,
		Approved:  len(mpaReq.GroupsSatisfied),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// MPARespondBody matches OpenAPI schema
type MPARespondBody struct {
	RequestID   string `json:"request_id"`
	Fingerprint string `json:"fingerprint"`
	Signature   string `json:"signature"`
	Approved    bool   `json:"approved"`
}

// RespondMPA handles POST /mpa/respond
func (h *Handler) RespondMPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MPARespondBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// Decode signature
	signature, err := decodeBase64(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SIGNATURE", "Signature must be base64")
		return
	}

	// Validate fingerprint format
	if len(req.Fingerprint) != 64 {
		writeError(w, http.StatusBadRequest, "INVALID_FINGERPRINT", "Fingerprint must be 64 hex characters")
		return
	}

	decision := "rejected"
	if req.Approved {
		decision = "approved"
	}

	mpaReq, err := h.mpaStore.Respond(r.Context(), mpa.Response{
		RequestID:   req.RequestID,
		Fingerprint: req.Fingerprint,
		Signature:   signature,
		Decision:    decision,
	})
	if err != nil {
		if err.Error() == "request not found" || err.Error() == "request expired" {
			writeError(w, http.StatusNotFound, "MPA_NOT_FOUND", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "MPA_RESPONSE_FAILED", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   mpaReq.Status,
		"approved": len(mpaReq.GroupsSatisfied),
		"required": mpaReq.Required,
	})
}

// GetMPAStatus handles GET /mpa/status/{request_id}
func (h *Handler) GetMPAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract request_id from path: /mpa/status/{request_id}
	requestID := r.URL.Path[len("/mpa/status/"):]
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Request ID required")
		return
	}

	mpaReq, err := h.mpaStore.GetRequest(r.Context(), requestID)
	if err != nil {
		writeError(w, http.StatusNotFound, "MPA_NOT_FOUND", err.Error())
		return
	}

	resp := MPARequestResponse{
		RequestID: mpaReq.RequestID,
		Status:    mpaReq.Status,
		Required:  mpaReq.Required,
		Approved:  len(mpaReq.GroupsSatisfied),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
