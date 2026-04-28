package handlers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sigilauth/server/internal/apikey"
	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/mpa"
)

// DeviceEntry pairs device fingerprint with public key for ECIES encryption.
// C3: Server encrypts action_context to each device's public key.
type DeviceEntry struct {
	Fingerprint string `json:"fingerprint"`
	Pubkey      string `json:"pubkey"` // base64-encoded compressed ECDSA P-256 public key
}

// MPARequestBody matches OpenAPI schema
type MPARequestBody struct {
	Devices  []DeviceEntry              `json:"devices"`  // C3: paired fingerprint+pubkey
	Action   map[string]interface{}     `json:"action"`
	Required int                        `json:"required"`
	Groups   []mpa.Group                `json:"groups,omitempty"`
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

	// SIG-2026-027: Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req MPARequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// C3: Support two input modes:
	// 1. Simple mode: devices array (each device = one group)
	// 2. Complex mode: groups array (multiple members per group)
	var groups []mpa.Group

	if len(req.Devices) > 0 && len(req.Groups) > 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Cannot specify both devices and groups")
		return
	}

	if len(req.Devices) > 0 {
		// Simple mode: Convert DeviceEntry array to Groups with single Members
		if req.Required < 1 || req.Required > len(req.Devices) {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Required must be between 1 and number of devices")
			return
		}

		groups = make([]mpa.Group, len(req.Devices))
		for i, device := range req.Devices {
			// Decode device public key from base64
			devicePubkeyBytes, err := base64.StdEncoding.DecodeString(device.Pubkey)
			if err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_PUBKEY", fmt.Sprintf("Device %d pubkey must be base64", i))
				return
			}

			// Validate fingerprint format (64 hex characters)
			if len(device.Fingerprint) != 64 {
				writeError(w, http.StatusBadRequest, "INVALID_FINGERPRINT", fmt.Sprintf("Device %d fingerprint must be 64 hex characters", i))
				return
			}

			groups[i] = mpa.Group{
				Members: []mpa.Member{
					{
						Fingerprint:     device.Fingerprint,
						DevicePublicKey: devicePubkeyBytes,
					},
				},
			}
		}
	} else if len(req.Groups) > 0 {
		// Complex mode: Use provided groups directly
		if req.Required < 1 || req.Required > len(req.Groups) {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Required must be between 1 and number of groups")
			return
		}
		groups = req.Groups
	} else {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Either devices or groups must be provided")
		return
	}

	// Create MPA request
	requestID := "mpa_" + uuid.New().String()

	// Convert action from map to mpa.Action
	actionType, _ := req.Action["type"].(string)
	actionDesc, _ := req.Action["description"].(string)
	actionParams, _ := req.Action["params"].(map[string]interface{})
	actionDetailsURL, _ := req.Action["details_url"].(string)

	mpaReq, err := h.mpaStore.CreateRequest(r.Context(), mpa.CreateRequest{
		RequestID: requestID,
		Action: mpa.Action{
			Type:        actionType,
			Description: actionDesc,
			Params:      actionParams,
			DetailsURL:  actionDetailsURL,
		},
		Groups:       groups,
		Required:     req.Required,
		RejectPolicy: "reject_on_quorum_impossible",
		ExpiresIn:    10 * time.Minute,
		ServerKey:    h.serverKey,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MPA_CREATION_FAILED", err.Error())
		return
	}

	// C3: Push encrypted action_context to each device via relay
	if h.relayClient != nil {
		// Iterate over all members in all groups
		for _, group := range groups {
			for _, member := range group.Members {
				// Decompress device public key for ECIES encryption
				devicePubkey, err := h.decompressPubkey(member.DevicePublicKey)
				if err != nil {
					// Log error but don't fail the request (push is best-effort)
					continue
				}

				// Serialize action_context for encryption
				actionContextBytes, err := json.Marshal(req.Action)
				if err != nil {
					continue
				}

				// C3: ECIES-encrypt action_context to device public key
				// Context: "SIGIL-MPA-V1" per protocol spec
				fingerprintBytes, _ := hex.DecodeString(member.Fingerprint)
				encryptedActionContext, err := h.encryptActionContext(devicePubkey, actionContextBytes, fingerprintBytes)
				if err != nil {
					// Log error but don't fail the request (push is best-effort)
					continue
				}

				// Build push payload with encrypted action_context
				payload := map[string]interface{}{
					"type":           "mpa.request",
					"request_id":     requestID,
					"action_context": base64.StdEncoding.EncodeToString(encryptedActionContext),
					"required":       req.Required,
					"server_id":      h.serverID,
					"server_pubkey":  h.serverPubkey,
				}

				// Dispatch push notification (async, don't block)
				h.dispatchPushNotification(member.Fingerprint, payload)
			}
		}
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

	// SIG-2026-027: Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

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

	// Fire mpa.approved webhook if MPA request is fully approved (async, don't block response)
	if mpaReq.Status == "approved" {
		keyID := apikey.GetKeyIDFromContext(r.Context())
		if keyID != "" {
			h.deliverWebhook(keyID, "mpa.approved", map[string]interface{}{
				"event":      "mpa.approved",
				"request_id": mpaReq.RequestID,
				"required":   mpaReq.Required,
				"approved":   len(mpaReq.GroupsSatisfied),
			})
		}
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

// decompressPubkey decompresses an ECDSA P-256 public key from compressed format.
func (h *Handler) decompressPubkey(compressed []byte) (*ecdsa.PublicKey, error) {
	return crypto.DecompressPublicKey(compressed)
}

// encryptActionContext encrypts action_context using ECIES for MPA push notifications.
//
// C3: Server encrypts action_context to each device's public key.
// Context: "SIGIL-MPA-V1" per protocol spec.
func (h *Handler) encryptActionContext(devicePubkey *ecdsa.PublicKey, actionContext, fingerprint []byte) ([]byte, error) {
	return crypto.Encrypt(devicePubkey, actionContext, fingerprint, "SIGIL-MPA-V1")
}
