package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sigilauth/server/internal/apikey"
	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/initrequest"
)

// InitRequestCreate matches OpenAPI schema for POST /implementor/init/request
type InitRequestCreate struct {
	Selectors         []string `json:"selectors"`          // device fingerprints or ["any"]
	ImplementorPubkey string   `json:"implementor_pubkey"` // base64(compressed P-256)
	TTLSeconds        int      `json:"ttl_seconds"`        // optional, default 300
}

// InitRequestResponse matches OpenAPI schema (both paths)
type InitRequestResponse struct {
	RequestID        string  `json:"request_id"`
	Status           string  `json:"status"`
	ClaimCode        *string `json:"claim_code,omitempty"`         // Path B only
	ClaimQRURL       *string `json:"claim_qr_url,omitempty"`       // Path B only
	ClaimExpiresAt   *string `json:"claim_expires_at,omitempty"`   // Path B only
	RequestExpiresAt string  `json:"request_expires_at,omitempty"` // Path B only (omit for Path A to match spec)
	ExpiresAt        string  `json:"expires_at,omitempty"`         // Path A only
}

// InitPollResponse matches OpenAPI schema for GET /implementor/init/poll
type InitPollResponse struct {
	Status                string  `json:"status"`
	EncryptedMnemonic     *string `json:"encrypted_mnemonic,omitempty"`
	ApprovedByFingerprint *string `json:"approved_by_fingerprint,omitempty"`
	ApprovedAt            *string `json:"approved_at,omitempty"`
	Reason                *string `json:"reason,omitempty"`
	ExpiresAt             *string `json:"expires_at,omitempty"`
}

// DeviceClaimRequest matches OpenAPI schema for POST /device/init/claim
type DeviceClaimRequest struct {
	RequestID         string `json:"request_id"`
	ClaimCode         string `json:"claim_code"`
	DeviceFingerprint string `json:"device_fingerprint"`
	DevicePubkey      string `json:"device_pubkey"`    // base64(compressed P-256, 33 bytes)
	Timestamp         string `json:"timestamp"`        // ISO8601 timestamp (SIG-2026-015: replay protection)
	DeviceSignature   string `json:"device_signature"` // base64(ECDSA sig over request_id || claim_code || timestamp)
}

// DeviceClaimResponse matches OpenAPI schema
type DeviceClaimResponse struct {
	Status              string `json:"status"`
	PinnedToFingerprint string `json:"pinned_to_fingerprint"`
}

// DeviceRespondRequest matches OpenAPI schema for POST /device/init/respond
type DeviceRespondRequest struct {
	RequestID         string  `json:"request_id"`
	DeviceFingerprint string  `json:"device_fingerprint"`
	DevicePubkey      string  `json:"device_pubkey"` // base64(compressed P-256, 33 bytes)
	Action            string  `json:"action"`        // "approve" or "reject"
	EncryptedMnemonic *string `json:"encrypted_mnemonic,omitempty"`
	RejectionReason   *string `json:"rejection_reason,omitempty"`
	Timestamp         string  `json:"timestamp"`        // ISO8601 timestamp (SIG-2026-015: replay protection)
	DeviceSignature   string  `json:"device_signature"` // base64(ECDSA sig over request_id || action || [hash] || timestamp)
}

// DeviceRespondResponse matches OpenAPI schema
type DeviceRespondResponse struct {
	Status string `json:"status"`
}

// ImplementorInitRequest handles POST /implementor/init/request
//
// Creates a new implementor engine initialization request. Two paths:
// - Path A: Specific device fingerprints (push to devices)
// - Path B: Open claim with code gate (user enters code)
func (h *Handler) ImplementorInitRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SIG-2026-027: Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req InitRequestCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// Validate selectors
	if len(req.Selectors) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_SELECTOR", "Selector array cannot be empty")
		return
	}

	// Decode and validate implementor public key
	pubkeyBytes, err := base64.StdEncoding.DecodeString(req.ImplementorPubkey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PUBKEY", "Implementor pubkey must be base64")
		return
	}
	if len(pubkeyBytes) != 33 {
		writeError(w, http.StatusBadRequest, "INVALID_PUBKEY", "Implementor pubkey must be 33-byte compressed P-256")
		return
	}

	// Validate TTL
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds == 0 {
		ttl = initrequest.DefaultRequestTTL
	}
	if ttl < initrequest.MinRequestTTL || ttl > initrequest.MaxRequestTTL {
		writeError(w, http.StatusBadRequest, "INVALID_TTL", fmt.Sprintf("TTL must be between %d and %d seconds", int(initrequest.MinRequestTTL.Seconds()), int(initrequest.MaxRequestTTL.Seconds())))
		return
	}

	// Generate request ID (SPEC-HIGH-3: MUST use CSPRNG, fail if unavailable)
	randID, err := generateRequestID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "CSPRNG failure - cannot generate secure request ID")
		return
	}
	requestID := fmt.Sprintf("init_req_%s", randID)

	// Create request in store
	initReq, err := h.initRequestStore.Create(r.Context(), requestID, req.Selectors, pubkeyBytes, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create request")
		return
	}

	// Build response
	resp := InitRequestResponse{
		RequestID: initReq.RequestID,
		Status:    initReq.Status,
	}

	// Path B: include claim code
	if initReq.Status == initrequest.StatusPendingClaim {
		resp.ClaimCode = &initReq.ClaimCode
		// Build QR URL using configured base URL
		baseURL := h.baseURL
		if baseURL == "" {
			baseURL = "https://sigil.example.com" // Fallback for development
		}
		qrURL := fmt.Sprintf("%s/claim?r=%s&c=%s", baseURL, initReq.RequestID, initReq.ClaimCode)
		resp.ClaimQRURL = &qrURL
		claimExpiry := initReq.ClaimExpiresAt.Format(time.RFC3339)
		resp.ClaimExpiresAt = &claimExpiry
		requestExpiry := initReq.ExpiresAt.Format(time.RFC3339)
		resp.RequestExpiresAt = requestExpiry
	} else {
		// Path A: include expires_at
		expiresAt := initReq.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = expiresAt
	}

	// Fire webhook (async)
	keyID := apikey.GetKeyIDFromContext(r.Context())
	if keyID != "" {
		h.deliverWebhook(keyID, "init.request.created", map[string]interface{}{
			"event":      "init.request.created",
			"request_id": requestID,
			"path":       initReq.Status,
		})
	}

	// Push notification dispatch (async)
	// Path A: push to all listed fingerprints immediately
	// Path B: DON'T push yet (wait for claim)
	if initReq.Status == initrequest.StatusPending {
		// Path A: push to all specific fingerprints
		implementorPubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes)
		for _, fingerprint := range initReq.Selectors {
			payload := map[string]interface{}{
				"type":               "init_request",
				"request_id":         initReq.RequestID,
				"server_id":          h.serverID,
				"server_pubkey":      h.serverPubkey,
				"implementor_pubkey": implementorPubkeyB64,
				"action": map[string]interface{}{
					"type":        "engine:init",
					"description": "Generate mnemonic for new engine",
				},
				"expires_at": initReq.ExpiresAt.Format(time.RFC3339),
			}
			h.dispatchPushNotification(fingerprint, payload)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// ImplementorInitPoll handles GET /implementor/init/poll
//
// Long-poll for init request status. Returns immediately on state change
// or after timeout_ms expires.
func (h *Handler) ImplementorInitPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SIG-2026-014 + SIG-2026-021: Limit concurrent long-poll connections
	keyID := apikey.GetKeyIDFromContext(r.Context())
	if keyID != "" {
		status := h.tryAcquirePollSlot(keyID)
		switch status {
		case PollSlotPerKeyLimitReached:
			writeError(w, http.StatusTooManyRequests, "TOO_MANY_POLLS",
				"Maximum concurrent poll connections exceeded (limit: 10 per API key)")
			return
		case PollSlotGlobalLimitReached:
			writeError(w, http.StatusServiceUnavailable, "SERVER_BUSY",
				"Server at capacity. Try again later.")
			return
		case PollSlotAcquired:
			defer h.releasePollSlot(keyID)
		}
	}

	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id required")
		return
	}

	// Parse timeout_ms (max 30000ms per spec)
	timeoutMs := 0
	if timeoutStr := r.URL.Query().Get("timeout_ms"); timeoutStr != "" {
		if _, err := fmt.Sscanf(timeoutStr, "%d", &timeoutMs); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_TIMEOUT", "timeout_ms must be integer")
			return
		}
		if timeoutMs < 0 || timeoutMs > 30000 {
			writeError(w, http.StatusBadRequest, "INVALID_TIMEOUT", "timeout_ms must be 0-30000")
			return
		}
	}

	// Get initial state
	req, err := h.initRequestStore.Get(requestID)
	if err != nil {
		if err == initrequest.ErrRequestNotFound {
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found or already cleaned up")
			return
		}
		if err == initrequest.ErrRequestExpired {
			h.respondPoll(w, initrequest.StatusExpired, nil, nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	initialStatus := req.Status

	// If timeout_ms specified and state is pending, long-poll
	if timeoutMs > 0 && isPendingState(initialStatus) {
		timeout := time.Duration(timeoutMs) * time.Millisecond
		deadline := time.Now().Add(timeout)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				req, err := h.initRequestStore.Get(requestID)
				if err != nil {
					if err == initrequest.ErrRequestExpired {
						h.respondPoll(w, initrequest.StatusExpired, nil, nil)
						return
					}
					if err == initrequest.ErrRequestNotFound {
						writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found")
						return
					}
					// Other errors: return current state
					h.respondPollWithRequest(w, req)
					return
				}

				// State changed to terminal state — return immediately
				if !isPendingState(req.Status) {
					h.respondPollWithRequest(w, req)
					return
				}

				// Check timeout
				if time.Now().After(deadline) {
					h.respondPollWithRequest(w, req)
					return
				}

			case <-r.Context().Done():
				// Client disconnected
				return
			}
		}
	}

	// No timeout or already terminal state — return immediately
	h.respondPollWithRequest(w, req)
}

// isPendingState returns true if status is pending/pending_claim/claimed
func isPendingState(status string) bool {
	return status == initrequest.StatusPending ||
		status == initrequest.StatusPendingClaim ||
		status == initrequest.StatusClaimed
}

// respondPollWithRequest builds and sends poll response from request
func (h *Handler) respondPollWithRequest(w http.ResponseWriter, req *initrequest.Request) {
	resp := InitPollResponse{
		Status: req.Status,
	}

	// Include expires_at for pending states
	if isPendingState(req.Status) {
		expiresAt := req.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &expiresAt
	}

	// Include encrypted mnemonic if approved
	if req.Status == initrequest.StatusApproved {
		mnemonicB64 := base64.StdEncoding.EncodeToString(req.EncryptedMnemonic)
		resp.EncryptedMnemonic = &mnemonicB64
		resp.ApprovedByFingerprint = &req.ApprovedByFingerprint
		approvedAt := req.ApprovedAt.Format(time.RFC3339)
		resp.ApprovedAt = &approvedAt
	}

	// Include reason for rejected/expired/invalidated
	if req.Status == initrequest.StatusRejected {
		resp.Reason = &req.RejectionReason
	}
	if req.Status == initrequest.StatusInvalidated {
		reason := "claim_brute_force"
		resp.Reason = &reason
	}
	if req.Status == initrequest.StatusExpired {
		reason := "ttl_expired"
		resp.Reason = &reason
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// respondPoll sends poll response with just status and optional reason
func (h *Handler) respondPoll(w http.ResponseWriter, status string, reason *string, expiresAt *string) {
	resp := InitPollResponse{
		Status:    status,
		Reason:    reason,
		ExpiresAt: expiresAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// DeviceInitClaim handles POST /device/init/claim
//
// Device claims an open init request (Path B) by submitting the claim code.
// After successful claim, request is pinned to this device's fingerprint.
func (h *Handler) DeviceInitClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SIG-2026-027: Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req DeviceClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// SIG-2026-015: Validate timestamp (replay protection)
	if err := validateTimestamp(req.Timestamp); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TIMESTAMP", err.Error())
		return
	}

	// Verify device signature (includes timestamp for replay protection)
	// Message signed: request_id || claim_code || timestamp
	message := []byte(req.RequestID + req.ClaimCode + req.Timestamp)
	if err := verifyDeviceSignature(req.DevicePubkey, req.DeviceFingerprint, req.DeviceSignature, message); err != nil {
		writeError(w, http.StatusUnauthorized, "SIGNATURE_INVALID", err.Error())
		return
	}

	// Attempt claim
	err := h.initRequestStore.Claim(req.RequestID, req.ClaimCode, req.DeviceFingerprint)
	if err != nil {
		if err == initrequest.ErrRequestNotFound {
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found")
			return
		}
		if err == initrequest.ErrAlreadyClaimed {
			writeError(w, http.StatusConflict, "ALREADY_CLAIMED", "Another device already claimed this request")
			return
		}
		if err == initrequest.ErrClaimCodeExpired {
			writeError(w, http.StatusGone, "CODE_EXPIRED", "Claim code expired (60s TTL)")
			return
		}
		if err == initrequest.ErrRequestExpired {
			writeError(w, http.StatusGone, "REQUEST_EXPIRED", "Request expired")
			return
		}
		if err == initrequest.ErrRequestInvalidated {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMIT", "Too many failed claim attempts - request invalidated")
			return
		}
		if err == initrequest.ErrInvalidLength || err == initrequest.ErrInvalidCharacter {
			// SIG-2026-013: store.Claim() already increments failure counter
			writeError(w, http.StatusBadRequest, "INVALID_CODE", err.Error())
			return
		}
		// Code mismatch or other error - store.Claim() already incremented counter
		writeError(w, http.StatusBadRequest, "INVALID_CODE", "Claim code mismatch")
		return
	}

	// Successfully claimed
	resp := DeviceClaimResponse{
		Status:              "claimed",
		PinnedToFingerprint: req.DeviceFingerprint,
	}

	// Push init request notification to claimed device
	// Need to fetch request to get implementor_pubkey
	claimedReq, err := h.initRequestStore.Get(req.RequestID)
	if err == nil {
		// Build push payload
		implementorPubkeyB64 := base64.StdEncoding.EncodeToString(claimedReq.ImplementorPubkey)
		payload := map[string]interface{}{
			"type":               "init_request",
			"request_id":         claimedReq.RequestID,
			"server_id":          h.serverID,
			"server_pubkey":      h.serverPubkey,
			"implementor_pubkey": implementorPubkeyB64,
			"action": map[string]interface{}{
				"type":        "engine:init",
				"description": "Generate mnemonic for new engine",
			},
			"expires_at": claimedReq.ExpiresAt.Format(time.RFC3339),
		}
		h.dispatchPushNotification(req.DeviceFingerprint, payload)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// DeviceInitRespond handles POST /device/init/respond
//
// Device approves or rejects an init request. Approval includes
// end-to-end encrypted mnemonic (device → implementor).
func (h *Handler) DeviceInitRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SIG-2026-027: Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req DeviceRespondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// SPEC-HIGH-2: Fetch request to check Path B fingerprint validation
	storedReq, err := h.initRequestStore.Get(req.RequestID)
	if err != nil {
		if err == initrequest.ErrRequestNotFound {
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found")
			return
		}
		if err == initrequest.ErrRequestExpired {
			writeError(w, http.StatusGone, "REQUEST_EXPIRED", "Request expired")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	// SPEC-HIGH-2: Path B fingerprint validation
	// If request was claimed (Path B), verify responder fingerprint matches claimer
	if storedReq.ClaimedByFingerprint != "" && storedReq.ClaimedByFingerprint != req.DeviceFingerprint {
		writeError(w, http.StatusForbidden, "FINGERPRINT_MISMATCH", "Device fingerprint does not match claiming device (Path B)")
		return
	}

	// SIG-2026-020: Path A selectors authorization
	// If request has specific selectors (Path A), verify responder is authorized
	if len(storedReq.Selectors) > 0 && storedReq.Selectors[0] != "any" {
		authorized := false
		for _, selector := range storedReq.Selectors {
			if selector == req.DeviceFingerprint {
				authorized = true
				break
			}
		}
		if !authorized {
			writeError(w, http.StatusForbidden, "UNAUTHORIZED", "Device fingerprint not in authorized selectors list (Path A)")
			return
		}
	}

	// SIG-2026-015: Validate timestamp (replay protection)
	if err := validateTimestamp(req.Timestamp); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TIMESTAMP", err.Error())
		return
	}

	// SPEC-HIGH-1 + SIG-2026-015: Build message for signature verification
	var message []byte
	var mnemonicBytes []byte

	if req.Action == "approve" {
		// Validate encrypted mnemonic present
		if req.EncryptedMnemonic == nil || *req.EncryptedMnemonic == "" {
			writeError(w, http.StatusBadRequest, "INVALID_MNEMONIC", "encrypted_mnemonic required for approve action")
			return
		}

		// Decode encrypted mnemonic
		mnemonicBytes, err = base64.StdEncoding.DecodeString(*req.EncryptedMnemonic)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_MNEMONIC", "encrypted_mnemonic must be base64")
			return
		}

		// SPEC-HIGH-1: Message includes SHA256 hash of encrypted_mnemonic
		// SIG-2026-015: Message includes timestamp for replay protection
		mnemonicHash := sha256.Sum256(mnemonicBytes)
		message = []byte(req.RequestID + req.Action)
		message = append(message, mnemonicHash[:]...)
		message = append(message, []byte(req.Timestamp)...)
	} else if req.Action == "reject" {
		// Reject: message = request_id || action || timestamp
		message = []byte(req.RequestID + req.Action + req.Timestamp)
	} else {
		writeError(w, http.StatusBadRequest, "INVALID_ACTION", "action must be 'approve' or 'reject'")
		return
	}

	// Verify device signature
	if err := verifyDeviceSignature(req.DevicePubkey, req.DeviceFingerprint, req.DeviceSignature, message); err != nil {
		writeError(w, http.StatusUnauthorized, "SIGNATURE_INVALID", err.Error())
		return
	}

	if req.Action == "approve" {

		// Approve
		err = h.initRequestStore.Approve(req.RequestID, req.DeviceFingerprint, mnemonicBytes)
		if err != nil {
			if err == initrequest.ErrRequestNotFound {
				writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found")
				return
			}
			if err == initrequest.ErrRequestExpired {
				writeError(w, http.StatusGone, "REQUEST_EXPIRED", "Request expired")
				return
			}
			if err == initrequest.ErrAlreadyApproved {
				writeError(w, http.StatusConflict, "ALREADY_APPROVED", "Another device already approved (first-wins)")
				return
			}
			if err == initrequest.ErrRequestInvalidated {
				writeError(w, http.StatusGone, "INVALIDATED", "Request invalidated")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		// TODO: Clear push notifications to other devices

	} else if req.Action == "reject" {
		reason := "user_declined"
		if req.RejectionReason != nil {
			reason = *req.RejectionReason
		}

		err := h.initRequestStore.Reject(req.RequestID, req.DeviceFingerprint, reason)
		if err != nil {
			if err == initrequest.ErrRequestNotFound {
				writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "Request not found")
				return
			}
			if err == initrequest.ErrRequestExpired {
				writeError(w, http.StatusGone, "REQUEST_EXPIRED", "Request expired")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

	} else {
		writeError(w, http.StatusBadRequest, "INVALID_ACTION", "action must be 'approve' or 'reject'")
		return
	}

	resp := DeviceRespondResponse{
		Status: "accepted",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// verifyDeviceSignature verifies device public key and signature.
//
// Verifies:
// 1. device_pubkey decodes to valid 33-byte compressed P-256 key
// 2. Fingerprint(device_pubkey) == device_fingerprint
// 3. Signature is valid for the given message
//
// Returns error with user-facing message on failure.
func verifyDeviceSignature(devicePubkeyB64, deviceFingerprintHex, deviceSignatureB64 string, message []byte) error {
	// Decode public key
	pubkeyBytes, err := base64.StdEncoding.DecodeString(devicePubkeyB64)
	if err != nil {
		return fmt.Errorf("device_pubkey must be base64")
	}
	if len(pubkeyBytes) != 33 {
		return fmt.Errorf("device_pubkey must be 33-byte compressed P-256, got %d bytes", len(pubkeyBytes))
	}

	// Decompress public key
	pubkey, err := crypto.DecompressPublicKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("invalid device_pubkey: %w", err)
	}

	// Verify fingerprint matches public key
	computedFingerprint := crypto.FingerprintFromPublicKey(pubkey)
	computedFingerprintHex := hex.EncodeToString(computedFingerprint)

	// SIG-2026-019: Constant-time comparison to prevent timing side-channel attacks
	if len(deviceFingerprintHex) != len(computedFingerprintHex) {
		return fmt.Errorf("device_fingerprint does not match device_pubkey")
	}
	if subtle.ConstantTimeCompare([]byte(deviceFingerprintHex), []byte(computedFingerprintHex)) != 1 {
		return fmt.Errorf("device_fingerprint does not match device_pubkey")
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(deviceSignatureB64)
	if err != nil {
		return fmt.Errorf("device_signature must be base64")
	}

	// Verify signature
	if err := crypto.Verify(pubkey, message, signatureBytes); err != nil {
		return fmt.Errorf("device_signature verification failed: %w", err)
	}

	return nil
}

// generateRequestID generates a unique request ID using crypto/rand.
//
// SPEC-HIGH-3: MUST use CSPRNG. Returns error if CSPRNG fails.
// NEVER falls back to predictable IDs (timestamps, counters).
func generateRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("CSPRNG failure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// validateTimestamp validates that timestamp is within acceptable window (±60s).
//
// SIG-2026-015: Replay protection. Rejects requests with stale or future timestamps.
// Accepts ISO8601 format (RFC3339).
func validateTimestamp(timestampStr string) error {
	// Parse ISO8601 timestamp
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return fmt.Errorf("timestamp must be ISO8601 format")
	}

	// Check if within ±60s window
	now := time.Now()
	diff := now.Sub(timestamp)
	if diff < -60*time.Second {
		return fmt.Errorf("timestamp too far in future (max 60s ahead)")
	}
	if diff > 60*time.Second {
		return fmt.Errorf("timestamp too old (max 60s behind)")
	}

	return nil
}
