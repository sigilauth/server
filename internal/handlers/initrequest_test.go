package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestDevice creates a test device with keypair, pubkey, fingerprint, and signature capability
func generateTestDevice(t *testing.T) (privateKey *ecdsa.PrivateKey, pubkeyB64 string, fingerprintHex string, signFunc func([]byte) string) {
	t.Helper()

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	compressedPubkey := crypto.CompressPublicKey(&deviceKey.PublicKey)
	pubkeyB64 = base64.StdEncoding.EncodeToString(compressedPubkey)

	fingerprint := crypto.FingerprintFromPublicKey(&deviceKey.PublicKey)
	fingerprintHex = hex.EncodeToString(fingerprint)

	signFunc = func(message []byte) string {
		sig, err := crypto.Sign(deviceKey, message)
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(sig)
	}

	return deviceKey, pubkeyB64, fingerprintHex, signFunc
}

func TestImplementorInitRequest_PathA(t *testing.T) {
	handler, _ := setupHandler(t)

	// Generate implementor keypair
	implKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	if implKey.PublicKey.Y.Bit(0) == 1 {
		compressedPubkey[0] = 0x03
	}
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	reqBody := map[string]interface{}{
		"selectors":          []string{"fp_abc123", "fp_def456"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ImplementorInitRequest(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["request_id"])
	assert.Equal(t, "pending", resp["status"])
	assert.NotEmpty(t, resp["expires_at"])
	assert.Nil(t, resp["claim_code"], "Path A should not have claim code")
}

func TestImplementorInitRequest_PathB(t *testing.T) {
	handler, _ := setupHandler(t)

	implKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	if implKey.PublicKey.Y.Bit(0) == 1 {
		compressedPubkey[0] = 0x03
	}
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	reqBody := map[string]interface{}{
		"selectors":          []string{"any"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ImplementorInitRequest(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["request_id"])
	assert.Equal(t, "pending_claim", resp["status"])
	assert.NotEmpty(t, resp["claim_code"], "Path B should have claim code")
	assert.Len(t, resp["claim_code"].(string), 6, "Claim code should be 6 characters")
	assert.NotEmpty(t, resp["claim_qr_url"])
	assert.NotEmpty(t, resp["claim_expires_at"])
	assert.NotEmpty(t, resp["request_expires_at"])
}

func TestImplementorInitRequest_InvalidPubkey(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"selectors":          []string{"any"},
		"implementor_pubkey": "invalid-base64",
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ImplementorInitRequest(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "INVALID_PUBKEY", resp["error"])
}

func TestImplementorInitPoll_Pending(t *testing.T) {
	handler, _ := setupHandler(t)

	// Create a request first
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{"fp_abc123"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)

	// Now poll
	pollReq := httptest.NewRequest(http.MethodGet, "/implementor/init/poll?request_id="+requestID, nil)
	pollW := httptest.NewRecorder()

	handler.ImplementorInitPoll(pollW, pollReq)

	assert.Equal(t, http.StatusOK, pollW.Code)

	var pollResp map[string]interface{}
	json.NewDecoder(pollW.Body).Decode(&pollResp)
	assert.Equal(t, "pending", pollResp["status"])
	assert.NotEmpty(t, pollResp["expires_at"])
}

func TestDeviceInitClaim_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	// Create Path B request
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{"any"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)
	claimCode := createResp["claim_code"].(string)

	// Generate device key and sign claim
	_, devicePubkeyB64, deviceFingerprintHex, signDevice := generateTestDevice(t)

	// SIG-2026-015: Include timestamp in signature
	timestamp := time.Now().Format(time.RFC3339)
	claimMessage := []byte(requestID + claimCode + timestamp)
	claimSignature := signDevice(claimMessage)

	// Claim it
	claimBody := map[string]interface{}{
		"request_id":         requestID,
		"claim_code":         claimCode,
		"device_fingerprint": deviceFingerprintHex,
		"device_pubkey":      devicePubkeyB64,
		"timestamp":          timestamp,
		"device_signature":   claimSignature,
	}

	claimBodyJSON, _ := json.Marshal(claimBody)
	claimReq := httptest.NewRequest(http.MethodPost, "/device/init/claim", bytes.NewReader(claimBodyJSON))
	claimW := httptest.NewRecorder()

	handler.DeviceInitClaim(claimW, claimReq)

	assert.Equal(t, http.StatusOK, claimW.Code)

	var claimResp map[string]interface{}
	json.NewDecoder(claimW.Body).Decode(&claimResp)
	assert.Equal(t, "claimed", claimResp["status"])
	assert.Equal(t, deviceFingerprintHex, claimResp["pinned_to_fingerprint"])
}

func TestDeviceInitRespond_Approve(t *testing.T) {
	handler, _ := setupHandler(t)

	// Generate device key first (needed for selectors in Path A)
	_, devicePubkeyB64, deviceFingerprintHex, signDevice := generateTestDevice(t)

	// Create Path A request with device fingerprint in selectors (SIG-2026-020)
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{deviceFingerprintHex},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)
	action := "approve"

	// SPEC-HIGH-1: Approve signature includes hash(encrypted_mnemonic)
	// SIG-2026-015: Signature includes timestamp for replay protection
	mnemonicData := []byte("encrypted mnemonic data")
	encryptedMnemonic := base64.StdEncoding.EncodeToString(mnemonicData)
	mnemonicHash := sha256.Sum256(mnemonicData)

	timestamp := time.Now().Format(time.RFC3339)
	respondMessage := []byte(requestID + action)
	respondMessage = append(respondMessage, mnemonicHash[:]...)
	respondMessage = append(respondMessage, []byte(timestamp)...)
	respondSignature := signDevice(respondMessage)

	respondBody := map[string]interface{}{
		"request_id":         requestID,
		"device_fingerprint": deviceFingerprintHex,
		"device_pubkey":      devicePubkeyB64,
		"action":             action,
		"encrypted_mnemonic": encryptedMnemonic,
		"timestamp":          timestamp,
		"device_signature":   respondSignature,
	}

	respondBodyJSON, _ := json.Marshal(respondBody)
	respondReq := httptest.NewRequest(http.MethodPost, "/device/init/respond", bytes.NewReader(respondBodyJSON))
	respondW := httptest.NewRecorder()

	handler.DeviceInitRespond(respondW, respondReq)

	assert.Equal(t, http.StatusOK, respondW.Code)

	var respondResp map[string]interface{}
	json.NewDecoder(respondW.Body).Decode(&respondResp)
	assert.Equal(t, "accepted", respondResp["status"])

	// Verify poll shows approved status
	pollReq := httptest.NewRequest(http.MethodGet, "/implementor/init/poll?request_id="+requestID, nil)
	pollW := httptest.NewRecorder()
	handler.ImplementorInitPoll(pollW, pollReq)

	var pollResp map[string]interface{}
	json.NewDecoder(pollW.Body).Decode(&pollResp)
	assert.Equal(t, "approved", pollResp["status"])
	assert.NotEmpty(t, pollResp["encrypted_mnemonic"])
	assert.Equal(t, deviceFingerprintHex, pollResp["approved_by_fingerprint"])
}

func TestImplementorInitPoll_LongPoll_ReturnsOnStateChange(t *testing.T) {
	handler, _ := setupHandler(t)

	// Create Path A request
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{"fp_abc123"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)

	// Start long-poll in goroutine
	pollStart := time.Now()
	pollDone := make(chan bool)
	var pollResp map[string]interface{}

	go func() {
		pollReq := httptest.NewRequest(http.MethodGet, "/implementor/init/poll?request_id="+requestID+"&timeout_ms=5000", nil)
		pollW := httptest.NewRecorder()
		handler.ImplementorInitPoll(pollW, pollReq)
		json.NewDecoder(pollW.Body).Decode(&pollResp)
		pollDone <- true
	}()

	// Wait 500ms then approve
	time.Sleep(500 * time.Millisecond)

	_, devicePubkeyB64, deviceFingerprintHex, signDevice := generateTestDevice(t)
	action := "approve"
	respondMessage := []byte(requestID + action)
	respondSignature := signDevice(respondMessage)

	encryptedMnemonic := base64.StdEncoding.EncodeToString([]byte("encrypted mnemonic"))
	respondBody := map[string]interface{}{
		"request_id":         requestID,
		"device_fingerprint": deviceFingerprintHex,
		"device_pubkey":      devicePubkeyB64,
		"action":             action,
		"encrypted_mnemonic": encryptedMnemonic,
		"device_signature":   respondSignature,
	}

	respondBodyJSON, _ := json.Marshal(respondBody)
	respondReq := httptest.NewRequest(http.MethodPost, "/device/init/respond", bytes.NewReader(respondBodyJSON))
	respondW := httptest.NewRecorder()
	handler.DeviceInitRespond(respondW, respondReq)

	// Wait for poll to complete
	<-pollDone
	pollDuration := time.Since(pollStart)

	// Poll should return immediately on state change (< 2s, well before 5s timeout)
	assert.Less(t, pollDuration, 2*time.Second, "poll should return immediately on state change")
	assert.Equal(t, "approved", pollResp["status"])
	assert.NotEmpty(t, pollResp["encrypted_mnemonic"])
}

func TestImplementorInitPoll_LongPoll_Timeout(t *testing.T) {
	handler, _ := setupHandler(t)

	// Create Path A request
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{"fp_abc123"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)

	// Long-poll with 1 second timeout, no state change
	pollStart := time.Now()
	pollReq := httptest.NewRequest(http.MethodGet, "/implementor/init/poll?request_id="+requestID+"&timeout_ms=1000", nil)
	pollW := httptest.NewRecorder()
	handler.ImplementorInitPoll(pollW, pollReq)
	pollDuration := time.Since(pollStart)

	var pollResp map[string]interface{}
	json.NewDecoder(pollW.Body).Decode(&pollResp)

	// Should wait approximately 1 second (allow some margin)
	assert.GreaterOrEqual(t, pollDuration, 1*time.Second, "should wait for timeout")
	assert.Less(t, pollDuration, 1500*time.Millisecond, "should not wait much longer than timeout")
	assert.Equal(t, "pending", pollResp["status"])
}

func TestImplementorInitPoll_NoTimeout_ImmediateReturn(t *testing.T) {
	handler, _ := setupHandler(t)

	// Create Path A request
	implKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubkeyBytes := elliptic.Marshal(implKey.Curve, implKey.PublicKey.X, implKey.PublicKey.Y)
	compressedPubkey := make([]byte, 33)
	compressedPubkey[0] = 0x02
	copy(compressedPubkey[1:], pubkeyBytes[1:33])

	createBody := map[string]interface{}{
		"selectors":          []string{"fp_abc123"},
		"implementor_pubkey": base64.StdEncoding.EncodeToString(compressedPubkey),
		"ttl_seconds":        300,
	}

	body, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/implementor/init/request", bytes.NewReader(body))
	createW := httptest.NewRecorder()
	handler.ImplementorInitRequest(createW, createReq)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	requestID := createResp["request_id"].(string)

	// Poll without timeout_ms — should return immediately
	pollStart := time.Now()
	pollReq := httptest.NewRequest(http.MethodGet, "/implementor/init/poll?request_id="+requestID, nil)
	pollW := httptest.NewRecorder()
	handler.ImplementorInitPoll(pollW, pollReq)
	pollDuration := time.Since(pollStart)

	var pollResp map[string]interface{}
	json.NewDecoder(pollW.Body).Decode(&pollResp)

	// Should return immediately (< 100ms)
	assert.Less(t, pollDuration, 100*time.Millisecond, "should return immediately without timeout_ms")
	assert.Equal(t, "pending", pollResp["status"])
}
