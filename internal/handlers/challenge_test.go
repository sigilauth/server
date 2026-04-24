package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigilauth/server/internal/session"
	"github.com/sigilauth/server/internal/telemetry"
)

// setupHandler creates a Handler with test dependencies
func setupHandler(t *testing.T) (*Handler, *ecdsa.PrivateKey) {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	tel := telemetry.New(telemetry.Config{
		ServiceName: "test-sigil-auth",
		Enabled:     false, // Disable telemetry in tests
	})

	sessionStore := session.NewStore()

	return New(sessionStore, tel, serverKey), serverKey
}

// generateDeviceKey generates a test ECDSA P-256 keypair
func generateDeviceKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate device key: %v", err)
	}

	pubKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), deviceKey.PublicKey.X, deviceKey.PublicKey.Y)
	return deviceKey, pubKeyBytes
}

// computeFingerprint computes SHA256 fingerprint of public key
func computeFingerprint(t *testing.T, pubKeyBytes []byte) string {
	t.Helper()

	hash := make([]byte, 32)
	copy(hash, pubKeyBytes) // Simplified for test
	return hex.EncodeToString(hash)
}

func TestCreateChallenge_Success(t *testing.T) {
	handler, _ := setupHandler(t)
	_, devicePubKeyBytes := generateDeviceKey(t)
	fingerprint := computeFingerprint(t, devicePubKeyBytes)

	reqBody := ChallengeRequest{
		Fingerprint:     fingerprint,
		DevicePublicKey: base64.StdEncoding.EncodeToString(devicePubKeyBytes),
		Action: map[string]interface{}{
			"type":        "login",
			"description": "Sign in to Acme Corp",
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.CreateChallenge(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var resp ChallengeResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.ChallengeID == "" {
		t.Error("Expected challenge_id to be set")
	}
	if len(resp.Pictogram) != 5 {
		t.Errorf("Expected 5 pictogram words, got %d", len(resp.Pictogram))
	}
	if resp.PictogramSpeakable == "" {
		t.Error("Expected pictogram_speakable to be set")
	}
	if resp.ExpiresAt == "" {
		t.Error("Expected expires_at to be set")
	}
	if resp.RespondTo != "/respond" {
		t.Errorf("Expected respond_to=/respond, got %s", resp.RespondTo)
	}
}

func TestCreateChallenge_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	w := httptest.NewRecorder()

	handler.CreateChallenge(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestCreateChallenge_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	handler.CreateChallenge(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_REQUEST" {
		t.Errorf("Expected error code INVALID_REQUEST, got %s", errResp["error"])
	}
}

func TestCreateChallenge_InvalidFingerprint(t *testing.T) {
	handler, _ := setupHandler(t)
	_, devicePubKeyBytes := generateDeviceKey(t)

	tests := []struct {
		name        string
		fingerprint string
		expectCode  int
	}{
		{"Too short", "abc123", http.StatusBadRequest},
		{"Too long", "a" + hex.EncodeToString(make([]byte, 32)), http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := ChallengeRequest{
				Fingerprint:     tc.fingerprint,
				DevicePublicKey: base64.StdEncoding.EncodeToString(devicePubKeyBytes),
				Action: map[string]interface{}{
					"type":        "login",
					"description": "Test",
				},
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.CreateChallenge(w, req)

			if w.Code != tc.expectCode {
				t.Errorf("Expected status %d, got %d", tc.expectCode, w.Code)
			}
		})
	}
}

func TestCreateChallenge_InvalidPublicKey(t *testing.T) {
	handler, _ := setupHandler(t)

	tests := []struct {
		name      string
		publicKey string
	}{
		{"Not base64", "not-base64!!!"},
		{"Wrong length", base64.StdEncoding.EncodeToString(make([]byte, 32))}, // Should be 33 bytes
		{"Empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := ChallengeRequest{
				Fingerprint:     hex.EncodeToString(make([]byte, 32)),
				DevicePublicKey: tc.publicKey,
				Action: map[string]interface{}{
					"type":        "login",
					"description": "Test",
				},
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.CreateChallenge(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}

			var errResp map[string]string
			json.NewDecoder(w.Body).Decode(&errResp)
			if errResp["error"] != "INVALID_PUBLIC_KEY" {
				t.Errorf("Expected error code INVALID_PUBLIC_KEY, got %s", errResp["error"])
			}
		})
	}
}

func TestRespond_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/respond", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.Respond(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestRespond_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/respond", nil)
	w := httptest.NewRecorder()

	handler.Respond(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestRespond_InvalidSignature(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := RespondRequest{
		ChallengeID: "550e8400-e29b-41d4-a716-446655440000",
		Fingerprint: hex.EncodeToString(make([]byte, 32)),
		Signature:   "not-base64!!!",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/respond", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Respond(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_SIGNATURE" {
		t.Errorf("Expected error code INVALID_SIGNATURE, got %s", errResp["error"])
	}
}

func TestRespond_InvalidFingerprint(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := RespondRequest{
		ChallengeID: "550e8400-e29b-41d4-a716-446655440000",
		Fingerprint: "not-hex",
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/respond", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Respond(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestRespond_ChallengeNotFound(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := RespondRequest{
		ChallengeID: "00000000-0000-0000-0000-000000000000",
		Fingerprint: hex.EncodeToString(make([]byte, 32)),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/respond", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.Respond(w, req)

	// Challenge not found returns 410 CHALLENGE_EXPIRED
	if w.Code != http.StatusGone {
		t.Errorf("Expected status 410, got %d", w.Code)
	}
}
