package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigilauth/server/internal/mpa"
)

// base64Encode helper for test device public keys
func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func TestCreateMPARequest_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	// Generate test device keys
	_, pk1 := generateDeviceKey(t)
	_, pk2 := generateDeviceKey(t)
	_, pk3 := generateDeviceKey(t)

	fp1 := computeFingerprint(t, pk1)
	fp2 := computeFingerprint(t, pk2)
	fp3 := computeFingerprint(t, pk3)

	reqBody := MPARequestBody{
		Devices: []DeviceEntry{
			{Fingerprint: fp1, Pubkey: base64Encode(pk1)},
			{Fingerprint: fp2, Pubkey: base64Encode(pk2)},
			{Fingerprint: fp3, Pubkey: base64Encode(pk3)},
		},
		Action: map[string]interface{}{
			"type":        "transfer",
			"description": "Transfer $10,000",
		},
		Required: 2,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/mpa/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.CreateMPARequest(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var resp MPARequestResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.RequestID == "" {
		t.Error("Expected request_id to be set")
	}
	if resp.Status != "pending" {
		t.Errorf("Expected status=pending, got %s", resp.Status)
	}
	if resp.Required != 2 {
		t.Errorf("Expected required=2, got %d", resp.Required)
	}
	if resp.Approved != 0 {
		t.Errorf("Expected approved=0, got %d", resp.Approved)
	}
}

func TestCreateMPARequest_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/mpa/request", nil)
	w := httptest.NewRecorder()

	handler.CreateMPARequest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestCreateMPARequest_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/mpa/request", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.CreateMPARequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCreateMPARequest_NoDevices(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := MPARequestBody{
		Devices:  []DeviceEntry{},
		Action:   map[string]interface{}{"type": "test"},
		Required: 1,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/mpa/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.CreateMPARequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["message"] != "Either devices or groups must be provided" {
		t.Errorf("Unexpected error message: %s", errResp["message"])
	}
}

func TestCreateMPARequest_InvalidRequired(t *testing.T) {
	handler, _ := setupHandler(t)

	// Generate test device keys
	_, pk1 := generateDeviceKey(t)
	_, pk2 := generateDeviceKey(t)
	_, pk3 := generateDeviceKey(t)

	fp1 := computeFingerprint(t, pk1)
	fp2 := computeFingerprint(t, pk2)
	fp3 := computeFingerprint(t, pk3)

	tests := []struct {
		name     string
		required int
	}{
		{"Required too low", 0},
		{"Required too high", 4},
		{"Required negative", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := MPARequestBody{
				Devices: []DeviceEntry{
					{Fingerprint: fp1, Pubkey: base64Encode(pk1)},
					{Fingerprint: fp2, Pubkey: base64Encode(pk2)},
					{Fingerprint: fp3, Pubkey: base64Encode(pk3)},
				},
				Action:   map[string]interface{}{"type": "test"},
				Required: tc.required,
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/mpa/request", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.CreateMPARequest(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}

			var errResp map[string]string
			json.NewDecoder(w.Body).Decode(&errResp)
			if errResp["message"] != "Required must be between 1 and number of devices" {
				t.Errorf("Unexpected error message: %s", errResp["message"])
			}
		})
	}
}

func TestCreateMPARequest_WithGroups(t *testing.T) {
	handler, _ := setupHandler(t)

	// Generate test device keys
	_, pk1 := generateDeviceKey(t)
	_, pk2 := generateDeviceKey(t)
	_, pk3 := generateDeviceKey(t)
	_, pk4 := generateDeviceKey(t)

	fp1 := computeFingerprint(t, pk1)
	fp2 := computeFingerprint(t, pk2)
	fp3 := computeFingerprint(t, pk3)
	fp4 := computeFingerprint(t, pk4)

	reqBody := MPARequestBody{
		Devices: []DeviceEntry{
			{Fingerprint: fp1, Pubkey: base64Encode(pk1)},
			{Fingerprint: fp2, Pubkey: base64Encode(pk2)},
			{Fingerprint: fp3, Pubkey: base64Encode(pk3)},
			{Fingerprint: fp4, Pubkey: base64Encode(pk4)},
		},
		Action:   map[string]interface{}{"type": "test"},
		Required: 2,
		Groups:   []mpa.Group{}, // Groups field exists but structure TBD
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/mpa/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.CreateMPARequest(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}

func TestRespondMPA_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/mpa/respond", nil)
	w := httptest.NewRecorder()

	handler.RespondMPA(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestRespondMPA_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/mpa/respond", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.RespondMPA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestRespondMPA_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := MPARespondBody{
		RequestID:   "mpa_123",
		Fingerprint: "abc123",
		Signature:   "sig_data",
		Approved:    true,
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/mpa/respond", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.RespondMPA(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "recorded" {
		t.Errorf("Expected status=recorded, got %s", resp["status"])
	}
}

func TestGetMPAStatus_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/mpa/status/123", nil)
	w := httptest.NewRecorder()

	handler.GetMPAStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestGetMPAStatus_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/mpa/status/mpa_123", nil)
	w := httptest.NewRecorder()

	handler.GetMPAStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp MPARequestResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "pending" {
		t.Errorf("Expected status=pending, got %s", resp.Status)
	}
}
