package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigureWebhook_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"url": "https://example.com/webhook",
		"events": []string{
			"challenge.verified",
			"challenge.rejected",
		},
		"secret": "whsec_test123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["webhook_id"] == "" || resp["webhook_id"] == nil {
		t.Error("Expected webhook_id to be set")
	}
	if resp["url"] != "https://example.com/webhook" {
		t.Errorf("Expected url to match request, got %v", resp["url"])
	}
	if resp["created_at"] == "" || resp["created_at"] == nil {
		t.Error("Expected created_at to be set")
	}

	events, ok := resp["events"].([]interface{})
	if !ok || len(events) != 2 {
		t.Errorf("Expected 2 events, got %v", resp["events"])
	}
}

func TestConfigureWebhook_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/config/webhooks", nil)
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestConfigureWebhook_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_REQUEST" {
		t.Errorf("Expected error code INVALID_REQUEST, got %s", errResp["error"])
	}
}

func TestConfigureWebhook_MissingURL(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"events": []string{"challenge.verified"},
		"secret": "whsec_test",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_REQUEST" {
		t.Errorf("Expected error INVALID_REQUEST, got %s", errResp["error"])
	}
}

func TestConfigureWebhook_MissingEvents(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"url":    "https://example.com/webhook",
		"secret": "whsec_test",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestConfigureWebhook_InvalidURL(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"url":    "not-a-valid-url",
		"events": []string{"challenge.verified"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestConfigureWebhook_InvalidEvent(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"url":    "https://example.com/webhook",
		"events": []string{"invalid.event.type"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestConfigureWebhook_NoSecret(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := map[string]interface{}{
		"url":    "https://example.com/webhook",
		"events": []string{"challenge.verified"},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()

	handler.ConfigureWebhook(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d (secret is optional)", w.Code)
	}
}

func TestConfigureWebhook_Overwrite(t *testing.T) {
	handler, _ := setupHandler(t)

	// First webhook config
	reqBody1 := map[string]interface{}{
		"url":    "https://example.com/webhook1",
		"events": []string{"challenge.verified"},
		"secret": "secret1",
	}

	body1, _ := json.Marshal(reqBody1)
	req1 := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body1))
	req1.Header.Set("Authorization", "Bearer test-api-key")
	w1 := httptest.NewRecorder()

	handler.ConfigureWebhook(w1, req1)

	// Second webhook config (same API key, should overwrite)
	reqBody2 := map[string]interface{}{
		"url":    "https://example.com/webhook2",
		"events": []string{"mpa.approved"},
		"secret": "secret2",
	}

	body2, _ := json.Marshal(reqBody2)
	req2 := httptest.NewRequest(http.MethodPost, "/v1/config/webhooks", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer test-api-key")
	w2 := httptest.NewRecorder()

	handler.ConfigureWebhook(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w2.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["url"] != "https://example.com/webhook2" {
		t.Errorf("Expected new URL to overwrite old, got %v", resp["url"])
	}
}
