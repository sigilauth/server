package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetChallengeStatus_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/challenge/123/status", nil)
	w := httptest.NewRecorder()

	handler.GetChallengeStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestGetChallengeStatus_InvalidPath(t *testing.T) {
	handler, _ := setupHandler(t)

	tests := []struct {
		name string
		path string
	}{
		{"Missing ID", "/v1/auth/challenge/"},
		{"Short path", "/v1/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()

			handler.GetChallengeStatus(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}

			var errResp map[string]string
			json.NewDecoder(w.Body).Decode(&errResp)
			if errResp["error"] != "INVALID_PATH" {
				t.Errorf("Expected error code INVALID_PATH, got %s", errResp["error"])
			}
		})
	}
}

func TestGetChallengeStatus_NotFound(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/challenge/nonexistent/status", nil)
	w := httptest.NewRecorder()

	handler.GetChallengeStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp ChallengeStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "expired" {
		t.Errorf("Expected status=expired, got %s", resp.Status)
	}
}

func TestGetDecryptStatus_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/secure/decrypt/123/status", nil)
	w := httptest.NewRecorder()

	handler.GetDecryptStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestGetDecryptStatus_InvalidPath(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/secure/", nil)
	w := httptest.NewRecorder()

	handler.GetDecryptStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetDecryptStatus_Success(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/secure/decrypt/abc123/status", nil)
	w := httptest.NewRecorder()

	handler.GetDecryptStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp DecryptStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.RequestID != "abc123" {
		t.Errorf("Expected request_id=abc123, got %s", resp.RequestID)
	}
	if resp.Status != "completed" {
		t.Errorf("Expected status=completed, got %s", resp.Status)
	}
}
