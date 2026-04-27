package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecureDecrypt_MethodNotAllowed(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/secure/decrypt", nil)
	w := httptest.NewRecorder()

	handler.SecureDecrypt(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestSecureDecrypt_InvalidJSON(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/secure/decrypt", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	handler.SecureDecrypt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_REQUEST" {
		t.Errorf("Expected error code INVALID_REQUEST, got %s", errResp["error"])
	}
}

func TestSecureDecrypt_InvalidCiphertext(t *testing.T) {
	handler, _ := setupHandler(t)

	reqBody := DecryptRequest{
		Ciphertext: "not-base64!!!",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/secure/decrypt", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SecureDecrypt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "INVALID_CIPHERTEXT" {
		t.Errorf("Expected error code INVALID_CIPHERTEXT, got %s", errResp["error"])
	}
}


func TestSecureDecrypt_DecryptionFailed(t *testing.T) {
	handler, _ := setupHandler(t)

	// Valid base64 but invalid ciphertext (will fail decryption)
	reqBody := DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("invalid ciphertext data")),
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/secure/decrypt", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SecureDecrypt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "DECRYPTION_FAILED" {
		t.Errorf("Expected error code DECRYPTION_FAILED, got %s", errResp["error"])
	}
}
