package sigilauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryOn429(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: struct {
					Code    string                 `json:"code"`
					Message string                 `json:"message"`
					Details map[string]interface{} `json:"details,omitempty"`
				}{
					Code:    "RATE_LIMITED",
					Message: "Rate limit exceeded",
				},
			})
		} else {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(ChallengeResult{
				ChallengeID: "test-success",
			})
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: server.URL,
	})
	require.NoError(t, err)
	client.httpClient = server.Client()

	result, err := client.Auth.CreateChallenge(context.Background(), &ChallengeRequest{
		Fingerprint:     "test",
		DevicePublicKey: "test",
		Action: Action{
			Type:        "test",
			Description: "test",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "test-success", result.ChallengeID)
	assert.Equal(t, 3, callCount)
}

func TestRetryOn5xx(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: struct {
					Code    string                 `json:"code"`
					Message string                 `json:"message"`
					Details map[string]interface{} `json:"details,omitempty"`
				}{
					Code:    "INTERNAL_ERROR",
					Message: "Internal server error",
				},
			})
		} else {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(ChallengeResult{
				ChallengeID: "test-success",
			})
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: server.URL,
	})
	require.NoError(t, err)
	client.httpClient = server.Client()

	result, err := client.Auth.CreateChallenge(context.Background(), &ChallengeRequest{
		Fingerprint:     "test",
		DevicePublicKey: "test",
		Action: Action{
			Type:        "test",
			Description: "test",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "test-success", result.ChallengeID)
	assert.Equal(t, 2, callCount)
}

func TestNoRetryOn4xxExcept429(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: struct {
				Code    string                 `json:"code"`
				Message string                 `json:"message"`
				Details map[string]interface{} `json:"details,omitempty"`
			}{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request",
			},
		})
	}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: server.URL,
	})
	require.NoError(t, err)
	client.httpClient = server.Client()

	_, err = client.Auth.CreateChallenge(context.Background(), &ChallengeRequest{
		Fingerprint:     "test",
		DevicePublicKey: "test",
		Action: Action{
			Type:        "test",
			Description: "test",
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "INVALID_REQUEST")
	assert.Equal(t, 1, callCount)
}

func TestMaxRetries(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: struct {
				Code    string                 `json:"code"`
				Message string                 `json:"message"`
				Details map[string]interface{} `json:"details,omitempty"`
			}{
				Code:    "RATE_LIMITED",
				Message: "Rate limit exceeded",
			},
		})
	}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: server.URL,
	})
	require.NoError(t, err)
	client.httpClient = server.Client()

	_, err = client.Auth.CreateChallenge(context.Background(), &ChallengeRequest{
		Fingerprint:     "test",
		DevicePublicKey: "test",
		Action: Action{
			Type:        "test",
			Description: "test",
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "RATE_LIMITED")
	assert.Equal(t, 4, callCount)
}
