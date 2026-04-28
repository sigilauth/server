package sigilauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Cleanup(func() { os.Unsetenv("SIGIL_API_KEY") })

	client, err := New(Config{
		ServiceURL: server.URL,
	})
	require.NoError(t, err)

	client.httpClient = server.Client()

	return client
}

func TestAuthCreateChallenge(t *testing.T) {
	tests := []struct {
		name       string
		request    *ChallengeRequest
		handler    http.HandlerFunc
		wantErr    bool
		wantResult *ChallengeResult
	}{
		{
			name: "successful challenge creation",
			request: &ChallengeRequest{
				Fingerprint:     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
				DevicePublicKey: "Ag8xYzI3ZWRkNDUzYmNlYzVmMTJjNmI5MzA4OGY0",
				Action: Action{
					Type:        "step_up",
					Description: "Add WebAuthn key",
				},
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/challenge", r.URL.Path)
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.Header.Get("Authorization"), "Bearer sgk_test_")

				var req ChallengeRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				require.NoError(t, err)
				assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", req.Fingerprint)

				resp := ChallengeResult{
					ChallengeID:        "550e8400-e29b-41d4-a716-446655440000",
					Fingerprint:        req.Fingerprint,
					Pictogram:          []string{"apple", "banana", "plane", "car", "dog"},
					PictogramSpeakable: "apple banana plane car dog",
					ExpiresAt:          time.Now().Add(5 * time.Minute),
				}
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(resp)
			},
			wantErr: false,
			wantResult: &ChallengeResult{
				ChallengeID: "550e8400-e29b-41d4-a716-446655440000",
				Fingerprint: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			},
		},
		{
			name: "API error response",
			request: &ChallengeRequest{
				Fingerprint:     "invalid",
				DevicePublicKey: "invalid",
				Action: Action{
					Type:        "step_up",
					Description: "Test",
				},
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: struct {
						Code    string                 `json:"code"`
						Message string                 `json:"message"`
						Details map[string]interface{} `json:"details,omitempty"`
					}{
						Code:    "INVALID_PUBLIC_KEY",
						Message: "Invalid device public key format",
					},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestClient(t, tt.handler)

			result, err := client.Auth.CreateChallenge(context.Background(), tt.request)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.wantResult.ChallengeID, result.ChallengeID)
				assert.Equal(t, tt.wantResult.Fingerprint, result.Fingerprint)
			}
		})
	}
}

func TestAuthGetStatus(t *testing.T) {
	tests := []struct {
		name        string
		challengeID string
		handler     http.HandlerFunc
		wantErr     bool
		wantStatus  string
	}{
		{
			name:        "pending challenge",
			challengeID: "550e8400-e29b-41d4-a716-446655440000",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/challenge/550e8400-e29b-41d4-a716-446655440000/status", r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				resp := ChallengeStatus{
					ChallengeID: "550e8400-e29b-41d4-a716-446655440000",
					Status:      "pending",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantErr:    false,
			wantStatus: "pending",
		},
		{
			name:        "verified challenge",
			challengeID: "550e8400-e29b-41d4-a716-446655440000",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := ChallengeStatus{
					ChallengeID:        "550e8400-e29b-41d4-a716-446655440000",
					Status:             "verified",
					Fingerprint:        "a1b2c3d4",
					Pictogram:          []string{"apple", "banana", "plane", "car", "dog"},
					PictogramSpeakable: "apple banana plane car dog",
					Decision:           "approved",
					VerifiedAt:         time.Now(),
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantErr:    false,
			wantStatus: "verified",
		},
		{
			name:        "not found",
			challengeID: "unknown",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: struct {
						Code    string                 `json:"code"`
						Message string                 `json:"message"`
						Details map[string]interface{} `json:"details,omitempty"`
					}{
						Code:    "CHALLENGE_NOT_FOUND",
						Message: "Challenge not found or expired",
					},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestClient(t, tt.handler)

			status, err := client.Auth.GetStatus(context.Background(), tt.challengeID)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantStatus, status.Status)
			}
		})
	}
}

func TestAuthAwaitResult(t *testing.T) {
	t.Run("polls until verified", func(t *testing.T) {
		callCount := 0
		handler := func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount < 3 {
				resp := ChallengeStatus{
					ChallengeID: "test-id",
					Status:      "pending",
				}
				json.NewEncoder(w).Encode(resp)
			} else {
				resp := ChallengeStatus{
					ChallengeID: "test-id",
					Status:      "verified",
					Decision:    "approved",
				}
				json.NewEncoder(w).Encode(resp)
			}
		}

		client := setupTestClient(t, handler)

		status, err := client.Auth.AwaitResult(context.Background(), "test-id", &AwaitOptions{
			PollInterval: 10,
			MaxAttempts:  10,
		})

		require.NoError(t, err)
		assert.Equal(t, "verified", status.Status)
		assert.GreaterOrEqual(t, callCount, 3)
	})

	t.Run("timeout on max attempts", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			resp := ChallengeStatus{
				ChallengeID: "test-id",
				Status:      "pending",
			}
			json.NewEncoder(w).Encode(resp)
		}

		client := setupTestClient(t, handler)

		_, err := client.Auth.AwaitResult(context.Background(), "test-id", &AwaitOptions{
			PollInterval: 10,
			MaxAttempts:  3,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "max polling attempts reached")
	})
}
