package sigilauth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMPARequest(t *testing.T) {
	tests := []struct {
		name       string
		request    *MPARequest
		handler    http.HandlerFunc
		wantErr    bool
		wantResult *MPAResult
	}{
		{
			name: "successful MPA request",
			request: &MPARequest{
				RequestID: "mpa_xyz789",
				Action: Action{
					Type:        "engine:cold-boot",
					Description: "Cold boot engine ENG-001",
					Params: map[string]interface{}{
						"engine_id": "eng_001",
					},
				},
				Required: 2,
				Groups: []MPAGroup{
					{
						Members: []MPAGroupMember{
							{
								Fingerprint:     "a1b2c3d4",
								DevicePublicKey: "Ag8xYzI3ZWRkNDUzYmNl",
							},
						},
					},
					{
						Members: []MPAGroupMember{
							{
								Fingerprint:     "b2c3d4e5",
								DevicePublicKey: "AhJkbG1hb3B3eHl6",
							},
						},
					},
				},
				RejectPolicy:     "continue",
				ExpiresInSeconds: 300,
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/mpa/request", r.URL.Path)
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.Header.Get("Authorization"), "Bearer sgk_test_")

				var req MPARequest
				err := json.NewDecoder(r.Body).Decode(&req)
				require.NoError(t, err)
				assert.Equal(t, "mpa_xyz789", req.RequestID)
				assert.Equal(t, 2, req.Required)

				resp := MPAResult{
					RequestID:      req.RequestID,
					Status:         "pending",
					GroupsRequired: req.Required,
					GroupsTotal:    len(req.Groups),
					ChallengesSent: 2,
					ExpiresAt:      time.Now().Add(5 * time.Minute),
				}
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(resp)
			},
			wantErr: false,
			wantResult: &MPAResult{
				RequestID: "mpa_xyz789",
				Status:    "pending",
			},
		},
		{
			name: "API error response",
			request: &MPARequest{
				RequestID: "invalid",
				Action: Action{
					Type:        "test",
					Description: "Test",
				},
				Required: 0,
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: struct {
						Code    string                 `json:"code"`
						Message string                 `json:"message"`
						Details map[string]interface{} `json:"details,omitempty"`
					}{
						Code:    "INVALID_REQUEST",
						Message: "Required must be at least 1",
					},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestClient(t, tt.handler)

			result, err := client.MPA.Request(context.Background(), tt.request)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.wantResult.RequestID, result.RequestID)
				assert.Equal(t, tt.wantResult.Status, result.Status)
			}
		})
	}
}

func TestMPAGetStatus(t *testing.T) {
	tests := []struct {
		name       string
		requestID  string
		handler    http.HandlerFunc
		wantErr    bool
		wantStatus string
	}{
		{
			name:      "pending MPA request",
			requestID: "mpa_xyz789",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/mpa/status/mpa_xyz789", r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				resp := MPAStatus{
					RequestID:       "mpa_xyz789",
					Status:          "pending",
					GroupsSatisfied: []int{0},
					GroupsRequired:  2,
					GroupsTotal:     2,
					ExpiresAt:       time.Now().Add(5 * time.Minute),
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantErr:    false,
			wantStatus: "pending",
		},
		{
			name:      "approved MPA request",
			requestID: "mpa_xyz789",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := MPAStatus{
					RequestID:       "mpa_xyz789",
					Status:          "approved",
					GroupsSatisfied: []int{0, 1},
					GroupsRequired:  2,
					GroupsTotal:     2,
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantErr:    false,
			wantStatus: "approved",
		},
		{
			name:      "not found",
			requestID: "unknown",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: struct {
						Code    string                 `json:"code"`
						Message string                 `json:"message"`
						Details map[string]interface{} `json:"details,omitempty"`
					}{
						Code:    "MPA_REQUEST_NOT_FOUND",
						Message: "MPA request not found",
					},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupTestClient(t, tt.handler)

			status, err := client.MPA.GetStatus(context.Background(), tt.requestID)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantStatus, status.Status)
			}
		})
	}
}

func TestMPAAwaitResult(t *testing.T) {
	t.Run("polls until approved", func(t *testing.T) {
		callCount := 0
		handler := func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount < 3 {
				resp := MPAStatus{
					RequestID:       "mpa_test",
					Status:          "pending",
					GroupsSatisfied: []int{0},
					GroupsRequired:  2,
					GroupsTotal:     2,
				}
				json.NewEncoder(w).Encode(resp)
			} else {
				resp := MPAStatus{
					RequestID:       "mpa_test",
					Status:          "approved",
					GroupsSatisfied: []int{0, 1},
					GroupsRequired:  2,
					GroupsTotal:     2,
				}
				json.NewEncoder(w).Encode(resp)
			}
		}

		client := setupTestClient(t, handler)

		status, err := client.MPA.AwaitResult(context.Background(), "mpa_test", &AwaitOptions{
			PollInterval: 10,
			MaxAttempts:  10,
		})

		require.NoError(t, err)
		assert.Equal(t, "approved", status.Status)
		assert.GreaterOrEqual(t, callCount, 3)
	})

	t.Run("timeout on max attempts", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			resp := MPAStatus{
				RequestID:      "mpa_test",
				Status:         "pending",
				GroupsRequired: 2,
				GroupsTotal:    2,
			}
			json.NewEncoder(w).Encode(resp)
		}

		client := setupTestClient(t, handler)

		_, err := client.MPA.AwaitResult(context.Background(), "mpa_test", &AwaitOptions{
			PollInterval: 10,
			MaxAttempts:  3,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "max polling attempts reached")
	})
}
