package sigilauth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAwaitResultDefaults(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		resp := ChallengeStatus{
			ChallengeID: "test-id",
			Status:      "verified",
		}
		json.NewEncoder(w).Encode(resp)
	}

	client := setupTestClient(t, handler)

	status, err := client.Auth.AwaitResult(context.Background(), "test-id", nil)
	require.NoError(t, err)
	require.NotNil(t, status)
}

func TestMPAAwaitResultDefaults(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		resp := MPAStatus{
			RequestID:      "test-id",
			Status:         "approved",
			GroupsRequired: 2,
			GroupsTotal:    2,
		}
		json.NewEncoder(w).Encode(resp)
	}

	client := setupTestClient(t, handler)

	status, err := client.MPA.AwaitResult(context.Background(), "test-id", nil)
	require.NoError(t, err)
	require.NotNil(t, status)
}
