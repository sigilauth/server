package sigilauth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestDoRequestNetworkError(t *testing.T) {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: "https://invalid.local.test:99999",
	})
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://invalid.local.test:99999/test", nil)

	var result map[string]interface{}
	err = client.doRequest(req, &result)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestDoRequestNilResult(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}

	client := setupTestClient(t, handler)

	req, _ := http.NewRequestWithContext(context.Background(), "POST", client.config.ServiceURL+"/test", nil)

	err := client.doRequest(req, nil)
	require.NoError(t, err)
}

func TestDoRequestInvalidJSON(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-valid-json"))
	}

	client := setupTestClient(t, handler)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", client.config.ServiceURL+"/test", nil)

	var result map[string]interface{}
	err := client.doRequest(req, &result)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

func TestDoRequestInvalidErrorJSON(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("not-valid-json"))
	}

	client := setupTestClient(t, handler)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", client.config.ServiceURL+"/test", nil)

	var result map[string]interface{}
	err := client.doRequest(req, &result)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 400")
}

func TestContextCancellation(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}

	client := setupTestClient(t, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status, err := client.Auth.AwaitResult(ctx, "test-id", &AwaitOptions{
		PollInterval: 10,
		MaxAttempts:  10,
	})

	require.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "context canceled")
}
