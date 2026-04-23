package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client := webhook.NewClient("test-api-key")
	require.NotNil(t, client)
}

func TestDeliverSuccess(t *testing.T) {
	apiKey := "test-api-key-12345"
	receivedBody := ""
	receivedSig := ""
	receivedTS := ""

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedSig = r.Header.Get("X-Sigil-Signature")
		receivedTS = r.Header.Get("X-Sigil-Timestamp")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := webhook.NewClient(apiKey)
	client.DisableSSRFForTesting()
	ctx := context.Background()

	payload := []byte(`{"event":"test","data":"value"}`)
	err := client.Deliver(ctx, server.URL, payload)

	require.NoError(t, err)
	assert.Equal(t, string(payload), receivedBody)
	assert.NotEmpty(t, receivedSig)
	assert.NotEmpty(t, receivedTS)

	ts, _ := strconv.ParseInt(receivedTS, 10, 64)
	assert.True(t, time.Now().Unix()-ts < 5, "timestamp should be recent")
}

func TestVerifySignature(t *testing.T) {
	apiKey := "test-secret"
	payload := []byte("test payload")
	timestamp := time.Now().Unix()

	sig := webhook.ComputeSignature(apiKey, payload, timestamp)

	valid := webhook.VerifySignature(apiKey, payload, timestamp, sig)
	assert.True(t, valid)
}

func TestVerifySignatureInvalid(t *testing.T) {
	apiKey := "test-secret"
	payload := []byte("test payload")
	timestamp := time.Now().Unix()

	wrongSig := "sha256=invalidhexstring1234567890abcdef"

	valid := webhook.VerifySignature(apiKey, payload, timestamp, wrongSig)
	assert.False(t, valid)
}

func TestVerifySignatureExpired(t *testing.T) {
	apiKey := "test-secret"
	payload := []byte("test payload")
	oldTimestamp := time.Now().Unix() - 400

	sig := webhook.ComputeSignature(apiKey, payload, oldTimestamp)

	valid := webhook.VerifySignature(apiKey, payload, oldTimestamp, sig)
	assert.False(t, valid, "timestamp >5min old should be rejected")
}

func TestDeliverRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := webhook.NewClient("test-key")
	client.DisableSSRFForTesting()
	client.SetFastRetryForTesting()
	ctx := context.Background()

	err := client.Deliver(ctx, server.URL, []byte("test"))

	require.NoError(t, err)
	assert.Equal(t, 3, attempts, "should retry on 500 errors")
}

func TestDeliverRetriesExhausted(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := webhook.NewClient("test-key")
	client.DisableSSRFForTesting()
	client.SetFastRetryForTesting()
	ctx := context.Background()

	err := client.Deliver(ctx, server.URL, []byte("test"))

	require.Error(t, err)
	assert.Equal(t, 4, attempts, "should retry 3 times (4 total attempts)")
}

func TestDeliverTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := webhook.NewClient("test-key")
	client.DisableSSRFForTesting()
	client.SetFastRetryForTesting()
	ctx := context.Background()

	err := client.Deliver(ctx, server.URL, []byte("test"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestSSRFProtection(t *testing.T) {
	tests := []struct {
		name string
		url  string
		blocked bool
	}{
		{
			name: "Localhost blocked",
			url:  "https://localhost/webhook",
			blocked: true,
		},
		{
			name: "127.0.0.1 blocked",
			url:  "https://127.0.0.1/webhook",
			blocked: true,
		},
		{
			name: "127.0.0.2 blocked",
			url:  "https://127.0.0.2/webhook",
			blocked: true,
		},
		{
			name: "10.0.0.0/8 blocked",
			url:  "https://10.1.2.3/webhook",
			blocked: true,
		},
		{
			name: "172.16.0.0/12 blocked",
			url:  "https://172.16.5.10/webhook",
			blocked: true,
		},
		{
			name: "172.31.255.255 blocked",
			url:  "https://172.31.255.255/webhook",
			blocked: true,
		},
		{
			name: "192.168.0.0/16 blocked",
			url:  "https://192.168.1.100/webhook",
			blocked: true,
		},
		{
			name: "169.254.0.0/16 link-local blocked",
			url:  "https://169.254.169.254/webhook",
			blocked: true,
		},
		{
			name: "Public IP allowed",
			url:  "https://example.com/webhook",
			blocked: false,
		},
		{
			name: "8.8.8.8 allowed",
			url:  "https://8.8.8.8/webhook",
			blocked: false,
		},
	}

	client := webhook.NewClient("test-key")
	client.SetFastRetryForTesting()
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.Deliver(ctx, tt.url, []byte("test"))

			if tt.blocked {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "SSRF")
			} else {
				if err != nil {
					assert.NotContains(t, err.Error(), "SSRF",
						"should not be SSRF error (connection error is ok)")
				}
			}
		})
	}
}

func TestHTTPSOnly(t *testing.T) {
	client := webhook.NewClient("test-key")
	ctx := context.Background()

	err := client.Deliver(ctx, "http://example.com/webhook", []byte("test"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS required")
}

func TestCircuitBreaker(t *testing.T) {
	failures := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failures++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := webhook.NewClient("test-key")
	client.DisableSSRFForTesting()
	client.SetFastRetryForTesting()
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		_ = client.Deliver(ctx, server.URL, []byte(fmt.Sprintf("attempt %d", i)))
	}

	state := client.CircuitState(server.URL)
	assert.Equal(t, "open", state, "circuit breaker should open after 5 consecutive failures")
}

func TestComputeSignature(t *testing.T) {
	apiKey := "my-secret-key"
	payload := []byte("test payload")
	timestamp := int64(1234567890)

	sig := webhook.ComputeSignature(apiKey, payload, timestamp)

	assert.True(t, len(sig) > 0)
	assert.True(t, sig[:7] == "sha256=", "signature should start with sha256=")

	expectedPayload := fmt.Sprintf("%d%s", timestamp, string(payload))
	h := hmac.New(sha256.New, []byte(apiKey))
	h.Write([]byte(expectedPayload))
	expectedSig := "sha256=" + hex.EncodeToString(h.Sum(nil))

	assert.Equal(t, expectedSig, sig)
}
