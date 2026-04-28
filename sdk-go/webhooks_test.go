package sigilauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWebhookVerify(t *testing.T) {
	secret := "whsec_test123"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	body := []byte(`{"event":"challenge.verified","data":{"challenge_id":"test"}}`)

	signedPayload := timestamp + "." + string(body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signedPayload))
	signature := hex.EncodeToString(h.Sum(nil))

	tests := []struct {
		name    string
		headers http.Header
		body    []byte
		secret  string
		wantErr bool
	}{
		{
			name: "valid signature",
			headers: http.Header{
				"X-Sigil-Signature": []string{"v1," + signature},
				"X-Sigil-Timestamp": []string{timestamp},
			},
			body:    body,
			secret:  secret,
			wantErr: false,
		},
		{
			name: "invalid signature",
			headers: http.Header{
				"X-Sigil-Signature": []string{"v1,invalid"},
				"X-Sigil-Timestamp": []string{timestamp},
			},
			body:    body,
			secret:  secret,
			wantErr: true,
		},
		{
			name: "missing signature header",
			headers: http.Header{
				"X-Sigil-Timestamp": []string{timestamp},
			},
			body:    body,
			secret:  secret,
			wantErr: true,
		},
		{
			name: "missing timestamp header",
			headers: http.Header{
				"X-Sigil-Signature": []string{"v1," + signature},
			},
			body:    body,
			secret:  secret,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &WebhookService{}

			err := service.Verify(tt.headers, tt.body, tt.secret)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWebhookVerifyTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		maxAge    int
		wantErr   bool
	}{
		{
			name:      "recent timestamp",
			timestamp: strconv.FormatInt(time.Now().Unix(), 10),
			maxAge:    300,
			wantErr:   false,
		},
		{
			name:      "old timestamp",
			timestamp: strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10),
			maxAge:    300,
			wantErr:   true,
		},
		{
			name:      "future timestamp",
			timestamp: strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10),
			maxAge:    300,
			wantErr:   true,
		},
		{
			name:      "invalid timestamp format",
			timestamp: "not-a-number",
			maxAge:    300,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &WebhookService{}

			err := service.VerifyTimestamp(tt.timestamp, tt.maxAge)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWebhookE2E(t *testing.T) {
	secret := "whsec_test123"
	body := []byte(`{"event":"mpa.approved","data":{"request_id":"mpa_xyz"}}`)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	signedPayload := timestamp + "." + string(body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signedPayload))
	signature := hex.EncodeToString(h.Sum(nil))

	headers := http.Header{
		"X-Sigil-Signature": []string{"v1," + signature},
		"X-Sigil-Timestamp": []string{timestamp},
	}

	service := &WebhookService{}

	err := service.Verify(headers, body, secret)
	require.NoError(t, err)

	err = service.VerifyTimestamp(timestamp, 300)
	require.NoError(t, err)
}
