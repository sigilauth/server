package sigilauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingSignature  = errors.New("missing X-Sigil-Signature header")
	ErrMissingTimestamp  = errors.New("missing X-Sigil-Timestamp header")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidTimestamp  = errors.New("invalid timestamp")
	ErrTimestampTooOld   = errors.New("timestamp too old")
	ErrTimestampInFuture = errors.New("timestamp in future")
)

type WebhookService struct {
	client *Client
}

func (s *WebhookService) Verify(headers http.Header, body []byte, secret string) error {
	sigHeader := headers.Get("X-Sigil-Signature")
	if sigHeader == "" {
		return ErrMissingSignature
	}

	timestamp := headers.Get("X-Sigil-Timestamp")
	if timestamp == "" {
		return ErrMissingTimestamp
	}

	parts := strings.SplitN(sigHeader, ",", 2)
	if len(parts) != 2 || parts[0] != "v1" {
		return ErrInvalidSignature
	}
	providedSig := parts[1]

	signedPayload := timestamp + "." + string(body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signedPayload))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(providedSig)) {
		return ErrInvalidSignature
	}

	return nil
}

func (s *WebhookService) VerifyTimestamp(timestamp string, maxAge int) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}

	now := time.Now().Unix()
	diff := now - ts

	if diff < 0 {
		return ErrTimestampInFuture
	}

	if math.Abs(float64(diff)) > float64(maxAge) {
		return ErrTimestampTooOld
	}

	return nil
}
