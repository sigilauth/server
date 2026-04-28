package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sigilauth/server/internal/crypto"
)

// Client handles push notification dispatch via the relay service.
type Client struct {
	baseURL  string
	serverID string
	serverKey *ecdsa.PrivateKey
	httpClient *http.Client
}

// NewClient creates a new relay client.
//
// baseURL: relay service base URL (e.g., "https://relay.sigilauth.com")
// serverID: unique identifier for this server instance
// serverKey: server's ECDSA P-256 private key for signing push requests
func NewClient(baseURL, serverID string, serverKey *ecdsa.PrivateKey) *Client {
	return &Client{
		baseURL:  baseURL,
		serverID: serverID,
		serverKey: serverKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// PushRequest represents a push notification dispatch request.
type PushRequest struct {
	ServerID         string                 `json:"server_id"`
	Fingerprint      string                 `json:"fingerprint"`
	Payload          map[string]interface{} `json:"payload"`
	Timestamp        string                 `json:"timestamp"`
	RequestSignature string                 `json:"request_signature"`
}

// PushResponse represents the relay's response to a push request.
type PushResponse struct {
	Status      string `json:"status"`
	PushID      string `json:"push_id,omitempty"`
	DeliveredAt string `json:"delivered_at,omitempty"`
}

// Push dispatches a push notification to a device via the relay.
//
// fingerprint: device fingerprint (SHA256 of device public key)
// payload: notification payload (type, request_id, action, etc.)
//
// Returns error if push fails or device not registered.
func (c *Client) Push(ctx context.Context, fingerprint string, payload map[string]interface{}) error {
	// Generate timestamp (Unix epoch as string)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Build signature payload: "SIGIL-RELAY-PUSH-V1\x00{server_id}\x00{fingerprint}\x00{timestamp}"
	signaturePayload := fmt.Sprintf("SIGIL-RELAY-PUSH-V1\x00%s\x00%s\x00%s", c.serverID, fingerprint, timestamp)

	// Sign the payload
	signatureBytes, err := crypto.Sign(c.serverKey, []byte(signaturePayload))
	if err != nil {
		return fmt.Errorf("failed to sign push request: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signatureBytes)

	// Build request
	req := PushRequest{
		ServerID:         c.serverID,
		Fingerprint:      fingerprint,
		Payload:          payload,
		Timestamp:        timestamp,
		RequestSignature: signatureB64,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal push request: %w", err)
	}

	// Make HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/push", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send push request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		// Parse error response
		var errResp struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return fmt.Errorf("push failed: %s - %s", errResp.Error.Code, errResp.Error.Message)
		}
		return fmt.Errorf("push failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse success response
	var pushResp PushResponse
	if err := json.Unmarshal(respBody, &pushResp); err != nil {
		return fmt.Errorf("failed to parse push response: %w", err)
	}

	// Verify delivered status
	if pushResp.Status != "delivered" {
		return fmt.Errorf("push not delivered: status=%s", pushResp.Status)
	}

	return nil
}
