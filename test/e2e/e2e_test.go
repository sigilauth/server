package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMain sets up the E2E test environment.
// BLOCKED: Requires B11 (docker-compose) to bring up test stack.
func TestMain(m *testing.M) {
	// Check if test stack is running
	if os.Getenv("SIGIL_E2E_ENABLED") != "true" {
		// Skip E2E tests if stack not running
		os.Exit(0)
	}
	
	os.Exit(m.Run())
}

// testTimeout is the default timeout for E2E operations.
const testTimeout = 30 * time.Second

// newTestContext creates a context with the test timeout.
func newTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// requireDockerStack skips the test if docker-compose stack isn't running.
func requireDockerStack(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGIL_E2E_ENABLED") != "true" {
		t.Skip("BLOCKED: Set SIGIL_E2E_ENABLED=true with docker-compose stack running")
	}
}

// Placeholder assertion to satisfy imports until real tests implemented.
var _ = require.New

// getBaseURL returns the base URL for the Sigil server
func getBaseURL() string {
	if url := os.Getenv("SIGIL_BASE_URL"); url != "" {
		return url
	}
	return "http://localhost:8443"
}

// TestChallenge represents a created challenge for testing
type TestChallenge struct {
	ChallengeID        string   `json:"challenge_id"`
	Fingerprint        string   `json:"fingerprint"`
	DevicePublicKey    string   `json:"device_public_key"`
	Pictogram          []string `json:"pictogram"`
	PictogramSpeakable string   `json:"pictogram_speakable"`
	ExpiresAt          string   `json:"expires_at"`
}

// createTestChallenge creates a challenge for testing (without real device)
func createTestChallenge(t *testing.T, client *http.Client, baseURL string) *TestChallenge {
	t.Helper()

	// Generate a real test device to get valid crypto
	device := generateTestDevice(t)

	// Use the real device for creating challenge
	return createTestChallengeForDevice(t, client, baseURL, device)
}

// ChallengeStatusResponse represents the status API response
type ChallengeStatusResponse struct {
	ChallengeID string `json:"challenge_id"`
	Status      string `json:"status"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// getChallengeStatus polls the challenge status endpoint
func getChallengeStatus(t *testing.T, client *http.Client, baseURL, challengeID string) *ChallengeStatusResponse {
	t.Helper()

	resp, err := client.Get(baseURL + "/v1/auth/challenge/" + challengeID + "/status")
	require.NoError(t, err, "Failed to get challenge status")
	defer resp.Body.Close()

	var statusResp ChallengeStatusResponse
	err = json.NewDecoder(resp.Body).Decode(&statusResp)
	require.NoError(t, err, "Failed to decode status response")

	return &statusResp
}

// respondToChallenge attempts to respond to a challenge
func respondToChallenge(t *testing.T, client *http.Client, baseURL, challengeID, fingerprint, signature string) error {
	t.Helper()

	reqBody := map[string]interface{}{
		"challenge_id": challengeID,
		"fingerprint":  fingerprint,
		"signature":    signature,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := client.Post(baseURL+"/respond", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errorCode, ok := errResp["error"]; ok {
			return fmt.Errorf("%s: %s", errorCode, errResp["message"])
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}

// TestDevice represents a simulated device with ECDSA P-256 keypair
type TestDevice struct {
	PrivateKey         *ecdsa.PrivateKey
	PublicKey          *ecdsa.PublicKey
	PublicKeyCompressed []byte
	Fingerprint        string
}

// generateTestDevice creates a test device with P-256 keypair
func generateTestDevice(t *testing.T) *TestDevice {
	t.Helper()

	// Generate P-256 keypair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate device keypair")

	// Compress public key (33 bytes: 0x02/0x03 + X coordinate)
	pubKeyCompressed := make([]byte, 33)
	privateKey.PublicKey.X.FillBytes(pubKeyCompressed[1:33])
	if privateKey.PublicKey.Y.Bit(0) == 0 {
		pubKeyCompressed[0] = 0x02
	} else {
		pubKeyCompressed[0] = 0x03
	}

	// Compute fingerprint = SHA256(compressed public key)
	hash := sha256.Sum256(pubKeyCompressed)
	fingerprintHex := hex.EncodeToString(hash[:])

	return &TestDevice{
		PrivateKey:          privateKey,
		PublicKey:           &privateKey.PublicKey,
		PublicKeyCompressed: pubKeyCompressed,
		Fingerprint:         fingerprintHex,
	}
}

// SignChallenge signs a challenge ID with the device's private key
func (d *TestDevice) SignChallenge(t *testing.T, challengeID string) string {
	t.Helper()

	// Sign the challenge ID (simplified - real implementation would sign challenge_bytes)
	message := []byte(challengeID)
	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, d.PrivateKey, hash[:])
	require.NoError(t, err, "Failed to sign challenge")

	// Normalize to low-S (BIP-62)
	curveOrder := elliptic.P256().Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curveOrder, s)
	}

	// Encode as r || s (64 bytes total)
	signature := make([]byte, 64)
	r.FillBytes(signature[0:32])
	s.FillBytes(signature[32:64])

	return base64.StdEncoding.EncodeToString(signature)
}

// createTestChallengeForDevice creates a challenge for a specific device
func createTestChallengeForDevice(t *testing.T, client *http.Client, baseURL string, device *TestDevice) *TestChallenge {
	t.Helper()

	devicePublicKeyB64 := base64.StdEncoding.EncodeToString(device.PublicKeyCompressed)

	reqBody := map[string]interface{}{
		"fingerprint":       device.Fingerprint,
		"device_public_key": devicePublicKeyB64,
		"action": map[string]interface{}{
			"type":        "step_up",
			"description": "Test authentication",
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := client.Post(baseURL+"/challenge", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "Failed to create challenge")
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "Challenge creation should return 201")

	var challengeResp TestChallenge
	err = json.NewDecoder(resp.Body).Decode(&challengeResp)
	require.NoError(t, err, "Failed to decode challenge response")

	challengeResp.Fingerprint = device.Fingerprint
	challengeResp.DevicePublicKey = devicePublicKeyB64

	return &challengeResp
}

// respondToChallengeWithSignature responds to a challenge with a pre-computed signature
func respondToChallengeWithSignature(t *testing.T, client *http.Client, baseURL, challengeID, fingerprint, signature string) error {
	t.Helper()
	return respondToChallenge(t, client, baseURL, challengeID, fingerprint, signature)
}
