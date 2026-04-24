package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRegisterAndAuth tests the complete registration and authentication flow.
// Scenario: Device registers, server requests challenge, device approves, server verifies.
func TestRegisterAndAuth(t *testing.T) {
	requireDockerStack(t)
	_ = newTestContext(t)

	client := newHTTPClient()
	baseURL := getBaseURL()

	// 1. Create simulated device with P-256 keypair
	device := generateTestDevice(t)
	t.Logf("Device fingerprint: %s", device.Fingerprint)

	// 2. Integrator creates authentication challenge
	challenge := createTestChallengeForDevice(t, client, baseURL, device)
	require.NotEmpty(t, challenge.ChallengeID, "Challenge ID should be returned")
	require.Equal(t, 5, len(challenge.Pictogram), "Pictogram should have 5 words")
	t.Logf("Challenge created: %s", challenge.ChallengeID)
	t.Logf("Pictogram: %v", challenge.Pictogram)

	// 3. Check challenge status - should be pending
	status := getChallengeStatus(t, client, baseURL, challenge.ChallengeID)
	require.Equal(t, "pending", status.Status, "Challenge should be pending")

	// 4. Device signs the challenge bytes
	signature := device.SignChallenge(t, challenge.ChallengeBytes)

	// 5. Device responds with signature
	err := respondToChallengeWithSignature(t, client, baseURL, challenge.ChallengeID, device.Fingerprint, signature)
	require.NoError(t, err, "Challenge response should succeed")

	// 6. Check challenge status - should be verified
	status = getChallengeStatus(t, client, baseURL, challenge.ChallengeID)
	require.Equal(t, "verified", status.Status, "Challenge should be verified after successful response")

	t.Log("✅ Full register+auth flow completed successfully")
}

// TestChallengeExpiry tests that expired challenges are rejected.
// Scenario: Challenge created, wait for expiry, device responds, server rejects.
func TestChallengeExpiry(t *testing.T) {
	requireDockerStack(t)
	_ = newTestContext(t)

	client := newHTTPClient()
	baseURL := getBaseURL()

	// 1. Create a challenge
	challenge := createTestChallenge(t, client, baseURL)

	// 2. Wait for challenge to expire (5 min default, but check status after 6 min)
	t.Log("Waiting for challenge to expire...")
	time.Sleep(6 * time.Minute)

	// 3. Check challenge status - should be expired
	statusResp := getChallengeStatus(t, client, baseURL, challenge.ChallengeID)
	require.Equal(t, "expired", statusResp.Status, "Challenge should be expired after 6 minutes")

	// 4. Attempt to respond to expired challenge
	err := respondToChallenge(t, client, baseURL, challenge.ChallengeID, challenge.Fingerprint, "fake_signature")
	require.Error(t, err, "Should reject expired challenge")
	require.Contains(t, err.Error(), "CHALLENGE_EXPIRED", "Should return CHALLENGE_EXPIRED error")
}

// TestReplayRejection tests that replayed responses are rejected.
// Scenario: Device responds to challenge, same response replayed, server rejects.
func TestReplayRejection(t *testing.T) {
	requireDockerStack(t)
	_ = newTestContext(t)

	client := newHTTPClient()
	baseURL := getBaseURL()

	// 1. Create device keypair
	device := generateTestDevice(t)

	// 2. Create challenge
	challenge := createTestChallengeForDevice(t, client, baseURL, device)

	// 3. Device signs the challenge bytes
	signature := device.SignChallenge(t, challenge.ChallengeBytes)

	// 4. First response - should succeed
	err := respondToChallengeWithSignature(t, client, baseURL, challenge.ChallengeID, device.Fingerprint, signature)
	require.NoError(t, err, "First response should succeed")

	// 5. Replay same signature - should be rejected
	err = respondToChallengeWithSignature(t, client, baseURL, challenge.ChallengeID, device.Fingerprint, signature)
	require.Error(t, err, "Replayed response should be rejected")
	require.Contains(t, err.Error(), "CHALLENGE_ALREADY_USED", "Should return CHALLENGE_ALREADY_USED error")
}

// TestFingerprintMismatch tests that responses from wrong device are rejected.
// Scenario: Challenge for device A, device B responds, server rejects.
// BLOCKED: Requires B1 (server).
func TestFingerprintMismatch(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx
	
	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")
	
	// TODO: Implementation when dependencies ready:
	// 1. Create device A and device B
	// 2. Challenge for device A's fingerprint
	// 3. Device B signs response with its own key
	// 4. Assert FINGERPRINT_MISMATCH error
}

// TestInvalidSignature tests that forged signatures are rejected.
// BLOCKED: Requires B1 (server).
func TestInvalidSignature(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx
	
	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")
	
	// TODO: Implementation when dependencies ready:
	// 1. Create valid challenge
	// 2. Respond with random/malformed signature
	// 3. Assert INVALID_SIGNATURE error
}
