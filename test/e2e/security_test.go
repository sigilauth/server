package e2e

import (
	"testing"
)

// Security tests per maren-qa-strategy.md §6

// === Signature Forgery (§6.1) ===

// TestSignatureForgeryRandom tests rejection of random signatures.
// BLOCKED: Requires B1 (server).
func TestSignatureForgeryRandom(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Random 64-byte signature on valid challenge → INVALID_SIGNATURE
}

// TestSignatureForgeryWrongKey tests signature from different key.
// BLOCKED: Requires B1 (server).
func TestSignatureForgeryWrongKey(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Valid signature but from different key → INVALID_SIGNATURE
}

// TestSignatureMalleabilityHighS tests high-S signature handling.
// BLOCKED: Requires B1 (server).
func TestSignatureMalleabilityHighS(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Signature with S > order/2 → reject or normalize
}

// TestSignatureTruncated tests truncated signature rejection.
// BLOCKED: Requires B1 (server).
func TestSignatureTruncated(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: 32-byte signature → INVALID_SIGNATURE
}

// TestSignatureEmpty tests empty signature rejection.
// BLOCKED: Requires B1 (server).
func TestSignatureEmpty(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Empty signature → INVALID_SIGNATURE
}

// === Replay Attacks (§6.2) ===

// TestReplaySameChallenge tests replay of valid response.
// BLOCKED: Requires B1 (server).
func TestReplaySameChallenge(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Valid response replayed → CHALLENGE_ALREADY_USED
}

// TestReplayModifiedTimestamp tests replay with modified timestamp.
// BLOCKED: Requires B1 (server).
func TestReplayModifiedTimestamp(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Response with modified timestamp → INVALID_SIGNATURE (timestamp in sig payload)
}

// TestReplayExpiredChallenge tests replay after challenge expiry.
// BLOCKED: Requires B1 (server).
func TestReplayExpiredChallenge(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Replay after challenge expired → CHALLENGE_NOT_FOUND
}

// TestReplayMPA tests replay of MPA approval.
// BLOCKED: Requires B1 (server).
func TestReplayMPA(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: MPA approval replayed → already recorded or expired
}

// === MITM Detection (§6.3) ===

// TestMITMServerSignature tests detection of invalid server signature.
// BLOCKED: Requires B1 (server).
func TestMITMServerSignature(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Challenge with invalid server_signature → device rejects pre-biometric
}

// TestMITMChallengeModification tests detection of modified challenge.
// BLOCKED: Requires B1 (server).
func TestMITMChallengeModification(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Modified challenge_bytes in transit → signature verification fails
}

// TestMITMKeySubstitution tests detection of substituted server key during pairing.
// BLOCKED: Requires B10 (web demo).
func TestMITMKeySubstitution(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B10 not implemented")
	t.Skip("Awaiting B10 (web demo)")

	// TODO: Substituted server_public_key in pairing → pictogram mismatch alerts user
}

// === Fingerprint Spoofing (§6.5) ===

// TestFingerprintFabricated tests rejection of fabricated fingerprint.
// BLOCKED: Requires B1 (server).
func TestFingerprintFabricated(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Response with public_key that doesn't hash to expected fingerprint → reject
}

// TestFingerprintMPANonMember tests MPA response from non-member device.
// BLOCKED: Requires B1 (server).
func TestFingerprintMPANonMember(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: MPA response from device not in any group → rejected
}

// === Timestamp Validation ===

// TestTimestampDrift tests rejection of timestamps outside acceptable window.
// BLOCKED: Requires B1 (server).
func TestTimestampDrift(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Response timestamp >5 min from server time → TIMESTAMP_INVALID
}

// TestTimestampFuture tests rejection of future timestamps.
// BLOCKED: Requires B1 (server).
func TestTimestampFuture(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Response timestamp >5 min in future → TIMESTAMP_INVALID
}
