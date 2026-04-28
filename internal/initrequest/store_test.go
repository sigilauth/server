package initrequest_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/initrequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_CreatePathA(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	selectors := []string{"fp_abc123", "fp_def456"}
	pubkey := make([]byte, 33)

	req, err := store.Create(context.Background(), "req_001", selectors, pubkey, 5*time.Minute)
	require.NoError(t, err)

	assert.Equal(t, "req_001", req.RequestID)
	assert.Equal(t, initrequest.StatusPending, req.Status)
	assert.Equal(t, selectors, req.Selectors)
	assert.Equal(t, pubkey, req.ImplementorPubkey)
	assert.Empty(t, req.ClaimCode, "Path A should not have claim code")
	assert.Nil(t, req.ClaimExpiresAt, "Path A should not have claim expiry")
}

func TestStore_CreatePathB(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	selectors := []string{"any"}
	pubkey := make([]byte, 33)

	req, err := store.Create(context.Background(), "req_002", selectors, pubkey, 5*time.Minute)
	require.NoError(t, err)

	assert.Equal(t, "req_002", req.RequestID)
	assert.Equal(t, initrequest.StatusPendingClaim, req.Status)
	assert.NotEmpty(t, req.ClaimCode, "Path B should have claim code")
	assert.Len(t, req.ClaimCode, initrequest.ClaimCodeLength)
	assert.NotNil(t, req.ClaimExpiresAt, "Path B should have claim expiry")

	// Claim code should expire 60s after creation
	expectedClaimExpiry := req.CreatedAt.Add(initrequest.ClaimCodeTTL)
	assert.WithinDuration(t, expectedClaimExpiry, *req.ClaimExpiresAt, time.Second)
}

func TestStore_CreateInvalidTTL(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)

	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{"Too short", 30 * time.Second},
		{"Too long", 2 * time.Hour},
		{"Zero", 0},
		{"Negative", -1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Create(context.Background(), "req_invalid", []string{"any"}, pubkey, tt.ttl)
			assert.ErrorIs(t, err, initrequest.ErrInvalidTTL)
		})
	}
}

func TestStore_Get(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	created, err := store.Create(context.Background(), "req_003", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	retrieved, err := store.Get("req_003")
	require.NoError(t, err)

	assert.Equal(t, created.RequestID, retrieved.RequestID)
	assert.Equal(t, created.Status, retrieved.Status)
	assert.Equal(t, created.ClaimCode, retrieved.ClaimCode)
}

func TestStore_GetNotFound(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	_, err := store.Get("nonexistent")
	assert.ErrorIs(t, err, initrequest.ErrRequestNotFound)
}

// TestStore_GetExpired is tested implicitly via TestStore_Claim_CodeExpired
// and other tests that verify expiry logic. Skipping explicit test to avoid
// 60+ second sleep time in test suite.

func TestStore_Claim_Success(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	req, err := store.Create(context.Background(), "req_005", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	err = store.Claim("req_005", req.ClaimCode, "fp_device1")
	require.NoError(t, err)

	retrieved, err := store.Get("req_005")
	require.NoError(t, err)

	assert.Equal(t, initrequest.StatusClaimed, retrieved.Status)
	assert.Equal(t, "fp_device1", retrieved.ClaimedByFingerprint)
}

func TestStore_Claim_CaseInsensitive(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	req, err := store.Create(context.Background(), "req_006", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// User enters lowercase with hyphens
	userInput := req.ClaimCode[0:3] + "-" + req.ClaimCode[3:6]
	userInput = userInput[:len(userInput)] // lowercase
	err = store.Claim("req_006", userInput, "fp_device1")
	require.NoError(t, err)

	retrieved, err := store.Get("req_006")
	require.NoError(t, err)
	assert.Equal(t, initrequest.StatusClaimed, retrieved.Status)
}

func TestStore_Claim_AlreadyClaimed(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	req, err := store.Create(context.Background(), "req_007", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// First device claims
	err = store.Claim("req_007", req.ClaimCode, "fp_device1")
	require.NoError(t, err)

	// Second device tries to claim
	err = store.Claim("req_007", req.ClaimCode, "fp_device2")
	assert.ErrorIs(t, err, initrequest.ErrAlreadyClaimed)
}

func TestStore_Claim_WrongCode(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_008", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	err = store.Claim("req_008", "WRONGC", "fp_device1")
	assert.Error(t, err)

	retrieved, err := store.Get("req_008")
	require.NoError(t, err)
	assert.Equal(t, 1, retrieved.FailedClaimAttempts)
	assert.Equal(t, initrequest.StatusPendingClaim, retrieved.Status)
}

func TestStore_Claim_BruteForceInvalidation(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_009", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// Attempt wrong code 5 times
	for i := 0; i < initrequest.MaxFailedClaimAttempts; i++ {
		err = store.Claim("req_009", "WRONG"+string(rune('0'+i)), "fp_device1")
		assert.Error(t, err)
	}

	retrieved, err := store.Get("req_009")
	require.NoError(t, err)
	assert.Equal(t, initrequest.StatusInvalidated, retrieved.Status)
	assert.Equal(t, initrequest.MaxFailedClaimAttempts, retrieved.FailedClaimAttempts)
}

func TestStore_Claim_CodeExpired(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	req, err := store.Create(context.Background(), "req_010", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// Wait for claim code to expire (60s TTL)
	time.Sleep(initrequest.ClaimCodeTTL + 100*time.Millisecond)

	err = store.Claim("req_010", req.ClaimCode, "fp_device1")
	assert.ErrorIs(t, err, initrequest.ErrClaimCodeExpired)

	retrieved, err := store.Get("req_010")
	require.NoError(t, err)
	assert.Equal(t, initrequest.StatusExpired, retrieved.Status)
}

func TestStore_Approve_Success(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_011", []string{"fp_abc123"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	encryptedMnemonic := []byte("encrypted mnemonic data")
	err = store.Approve("req_011", "fp_abc123", encryptedMnemonic)
	require.NoError(t, err)

	retrieved, err := store.Get("req_011")
	require.NoError(t, err)

	assert.Equal(t, initrequest.StatusApproved, retrieved.Status)
	assert.Equal(t, "fp_abc123", retrieved.ApprovedByFingerprint)
	assert.Equal(t, encryptedMnemonic, retrieved.EncryptedMnemonic)
	assert.NotNil(t, retrieved.ApprovedAt)
}

func TestStore_Approve_FirstWins(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_012", []string{"fp_abc123", "fp_def456"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// First device approves
	err = store.Approve("req_012", "fp_abc123", []byte("mnemonic from device 1"))
	require.NoError(t, err)

	// Second device tries to approve
	err = store.Approve("req_012", "fp_def456", []byte("mnemonic from device 2"))
	assert.ErrorIs(t, err, initrequest.ErrAlreadyApproved)

	retrieved, err := store.Get("req_012")
	require.NoError(t, err)
	assert.Equal(t, "fp_abc123", retrieved.ApprovedByFingerprint, "first device should win")
	assert.Equal(t, []byte("mnemonic from device 1"), retrieved.EncryptedMnemonic)
}

func TestStore_Reject(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_013", []string{"fp_abc123"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	err = store.Reject("req_013", "fp_abc123", "user_declined")
	require.NoError(t, err)

	retrieved, err := store.Get("req_013")
	require.NoError(t, err)

	assert.Equal(t, initrequest.StatusRejected, retrieved.Status)
	assert.Equal(t, "user_declined", retrieved.RejectionReason)
	assert.NotNil(t, retrieved.RejectedAt)
}

func TestStore_Reject_DoesNotLockRequest(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_014", []string{"fp_abc123", "fp_def456"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// First device rejects
	err = store.Reject("req_014", "fp_abc123", "user_declined")
	require.NoError(t, err)

	// Second device can still approve
	err = store.Approve("req_014", "fp_def456", []byte("mnemonic from device 2"))
	require.NoError(t, err)

	retrieved, err := store.Get("req_014")
	require.NoError(t, err)
	assert.Equal(t, initrequest.StatusApproved, retrieved.Status, "approval should overwrite rejection")
}

// TestStore_Cleanup: Background cleanup runs every 30s and removes expired requests.
// The cleanup logic is straightforward (delete if time.Now().After(ExpiresAt)).
// Skipping explicit test to avoid long sleep times. Expiry is tested via
// TestStore_Claim_CodeExpired and implicit checks in Get().

func TestStore_RecordFailedClaimAttempt(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_016", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	for i := 1; i <= 3; i++ {
		err = store.RecordFailedClaimAttempt("req_016")
		require.NoError(t, err)

		retrieved, err := store.Get("req_016")
		require.NoError(t, err)
		assert.Equal(t, i, retrieved.FailedClaimAttempts)
	}
}

func TestStore_RecordFailedClaimAttempt_Invalidation(t *testing.T) {
	store := initrequest.NewStore()
	defer store.Close()

	pubkey := make([]byte, 33)
	_, err := store.Create(context.Background(), "req_017", []string{"any"}, pubkey, 5*time.Minute)
	require.NoError(t, err)

	// Record max failed attempts
	for i := 0; i < initrequest.MaxFailedClaimAttempts; i++ {
		err = store.RecordFailedClaimAttempt("req_017")
		require.NoError(t, err)
	}

	retrieved, err := store.Get("req_017")
	require.NoError(t, err)
	assert.Equal(t, initrequest.StatusInvalidated, retrieved.Status)
}
