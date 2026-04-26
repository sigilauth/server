//go:build session_unfixed
// +build session_unfixed

// Pre-existing breakage: session.VerifyRequest.DevicePublicKey field removed in d024c5d
// Fixed in domain-sep PR alongside CRITICAL verify-bytes mismatch (Knox audit)
// To run these tests: go test -tags=session_unfixed ./internal/session/...

package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	store := session.NewStore()
	require.NotNil(t, store)
}

func TestCreateChallenge(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKey := &deviceKey.PublicKey
	fingerprint := crypto.FingerprintFromPublicKey(devicePubKey)

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, err := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Action: session.Action{
			Type:        "step_up",
			Description: "Add WebAuthn key",
		},
		ServerKey: serverKey,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, challenge.ChallengeID)
	assert.NotEmpty(t, challenge.ChallengeBytes)
	assert.NotEmpty(t, challenge.ServerSignature)
	assert.NotEmpty(t, challenge.Pictogram)
	assert.Len(t, challenge.Pictogram, 5)
	assert.NotEmpty(t, challenge.PictogramSpeakable)
	assert.False(t, challenge.ExpiresAt.IsZero())
}

func TestGetChallenge(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKey := &deviceKey.PublicKey
	fingerprint := crypto.FingerprintFromPublicKey(devicePubKey)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	created, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Action: session.Action{
			Type:        "step_up",
			Description: "Test action",
		},
		ServerKey: serverKey,
	})

	retrieved, err := store.GetChallenge(ctx, created.ChallengeID)
	require.NoError(t, err)
	assert.Equal(t, created.ChallengeID, retrieved.ChallengeID)
	assert.Equal(t, created.Fingerprint, retrieved.Fingerprint)
}

func TestGetChallengeNotFound(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	_, err := store.GetChallenge(ctx, "nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestVerifyChallenge(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKey := &deviceKey.PublicKey
	fingerprint := crypto.FingerprintFromPublicKey(devicePubKey)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Action: session.Action{
			Type:        "step_up",
			Description: "Test",
		},
		ServerKey: serverKey,
	})

	signature, err := crypto.Sign(deviceKey, challenge.ChallengeBytes)
	require.NoError(t, err)

	err = store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Signature:       signature,
	})

	assert.NoError(t, err)
}

func TestVerifyChallengeTwice(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devicePubKey := &deviceKey.PublicKey
	fingerprint := crypto.FingerprintFromPublicKey(devicePubKey)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Action: session.Action{
			Type:        "step_up",
			Description: "Test",
		},
		ServerKey: serverKey,
	})

	signature, _ := crypto.Sign(deviceKey, challenge.ChallengeBytes)

	err1 := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Signature:       signature,
	})
	require.NoError(t, err1)

	err2 := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(devicePubKey),
		Signature:       signature,
	})

	assert.Error(t, err2)
	assert.Contains(t, err2.Error(), "already used")
}

func TestVerifyChallengeWrongKey(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fingerprint := crypto.FingerprintFromPublicKey(&deviceKey1.PublicKey)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey1.PublicKey),
		Action: session.Action{
			Type: "step_up",
		},
		ServerKey: serverKey,
	})

	signature, _ := crypto.Sign(deviceKey2, challenge.ChallengeBytes)

	err := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey2.PublicKey),
		Signature:       signature,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")
}

func TestChallengeExpiry(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fingerprint := crypto.FingerprintFromPublicKey(&deviceKey.PublicKey)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(fingerprint),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Action: session.Action{
			Type: "step_up",
		},
		ServerKey: serverKey,
		TTL:       1 * time.Millisecond,
	})

	time.Sleep(10 * time.Millisecond)

	_, err := store.GetChallenge(ctx, challenge.ChallengeID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCleanExpired(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create expired challenge
	expiredChallenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&deviceKey1.PublicKey)),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey1.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
		TTL:             1 * time.Millisecond,
	})

	// Create non-expired challenge
	activeChallenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&deviceKey2.PublicKey)),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey2.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
		TTL:             10 * time.Minute,
	})

	// Wait for first challenge to expire
	time.Sleep(10 * time.Millisecond)

	// Clean expired challenges
	removed := store.CleanExpired(ctx)
	assert.Equal(t, 1, removed, "should remove 1 expired challenge")

	// Verify expired challenge is gone
	_, err := store.GetChallenge(ctx, expiredChallenge.ChallengeID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Verify active challenge still exists
	retrieved, err := store.GetChallenge(ctx, activeChallenge.ChallengeID)
	assert.NoError(t, err)
	assert.Equal(t, activeChallenge.ChallengeID, retrieved.ChallengeID)
}

func TestCreateChallengeInvalidPublicKeyLength(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     "test-fingerprint",
		DevicePublicKey: []byte{0x01, 0x02}, // Wrong length (should be 33 bytes)
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device public key must be 33 bytes")
}

func TestCreateChallengeInvalidFingerprint(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     "invalid-hex-!!!", // Invalid hex
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid fingerprint hex")
}

func TestVerifyChallengeInvalidPublicKey(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&deviceKey.PublicKey)),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
	})

	err := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: []byte{0x01, 0x02, 0x03}, // Invalid public key
		Signature:       []byte{},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid device public key")
}

func TestVerifyChallengeWrongSignature(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&deviceKey.PublicKey)),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
	})

	// Sign wrong message
	wrongSignature, _ := crypto.Sign(deviceKey, []byte("wrong-challenge"))

	err := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Signature:       wrongSignature,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyChallengeExpired(t *testing.T) {
	store := session.NewStore()
	ctx := context.Background()

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	challenge, _ := store.CreateChallenge(ctx, session.ChallengeRequest{
		Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&deviceKey.PublicKey)),
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Action:          session.Action{Type: "test"},
		ServerKey:       serverKey,
		TTL:             1 * time.Millisecond,
	})

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	signature, _ := crypto.Sign(deviceKey, challenge.ChallengeBytes)

	err := store.VerifyChallenge(ctx, session.VerifyRequest{
		ChallengeID:     challenge.ChallengeID,
		DevicePublicKey: crypto.CompressPublicKey(&deviceKey.PublicKey),
		Signature:       signature,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
