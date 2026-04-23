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
