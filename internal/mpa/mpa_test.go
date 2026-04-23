package mpa_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/mpa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	store := mpa.NewStore()
	require.NotNil(t, store)
}

func TestCreateRequest(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	groups := []mpa.Group{
		{
			Members: []mpa.Member{
				{
					Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device1.PublicKey)),
					DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
				},
			},
		},
		{
			Members: []mpa.Member{
				{
					Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device2.PublicKey)),
					DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
				},
			},
		},
		{
			Members: []mpa.Member{
				{
					Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device3.PublicKey)),
					DevicePublicKey: crypto.CompressPublicKey(&device3.PublicKey),
				},
			},
		},
	}

	request, err := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID: "test-request-123",
		Action: mpa.Action{
			Type:        "engine:cold-boot",
			Description: "Cold boot engine ENG-001",
		},
		Groups:         groups,
		Required:       2,
		RejectPolicy:   "continue",
		ExpiresIn:      5 * time.Minute,
		ServerKey:      serverKey,
	})

	require.NoError(t, err)
	assert.Equal(t, "test-request-123", request.RequestID)
	assert.Equal(t, 2, request.Required)
	assert.Equal(t, 3, request.GroupsTotal)
	assert.Len(t, request.Groups, 3)
	assert.Equal(t, "pending", request.Status)
}

func TestRespondToMPA(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	groups := []mpa.Group{
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device1.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		}}},
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device2.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
		}}},
	}

	request, _ := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID:    "test-123",
		Action:       mpa.Action{Type: "test"},
		Groups:       groups,
		Required:     2,
		RejectPolicy: "continue",
		ExpiresIn:    5 * time.Minute,
		ServerKey:    serverKey,
	})

	signature, _ := crypto.Sign(device1, []byte(request.RequestID))

	result, err := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		Signature:       signature,
		Decision:        "approved",
	})

	require.NoError(t, err)
	assert.Equal(t, "pending", result.Status)
	assert.Len(t, result.GroupsSatisfied, 1)
}

func TestMPAQuorumReached(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	groups := []mpa.Group{
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device1.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		}}},
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device2.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
		}}},
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device3.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device3.PublicKey),
		}}},
	}

	request, _ := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID:    "test-quorum",
		Action:       mpa.Action{Type: "test"},
		Groups:       groups,
		Required:     2,
		RejectPolicy: "continue",
		ExpiresIn:    5 * time.Minute,
		ServerKey:    serverKey,
	})

	sig1, _ := crypto.Sign(device1, []byte(request.RequestID))
	result1, _ := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		Signature:       sig1,
		Decision:        "approved",
	})
	assert.Equal(t, "pending", result1.Status)

	sig2, _ := crypto.Sign(device2, []byte(request.RequestID))
	result2, _ := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
		Signature:       sig2,
		Decision:        "approved",
	})

	assert.Equal(t, "approved", result2.Status)
	assert.Len(t, result2.GroupsSatisfied, 2)
}

func TestMPASameGroupDoubleApproval(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp1 := crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device1.PublicKey))
	fp2 := crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device2.PublicKey))

	groups := []mpa.Group{
		{Members: []mpa.Member{
			{Fingerprint: fp1, DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey)},
			{Fingerprint: fp2, DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey)},
		}},
	}

	request, _ := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID:    "test-same-group",
		Action:       mpa.Action{Type: "test"},
		Groups:       groups,
		Required:     1,
		RejectPolicy: "continue",
		ExpiresIn:    5 * time.Minute,
		ServerKey:    serverKey,
	})

	sig1, _ := crypto.Sign(device1, []byte(request.RequestID))
	result1, _ := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		Signature:       sig1,
		Decision:        "approved",
	})
	assert.Equal(t, "approved", result1.Status)

	sig2, _ := crypto.Sign(device2, []byte(request.RequestID))
	result2, err := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
		Signature:       sig2,
		Decision:        "approved",
	})

	require.Error(t, err)
	errMsg := err.Error()
	validError := (errMsg == "group already satisfied" || errMsg == "request already completed with status: approved")
	assert.True(t, validError, "error should indicate group already satisfied or request completed, got: %s", errMsg)
	assert.Nil(t, result2)
}

func TestMPARejectOnFirst(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	groups := []mpa.Group{
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device1.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		}}},
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device2.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device2.PublicKey),
		}}},
	}

	request, _ := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID:    "test-reject",
		Action:       mpa.Action{Type: "test"},
		Groups:       groups,
		Required:     2,
		RejectPolicy: "reject_on_first",
		ExpiresIn:    5 * time.Minute,
		ServerKey:    serverKey,
	})

	sig1, _ := crypto.Sign(device1, []byte(request.RequestID))
	result, _ := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device1.PublicKey),
		Signature:       sig1,
		Decision:        "rejected",
	})

	assert.Equal(t, "rejected", result.Status)
}

func TestMPAExpiry(t *testing.T) {
	store := mpa.NewStore()
	ctx := context.Background()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	groups := []mpa.Group{
		{Members: []mpa.Member{{
			Fingerprint:     crypto.FingerprintHex(crypto.FingerprintFromPublicKey(&device.PublicKey)),
			DevicePublicKey: crypto.CompressPublicKey(&device.PublicKey),
		}}},
	}

	request, _ := store.CreateRequest(ctx, mpa.CreateRequest{
		RequestID:    "test-expiry",
		Action:       mpa.Action{Type: "test"},
		Groups:       groups,
		Required:     1,
		RejectPolicy: "continue",
		ExpiresIn:    1 * time.Millisecond,
		ServerKey:    serverKey,
	})

	time.Sleep(10 * time.Millisecond)

	sig, _ := crypto.Sign(device, []byte(request.RequestID))
	_, err := store.Respond(ctx, mpa.Response{
		RequestID:       request.RequestID,
		DevicePublicKey: crypto.CompressPublicKey(&device.PublicKey),
		Signature:       sig,
		Decision:        "approved",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
