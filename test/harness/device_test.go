package harness

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDevice(t *testing.T) {
	device, err := NewDevice(rand.Reader)
	require.NoError(t, err)

	assert.NotNil(t, device.privateKey)
	assert.NotNil(t, device.publicKey)
	assert.Len(t, device.Fingerprint, 64, "fingerprint should be 64 hex chars")
	assert.Len(t, device.Pictogram, 5, "pictogram should have 5 emojis")
	assert.NotEmpty(t, device.Speakable)
}

func TestNewDeviceWithDeterministicRNG(t *testing.T) {
	// Verify deterministic RNG can be injected for key generation
	seed := []byte("deterministic-device-test")
	rng := NewDeterministicRNG(seed)

	device, err := NewDevice(rng)
	require.NoError(t, err)

	assert.NotEmpty(t, device.Fingerprint)
	assert.Len(t, device.Pictogram, 5)
	assert.NotEmpty(t, device.Speakable)
	
	// Note: Full reproducibility requires controlling ecdsa.GenerateKey internals.
	// This test verifies RNG injection works; E2E reproducibility achieved via
	// pre-generated test fixture keys rather than runtime generation.
}

func TestPublicKeyCompressed(t *testing.T) {
	device, err := NewDevice(rand.Reader)
	require.NoError(t, err)

	pubKey := device.PublicKeyCompressed()
	assert.Len(t, pubKey, 33, "compressed P-256 public key should be 33 bytes")

	// First byte should be 0x02 or 0x03 (compressed point format)
	assert.True(t, pubKey[0] == 0x02 || pubKey[0] == 0x03, "invalid compressed key prefix")
}

func TestFingerprintIsSHA256OfPublicKey(t *testing.T) {
	device, err := NewDevice(rand.Reader)
	require.NoError(t, err)

	// Fingerprint should be SHA256 of compressed public key
	pubKey := device.PublicKeyCompressed()
	expectedHash := sha256.Sum256(pubKey)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])
	
	assert.Equal(t, expectedFingerprint, device.Fingerprint, "fingerprint should be SHA256 of compressed public key")
}

func TestMultipleDevicesUnique(t *testing.T) {
	fingerprints := make(map[string]bool)

	for i := 0; i < 10; i++ {
		device, err := NewDevice(rand.Reader)
		require.NoError(t, err)

		assert.False(t, fingerprints[device.Fingerprint], "fingerprint collision")
		fingerprints[device.Fingerprint] = true
	}
}
