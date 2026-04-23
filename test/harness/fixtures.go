package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
)

// TestFixtures provides pre-generated test data for reproducible E2E tests.
// Keys and fingerprints are deterministic, derived from known seeds.

// FixtureDevice represents a pre-generated device for testing.
type FixtureDevice struct {
	Name        string
	PrivateKey  *ecdsa.PrivateKey
	PublicKey   *ecdsa.PublicKey
	Fingerprint string
	Pictogram   []string
	Speakable   string
}

// TestDevices returns a set of pre-generated devices for E2E testing.
// These devices have deterministic keys for reproducible tests.
func TestDevices() ([]*FixtureDevice, error) {
	devices := make([]*FixtureDevice, 0)

	// Generate devices with deterministic RNG for reproducibility
	seeds := []string{
		"sarah-iphone-seed-001",
		"sarah-ipad-seed-002",
		"mike-pixel-seed-003",
		"damon-iphone-seed-004",
		"damon-macbook-seed-005",
	}

	names := []string{
		"Sarah's iPhone",
		"Sarah's iPad",
		"Mike's Pixel",
		"Damon's iPhone",
		"Damon's MacBook",
	}

	for i, seed := range seeds {
		rng := NewDeterministicRNG([]byte(seed))
		device, err := NewDevice(rng)
		if err != nil {
			return nil, err
		}

		devices = append(devices, &FixtureDevice{
			Name:        names[i],
			PrivateKey:  device.PrivateKey(),
			PublicKey:   device.publicKey,
			Fingerprint: device.Fingerprint,
			Pictogram:   device.Pictogram,
			Speakable:   device.Speakable,
		})
	}

	return devices, nil
}

// TestServerKey returns a pre-generated server keypair for testing.
// In production, server key is derived from mnemonic.
func TestServerKey() (*ecdsa.PrivateKey, error) {
	rng := NewDeterministicRNG([]byte("test-server-key-seed-sigil-auth"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rng)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// MPATestGroups returns device groups for MPA testing.
// Returns 3 groups with 5 devices total (2, 1, 2 distribution).
func MPATestGroups() ([][]*FixtureDevice, error) {
	devices, err := TestDevices()
	if err != nil {
		return nil, err
	}

	return [][]*FixtureDevice{
		{devices[0], devices[1]}, // Sarah's devices (group 0)
		{devices[2]},             // Mike's device (group 1)
		{devices[3], devices[4]}, // Damon's devices (group 2)
	}, nil
}

// TestChallenge represents a test challenge fixture.
type TestChallenge struct {
	ID             string
	ChallengeBytes []byte
	Fingerprint    string
	Action         Action
	ExpiresAt      string
}

// NewTestChallenge creates a test challenge with deterministic data.
func NewTestChallenge(fingerprint string) *TestChallenge {
	return &TestChallenge{
		ID:             "550e8400-e29b-41d4-a716-446655440000",
		ChallengeBytes: []byte("Hello World! This is a test challenge"),
		Fingerprint:    fingerprint,
		Action: Action{
			Type:        "step_up",
			Description: "Add WebAuthn key",
			Params: map[string]interface{}{
				"key_name": "Test YubiKey",
			},
		},
		ExpiresAt: "2026-04-23T10:05:00Z",
	}
}

// DecodePrivateKeyHex decodes a hex-encoded P-256 private key scalar.
func DecodePrivateKeyHex(hexKey string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = new(big.Int).SetBytes(keyBytes)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(keyBytes)

	return priv, nil
}

// DecodePublicKeyCompressed decodes a compressed P-256 public key (33 bytes).
func DecodePublicKeyCompressed(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != 33 {
		return nil, x509.UnknownAuthorityError{}
	}

	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, x509.UnknownAuthorityError{}
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Placeholder for PEM encoding - use when exporting keys for external validation
var _ = pem.Encode
