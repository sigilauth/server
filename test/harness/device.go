package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
)

// SimulatedDevice represents a test device with P-256 keypair.
// Mimics mobile app behavior for E2E testing.
type SimulatedDevice struct {
	mu         sync.RWMutex
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	
	Fingerprint string
	Pictogram   []string
	Speakable   string
	
	// Registered servers (server_url -> push_token)
	servers map[string]string
	
	// Pending challenges (challenge_id -> Challenge)
	challenges map[string]*Challenge
}

// Challenge represents a pending challenge from a server.
type Challenge struct {
	ID              string
	ServerID        string
	ChallengeBytes  []byte
	Action          Action
	ServerSignature []byte
	ExpiresAt       string
	RespondTo       string
}

// Action represents the action context for a challenge.
type Action struct {
	Type        string
	Description string
	Params      map[string]interface{}
}

// NewDevice creates a new simulated device with a fresh P-256 keypair.
// Uses crypto/rand by default. Pass a deterministic reader for reproducible tests.
func NewDevice(randReader io.Reader) (*SimulatedDevice, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, err
	}
	
	pubKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	fingerprint := sha256.Sum256(pubKeyBytes)
	
	d := &SimulatedDevice{
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		servers:     make(map[string]string),
		challenges:  make(map[string]*Challenge),
	}
	
	d.Pictogram, d.Speakable = derivePictogram(fingerprint[:])
	
	return d, nil
}

// PublicKeyCompressed returns the compressed P-256 public key (33 bytes).
func (d *SimulatedDevice) PublicKeyCompressed() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), d.publicKey.X, d.publicKey.Y)
}

// PrivateKey returns the ECDSA private key for signing operations.
func (d *SimulatedDevice) PrivateKey() *ecdsa.PrivateKey {
	return d.privateKey
}
