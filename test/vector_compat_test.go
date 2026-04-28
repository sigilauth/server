package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
)

// TestCryptoCompatibility verifies fuzzer-generated test vectors are compatible
// with server crypto implementation (ECIES decrypt test)
func TestCryptoCompatibility(t *testing.T) {
	// Load ADV-01 vector (relative to server/ directory)
	data, err := os.ReadFile("../../tests/cross-impl/vectors/adversarial/ADV-01.json")
	if err != nil {
		t.Fatalf("Failed to load ADV-01.json: %v", err)
	}

	var vector struct {
		Baseline struct {
			EnvelopeB64   string `json:"envelope_b64"`
			ServerPrivHex string `json:"server_priv_hex"`
			ClientPubHex  string `json:"client_pub_hex"`
		} `json:"baseline"`
	}

	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("Failed to parse ADV-01.json: %v", err)
	}

	// Decode envelope (base64)
	envelope, err := base64.StdEncoding.DecodeString(vector.Baseline.EnvelopeB64)
	if err != nil {
		t.Fatalf("Failed to decode envelope: %v", err)
	}

	// Decode server private key (hex)
	serverPrivBytes, err := hex.DecodeString(vector.Baseline.ServerPrivHex)
	if err != nil {
		t.Fatalf("Failed to decode server private key: %v", err)
	}

	// Reconstruct ECDSA private key from bytes
	serverPriv := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(serverPrivBytes),
	}
	serverPriv.PublicKey.Curve = elliptic.P256()
	serverPriv.PublicKey.X, serverPriv.PublicKey.Y = serverPriv.PublicKey.Curve.ScalarBaseMult(serverPrivBytes)

	// Decode client public key (hex, compressed format)
	clientPubBytes, err := hex.DecodeString(vector.Baseline.ClientPubHex)
	if err != nil {
		t.Fatalf("Failed to decode client public key: %v", err)
	}

	// Decompress client public key (not used for salt, but validates the test vector)
	_, err = crypto.DecompressPublicKey(clientPubBytes)
	if err != nil {
		t.Fatalf("Failed to decompress client public key: %v", err)
	}

	// Compute salt = SHA256(server_pub_compressed)
	// Salt = recipient's fingerprint, and for client→server envelope, recipient = server
	salt := crypto.FingerprintFromPublicKey(&serverPriv.PublicKey)

	// Attempt decrypt using server's ECIES implementation
	plaintext, err := crypto.Decrypt(serverPriv, envelope, salt)

	if err != nil {
		t.Fatalf("❌ Decrypt failed: %v - CRYPTO INCOMPATIBLE", err)
	}

	// Verify plaintext is valid JSON (should contain payload)
	var payload map[string]interface{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("❌ Decrypted plaintext is not valid JSON: %v", err)
	}

	t.Logf("✅ Decrypt succeeded: %d bytes - CRYPTO COMPATIBLE", len(plaintext))
	t.Logf("   Payload keys: %v", keysOf(payload))
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
