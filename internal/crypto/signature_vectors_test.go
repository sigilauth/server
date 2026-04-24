package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SignatureTestCase from invalid-signatures.json
type SignatureTestCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	SignatureR    string `json:"signature_r,omitempty"`
	SignatureS    string `json:"signature_s,omitempty"`
	SignatureB64  string `json:"signature_base64,omitempty"`
	ExpectedError string `json:"expected_error"`
	ExpectedResult string `json:"expected_result"`
}

type SignatureTestFixture struct {
	Description string            `json:"description"`
	Curve       string            `json:"curve"`
	Hash        string            `json:"hash"`
	TestCases   []SignatureTestCase `json:"test_cases"`
}

func loadSignatureFixtures(t *testing.T, filename string) *SignatureTestFixture {
	projectRoot := findProjectRoot(t)
	path := filepath.Join(projectRoot, "security", "test-vectors", "signatures", filename)
	
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture file: %s", path)
	
	var fixture SignatureTestFixture
	err = json.Unmarshal(data, &fixture)
	require.NoError(t, err, "failed to parse fixture file")
	
	return &fixture
}

func findProjectRoot(t *testing.T) string {
	dir, _ := os.Getwd()
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "security", "test-vectors")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return "/Volumes/Expansion/src/sigilauth"
}

// TestInvalidSignaturesFromVectors tests rejection of invalid signatures
// Uses test vectors from security/test-vectors/signatures/invalid-signatures.json
func TestInvalidSignaturesFromVectors(t *testing.T) {
	fixture := loadSignatureFixtures(t, "invalid-signatures.json")
	
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	message := []byte("test message for signature verification")
	
	for _, tc := range fixture.TestCases {
		t.Run(tc.ID+"_"+tc.Description, func(t *testing.T) {
			var signature []byte
			
			switch tc.ID {
			case "SIG-INV-001": // Empty signature
				signature = []byte{}
			case "SIG-INV-002": // Truncated (32 bytes)
				signature = make([]byte, 32)
			case "SIG-INV-003": // Oversized (128 bytes)
				signature = make([]byte, 128)
			case "SIG-INV-004": // All zeros
				signature = make([]byte, 64)
			case "SIG-INV-011": // Random bytes
				signature = make([]byte, 64)
				rand.Read(signature)
			default:
				t.Skip("Test case not implemented yet")
				return
			}
			
			err := crypto.Verify(&privateKey.PublicKey, message, signature)
			assert.Error(t, err, "Signature should be rejected: %s", tc.Description)
		})
	}
}

// TestHighSSignatureRejection tests BIP-62 low-S enforcement
// This is the critical test for SIG-2026-002
func TestHighSSignatureRejection(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	message := []byte("test message")
	
	// Generate a valid low-S signature
	validSig, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)
	require.Len(t, validSig, 64)
	
	// Extract S and create high-S variant
	curve := elliptic.P256()
	order := curve.Params().N
	
	r := new(big.Int).SetBytes(validSig[0:32])
	s := new(big.Int).SetBytes(validSig[32:64])
	
	// Compute high-S = order - s
	highS := new(big.Int).Sub(order, s)
	
	// Verify highS > order/2 (it should be, since original s <= order/2)
	halfOrder := new(big.Int).Rsh(order, 1)
	require.True(t, highS.Cmp(halfOrder) > 0, "highS should be > order/2")
	
	// Create high-S signature
	highSSig := make([]byte, 64)
	r.FillBytes(highSSig[0:32])
	highS.FillBytes(highSSig[32:64])
	
	// This test will FAIL until SIG-2026-002 is fixed
	// Verify() should reject high-S signatures per BIP-62
	err = crypto.Verify(&privateKey.PublicKey, message, highSSig)
	assert.Error(t, err, "High-S signature MUST be rejected per BIP-62 (SIG-2026-002)")
	
	if err != nil {
		assert.Contains(t, err.Error(), "high-S", 
			"Error message should indicate high-S rejection")
	}
}

// TestLowSSignatureAccepted tests that properly normalized signatures pass
func TestLowSSignatureAccepted(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	message := []byte("test message")
	
	// Sign() produces low-S normalized signatures
	signature, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)
	
	// Verify S <= order/2
	s := crypto.ExtractS(signature)
	halfOrder := crypto.HalfOrder(elliptic.P256())
	require.True(t, s.Cmp(halfOrder) <= 0, "Sign() must produce low-S signature")
	
	// Should verify successfully
	err = crypto.Verify(&privateKey.PublicKey, message, signature)
	assert.NoError(t, err, "Low-S signature should be accepted")
}
