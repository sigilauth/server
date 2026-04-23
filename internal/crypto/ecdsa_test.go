package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for signing")

	signature, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)

	assert.Len(t, signature, 64, "signature must be exactly 64 bytes (r || s)")

	err = crypto.Verify(&privateKey.PublicKey, message, signature)
	assert.NoError(t, err, "signature must verify with corresponding public key")
}

func TestSignDeterministicMessage(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("same message")

	sig1, err1 := crypto.Sign(privateKey, message)
	sig2, err2 := crypto.Sign(privateKey, message)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.NotEqual(t, sig1, sig2, "signatures should differ due to random k (ECDSA nonce)")

	assert.NoError(t, crypto.Verify(&privateKey.PublicKey, message, sig1))
	assert.NoError(t, crypto.Verify(&privateKey.PublicKey, message, sig2))
}

func TestSignLowSNormalization(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("test message")

	signature, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)
	require.Len(t, signature, 64)

	curve := elliptic.P256()
	halfOrder := crypto.HalfOrder(curve)

	s := crypto.ExtractS(signature)

	assert.True(t, s.Cmp(halfOrder) <= 0,
		"S component must be <= N/2 (low-S normalized per BIP-62)")
}

func TestVerifyValid(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("valid message")

	signature, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)

	err = crypto.Verify(&privateKey.PublicKey, message, signature)
	assert.NoError(t, err)
}

func TestVerifyInvalidSignature(t *testing.T) {
	tests := []struct {
		name      string
		signature []byte
		wantError string
	}{
		{
			name:      "Empty signature",
			signature: []byte{},
			wantError: "signature must be 64 bytes",
		},
		{
			name:      "Truncated signature (32 bytes)",
			signature: make([]byte, 32),
			wantError: "signature must be 64 bytes",
		},
		{
			name:      "Too long signature (96 bytes)",
			signature: make([]byte, 96),
			wantError: "signature must be 64 bytes",
		},
	}

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("test message")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.Verify(&privateKey.PublicKey, message, tt.signature)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestVerifyWrongKey(t *testing.T) {
	privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	message := []byte("test message")
	signature, err := crypto.Sign(privateKey1, message)
	require.NoError(t, err)

	err = crypto.Verify(&privateKey2.PublicKey, message, signature)
	assert.Error(t, err, "signature from key1 should not verify with key2")
	assert.Contains(t, err.Error(), "invalid signature")
}

func TestVerifyModifiedMessage(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	originalMessage := []byte("original message")
	modifiedMessage := []byte("modified message")

	signature, err := crypto.Sign(privateKey, originalMessage)
	require.NoError(t, err)

	err = crypto.Verify(&privateKey.PublicKey, modifiedMessage, signature)
	assert.Error(t, err, "signature for original should not verify modified message")
}

func TestVerifyModifiedSignature(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("test message")

	signature, err := crypto.Sign(privateKey, message)
	require.NoError(t, err)

	modifiedSignature := make([]byte, 64)
	copy(modifiedSignature, signature)
	modifiedSignature[0] ^= 0x01

	err = crypto.Verify(&privateKey.PublicKey, message, modifiedSignature)
	assert.Error(t, err, "modified signature should not verify")
}

func TestCompressPublicKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	compressed := crypto.CompressPublicKey(&privateKey.PublicKey)

	assert.Len(t, compressed, 33, "compressed public key must be 33 bytes")

	firstByte := compressed[0]
	assert.True(t, firstByte == 0x02 || firstByte == 0x03,
		"first byte must be 0x02 or 0x03 (compressed format marker)")
}

func TestDecompressPublicKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	originalPubKey := &privateKey.PublicKey

	compressed := crypto.CompressPublicKey(originalPubKey)

	decompressed, err := crypto.DecompressPublicKey(compressed)
	require.NoError(t, err)

	assert.True(t, originalPubKey.Equal(decompressed),
		"decompressed key must equal original")
}

func TestDecompressInvalidPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		compressed []byte
		wantError string
	}{
		{
			name:      "Too short",
			compressed: make([]byte, 32),
			wantError: "must be 33 bytes",
		},
		{
			name:      "Too long",
			compressed: make([]byte, 34),
			wantError: "must be 33 bytes",
		},
		{
			name:      "Invalid prefix",
			compressed: append([]byte{0x04}, make([]byte, 32)...),
			wantError: "invalid compressed key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DecompressPublicKey(tt.compressed)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestFingerprintFromPublicKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fingerprint := crypto.FingerprintFromPublicKey(&privateKey.PublicKey)

	assert.Len(t, fingerprint, 32, "fingerprint is SHA-256 hash (32 bytes)")

	fingerprint2 := crypto.FingerprintFromPublicKey(&privateKey.PublicKey)
	assert.Equal(t, fingerprint, fingerprint2, "fingerprint must be deterministic")
}

func TestFingerprintHex(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fingerprint := crypto.FingerprintFromPublicKey(&privateKey.PublicKey)

	hexFingerprint := crypto.FingerprintHex(fingerprint)

	assert.Len(t, hexFingerprint, 64, "hex fingerprint must be 64 chars (32 bytes * 2)")

	decoded, err := hex.DecodeString(hexFingerprint)
	require.NoError(t, err)
	assert.Equal(t, fingerprint, decoded)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "Empty message",
			message: []byte{},
		},
		{
			name:    "Short message",
			message: []byte("hi"),
		},
		{
			name:    "Long message",
			message: make([]byte, 1024),
		},
		{
			name:    "Binary data",
			message: []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			signature, err := crypto.Sign(privateKey, tt.message)
			require.NoError(t, err)

			err = crypto.Verify(&privateKey.PublicKey, tt.message, signature)
			assert.NoError(t, err)
		})
	}
}
