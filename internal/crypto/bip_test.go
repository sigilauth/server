package crypto_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := crypto.GenerateMnemonic()
	require.NoError(t, err)

	words := strings.Split(mnemonic, " ")
	assert.Len(t, words, 24, "mnemonic must have exactly 24 words (256-bit entropy)")

	_, err = crypto.MnemonicToEntropy(mnemonic)
	assert.NoError(t, err, "generated mnemonic must be valid")
}

func TestEntropyToMnemonic(t *testing.T) {
	tests := []struct {
		name             string
		entropyHex       string
		expectedMnemonic string
	}{
		{
			name:             "All zeros entropy",
			entropyHex:       "0000000000000000000000000000000000000000000000000000000000000000",
			expectedMnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
		{
			name:             "All 0xFF entropy",
			entropyHex:       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedMnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		},
		{
			name:             "Standard test vector 1",
			entropyHex:       "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
			expectedMnemonic: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := hex.DecodeString(tt.entropyHex)
			require.NoError(t, err)
			require.Len(t, entropy, 32)

			mnemonic, err := crypto.EntropyToMnemonic(entropy)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedMnemonic, mnemonic)
		})
	}
}

func TestMnemonicToEntropy(t *testing.T) {
	tests := []struct {
		name        string
		mnemonic    string
		entropyHex  string
	}{
		{
			name:       "All zeros",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			entropyHex: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:       "All 0xFF",
			mnemonic:   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
			entropyHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := crypto.MnemonicToEntropy(tt.mnemonic)
			require.NoError(t, err)

			assert.Equal(t, tt.entropyHex, hex.EncodeToString(entropy))
		})
	}
}

func TestMnemonicRoundTrip(t *testing.T) {
	originalEntropy := make([]byte, 32)
	for i := range originalEntropy {
		originalEntropy[i] = byte(i)
	}

	mnemonic, err := crypto.EntropyToMnemonic(originalEntropy)
	require.NoError(t, err)

	recoveredEntropy, err := crypto.MnemonicToEntropy(mnemonic)
	require.NoError(t, err)

	assert.Equal(t, originalEntropy, recoveredEntropy, "entropy → mnemonic → entropy must be identity")
}

func TestVerificationCode(t *testing.T) {
	tests := []struct {
		name         string
		mnemonic     string
		expectedCode string
	}{
		{
			name:         "All zeros mnemonic",
			mnemonic:     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			expectedCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := crypto.VerificationCode(tt.mnemonic)

			assert.Len(t, code, 6, "verification code must be 6 uppercase hex characters")

			_, err := hex.DecodeString(code)
			assert.NoError(t, err, "verification code must be valid hex")

			hash := sha256.Sum256([]byte(strings.TrimSpace(tt.mnemonic)))
			expected := strings.ToUpper(hex.EncodeToString(hash[:])[:6])

			assert.Equal(t, expected, code)
		})
	}
}

func TestDeriveServerKeypair(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	privateKey, err := crypto.DeriveServerKeypair(mnemonic)
	require.NoError(t, err)

	assert.NotNil(t, privateKey)
	assert.NotNil(t, privateKey.PublicKey)

	privateKey2, err := crypto.DeriveServerKeypair(mnemonic)
	require.NoError(t, err)

	assert.True(t, privateKey.Equal(privateKey2), "same mnemonic must produce same keypair (deterministic)")
}

func TestDeriveServerKeypairInvalidMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
	}{
		{
			name:     "Empty mnemonic",
			mnemonic: "",
		},
		{
			name:     "Invalid word count",
			mnemonic: "abandon abandon abandon",
		},
		{
			name:     "Invalid word",
			mnemonic: "invalid word abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		},
		{
			name:     "Invalid checksum",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DeriveServerKeypair(tt.mnemonic)
			require.Error(t, err)
		})
	}
}
