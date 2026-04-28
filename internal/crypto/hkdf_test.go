package crypto_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	ikm, _ := hex.DecodeString("0102030405060708091011121314151617181920212223242526272829303132")
	salt, _ := hex.DecodeString("4167387831633237656464343533626365633566313263366239333038386634")
	info := "sigil-decrypt-v1"

	key, err := crypto.DeriveKey(ikm, salt, info, 32)
	require.NoError(t, err)

	assert.Len(t, key, 32, "derived key must be 32 bytes")
}

func TestDeriveKeyDeterministic(t *testing.T) {
	ikm := []byte("input key material")
	salt := []byte("salt value")
	info := "test-context"

	key1, err1 := crypto.DeriveKey(ikm, salt, info, 32)
	key2, err2 := crypto.DeriveKey(ikm, salt, info, 32)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, key1, key2, "HKDF must be deterministic")
}

func TestDeriveKeyDifferentInfo(t *testing.T) {
	ikm := []byte("shared input material")
	salt := []byte("shared salt")

	key1, _ := crypto.DeriveKey(ikm, salt, "sigil-decrypt-v1", 32)
	key2, _ := crypto.DeriveKey(ikm, salt, "sigil-mnemonic-v1", 32)

	assert.NotEqual(t, key1, key2, "different info strings must produce different keys")
}

func TestDeriveKeyTestVectors(t *testing.T) {
	tests := []struct {
		name          string
		ikmHex        string
		saltHex       string
		info          string
		outputLength  int
	}{
		{
			name:         "Secure decrypt key derivation",
			ikmHex:       "0102030405060708091011121314151617181920212223242526272829303132",
			saltHex:      "4167387831633237656464343533626365633566313263366239333038386634",
			info:         "sigil-decrypt-v1",
			outputLength: 32,
		},
		{
			name:         "Mnemonic encryption key derivation",
			ikmHex:       "deadbeefcafebabe0102030405060708091011121314151617181920212223",
			saltHex:      "73746b5f6162633132333435363738393061626364656667",
			info:         "sigil-mnemonic-v1",
			outputLength: 32,
		},
		{
			name:         "Transport encryption key derivation",
			ikmHex:       "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
			saltHex:      "72657175657374313233343536373839",
			info:         "sigil-transport-v1",
			outputLength: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ikm, err := hex.DecodeString(tt.ikmHex)
			require.NoError(t, err)

			salt, err := hex.DecodeString(tt.saltHex)
			require.NoError(t, err)

			key, err := crypto.DeriveKey(ikm, salt, tt.info, tt.outputLength)
			require.NoError(t, err)

			assert.Len(t, key, tt.outputLength)

			t.Logf("Derived key for %s: %s", tt.info, hex.EncodeToString(key))
		})
	}
}

func TestDeriveKeyEmptyInputs(t *testing.T) {
	tests := []struct {
		name   string
		ikm    []byte
		salt   []byte
		info   string
		length int
	}{
		{
			name:   "Empty IKM",
			ikm:    []byte{},
			salt:   []byte("salt"),
			info:   "info",
			length: 32,
		},
		{
			name:   "Nil IKM",
			ikm:    nil,
			salt:   []byte("salt"),
			info:   "info",
			length: 32,
		},
		{
			name:   "Empty salt (allowed)",
			ikm:    []byte("ikm"),
			salt:   []byte{},
			info:   "info",
			length: 32,
		},
		{
			name:   "Empty info (allowed)",
			ikm:    []byte("ikm"),
			salt:   []byte("salt"),
			info:   "",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.DeriveKey(tt.ikm, tt.salt, tt.info, tt.length)

			if tt.ikm == nil || len(tt.ikm) == 0 {
				require.Error(t, err, "nil or empty IKM should error")
			} else {
				require.NoError(t, err)
				assert.Len(t, key, tt.length)
			}
		})
	}
}

func TestDeriveKeyInvalidLength(t *testing.T) {
	ikm := []byte("input key material")
	salt := []byte("salt")
	info := "info"

	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "Zero length",
			length: 0,
		},
		{
			name:   "Negative length",
			length: -1,
		},
		{
			name:   "Too large (> 255 * 32)",
			length: 8160 + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.DeriveKey(ikm, salt, info, tt.length)

			require.Error(t, err)
			assert.Nil(t, key)
		})
	}
}

func TestDeriveKeyVariableLengths(t *testing.T) {
	ikm := []byte("input key material")
	salt := []byte("salt")
	info := "test"

	lengths := []int{16, 32, 48, 64, 128, 256}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			key, err := crypto.DeriveKey(ikm, salt, info, length)

			require.NoError(t, err)
			assert.Len(t, key, length)
		})
	}
}
