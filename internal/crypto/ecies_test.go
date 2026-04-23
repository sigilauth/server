package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	recipientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plaintext := []byte("secret message for ECIES encryption")
	salt := []byte("request-id-12345")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, salt)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptProducesValidCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("test data")
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	assert.Greater(t, len(ciphertext), len(plaintext),
		"ciphertext should be longer than plaintext (includes ephemeral key + nonce + tag)")

	expectedMinLength := 33 + 12 + len(plaintext) + 16
	assert.GreaterOrEqual(t, len(ciphertext), expectedMinLength,
		"ciphertext should include ephemeral public key (33) + nonce (12) + plaintext + tag (16)")
}

func TestEncryptDifferentEphemeralKeys(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("same message")
	salt := []byte("same salt")

	ct1, err1 := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	ct2, err2 := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.NotEqual(t, ct1, ct2,
		"ciphertexts should differ due to random ephemeral key and nonce")

	decrypted1, _ := crypto.Decrypt(recipientKey, ct1, salt)
	decrypted2, _ := crypto.Decrypt(recipientKey, ct2, salt)

	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	salt := []byte("salt")

	tests := []struct {
		name       string
		ciphertext []byte
		wantError  string
	}{
		{
			name:       "Empty ciphertext",
			ciphertext: []byte{},
			wantError:  "too short",
		},
		{
			name:       "Truncated ciphertext",
			ciphertext: make([]byte, 40),
			wantError:  "too short",
		},
		{
			name:       "Invalid ephemeral key",
			ciphertext: append(make([]byte, 33), make([]byte, 40)...),
			wantError:  "decompress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.Decrypt(recipientKey, tt.ciphertext, salt)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestDecryptModifiedCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("original message")
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	modifiedCiphertext := make([]byte, len(ciphertext))
	copy(modifiedCiphertext, ciphertext)
	modifiedCiphertext[len(modifiedCiphertext)-1] ^= 0x01

	_, err = crypto.Decrypt(recipientKey, modifiedCiphertext, salt)
	assert.Error(t, err, "modified ciphertext should fail authentication")
}

func TestDecryptWrongKey(t *testing.T) {
	recipientKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	recipientKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	plaintext := []byte("secret")
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey1.PublicKey, plaintext, salt)
	require.NoError(t, err)

	_, err = crypto.Decrypt(recipientKey2, ciphertext, salt)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestDecryptWrongSalt(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("secret")
	salt1 := []byte("original-salt")
	salt2 := []byte("different-salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt1)
	require.NoError(t, err)

	_, err = crypto.Decrypt(recipientKey, ciphertext, salt2)
	assert.Error(t, err, "decryption with wrong salt should fail")
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte{}
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, salt)
	require.NoError(t, err)

	assert.Len(t, decrypted, 0, "empty plaintext should decrypt to empty (nil or []byte{})")
}

func TestEncryptLargePlaintext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 10*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, salt)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestECIESCiphertextFormat(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("test")
	salt := []byte("salt")

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, salt)
	require.NoError(t, err)

	assert.Len(t, ciphertext[:33], 33, "first 33 bytes are ephemeral public key")

	ephemeralKeyPrefix := ciphertext[0]
	assert.True(t, ephemeralKeyPrefix == 0x02 || ephemeralKeyPrefix == 0x03,
		"ephemeral key must use compressed format")

	assert.Len(t, ciphertext[33:45], 12, "next 12 bytes are nonce")

	remainder := ciphertext[45:]
	assert.GreaterOrEqual(t, len(remainder), len(plaintext)+16,
		"remainder should be at least plaintext + 16-byte tag")
}
