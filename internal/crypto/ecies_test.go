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
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-decrypt-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, fingerprint, context)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptProducesValidCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("test data")
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, "sigil-test-v1")
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
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

	ct1, err1 := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	ct2, err2 := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.NotEqual(t, ct1, ct2,
		"ciphertexts should differ due to random ephemeral key and nonce")

	decrypted1, _ := crypto.Decrypt(recipientKey, ct1, fingerprint, context)
	decrypted2, _ := crypto.Decrypt(recipientKey, ct2, fingerprint, context)

	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

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
			_, err := crypto.Decrypt(recipientKey, tt.ciphertext, fingerprint, context)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestDecryptModifiedCiphertext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("original message")
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	require.NoError(t, err)

	modifiedCiphertext := make([]byte, len(ciphertext))
	copy(modifiedCiphertext, ciphertext)
	modifiedCiphertext[len(modifiedCiphertext)-1] ^= 0x01

	_, err = crypto.Decrypt(recipientKey, modifiedCiphertext, fingerprint, context)
	assert.Error(t, err, "modified ciphertext should fail authentication")
}

func TestDecryptWrongKey(t *testing.T) {
	recipientKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	recipientKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	plaintext := []byte("secret")
	fingerprint1 := crypto.FingerprintFromPublicKey(&recipientKey1.PublicKey)
	fingerprint2 := crypto.FingerprintFromPublicKey(&recipientKey2.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey1.PublicKey, plaintext, fingerprint1, context)
	require.NoError(t, err)

	_, err = crypto.Decrypt(recipientKey2, ciphertext, fingerprint2, context)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestDecryptWrongFingerprint(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	plaintext := []byte("secret")
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	wrongFingerprint := crypto.FingerprintFromPublicKey(&otherKey.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	require.NoError(t, err)

	_, err = crypto.Decrypt(recipientKey, ciphertext, wrongFingerprint, context)
	assert.Error(t, err, "decryption with wrong fingerprint should fail")
}

func TestDecryptWrongContext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("secret")
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, "sigil-test-v1")
	require.NoError(t, err)

	_, err = crypto.Decrypt(recipientKey, ciphertext, fingerprint, "sigil-wrong-v1")
	assert.Error(t, err, "decryption with wrong context should fail")
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte{}
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, fingerprint, context)
	require.NoError(t, err)

	assert.Len(t, decrypted, 0, "empty plaintext should decrypt to empty (nil or []byte{})")
}

func TestEncryptLargePlaintext(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := make([]byte, 10*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(recipientKey, ciphertext, fingerprint, context)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestECIESCiphertextFormat(t *testing.T) {
	recipientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("test")
	fingerprint := crypto.FingerprintFromPublicKey(&recipientKey.PublicKey)
	context := "sigil-test-v1"

	ciphertext, err := crypto.Encrypt(&recipientKey.PublicKey, plaintext, fingerprint, context)
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
