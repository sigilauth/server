package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// Encrypt encrypts plaintext using ECIES (Elliptic Curve Integrated Encryption Scheme).
//
// Algorithm per spec §2.3 (SIGIL-CONV-V1):
// 1. Generate ephemeral P-256 keypair
// 2. ECDH(ephemeral_private, recipient_public) → shared_point
// 3. shared_secret = shared_point.x (raw, no hash)
// 4. encryption_key = HKDF(ikm=shared_secret, salt=recipient_fingerprint, info="SIGIL-CONV-V1-AES256", length=32)
// 5. nonce = random 12 bytes
// 6. ciphertext = AES-256-GCM.encrypt(key=encryption_key, nonce=nonce, plaintext=plaintext, aad=ephemeral_public)
//
// Returns: ephemeral_public_key (33 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
//
// Salt must be the recipient's public key fingerprint (SHA256 of compressed pubkey).
func Encrypt(recipientPublicKey *ecdsa.PublicKey, plaintext, salt []byte) ([]byte, error) {
	ephemeralPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	sharedX, _ := recipientPublicKey.Curve.ScalarMult(
		recipientPublicKey.X,
		recipientPublicKey.Y,
		ephemeralPrivateKey.D.Bytes(),
	)

	encryptionKey, err := DeriveKey(sharedX.Bytes(), salt, "SIGIL-CONV-V1-AES256", 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ephemeralPublicKeyCompressed := CompressPublicKey(&ephemeralPrivateKey.PublicKey)

	// AAD = ephemeral_public per spec §2.3 (SIGIL-CONV-V1)
	ciphertextAndTag := gcm.Seal(nil, nonce, plaintext, ephemeralPublicKeyCompressed)

	result := make([]byte, 0, 33+12+len(ciphertextAndTag))
	result = append(result, ephemeralPublicKeyCompressed...)
	result = append(result, nonce...)
	result = append(result, ciphertextAndTag...)

	return result, nil
}

// Decrypt decrypts ECIES ciphertext using the recipient's private key.
//
// Ciphertext format: ephemeral_public_key (33) || nonce (12) || ciphertext || tag (16)
//
// Algorithm per spec §2.3 (SIGIL-CONV-V1):
// 1. Extract ephemeral public key, nonce, ciphertext+tag
// 2. ECDH(recipient_private, ephemeral_public) → shared_point
// 3. shared_secret = shared_point.x (raw, no hash)
// 4. encryption_key = HKDF(ikm=shared_secret, salt=recipient_fingerprint, info="SIGIL-CONV-V1-AES256", length=32)
// 5. plaintext = AES-256-GCM.decrypt(key=encryption_key, nonce=nonce, ciphertext=ciphertext, aad=ephemeral_public)
//
// Returns error if authentication fails (modified ciphertext, wrong key, wrong salt).
func Decrypt(recipientPrivateKey *ecdsa.PrivateKey, ciphertext, salt []byte) ([]byte, error) {
	minLength := 33 + 12 + 16
	if len(ciphertext) < minLength {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minLength, len(ciphertext))
	}

	ephemeralPublicKeyCompressed := ciphertext[0:33]
	nonce := ciphertext[33:45]
	ciphertextAndTag := ciphertext[45:]

	ephemeralPublicKey, err := DecompressPublicKey(ephemeralPublicKeyCompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress ephemeral public key: %w", err)
	}

	sharedX, _ := ephemeralPublicKey.Curve.ScalarMult(
		ephemeralPublicKey.X,
		ephemeralPublicKey.Y,
		recipientPrivateKey.D.Bytes(),
	)

	encryptionKey, err := DeriveKey(sharedX.Bytes(), salt, "SIGIL-CONV-V1-AES256", 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// AAD = ephemeral_public per spec §2.3 (SIGIL-CONV-V1)
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, ephemeralPublicKeyCompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: authentication failed or wrong key")
	}

	return plaintext, nil
}
