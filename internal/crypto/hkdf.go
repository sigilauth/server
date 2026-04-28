package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey uses HKDF-SHA256 to derive a key from input key material.
//
// Parameters:
// - ikm: Input key material (shared secret, ECDH output, etc.)
// - salt: Optional salt value (can be empty)
// - info: Context/application-specific info string
// - length: Desired output key length in bytes
//
// Per Knox §3.1: Used for ECIES key derivation with specific info strings:
// - "sigil-decrypt-v1" for secure decrypt operations
// - "sigil-mnemonic-v1" for mnemonic encryption
// - "sigil-transport-v1" for transport encryption
func DeriveKey(ikm, salt []byte, info string, length int) ([]byte, error) {
	if ikm == nil || len(ikm) == 0 {
		return nil, fmt.Errorf("ikm cannot be nil or empty")
	}

	if length <= 0 {
		return nil, fmt.Errorf("length must be positive, got %d", length)
	}

	maxLength := 255 * sha256.Size
	if length > maxLength {
		return nil, fmt.Errorf("length exceeds HKDF maximum (%d bytes)", maxLength)
	}

	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(info))

	key := make([]byte, length)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf key derivation failed: %w", err)
	}

	return key, nil
}
