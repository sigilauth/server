// Package initrequest manages implementor engine initialization requests.
package initrequest

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	// ClaimCodeAlphabet is the Crockford Base32 variant (excludes I, O, 0, 1).
	ClaimCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	ClaimCodeLength   = 6
)

var (
	ErrInvalidLength    = errors.New("claim code must be exactly 6 characters")
	ErrInvalidCharacter = errors.New("claim code contains invalid characters")
)

// GenerateClaimCode generates a 6-character claim code using Crockford Base32.
//
// Algorithm:
// 1. Generate 4 bytes (32 bits) from CSPRNG
// 2. Extract 5 bits at a time to index into 32-character alphabet
// 3. Returns 6 characters (30 bits of entropy, 2 bits unused)
//
// Entropy: 2^30 = 1,073,741,824 unique codes
func GenerateClaimCode() (string, error) {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	value := binary.BigEndian.Uint32(randomBytes)
	code := make([]byte, ClaimCodeLength)

	for i := 0; i < ClaimCodeLength; i++ {
		code[i] = ClaimCodeAlphabet[value&0x1F] // Take 5 bits
		value >>= 5
	}

	return string(code), nil
}

// NormalizeClaimCode normalizes a claim code for comparison.
//
// Normalization:
// - Remove whitespace and hyphens (allow "A3K-9F2" or "A3K 9F2" input)
// - Convert to uppercase
//
// Example: "a3k-9f2" → "A3K9F2"
func NormalizeClaimCode(input string) string {
	input = strings.ReplaceAll(input, " ", "")
	input = strings.ReplaceAll(input, "-", "")
	return strings.ToUpper(input)
}

// ValidateClaimCode validates a normalized claim code.
//
// Checks:
// - Length exactly 6 characters
// - All characters in Crockford Base32 alphabet
//
// Input MUST be normalized before calling this function.
func ValidateClaimCode(normalized string) error {
	if len(normalized) != ClaimCodeLength {
		return ErrInvalidLength
	}

	for _, c := range normalized {
		if !strings.ContainsRune(ClaimCodeAlphabet, c) {
			return ErrInvalidCharacter
		}
	}

	return nil
}

// CompareClaimCode performs constant-time comparison of two claim codes.
//
// Both inputs MUST be normalized before calling this function.
// Returns true if codes match, false otherwise.
func CompareClaimCode(stored, input string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(input)) == 1
}
