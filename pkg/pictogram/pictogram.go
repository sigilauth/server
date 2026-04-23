// Package pictogram provides deterministic pictogram derivation from device fingerprints.
//
// A pictogram is a sequence of 5 human-friendly words derived from the first 30 bits
// of a SHA-256 fingerprint. Each word is selected from a canonical 64-word list using
// 6-bit indices extracted from the fingerprint.
//
// This package is public and importable by devices, SDKs, and integrators to ensure
// consistent pictogram generation across all Sigil Auth components.
package pictogram

import (
	"fmt"
	"strings"
)

// Pictogram represents a derived pictogram from a device fingerprint.
type Pictogram struct {
	// Words is the 5-word pictogram sequence
	Words []string

	// Indices are the 6-bit indices (0-63) extracted from the fingerprint
	Indices []int
}

// Speakable returns the pictogram in space-separated format per D10.
// This format is used in JSON payloads and for verbal verification over phone/radio.
//
// Example: "apple banana plane car dog"
func (p *Pictogram) Speakable() string {
	return strings.Join(p.Words, " ")
}

// URLFormat returns the pictogram in hyphen-separated format per D10.
// This format is used in URL query parameters where spaces are not permitted.
//
// Example: "apple-banana-plane-car-dog"
func (p *Pictogram) URLFormat() string {
	return strings.Join(p.Words, "-")
}

// Derive computes a pictogram from a 32-byte fingerprint (SHA-256 hash).
//
// Algorithm (per protocol-spec §3.6):
// 1. Extract first 4 bytes of fingerprint
// 2. Extract 5 x 6-bit indices from first 30 bits
// 3. Map each index to a word from the canonical wordlist
//
// Panics if fingerprint is not exactly 32 bytes.
func Derive(fingerprint []byte) *Pictogram {
	if len(fingerprint) != 32 {
		panic(fmt.Sprintf("pictogram: fingerprint must be 32 bytes, got %d", len(fingerprint)))
	}

	indices := DeriveIndices(fingerprint)
	words := make([]string, 5)

	wordlist := Wordlist()
	for i, idx := range indices {
		words[i] = wordlist[idx]
	}

	return &Pictogram{
		Words:   words,
		Indices: indices,
	}
}

// DeriveIndices extracts 5 x 6-bit indices from the first 30 bits of a fingerprint.
//
// Bit extraction pattern:
// - Index 0: bits 0-5
// - Index 1: bits 6-11
// - Index 2: bits 12-17
// - Index 3: bits 18-23
// - Index 4: bits 24-29
//
// Each index is in the range [0, 63].
func DeriveIndices(fingerprint []byte) []int {
	if len(fingerprint) < 4 {
		panic(fmt.Sprintf("pictogram: fingerprint must be at least 4 bytes, got %d", len(fingerprint)))
	}

	// Extract first 4 bytes as a 32-bit integer (big-endian)
	first4 := uint32(fingerprint[0])<<24 |
		uint32(fingerprint[1])<<16 |
		uint32(fingerprint[2])<<8 |
		uint32(fingerprint[3])

	indices := make([]int, 5)

	// Extract 5 x 6-bit indices from first 30 bits
	// Start from most significant bit (bit 31) and work down
	for i := 0; i < 5; i++ {
		// Shift to align desired 6 bits to the right, then mask with 0x3F (63)
		bitOffset := 26 - (i * 6) // 26, 20, 14, 8, 2
		indices[i] = int((first4 >> bitOffset) & 0x3F)
	}

	return indices
}
