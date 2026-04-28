package pictogram_test

import (
	"encoding/hex"
	"testing"

	"github.com/sigilauth/server/pkg/pictogram"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerive(t *testing.T) {
	tests := []struct {
		name                string
		fingerprintHex      string
		expectedIndices     []int
		expectedPictogram   []string
		expectedSpeakable   string
	}{
		{
			name:                "Example from protocol-spec §11.4",
			fingerprintHex:      "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			expectedIndices:     []int{40, 27, 11, 3, 53},
			expectedPictogram:   []string{"tree", "rocket", "mushroom", "orange", "moai"},
			expectedSpeakable:   "tree rocket mushroom orange moai",
		},
		{
			name:                "All zeros fingerprint",
			fingerprintHex:      "0000000000000000000000000000000000000000000000000000000000000000",
			expectedIndices:     []int{0, 0, 0, 0, 0},
			expectedPictogram:   []string{"apple", "apple", "apple", "apple", "apple"},
			expectedSpeakable:   "apple apple apple apple apple",
		},
		{
			name:                "All 0xFF fingerprint (max indices)",
			fingerprintHex:      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedIndices:     []int{63, 63, 63, 63, 63},
			expectedPictogram:   []string{"fire", "fire", "fire", "fire", "fire"},
			expectedSpeakable:   "fire fire fire fire fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint, err := hex.DecodeString(tt.fingerprintHex)
			require.NoError(t, err, "test vector fingerprint must decode")
			require.Len(t, fingerprint, 32, "fingerprint must be 32 bytes")

			result := pictogram.Derive(fingerprint)

			assert.Equal(t, tt.expectedPictogram, result.Words, "pictogram words mismatch")
			assert.Equal(t, tt.expectedSpeakable, result.Speakable(), "speakable format mismatch")
			assert.Equal(t, tt.expectedIndices, result.Indices, "extracted indices mismatch")
		})
	}
}

func TestDeriveIndices(t *testing.T) {
	tests := []struct {
		name            string
		fingerprintHex  string
		expectedIndices []int
	}{
		{
			name:            "Extract 5 x 6-bit indices from first 30 bits",
			fingerprintHex:  "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			expectedIndices: []int{40, 27, 11, 3, 53},
		},
		{
			name:            "All zeros",
			fingerprintHex:  "0000000000000000000000000000000000000000000000000000000000000000",
			expectedIndices: []int{0, 0, 0, 0, 0},
		},
		{
			name:            "All ones (max index = 63)",
			fingerprintHex:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedIndices: []int{63, 63, 63, 63, 63},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint, err := hex.DecodeString(tt.fingerprintHex)
			require.NoError(t, err)

			indices := pictogram.DeriveIndices(fingerprint)

			assert.Len(t, indices, 5, "must extract exactly 5 indices")
			assert.Equal(t, tt.expectedIndices, indices)

			for i, idx := range indices {
				assert.GreaterOrEqual(t, idx, 0, "index %d must be >= 0", i)
				assert.LessOrEqual(t, idx, 63, "index %d must be <= 63", i)
			}
		})
	}
}

func TestDeriveDeterministic(t *testing.T) {
	fingerprint, _ := hex.DecodeString("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")

	result1 := pictogram.Derive(fingerprint)
	result2 := pictogram.Derive(fingerprint)

	assert.Equal(t, result1.Words, result2.Words, "same fingerprint must produce same pictogram")
	assert.Equal(t, result1.Speakable(), result2.Speakable(), "speakable must be deterministic")
	assert.Equal(t, result1.Indices, result2.Indices, "indices must be deterministic")
}

func TestSpeakableFormat(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		expected string
	}{
		{
			name:     "Space-separated per D10",
			words:    []string{"apple", "banana", "plane", "car", "dog"},
			expected: "apple banana plane car dog",
		},
		{
			name:     "Single word repeated",
			words:    []string{"fire", "fire", "fire", "fire", "fire"},
			expected: "fire fire fire fire fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &pictogram.Pictogram{Words: tt.words}
			assert.Equal(t, tt.expected, result.Speakable())
		})
	}
}

func TestURLFormat(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		expected string
	}{
		{
			name:     "Hyphen-separated per D10",
			words:    []string{"apple", "banana", "plane", "car", "dog"},
			expected: "apple-banana-plane-car-dog",
		},
		{
			name:     "URL-safe encoding",
			words:    []string{"tree", "rocket", "mushroom", "orange", "moai"},
			expected: "tree-rocket-mushroom-orange-moai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &pictogram.Pictogram{Words: tt.words}
			assert.Equal(t, tt.expected, result.URLFormat())
		})
	}
}

func TestWordListCompleteness(t *testing.T) {
	wordlist := pictogram.Wordlist()

	require.Len(t, wordlist, 64, "wordlist must have exactly 64 entries")

	seen := make(map[string]bool)
	for i, word := range wordlist {
		assert.NotEmpty(t, word, "word at index %d must not be empty", i)
		assert.False(t, seen[word], "word %q at index %d is duplicate", word, i)
		seen[word] = true
	}
}

func TestWordListMatchesTestVectors(t *testing.T) {
	wordlist := pictogram.Wordlist()

	assert.Equal(t, "apple", wordlist[0], "index 0 must be 'apple'")
	assert.Equal(t, "banana", wordlist[1], "index 1 must be 'banana'")
	assert.Equal(t, "tree", wordlist[40], "index 40 must be 'tree'")
	assert.Equal(t, "fire", wordlist[63], "index 63 must be 'fire'")
}

func TestInvalidFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint []byte
		expectPanic bool
	}{
		{
			name:        "Too short (31 bytes)",
			fingerprint: make([]byte, 31),
			expectPanic: true,
		},
		{
			name:        "Too long (33 bytes)",
			fingerprint: make([]byte, 33),
			expectPanic: true,
		},
		{
			name:        "Nil fingerprint",
			fingerprint: nil,
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					pictogram.Derive(tt.fingerprint)
				}, "invalid fingerprint should panic")
			}
		})
	}
}
