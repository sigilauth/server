package harness

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from /api/test-vectors/pictogram.json
func TestDerivePictogram(t *testing.T) {
	tests := []struct {
		name              string
		fingerprintHex    string
		expectedIndices   []int
		expectedSpeakable string
	}{
		{
			name:              "Example from protocol-spec §11.4",
			fingerprintHex:    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			expectedIndices:   []int{40, 27, 11, 3, 53},
			expectedSpeakable: "tree-rocket-mushroom-orange-moai",
		},
		{
			name:              "All zeros fingerprint",
			fingerprintHex:    "0000000000000000000000000000000000000000000000000000000000000000",
			expectedIndices:   []int{0, 0, 0, 0, 0},
			expectedSpeakable: "apple-apple-apple-apple-apple",
		},
		{
			name:              "All 0xFF fingerprint (max indices)",
			fingerprintHex:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedIndices:   []int{63, 63, 63, 63, 63},
			expectedSpeakable: "fire-fire-fire-fire-fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint, err := hex.DecodeString(tt.fingerprintHex)
			require.NoError(t, err)

			emojis, speakable := derivePictogram(fingerprint)

			assert.Len(t, emojis, 5, "pictogram should have 5 emojis")
			assert.Equal(t, tt.expectedSpeakable, speakable, "speakable mismatch")

			// Verify indices match expected
			for i, expectedIdx := range tt.expectedIndices {
				assert.Equal(t, emojiList[expectedIdx], emojis[i], "emoji %d mismatch", i)
				assert.Equal(t, emojiNames[expectedIdx], extractName(speakable, i), "name %d mismatch", i)
			}
		})
	}
}

func extractName(speakable string, index int) string {
	names := splitSpeakable(speakable)
	if index < len(names) {
		return names[index]
	}
	return ""
}

func splitSpeakable(s string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '-' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	return result
}

func TestPictogramDeterminism(t *testing.T) {
	fingerprint, _ := hex.DecodeString("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")

	emojis1, speakable1 := derivePictogram(fingerprint)
	emojis2, speakable2 := derivePictogram(fingerprint)

	assert.Equal(t, emojis1, emojis2, "pictogram should be deterministic")
	assert.Equal(t, speakable1, speakable2, "speakable should be deterministic")
}

func TestPictogramLength(t *testing.T) {
	// Property: all pictograms have exactly 5 emojis
	testCases := 100
	rng := NewDeterministicRNG([]byte("pictogram-length-test"))

	for i := 0; i < testCases; i++ {
		fingerprint := make([]byte, 32)
		rng.Read(fingerprint)

		emojis, _ := derivePictogram(fingerprint)
		assert.Len(t, emojis, 5, "pictogram should always have 5 emojis")
	}
}

func TestEmojiListLength(t *testing.T) {
	assert.Len(t, emojiList, 64, "emoji list should have exactly 64 entries")
	assert.Len(t, emojiNames, 64, "emoji names should have exactly 64 entries")
}
