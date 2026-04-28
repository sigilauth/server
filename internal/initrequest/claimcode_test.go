package initrequest_test

import (
	"testing"

	"github.com/sigilauth/server/internal/initrequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateClaimCode(t *testing.T) {
	code, err := initrequest.GenerateClaimCode()
	require.NoError(t, err)

	assert.Len(t, code, initrequest.ClaimCodeLength,
		"generated code must be exactly 6 characters")

	for _, c := range code {
		assert.Contains(t, initrequest.ClaimCodeAlphabet, string(c),
			"all characters must be in Crockford Base32 alphabet")
	}
}

func TestGenerateClaimCode_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		code, err := initrequest.GenerateClaimCode()
		require.NoError(t, err)
		seen[code] = true
	}

	// With 2^30 entropy, collision in 1000 samples is astronomically unlikely
	assert.Len(t, seen, iterations,
		"expected all codes to be unique in small sample")
}

func TestNormalizeClaimCode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Already normalized",
			input: "A3K9F2",
			want:  "A3K9F2",
		},
		{
			name:  "Lowercase",
			input: "a3k9f2",
			want:  "A3K9F2",
		},
		{
			name:  "With hyphens",
			input: "A3K-9F2",
			want:  "A3K9F2",
		},
		{
			name:  "With spaces",
			input: "A3K 9F2",
			want:  "A3K9F2",
		},
		{
			name:  "Mixed case with separators",
			input: "a3k-9F 2",
			want:  "A3K9F2",
		},
		{
			name:  "Multiple separators",
			input: "A-3-K-9-F-2",
			want:  "A3K9F2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := initrequest.NormalizeClaimCode(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateClaimCode(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantError error
	}{
		{
			name:      "Valid code",
			code:      "A3K9F2",
			wantError: nil,
		},
		{
			name:      "Valid with all letters",
			code:      "ABCDEF",
			wantError: nil,
		},
		{
			name:      "Valid with all digits",
			code:      "234567",
			wantError: nil,
		},
		{
			name:      "Too short",
			code:      "A3K9F",
			wantError: initrequest.ErrInvalidLength,
		},
		{
			name:      "Too long",
			code:      "A3K9F22",
			wantError: initrequest.ErrInvalidLength,
		},
		{
			name:      "Empty",
			code:      "",
			wantError: initrequest.ErrInvalidLength,
		},
		{
			name:      "Contains forbidden letter I",
			code:      "A3K9FI",
			wantError: initrequest.ErrInvalidCharacter,
		},
		{
			name:      "Contains forbidden letter O",
			code:      "A3K9FO",
			wantError: initrequest.ErrInvalidCharacter,
		},
		{
			name:      "Contains forbidden digit 0",
			code:      "A3K9F0",
			wantError: initrequest.ErrInvalidCharacter,
		},
		{
			name:      "Contains forbidden digit 1",
			code:      "A3K9F1",
			wantError: initrequest.ErrInvalidCharacter,
		},
		{
			name:      "Contains lowercase (must normalize first)",
			code:      "a3k9f2",
			wantError: initrequest.ErrInvalidCharacter,
		},
		{
			name:      "Contains hyphen (must normalize first)",
			code:      "A3K-9F2",
			wantError: initrequest.ErrInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := initrequest.ValidateClaimCode(tt.code)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompareClaimCode(t *testing.T) {
	tests := []struct {
		name   string
		stored string
		input  string
		want   bool
	}{
		{
			name:   "Exact match",
			stored: "A3K9F2",
			input:  "A3K9F2",
			want:   true,
		},
		{
			name:   "Mismatch",
			stored: "A3K9F2",
			input:  "B4L8G3",
			want:   false,
		},
		{
			name:   "One character different",
			stored: "A3K9F2",
			input:  "A3K9F3",
			want:   false,
		},
		{
			name:   "Different length (must normalize first)",
			stored: "A3K9F2",
			input:  "A3K9F",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := initrequest.CompareClaimCode(tt.stored, tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCompareClaimCode_ConstantTime(t *testing.T) {
	// This test doesn't measure timing (too flaky), but documents
	// the requirement that CompareClaimCode must use constant-time comparison
	stored := "A3K9F2"
	input1 := "A3K9F2" // match
	input2 := "B00000" // total mismatch

	// Both should return without timing side-channel
	match1 := initrequest.CompareClaimCode(stored, input1)
	match2 := initrequest.CompareClaimCode(stored, input2)

	assert.True(t, match1)
	assert.False(t, match2)
}

func TestNormalizeAndValidate_Integration(t *testing.T) {
	// Typical user input flow: normalize → validate → compare

	tests := []struct {
		name      string
		userInput string
		stored    string
		wantMatch bool
		wantError error
	}{
		{
			name:      "User enters lowercase with hyphens",
			userInput: "a3k-9f2",
			stored:    "A3K9F2",
			wantMatch: true,
			wantError: nil,
		},
		{
			name:      "User enters with spaces",
			userInput: "A3K 9F2",
			stored:    "A3K9F2",
			wantMatch: true,
			wantError: nil,
		},
		{
			name:      "User enters wrong code",
			userInput: "B4L8G3",
			stored:    "A3K9F2",
			wantMatch: false,
			wantError: nil,
		},
		{
			name:      "User enters invalid character",
			userInput: "A3K9FO", // O is forbidden
			stored:    "A3K9F2",
			wantMatch: false,
			wantError: initrequest.ErrInvalidCharacter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := initrequest.NormalizeClaimCode(tt.userInput)
			err := initrequest.ValidateClaimCode(normalized)

			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
				return
			}

			require.NoError(t, err)
			match := initrequest.CompareClaimCode(tt.stored, normalized)
			assert.Equal(t, tt.wantMatch, match)
		})
	}
}
