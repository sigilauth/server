package harness

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeterministicRNG(t *testing.T) {
	seed := []byte("test-seed-for-deterministic-rng")

	// Same seed should produce same output
	rng1 := NewDeterministicRNG(seed)
	rng2 := NewDeterministicRNG(seed)

	buf1 := make([]byte, 64)
	buf2 := make([]byte, 64)

	n1, err1 := rng1.Read(buf1)
	n2, err2 := rng2.Read(buf2)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, 64, n1)
	assert.Equal(t, 64, n2)
	assert.True(t, bytes.Equal(buf1, buf2), "same seed should produce same output")
}

func TestDeterministicRNGDifferentSeeds(t *testing.T) {
	rng1 := NewDeterministicRNG([]byte("seed-one"))
	rng2 := NewDeterministicRNG([]byte("seed-two"))

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)

	rng1.Read(buf1)
	rng2.Read(buf2)

	assert.False(t, bytes.Equal(buf1, buf2), "different seeds should produce different output")
}

func TestDeterministicRNGSequence(t *testing.T) {
	seed := []byte("sequence-test")

	// Sequential reads should produce different data
	rng := NewDeterministicRNG(seed)

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)

	rng.Read(buf1)
	rng.Read(buf2)

	assert.False(t, bytes.Equal(buf1, buf2), "sequential reads should produce different data")
}

func TestDeterministicRNGKeyGeneration(t *testing.T) {
	// Test that deterministic RNG works with device creation
	seed := []byte("device-key-test-seed")
	rng := NewDeterministicRNG(seed)

	device, err := NewDevice(rng)
	assert.NoError(t, err)
	assert.NotEmpty(t, device.Fingerprint)
	
	// Note: Key generation reproducibility depends on ecdsa.GenerateKey internals.
	// For true reproducibility, may need to generate raw key bytes and construct key directly.
	// Current implementation verifies RNG is injectable and produces valid keys.
}

func TestDeterministicRNGStableForSameReadPattern(t *testing.T) {
	// Verify that identical read patterns produce identical output
	seed := []byte("pattern-test")

	rng1 := NewDeterministicRNG(seed)
	rng2 := NewDeterministicRNG(seed)

	// Identical read pattern
	buf1a := make([]byte, 32)
	buf1b := make([]byte, 16)
	buf1c := make([]byte, 48)

	buf2a := make([]byte, 32)
	buf2b := make([]byte, 16)
	buf2c := make([]byte, 48)

	rng1.Read(buf1a)
	rng1.Read(buf1b)
	rng1.Read(buf1c)

	rng2.Read(buf2a)
	rng2.Read(buf2b)
	rng2.Read(buf2c)

	assert.True(t, bytes.Equal(buf1a, buf2a), "first read should match")
	assert.True(t, bytes.Equal(buf1b, buf2b), "second read should match")
	assert.True(t, bytes.Equal(buf1c, buf2c), "third read should match")
}
