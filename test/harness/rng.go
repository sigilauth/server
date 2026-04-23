package harness

import (
	"crypto/sha256"
	"io"
)

// DeterministicRNG provides reproducible random bytes for testing.
// Uses SHA256 DRBG pattern: each read hashes current state and returns output.
type DeterministicRNG struct {
	state []byte
}

// NewDeterministicRNG creates a new deterministic RNG from a seed.
// Same seed always produces the same sequence of bytes.
func NewDeterministicRNG(seed []byte) *DeterministicRNG {
	h := sha256.Sum256(seed)
	return &DeterministicRNG{state: h[:]}
}

// Read fills p with deterministic pseudo-random bytes.
// Implements io.Reader.
func (r *DeterministicRNG) Read(p []byte) (n int, err error) {
	for n < len(p) {
		// Hash current state to get output
		h := sha256.Sum256(r.state)
		
		// Copy output to p
		copied := copy(p[n:], h[:])
		n += copied
		
		// Update state for next iteration
		r.state = h[:]
	}
	return n, nil
}

// Ensure DeterministicRNG implements io.Reader
var _ io.Reader = (*DeterministicRNG)(nil)
