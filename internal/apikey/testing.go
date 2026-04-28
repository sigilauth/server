package apikey

import "golang.org/x/crypto/bcrypt"

// NewTestStore creates an API key store with minimum bcrypt cost for fast tests.
//
// Uses bcrypt.MinCost (4) instead of DefaultBcryptCost (12).
// This reduces bcrypt time from ~250ms to ~10ms per operation, allowing tests
// to run under race detector without timeouts.
//
// Only for use in tests - do not use in production code.
func NewTestStore() *Store {
	return &Store{
		keys: make(map[string]*Key),
		cost: bcrypt.MinCost,
	}
}
