// Package apikey manages API key generation, verification, and rotation.
//
// Per Knox §5.4:
// - Keys stored as bcrypt hashes (cost 12)
// - Format: sgk_live_<64-hex>
// - Plaintext shown once at generation
// - Rotation replaces hash, old key immediately invalid
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	keyPrefix   = "sgk_live_"
	keyLength   = 32 // 32 bytes = 64 hex chars
	bcryptCost  = 12 // Knox §5.4
)

// Key represents an API key with metadata.
type Key struct {
	ID        string
	Hash      string
	Plaintext string // Only populated during generation, never stored
	CreatedAt int64
	RevokedAt int64
}

// Store manages API keys in memory.
// Lost on restart (keys must be reloaded from env).
type Store struct {
	mu   sync.RWMutex
	keys map[string]*Key // keyID -> Key
}

// NewStore creates a new API key store.
func NewStore() *Store {
	return &Store{
		keys: make(map[string]*Key),
	}
}

// Generate creates a new API key.
//
// Format: sgk_live_<64-hex>
// Returns plaintext key (must be saved immediately, never shown again).
func Generate() string {
	randomBytes := make([]byte, keyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("failed to generate random key: %v", err))
	}

	return keyPrefix + hex.EncodeToString(randomBytes)
}

// hashKey applies SHA-256 to key before bcrypt (bcrypt has 72-byte limit).
func hashKey(plaintextKey string) []byte {
	hash := sha256.Sum256([]byte(plaintextKey))
	return hash[:]
}

// AddKey adds a new API key to the store.
//
// Hashes the plaintext key with SHA-256 then bcrypt cost 12.
// Returns error if keyID already exists.
func (s *Store) AddKey(ctx context.Context, keyID string, plaintextKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; exists {
		return fmt.Errorf("key ID %s already exists", keyID)
	}

	keyHash := hashKey(plaintextKey)
	hash, err := bcrypt.GenerateFromPassword(keyHash, bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash key: %w", err)
	}

	s.keys[keyID] = &Key{
		ID:   keyID,
		Hash: string(hash),
	}

	return nil
}

// VerifyKey checks if a plaintext key is valid.
//
// Returns:
// - valid: true if key matches any stored hash
// - keyID: the ID of the matching key (empty if not valid)
func (s *Store) VerifyKey(ctx context.Context, plaintextKey string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyHash := hashKey(plaintextKey)
	for keyID, key := range s.keys {
		err := bcrypt.CompareHashAndPassword([]byte(key.Hash), keyHash)
		if err == nil {
			return true, keyID
		}
	}

	return false, ""
}

// RevokeKey removes a key from the store.
//
// Key immediately becomes invalid.
// Returns error if key not found.
func (s *Store) RevokeKey(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; !exists {
		return fmt.Errorf("key ID %s not found", keyID)
	}

	delete(s.keys, keyID)
	return nil
}

// RotateKey replaces an existing key with a new one.
//
// Updates the hash for keyID with the new plaintext key.
// Old key immediately becomes invalid.
func (s *Store) RotateKey(ctx context.Context, keyID string, newPlaintextKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; !exists {
		return fmt.Errorf("key ID %s not found", keyID)
	}

	keyHash := hashKey(newPlaintextKey)
	hash, err := bcrypt.GenerateFromPassword(keyHash, bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash new key: %w", err)
	}

	s.keys[keyID].Hash = string(hash)
	return nil
}

// ListKeys returns all keys (without plaintext).
//
// Used for admin UI to show active keys.
func (s *Store) ListKeys(ctx context.Context) []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]Key, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, Key{
			ID:   key.ID,
			Hash: key.Hash,
		})
	}

	return keys
}

// LoadFromMap loads keys from a map (e.g., environment variables).
//
// Expected format:
//   map["prod"] = "sgk_live_<64-hex>"
//   map["staging"] = "sgk_live_<64-hex>"
//
// Returns a Store with all keys hashed and ready to verify.
func LoadFromMap(envKeys map[string]string) *Store {
	store := NewStore()
	ctx := context.Background()

	for keyID, plaintextKey := range envKeys {
		if err := store.AddKey(ctx, keyID, plaintextKey); err != nil {
			// Log error but continue loading other keys
			fmt.Printf("failed to load key %s: %v\n", keyID, err)
		}
	}

	return store
}
