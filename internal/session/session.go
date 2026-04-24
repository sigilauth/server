// Package session manages ephemeral challenge sessions.
//
// Challenges are stored in-memory with a 5-minute TTL. No database.
// Lost on server restart (stateless design).
package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/pkg/pictogram"
)

const DefaultChallenTTL = 5 * time.Minute

// Action represents the action being authorized.
type Action struct {
	Type        string
	Description string
	Params      map[string]interface{}
}

// ChallengeRequest is the input for creating a challenge.
type ChallengeRequest struct {
	Fingerprint     string
	DevicePublicKey []byte
	Action          Action
	ServerKey       *ecdsa.PrivateKey
	TTL             time.Duration
}

// Challenge represents an active challenge session.
type Challenge struct {
	ChallengeID         string
	Fingerprint         string
	DevicePublicKey     []byte
	ChallengeBytes      []byte
	ServerSignature     []byte
	Action              Action
	Pictogram           []string
	PictogramSpeakable  string
	ExpiresAt           time.Time
	CreatedAt           time.Time
	Consumed            bool
}

// VerifyRequest is the input for verifying a challenge response.
type VerifyRequest struct {
	ChallengeID string
	Fingerprint string
	Signature   []byte
}

// Store manages in-memory challenge sessions.
type Store struct {
	mu        sync.RWMutex
	challenges map[string]*Challenge
}

// NewStore creates a new session store.
func NewStore() *Store {
	return &Store{
		challenges: make(map[string]*Challenge),
	}
}

// CreateChallenge creates a new challenge session.
//
// Returns a challenge with:
// - Random 32-byte challenge
// - Server signature
// - Pictogram derived from device fingerprint
// - 5-minute expiry
func (s *Store) CreateChallenge(ctx context.Context, req ChallengeRequest) (*Challenge, error) {
	if len(req.DevicePublicKey) != 33 {
		return nil, fmt.Errorf("device public key must be 33 bytes (compressed), got %d", len(req.DevicePublicKey))
	}

	challengeID := uuid.New().String()

	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	fingerprintBytes, err := hex.DecodeString(req.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("invalid fingerprint hex: %w", err)
	}

	pg := pictogram.Derive(fingerprintBytes)

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultChallenTTL
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	signature, err := crypto.Sign(req.ServerKey, challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	challenge := &Challenge{
		ChallengeID:        challengeID,
		Fingerprint:        req.Fingerprint,
		DevicePublicKey:    req.DevicePublicKey,
		ChallengeBytes:     challengeBytes,
		ServerSignature:    signature,
		Action:             req.Action,
		Pictogram:          pg.Words,
		PictogramSpeakable: pg.Speakable(),
		ExpiresAt:          expiresAt,
		CreatedAt:          now,
		Consumed:           false,
	}

	s.mu.Lock()
	s.challenges[challengeID] = challenge
	s.mu.Unlock()

	return challenge, nil
}

// GetChallenge retrieves a challenge by ID.
//
// Returns error if challenge not found or expired.
func (s *Store) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	s.mu.RLock()
	challenge, exists := s.challenges[challengeID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("challenge not found")
	}

	if time.Now().After(challenge.ExpiresAt) {
		s.mu.Lock()
		delete(s.challenges, challengeID)
		s.mu.Unlock()
		return nil, fmt.Errorf("challenge expired")
	}

	return challenge, nil
}

// VerifyChallenge verifies a device's response to a challenge.
//
// Checks:
// - Challenge exists and not expired
// - Device fingerprint matches expected
// - Signature is valid
// - Challenge not already consumed (single-use)
//
// Marks challenge as consumed on success.
func (s *Store) VerifyChallenge(ctx context.Context, req VerifyRequest) error {
	challenge, err := s.GetChallenge(ctx, req.ChallengeID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if challenge.Consumed {
		return fmt.Errorf("challenge already used")
	}

	// Verify fingerprint matches the challenge
	if req.Fingerprint != challenge.Fingerprint {
		return fmt.Errorf("fingerprint mismatch")
	}

	// Use stored device public key for signature verification
	devicePubKey, err := crypto.DecompressPublicKey(challenge.DevicePublicKey)
	if err != nil {
		return fmt.Errorf("invalid stored device public key: %w", err)
	}

	if err := crypto.Verify(devicePubKey, challenge.ChallengeBytes, req.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	challenge.Consumed = true
	return nil
}

// CleanExpired removes expired challenges.
// Should be called periodically (e.g., every 30 seconds).
func (s *Store) CleanExpired(ctx context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, id)
			removed++
		}
	}

	return removed
}
