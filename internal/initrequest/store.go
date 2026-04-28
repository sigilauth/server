package initrequest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	StatusPending      = "pending"
	StatusPendingClaim = "pending_claim"
	StatusClaimed      = "claimed"
	StatusApproved     = "approved"
	StatusRejected     = "rejected"
	StatusExpired      = "expired"
	StatusInvalidated  = "invalidated"

	DefaultRequestTTL      = 5 * time.Minute
	ClaimCodeTTL           = 60 * time.Second
	MaxRequestTTL          = 1 * time.Hour
	MinRequestTTL          = 60 * time.Second
	MaxFailedClaimAttempts = 5
)

var (
	ErrRequestNotFound    = errors.New("request not found")
	ErrRequestExpired     = errors.New("request expired")
	ErrRequestInvalidated = errors.New("request invalidated")
	ErrAlreadyClaimed     = errors.New("already claimed")
	ErrAlreadyApproved    = errors.New("already approved")
	ErrClaimCodeExpired   = errors.New("claim code expired")
	ErrInvalidTTL         = errors.New("ttl out of range")
)

// Request represents an implementor engine initialization request.
type Request struct {
	RequestID             string
	Status                string
	Selectors             []string // device fingerprints or ["any"]
	ImplementorPubkey     []byte   // compressed P-256 (33 bytes)
	ClaimCode             string   // only if path B
	ClaimedByFingerprint  string   // only if path B after claim
	EncryptedMnemonic     []byte   // only after approval
	ApprovedByFingerprint string   // only after approval
	RejectionReason       string   // only after rejection
	FailedClaimAttempts   int      // only if path B
	CreatedAt             time.Time
	ExpiresAt             time.Time
	ClaimExpiresAt        *time.Time // only if path B
	ApprovedAt            *time.Time
	RejectedAt            *time.Time
}

// Store manages ephemeral init requests.
type Store struct {
	mu       sync.RWMutex
	requests map[string]*Request
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewStore creates a new init request store and starts background cleanup.
func NewStore() *Store {
	s := &Store{
		requests: make(map[string]*Request),
		stopCh:   make(chan struct{}),
	}
	s.startCleanup()
	return s
}

// Close stops the background cleanup goroutine.
func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

// Create creates a new init request.
func (s *Store) Create(ctx context.Context, requestID string, selectors []string, implementorPubkey []byte, ttl time.Duration) (*Request, error) {
	if ttl < MinRequestTTL || ttl > MaxRequestTTL {
		return nil, ErrInvalidTTL
	}

	now := time.Now()
	req := &Request{
		RequestID:         requestID,
		Selectors:         selectors,
		ImplementorPubkey: implementorPubkey,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}

	// Path B: open claim with code gate
	if len(selectors) == 1 && selectors[0] == "any" {
		claimCode, err := GenerateClaimCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate claim code: %w", err)
		}

		req.Status = StatusPendingClaim
		req.ClaimCode = claimCode
		claimExpiry := now.Add(ClaimCodeTTL)
		req.ClaimExpiresAt = &claimExpiry
	} else {
		// Path A: specific device fingerprints
		req.Status = StatusPending
	}

	s.mu.Lock()
	s.requests[requestID] = req
	s.mu.Unlock()

	return req, nil
}

// Get retrieves a request by ID.
func (s *Store) Get(requestID string) (*Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[requestID]
	if !ok {
		return nil, ErrRequestNotFound
	}

	// Check expiry
	if time.Now().After(req.ExpiresAt) {
		return nil, ErrRequestExpired
	}

	return req, nil
}

// Claim marks a request as claimed by a specific device (Path B only).
//
// Returns ErrAlreadyClaimed if another device already claimed.
// Returns ErrClaimCodeExpired if claim code TTL expired.
func (s *Store) Claim(requestID, claimCode, deviceFingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok {
		return ErrRequestNotFound
	}

	if req.Status == StatusInvalidated {
		return ErrRequestInvalidated
	}

	if time.Now().After(req.ExpiresAt) {
		return ErrRequestExpired
	}

	// Check claim code expiry
	if req.ClaimExpiresAt != nil && time.Now().After(*req.ClaimExpiresAt) {
		req.Status = StatusExpired
		return ErrClaimCodeExpired
	}

	// Check if already claimed by another device
	if req.Status == StatusClaimed && req.ClaimedByFingerprint != deviceFingerprint {
		return ErrAlreadyClaimed
	}

	// Verify claim code (constant-time comparison)
	normalizedInput := NormalizeClaimCode(claimCode)
	if err := ValidateClaimCode(normalizedInput); err != nil {
		req.FailedClaimAttempts++
		if req.FailedClaimAttempts >= MaxFailedClaimAttempts {
			req.Status = StatusInvalidated
		}
		return err
	}

	normalizedStored := NormalizeClaimCode(req.ClaimCode)
	if !CompareClaimCode(normalizedStored, normalizedInput) {
		req.FailedClaimAttempts++
		if req.FailedClaimAttempts >= MaxFailedClaimAttempts {
			req.Status = StatusInvalidated
		}
		return errors.New("claim code mismatch")
	}

	// Successfully claimed
	req.Status = StatusClaimed
	req.ClaimedByFingerprint = deviceFingerprint

	return nil
}

// Approve marks a request as approved with encrypted mnemonic.
//
// Returns ErrAlreadyApproved if another device already approved (first-wins).
func (s *Store) Approve(requestID, deviceFingerprint string, encryptedMnemonic []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok {
		return ErrRequestNotFound
	}

	if time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		return ErrRequestExpired
	}

	if req.Status == StatusInvalidated {
		return ErrRequestInvalidated
	}

	// First-wins: reject if already approved by another device
	if req.Status == StatusApproved {
		return ErrAlreadyApproved
	}

	// Approve
	req.Status = StatusApproved
	req.EncryptedMnemonic = encryptedMnemonic
	req.ApprovedByFingerprint = deviceFingerprint
	now := time.Now()
	req.ApprovedAt = &now

	return nil
}

// Reject marks a request as rejected.
//
// First rejection does NOT lock the request — other devices can still approve.
func (s *Store) Reject(requestID, deviceFingerprint, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok {
		return ErrRequestNotFound
	}

	if time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		return ErrRequestExpired
	}

	// Don't overwrite approved state with rejection
	if req.Status == StatusApproved {
		return nil // silently ignore, already approved
	}

	req.Status = StatusRejected
	req.RejectionReason = reason
	now := time.Now()
	req.RejectedAt = &now

	return nil
}

// RecordFailedClaimAttempt increments failed claim counter.
//
// After MaxFailedClaimAttempts, the request is invalidated.
func (s *Store) RecordFailedClaimAttempt(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok {
		return ErrRequestNotFound
	}

	req.FailedClaimAttempts++
	if req.FailedClaimAttempts >= MaxFailedClaimAttempts {
		req.Status = StatusInvalidated
	}

	return nil
}

// startCleanup starts a background goroutine that removes expired requests.
func (s *Store) startCleanup() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

// cleanup removes expired requests.
func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, req := range s.requests {
		if now.After(req.ExpiresAt) {
			delete(s.requests, id)
		}
	}
}
