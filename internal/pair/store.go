package pair

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

type PendingPair struct {
	ServerNonce       []byte
	ClientPublicKey   []byte
	SessionPictogram  []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	Approved          bool
	DeviceInfo        map[string]interface{}
}

type Store struct {
	mu       sync.RWMutex
	pairs    map[string]*PendingPair
	byIP     map[string]int
	stopCh   chan struct{}
	stopped  bool
}

func NewStore() *Store {
	store := &Store{
		pairs:   make(map[string]*PendingPair),
		byIP:    make(map[string]int),
		stopCh:  make(chan struct{}),
	}
	go store.cleanup()
	return store
}

func (s *Store) Create(ctx context.Context, nonce, clientPub []byte, pictogram []string, handshakeTTL, approvalTTL time.Duration) error {
	if len(nonce) != 32 {
		return fmt.Errorf("nonce must be 32 bytes, got %d", len(nonce))
	}

	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.pairs[nonceKey] = &PendingPair{
		ServerNonce:      nonce,
		ClientPublicKey:  clientPub,
		SessionPictogram: pictogram,
		IssuedAt:         now,
		ExpiresAt:        now.Add(approvalTTL),
		Approved:         false,
	}

	return nil
}

func (s *Store) Get(ctx context.Context, nonce []byte) (*PendingPair, bool) {
	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	s.mu.RLock()
	defer s.mu.RUnlock()

	pair, exists := s.pairs[nonceKey]
	return pair, exists
}

func (s *Store) Consume(ctx context.Context, nonce []byte) error {
	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	pair, exists := s.pairs[nonceKey]
	if !exists {
		return fmt.Errorf("nonce not found")
	}

	if time.Now().After(pair.ExpiresAt) {
		delete(s.pairs, nonceKey)
		return fmt.Errorf("nonce expired")
	}

	if !pair.Approved {
		return fmt.Errorf("pair not approved")
	}

	delete(s.pairs, nonceKey)
	return nil
}

func (s *Store) Approve(ctx context.Context, nonce []byte) error {
	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	pair, exists := s.pairs[nonceKey]
	if !exists {
		return fmt.Errorf("nonce not found")
	}

	if time.Now().After(pair.ExpiresAt) {
		delete(s.pairs, nonceKey)
		return fmt.Errorf("nonce expired")
	}

	pair.Approved = true
	return nil
}

func (s *Store) CheckRateLimit(ctx context.Context, sourceIP string, maxConcurrent, maxPerMinute int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := s.byIP[sourceIP]
	if count >= maxConcurrent {
		return fmt.Errorf("rate limit: max %d concurrent handshakes per IP", maxConcurrent)
	}

	return nil
}

func (s *Store) IncrementIP(ctx context.Context, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byIP[sourceIP]++
}

func (s *Store) DecrementIP(ctx context.Context, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byIP[sourceIP] > 0 {
		s.byIP[sourceIP]--
	}
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.removeExpired()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Store) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for nonceKey, pair := range s.pairs {
		if now.After(pair.ExpiresAt) {
			delete(s.pairs, nonceKey)
		}
	}
}

func (s *Store) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		close(s.stopCh)
		s.stopped = true
	}
}

func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pairs)
}
