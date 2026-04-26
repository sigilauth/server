package replay

import (
	"context"
	"sync"
	"time"
)

type NonceStore struct {
	mu      sync.RWMutex
	nonces  map[string]time.Time
	ttl     time.Duration
	stopCh  chan struct{}
	stopped bool
}

func NewNonceStore(ttl time.Duration) *NonceStore {
	store := &NonceStore{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go store.cleanup()
	return store
}

func (s *NonceStore) Check(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.nonces[nonce]; exists {
		return false
	}

	s.nonces[nonce] = time.Now()
	return true
}

func (s *NonceStore) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
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

func (s *NonceStore) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for nonce, timestamp := range s.nonces {
		if now.Sub(timestamp) > s.ttl {
			delete(s.nonces, nonce)
		}
	}
}

func (s *NonceStore) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		close(s.stopCh)
		s.stopped = true
	}
}

func (s *NonceStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nonces)
}

func VerifyTimestamp(ctx context.Context, timestamp int64, window int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}
