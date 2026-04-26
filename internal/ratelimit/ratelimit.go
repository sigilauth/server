// Package ratelimit implements token-bucket rate limiting per Knox §4.
//
// Supports three scopes:
// - Per-IP (for anonymous endpoints)
// - Per-fingerprint (for device-specific endpoints)
// - Per-API-key (for integrator endpoints)
//
// Uses golang.org/x/time/rate for token-bucket implementation.
// All state is in-memory, lost on restart (acceptable per spec).
package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Knox §4 rate limits (per-API-key for integrator endpoints)
var endpointLimits = map[string]limitConfig{
	"POST /challenge":                      {requests: 100, window: 15 * time.Minute, scope: "apikey"},
	"POST /respond":                        {requests: 100, window: 15 * time.Minute, scope: "apikey"},
	"GET /v1/auth/challenge/:id/status":    {requests: 1000, window: 1 * time.Hour, scope: "apikey"},
	"POST /mpa/request":                    {requests: 50, window: 15 * time.Minute, scope: "apikey"},
	"POST /mpa/respond":                    {requests: 50, window: 15 * time.Minute, scope: "apikey"},
	"GET /mpa/status/:id":                  {requests: 1000, window: 1 * time.Hour, scope: "apikey"},
	"POST /v1/secure/decrypt":              {requests: 50, window: 15 * time.Minute, scope: "apikey"},
	"GET /v1/secure/decrypt/:id/status":    {requests: 1000, window: 1 * time.Hour, scope: "apikey"},
	"POST /v1/config/webhooks":             {requests: 50, window: 15 * time.Minute, scope: "apikey"},
}

type limitConfig struct {
	requests int
	window   time.Duration
	scope    string
}

type bucketKey struct {
	scope    string
	identity string
	endpoint string
}

// Limiter manages rate limiting across multiple scopes.
type Limiter struct {
	mu      sync.RWMutex
	buckets map[bucketKey]*rate.Limiter
	fastDecay bool // For testing: speeds up token refill
}

// NewLimiter creates a new rate limiter.
func NewLimiter() *Limiter {
	return &Limiter{
		buckets: make(map[bucketKey]*rate.Limiter),
	}
}

// AllowPerIP checks if request is allowed under per-IP rate limit.
//
// Returns:
// - allowed: true if request should proceed
// - retryAfter: seconds until next token available (0 if allowed)
func (l *Limiter) AllowPerIP(ctx context.Context, ip string, endpoint string) (bool, int) {
	return l.allow(ctx, "ip", ip, endpoint)
}

// AllowPerFingerprint checks if request is allowed under per-fingerprint limit.
func (l *Limiter) AllowPerFingerprint(ctx context.Context, fingerprint string, endpoint string) (bool, int) {
	return l.allow(ctx, "fingerprint", fingerprint, endpoint)
}

// AllowPerAPIKey checks if request is allowed under per-API-key limit.
func (l *Limiter) AllowPerAPIKey(ctx context.Context, apiKey string, endpoint string) (bool, int) {
	return l.allow(ctx, "apikey", apiKey, endpoint)
}

// allow is the core rate limiting logic.
func (l *Limiter) allow(ctx context.Context, scope string, identity string, endpoint string) (bool, int) {
	// Normalize endpoint (remove path params)
	normalizedEndpoint := normalizeEndpoint(endpoint)

	config, exists := endpointLimits[normalizedEndpoint]
	if !exists {
		// Unknown endpoint, allow by default (fail open)
		return true, 0
	}

	// Get or create limiter for this scope+identity+endpoint
	key := bucketKey{scope: scope, identity: identity, endpoint: normalizedEndpoint}
	limiter := l.getOrCreateLimiter(key, config)

	// Try to consume a token
	reservation := limiter.Reserve()
	if !reservation.OK() {
		// Should never happen with token bucket, but handle defensively
		return false, int(config.window.Seconds())
	}

	delay := reservation.Delay()
	if delay == 0 {
		// Token available immediately
		return true, 0
	}

	// Rate limited - cancel reservation and return retry-after
	reservation.Cancel()
	retryAfter := int(delay.Seconds())
	if retryAfter < 1 {
		retryAfter = 1 // Minimum 1 second
	}
	return false, retryAfter
}

// getOrCreateLimiter retrieves or creates a token-bucket limiter for the given key.
func (l *Limiter) getOrCreateLimiter(key bucketKey, config limitConfig) *rate.Limiter {
	l.mu.RLock()
	limiter, exists := l.buckets[key]
	l.mu.RUnlock()

	if exists {
		return limiter
	}

	// Create new limiter
	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := l.buckets[key]; exists {
		return limiter
	}

	// Token bucket params:
	// - Burst: number of requests allowed in window
	// - Rate: tokens per second to refill
	burst := config.requests
	tokensPerSecond := float64(config.requests) / config.window.Seconds()

	// For testing: speed up token refill
	if l.fastDecay {
		tokensPerSecond = float64(config.requests) / 0.1 // Refill in 100ms
	}

	limiter = rate.NewLimiter(rate.Limit(tokensPerSecond), burst)
	l.buckets[key] = limiter

	return limiter
}

// normalizeEndpoint removes path parameters for endpoint matching.
//
// Examples:
// - "GET /v1/auth/challenge/abc123/status" → "GET /v1/auth/challenge/:id/status"
// - "POST /v1/auth/challenge" → "POST /v1/auth/challenge"
func normalizeEndpoint(endpoint string) string {
	// For now, direct match. In real implementation, would use path pattern matching.
	// Knox §4 uses fixed endpoints, so direct match works.

	// Handle challenge ID status endpoint
	// Pattern: GET /v1/auth/challenge/{uuid}/status
	if len(endpoint) > 50 && endpoint[:24] == "GET /v1/auth/challenge/" && endpoint[len(endpoint)-7:] == "/status" {
		return "GET /v1/auth/challenge/:id/status"
	}

	return endpoint
}

// SetFastDecayForTesting speeds up token refill for testing.
// DO NOT USE IN PRODUCTION.
func (l *Limiter) SetFastDecayForTesting() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fastDecay = true
	// Clear existing buckets to apply new rate
	l.buckets = make(map[bucketKey]*rate.Limiter)
}
