package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLimiter(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	require.NotNil(t, limiter)
}

func TestPerIPLimit(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	// Knox §4: 100 req/15min per IP for /v1/auth/challenge
	for i := 0; i < 100; i++ {
		allowed, retryAfter := limiter.AllowPerIP(ctx, "192.168.1.100", "POST /v1/auth/challenge")
		assert.True(t, allowed, "request %d should be allowed", i+1)
		assert.Equal(t, 0, retryAfter)
	}

	// 101st request should be rate limited
	allowed, retryAfter := limiter.AllowPerIP(ctx, "192.168.1.100", "POST /v1/auth/challenge")
	assert.False(t, allowed, "101st request should be rate limited")
	assert.Greater(t, retryAfter, 0, "should have retry-after value")
	assert.LessOrEqual(t, retryAfter, 900, "retry-after should be <=15min")
}

func TestPerFingerprintLimit(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	fingerprint := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

	// Knox §4: 100 req/15min per fingerprint for /v1/auth/respond
	for i := 0; i < 100; i++ {
		allowed, retryAfter := limiter.AllowPerFingerprint(ctx, fingerprint, "POST /v1/auth/respond")
		assert.True(t, allowed, "request %d should be allowed", i+1)
		assert.Equal(t, 0, retryAfter)
	}

	// 101st request should be rate limited
	allowed, retryAfter := limiter.AllowPerFingerprint(ctx, fingerprint, "POST /v1/auth/respond")
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, 0)
}

func TestPerAPIKeyLimit(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	apiKey := "sgk_test_1234567890abcdef"

	// Knox §4: 50 req/15min per API key for /v1/mpa/request
	for i := 0; i < 50; i++ {
		allowed, retryAfter := limiter.AllowPerAPIKey(ctx, apiKey, "POST /v1/mpa/request")
		assert.True(t, allowed, "request %d should be allowed", i+1)
		assert.Equal(t, 0, retryAfter)
	}

	// 51st request should be rate limited
	allowed, retryAfter := limiter.AllowPerAPIKey(ctx, apiKey, "POST /v1/mpa/request")
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, 0)
	assert.LessOrEqual(t, retryAfter, 900)
}

func TestDifferentScopesIndependent(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	ip := "10.0.0.1"
	fingerprint := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	apiKey := "sgk_test_key"

	// Consume per-IP limit
	for i := 0; i < 100; i++ {
		limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	}
	allowed, _ := limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	assert.False(t, allowed, "per-IP limit exhausted")

	// Per-fingerprint should still allow
	allowed, _ = limiter.AllowPerFingerprint(ctx, fingerprint, "POST /v1/auth/respond")
	assert.True(t, allowed, "per-fingerprint should be independent")

	// Per-API-key should still allow
	allowed, _ = limiter.AllowPerAPIKey(ctx, apiKey, "POST /v1/mpa/request")
	assert.True(t, allowed, "per-API-key should be independent")
}

func TestDifferentIdentitiesIndependent(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	// Exhaust limit for IP1
	ip1 := "192.168.1.1"
	for i := 0; i < 100; i++ {
		limiter.AllowPerIP(ctx, ip1, "POST /v1/auth/challenge")
	}

	// IP2 should still be allowed
	ip2 := "192.168.1.2"
	allowed, _ := limiter.AllowPerIP(ctx, ip2, "POST /v1/auth/challenge")
	assert.True(t, allowed, "different IP should have independent limit")
}

func TestRateLimitDecay(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	limiter.SetFastDecayForTesting() // Speed up time for testing
	ctx := context.Background()

	ip := "10.1.1.1"

	// Consume limit
	for i := 0; i < 100; i++ {
		limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	}

	// Should be rate limited
	allowed, _ := limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	assert.False(t, allowed)

	// Wait for tokens to refill (with fast decay, should be quick)
	time.Sleep(200 * time.Millisecond)

	// Should be allowed again
	allowed, retryAfter := limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	assert.True(t, allowed, "should allow after token refill")
	assert.Equal(t, 0, retryAfter)
}

func TestMultipleEndpointsDifferentLimits(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	apiKey := "sgk_test_multi"

	// Knox §4: 50 req/15min for MPA, 1000 req/hour for status
	// Consume MPA limit
	for i := 0; i < 50; i++ {
		allowed, _ := limiter.AllowPerAPIKey(ctx, apiKey, "POST /v1/mpa/request")
		assert.True(t, allowed, "MPA request %d should be allowed", i+1)
	}

	// MPA should be exhausted
	allowed, _ := limiter.AllowPerAPIKey(ctx, apiKey, "POST /v1/mpa/request")
	assert.False(t, allowed, "MPA limit should be exhausted")

	// Status endpoint should still work (different limit)
	allowed, retryAfter := limiter.AllowPerAPIKey(ctx, apiKey, "GET /v1/auth/challenge/123/status")
	assert.True(t, allowed, "status endpoint should have independent limit")
	assert.Equal(t, 0, retryAfter)
}

func TestRetryAfterAccuracy(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	ip := "10.2.2.2"

	// Exhaust limit
	for i := 0; i < 100; i++ {
		limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	}

	// Check retry-after is reasonable
	_, retryAfter := limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	assert.Greater(t, retryAfter, 0, "should have retry-after")
	assert.LessOrEqual(t, retryAfter, 900, "retry-after should not exceed window (900s = 15min)")
}

func TestConcurrentAccess(t *testing.T) {
	limiter := ratelimit.NewLimiter()
	ctx := context.Background()

	ip := "10.3.3.3"
	done := make(chan bool, 10)

	// 10 goroutines each making 10 requests concurrently
	for g := 0; g < 10; g++ {
		go func() {
			for i := 0; i < 10; i++ {
				limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for g := 0; g < 10; g++ {
		<-done
	}

	// Total 100 requests made, limit should be hit
	allowed, _ := limiter.AllowPerIP(ctx, ip, "POST /v1/auth/challenge")
	assert.False(t, allowed, "concurrent requests should respect limit")
}
