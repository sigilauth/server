package ratelimit

import (
	"context"
	"testing"
)

func TestDirectLimiter(t *testing.T) {
	limiter := NewLimiter()
	ctx := context.Background()
	
	// Test without fast decay first
	for i := 0; i < 100; i++ {
		allowed, _ := limiter.AllowPerAPIKey(ctx, "test-key", "POST /challenge")
		if !allowed {
			t.Fatalf("Request %d should be allowed (limit is 100)", i+1)
		}
	}
	
	// 101st request should be blocked
	allowed, retryAfter := limiter.AllowPerAPIKey(ctx, "test-key", "POST /challenge")
	if allowed {
		t.Errorf("Request 101 should be blocked")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter should be > 0, got %d", retryAfter)
	}
}
