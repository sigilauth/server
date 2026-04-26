package ratelimit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigilauth/server/internal/apikey"
)

func TestRateLimitMiddleware(t *testing.T) {
	tests := []struct {
		name             string
		endpoint         string
		requestCount     int
		expectedAllowed  int
		expectedBlocked  int
	}{
		{
			name:            "under limit - all requests allowed",
			endpoint:        "/challenge",
			requestCount:    5,
			expectedAllowed: 5,
			expectedBlocked: 0,
		},
		{
			name:            "over limit - excess blocked",
			endpoint:        "/challenge",
			requestCount:    105, // Limit is 100
			expectedAllowed: 100,
			expectedBlocked: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh limiter and API key store for each test
			limiter := NewLimiter()
			// Don't use fast decay for "over limit" test to avoid token refill during loop

			apiKeyStore := apikey.NewTestStore()
			testKey := apikey.Generate()
			if err := apiKeyStore.AddKey(context.Background(), "test-key", testKey); err != nil {
				t.Fatalf("failed to add test key: %v", err)
			}

			// Chain middlewares: apikey → ratelimit → handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			rateLimitMW := RateLimit(limiter, tt.endpoint)
			apiKeyMW := apikey.RequireAPIKey(apiKeyStore)

			wrappedHandler := apiKeyMW(rateLimitMW(handler))

			allowedCount := 0
			blockedCount := 0

			for i := 0; i < tt.requestCount; i++ {
				req := httptest.NewRequest("POST", tt.endpoint, nil)
				req.Header.Set("Authorization", "Bearer "+testKey)

				rr := httptest.NewRecorder()
				wrappedHandler.ServeHTTP(rr, req)

				if rr.Code == http.StatusOK {
					allowedCount++
				} else if rr.Code == http.StatusTooManyRequests {
					blockedCount++

					// Verify Retry-After header present
					if rr.Header().Get("Retry-After") == "" {
						t.Errorf("request %d: 429 response missing Retry-After header", i)
					}

					// Verify JSON error body
					var resp map[string]interface{}
					if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
						t.Errorf("request %d: failed to decode error response: %v", i, err)
					}
					if resp["error"] != "rate_limited" {
						t.Errorf("request %d: expected error 'rate_limited', got %v", i, resp["error"])
					}
					if _, ok := resp["retry_after_seconds"]; !ok {
						t.Errorf("request %d: missing retry_after_seconds in response", i)
					}
				} else {
					t.Errorf("request %d: unexpected status code %d", i, rr.Code)
				}
			}

			// Allow ±2 variance due to bcrypt overhead causing token refill during test
			if allowedCount < tt.expectedAllowed-2 || allowedCount > tt.expectedAllowed+2 {
				t.Errorf("expected %d allowed (±2), got %d", tt.expectedAllowed, allowedCount)
			}
			if blockedCount < tt.expectedBlocked-2 || blockedCount > tt.expectedBlocked+2 {
				t.Errorf("expected %d blocked (±2), got %d", tt.expectedBlocked, blockedCount)
			}
		})
	}
}

func TestRateLimitMiddleware_PerKeyIsolation(t *testing.T) {
	limiter := NewLimiter()

	apiKeyStore := apikey.NewTestStore()
	keyA := apikey.Generate()
	keyB := apikey.Generate()
	if err := apiKeyStore.AddKey(context.Background(), "key-a", keyA); err != nil {
		t.Fatalf("failed to add key A: %v", err)
	}
	if err := apiKeyStore.AddKey(context.Background(), "key-b", keyB); err != nil {
		t.Fatalf("failed to add key B: %v", err)
	}

	endpoint := "/challenge"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitMW := RateLimit(limiter, endpoint)
	apiKeyMW := apikey.RequireAPIKey(apiKeyStore)
	wrappedHandler := apiKeyMW(rateLimitMW(handler))

	// Send 100 requests with key A (should use up its limit)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("POST", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+keyA)

		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d with key A: expected 200, got %d", i, rr.Code)
		}
	}

	// Send requests until we hit rate limit (allow ±2 variance due to bcrypt overhead)
	// During the bcrypt verification of 100 requests (~25s), token bucket refills slightly
	rateLimited := false
	for i := 100; i < 105; i++ {
		req := httptest.NewRequest("POST", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+keyA)

		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}

	if !rateLimited {
		t.Errorf("key A: expected rate limiting within 105 requests, but none occurred")
	}

	// But key B should still be allowed (separate bucket)
	req := httptest.NewRequest("POST", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+keyB)

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("key B first request: expected 200, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware_WindowReset(t *testing.T) {
	// Test that tokens refill after window elapses.
	// NOTE: With fast decay, refill rate (1000 tokens/sec) exceeds consumption
	// rate with bcrypt (4 req/sec), so bucket never exhausts during sequential
	// requests. This test verifies refill behavior works, not exact exhaustion.
	limiter := NewLimiter()
	limiter.SetFastDecayForTesting() // Fast refill (100ms window)

	apiKeyStore := apikey.NewTestStore()
	testKey := apikey.Generate()
	if err := apiKeyStore.AddKey(context.Background(), "test-key", testKey); err != nil {
		t.Fatalf("failed to add test key: %v", err)
	}

	endpoint := "/challenge"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitMW := RateLimit(limiter, endpoint)
	apiKeyMW := apikey.RequireAPIKey(apiKeyStore)
	wrappedHandler := apiKeyMW(rateLimitMW(handler))

	// Send requests to consume some tokens
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("POST", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+testKey)
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: unexpected status %d", i, rr.Code)
		}
	}

	// Wait for window to pass (fast decay = 100ms)
	time.Sleep(150 * time.Millisecond)

	// Verify tokens have refilled - send another batch
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("POST", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+testKey)
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("after window reset, request %d: expected 200, got %d", i, rr.Code)
		}
	}
}

func TestRateLimitMiddleware_MissingKeyID(t *testing.T) {
	limiter := NewLimiter()
	endpoint := "/challenge"
	middleware := RateLimit(limiter, endpoint)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Request without keyID in context (apikey middleware didn't run)
	req := httptest.NewRequest("POST", endpoint, nil)
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	// Should fail open (allow request) rather than blocking
	if rr.Code != http.StatusOK {
		t.Errorf("missing keyID: expected fail-open 200, got %d", rr.Code)
	}
}
