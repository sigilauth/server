package ratelimit

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sigilauth/server/internal/apikey"
)

// RateLimit returns middleware that enforces per-API-key rate limiting.
//
// Chain order: RequireAPIKey → RateLimit → handler
// (keyID must be in context from apikey middleware)
//
// On rate limit exceeded:
// - Returns 429 Too Many Requests
// - Sets Retry-After header (seconds)
// - JSON body: {"error":"rate_limited","retry_after_seconds":N}
func RateLimit(limiter *Limiter, endpoint string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract keyID from context (set by apikey middleware)
			keyID := apikey.GetKeyIDFromContext(r.Context())
			if keyID == "" {
				// This should never happen if middleware chain is correct
				// (RequireAPIKey should run before RateLimit)
				// Fail open rather than blocking legitimate traffic
				next.ServeHTTP(w, r)
				return
			}

			// Build endpoint identifier: "METHOD /path"
			endpointID := r.Method + " " + endpoint

			// Check rate limit
			allowed, retryAfter := limiter.AllowPerAPIKey(r.Context(), keyID, endpointID)
			if !allowed {
				respondRateLimited(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func respondRateLimited(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":                "rate_limited",
		"retry_after_seconds": retryAfter,
	})
}
