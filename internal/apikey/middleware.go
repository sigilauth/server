package apikey

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const (
	// keyIDContextKey is the context key for storing the verified API key ID.
	keyIDContextKey contextKey = "api_key_id"
)

// RequireAPIKey returns middleware that validates Bearer API keys.
//
// Reads Authorization: Bearer <key>, calls store.VerifyKey(key).
// On success: attaches keyID to request context and continues.
// On failure: returns 401 with {"error":"invalid_api_key"}.
func RequireAPIKey(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondUnauthorized(w, "missing authorization header")
				return
			}

			// Extract Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondUnauthorized(w, "invalid authorization format")
				return
			}

			plaintextKey := parts[1]
			if plaintextKey == "" {
				respondUnauthorized(w, "empty api key")
				return
			}

			// Verify key
			valid, keyID := store.VerifyKey(r.Context(), plaintextKey)
			if !valid {
				respondUnauthorized(w, "invalid_api_key")
				return
			}

			// Attach keyID to context
			ctx := context.WithValue(r.Context(), keyIDContextKey, keyID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetKeyIDFromContext retrieves the verified API key ID from request context.
//
// Returns empty string if not found (request not authenticated).
func GetKeyIDFromContext(ctx context.Context) string {
	keyID, ok := ctx.Value(keyIDContextKey).(string)
	if !ok {
		return ""
	}
	return keyID
}

func respondUnauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error": reason,
	})
}
