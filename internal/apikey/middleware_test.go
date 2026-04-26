package apikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAPIKey(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	// Add a valid test key
	validKey := Generate()
	validKeyID := "test-integration"
	if err := store.AddKey(ctx, validKeyID, validKey); err != nil {
		t.Fatalf("failed to add test key: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedKeyID  string
	}{
		{
			name:           "valid key",
			authHeader:     "Bearer " + validKey,
			expectedStatus: http.StatusOK,
			expectedKeyID:  validKeyID,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
		{
			name:           "invalid format - no Bearer prefix",
			authHeader:     validKey,
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
		{
			name:           "invalid format - wrong scheme",
			authHeader:     "Basic " + validKey,
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
		{
			name:           "empty key",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
		{
			name:           "invalid key",
			authHeader:     "Bearer sgk_live_invalidkeyinvalidkeyinvalidkeyinvalidkeyinvalidkeyinvalid",
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
		{
			name:           "malformed key - wrong prefix",
			authHeader:     "Bearer sgk_test_1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
			expectedStatus: http.StatusUnauthorized,
			expectedKeyID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test handler that checks context
			var capturedKeyID string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedKeyID = GetKeyIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			middleware := RequireAPIKey(store)
			wrappedHandler := middleware(handler)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Record response
			rr := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rr, req)

			// Check status
			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check keyID in context (only for successful auth)
			if tt.expectedStatus == http.StatusOK {
				if capturedKeyID != tt.expectedKeyID {
					t.Errorf("expected keyID %q, got %q", tt.expectedKeyID, capturedKeyID)
				}
			}
		})
	}
}

func TestGetKeyIDFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "key present",
			ctx:      context.WithValue(context.Background(), keyIDContextKey, "test-key"),
			expected: "test-key",
		},
		{
			name:     "key not present",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name:     "wrong type in context",
			ctx:      context.WithValue(context.Background(), keyIDContextKey, 123),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetKeyIDFromContext(tt.ctx)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestRequireAPIKey_ConcurrentRequests(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	// Add multiple keys
	keys := make(map[string]string)
	for i := 0; i < 10; i++ {
		key := Generate()
		keyID := "concurrent-" + string(rune('a'+i))
		if err := store.AddKey(ctx, keyID, key); err != nil {
			t.Fatalf("failed to add key %s: %v", keyID, err)
		}
		keys[keyID] = key
	}

	middleware := RequireAPIKey(store)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyID := GetKeyIDFromContext(r.Context())
		if keyID == "" {
			t.Error("expected keyID in context, got empty string")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	// Run concurrent requests
	done := make(chan bool)
	for keyID, key := range keys {
		go func(kid, k string) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+k)
			rr := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("key %s: expected status 200, got %d", kid, rr.Code)
			}
			done <- true
		}(keyID, key)
	}

	// Wait for all requests
	for i := 0; i < len(keys); i++ {
		<-done
	}
}
