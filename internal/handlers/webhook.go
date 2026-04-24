package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WebhookConfigStore manages webhook configurations in memory.
//
// IMPORTANT: Webhook configs are stored in-memory, keyed by API key ID.
// Configs are LOST ON SERVER RESTART. Integrators must re-POST webhook
// configuration after server reboot. This is intentional per D1 (stateless
// server design — no database).
type WebhookConfigStore struct {
	mu      sync.RWMutex
	configs map[string]*WebhookConfig // Key: API key ID
}

// WebhookConfig represents a stored webhook configuration
type WebhookConfig struct {
	WebhookID string
	URL       string
	Events    []string
	Secret    string
	CreatedAt time.Time
}

var (
	webhookStore     *WebhookConfigStore
	webhookStoreOnce sync.Once
)

// getWebhookStore returns the singleton webhook config store
func getWebhookStore() *WebhookConfigStore {
	webhookStoreOnce.Do(func() {
		webhookStore = &WebhookConfigStore{
			configs: make(map[string]*WebhookConfig),
		}
	})
	return webhookStore
}

// WebhookConfigRequest matches OpenAPI WebhookConfig schema
type WebhookConfigRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"`
}

// WebhookCreatedResponse matches OpenAPI WebhookCreated schema
type WebhookCreatedResponse struct {
	WebhookID string   `json:"webhook_id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	CreatedAt string   `json:"created_at"`
}

// Valid webhook event types per OpenAPI spec
var validEvents = map[string]bool{
	"challenge.verified":  true,
	"challenge.rejected":  true,
	"challenge.expired":   true,
	"decrypt.completed":   true,
	"decrypt.rejected":    true,
	"decrypt.expired":     true,
	"mpa.approved":        true,
	"mpa.rejected":        true,
	"mpa.timeout":         true,
}

// ConfigureWebhook handles POST /v1/config/webhooks
//
// Stores webhook configuration in memory, keyed by API key ID.
// Configuration is LOST ON SERVER RESTART — integrators must re-POST
// after reboot. This is intentional per D1 (stateless server).
//
// Per OpenAPI spec:
// - url: required, must be valid URI
// - events: required, array of valid event types
// - secret: optional, HMAC secret for signature verification
func (h *Handler) ConfigureWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WebhookConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON")
		return
	}

	// Validate required fields
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "URL is required")
		return
	}

	if len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Events array cannot be empty")
		return
	}

	// Validate URL format
	parsedURL, err := url.Parse(req.URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "URL must be a valid URI with scheme and host")
		return
	}

	// Validate events
	for _, event := range req.Events {
		if !validEvents[event] {
			writeError(w, http.StatusBadRequest, "INVALID_EVENT", "Event type not recognized: "+event)
			return
		}
	}

	// Extract API key from Authorization header
	// Format: "Bearer <api-key>"
	apiKey := extractAPIKey(r)
	if apiKey == "" {
		apiKey = "default" // Fallback for tests without auth
	}

	// Store webhook config (overwrites existing config for this API key)
	webhookID := "whk_" + uuid.New().String()
	config := &WebhookConfig{
		WebhookID: webhookID,
		URL:       req.URL,
		Events:    req.Events,
		Secret:    req.Secret,
		CreatedAt: time.Now(),
	}

	store := getWebhookStore()
	store.mu.Lock()
	store.configs[apiKey] = config
	store.mu.Unlock()

	// Return response
	resp := WebhookCreatedResponse{
		WebhookID: webhookID,
		URL:       config.URL,
		Events:    config.Events,
		CreatedAt: config.CreatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// extractAPIKey extracts the API key from Authorization header
func extractAPIKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// GetWebhookConfig retrieves webhook config for an API key (internal use)
func (h *Handler) GetWebhookConfig(apiKey string) *WebhookConfig {
	store := getWebhookStore()
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.configs[apiKey]
}
