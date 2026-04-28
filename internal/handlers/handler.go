package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"sync"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/initrequest"
	"github.com/sigilauth/server/internal/mpa"
	"github.com/sigilauth/server/internal/relay"
	"github.com/sigilauth/server/internal/session"
	"github.com/sigilauth/server/internal/telemetry"
	"github.com/sigilauth/server/internal/webhook"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	sessionStore     *session.Store
	mpaStore         *mpa.Store
	initRequestStore *initrequest.Store
	telemetry        *telemetry.Telemetry
	serverKey        *ecdsa.PrivateKey
	serverID         string         // server identifier for push payloads
	serverPubkey     string         // base64 compressed server public key
	baseURL          string         // base URL for QR codes (e.g., "https://auth.example.com")
	relayClient      *relay.Client // optional: push notification dispatch

	// SIG-2026-014: Concurrent long-poll connection limiter (per-key)
	pollCountMu sync.RWMutex
	pollCounts  map[string]int // apikey -> active poll count

	// SIG-2026-021: Global long-poll connection limiter (cross-key)
	globalPollMu    sync.Mutex
	globalPollCount int // total active polls across all keys
}

// New creates a new handler instance
func New(sessionStore *session.Store, tel *telemetry.Telemetry, serverKey *ecdsa.PrivateKey) *Handler {
	// Compute server public key for push payloads
	compressedPubkey := crypto.CompressPublicKey(&serverKey.PublicKey)
	serverPubkeyB64 := base64.StdEncoding.EncodeToString(compressedPubkey)

	return &Handler{
		sessionStore:     sessionStore,
		mpaStore:         mpa.NewStore(),
		initRequestStore: initrequest.NewStore(),
		telemetry:        tel,
		serverKey:        serverKey,
		serverPubkey:     serverPubkeyB64,
		pollCounts:       make(map[string]int),
	}
}

// SetRelayClient configures the relay client for push notification dispatch.
//
// relayBaseURL: relay service base URL (e.g., "https://relay.sigilauth.com")
// serverID: unique identifier for this server instance
func (h *Handler) SetRelayClient(relayBaseURL, serverID string) {
	h.serverID = serverID
	h.relayClient = relay.NewClient(relayBaseURL, serverID, h.serverKey)
}

// SetBaseURL configures the base URL for QR code generation.
//
// baseURL: service base URL (e.g., "https://auth.example.com")
func (h *Handler) SetBaseURL(baseURL string) {
	h.baseURL = baseURL
}

// PollSlotStatus indicates the result of trying to acquire a poll slot.
type PollSlotStatus int

const (
	PollSlotAcquired PollSlotStatus = iota
	PollSlotPerKeyLimitReached
	PollSlotGlobalLimitReached
)

// tryAcquirePollSlot attempts to acquire a concurrent poll slot for the given API key.
//
// SIG-2026-014: Limits concurrent long-poll connections per API key to prevent DoS.
// SIG-2026-021: Limits global concurrent long-poll connections across all API keys.
// Returns PollSlotAcquired if successful, or the specific limit that was reached.
const (
	maxConcurrentPollsPerKey = 10
	maxGlobalConcurrentPolls = 1000
)

func (h *Handler) tryAcquirePollSlot(keyID string) PollSlotStatus {
	// SIG-2026-021: Check global limit first
	h.globalPollMu.Lock()
	if h.globalPollCount >= maxGlobalConcurrentPolls {
		h.globalPollMu.Unlock()
		return PollSlotGlobalLimitReached
	}
	h.globalPollCount++
	h.globalPollMu.Unlock()

	// SIG-2026-014: Check per-key limit
	h.pollCountMu.Lock()
	if h.pollCounts[keyID] >= maxConcurrentPollsPerKey {
		// Exceeded per-key limit - release global slot and reject
		h.pollCountMu.Unlock()
		h.globalPollMu.Lock()
		h.globalPollCount--
		h.globalPollMu.Unlock()
		return PollSlotPerKeyLimitReached
	}
	h.pollCounts[keyID]++
	h.pollCountMu.Unlock()

	return PollSlotAcquired
}

// releasePollSlot releases a concurrent poll slot for the given API key.
//
// SIG-2026-014 + SIG-2026-021: Decrements both per-key and global counters.
func (h *Handler) releasePollSlot(keyID string) {
	// SIG-2026-014: Release per-key slot
	h.pollCountMu.Lock()
	if h.pollCounts[keyID] > 0 {
		h.pollCounts[keyID]--
	}
	if h.pollCounts[keyID] == 0 {
		delete(h.pollCounts, keyID) // Clean up zero entries
	}
	h.pollCountMu.Unlock()

	// SIG-2026-021: Release global slot
	h.globalPollMu.Lock()
	if h.globalPollCount > 0 {
		h.globalPollCount--
	}
	h.globalPollMu.Unlock()
}

// dispatchPushNotification dispatches push notification to a device via relay.
//
// Does NOT block the response. Spawns goroutine, logs delivery failures.
// If relay client not configured, silently skips (push notifications are optional).
func (h *Handler) dispatchPushNotification(fingerprint string, payload map[string]interface{}) {
	if h.relayClient == nil {
		// Relay not configured - skip push (not an error, just means push disabled)
		return
	}

	// Deliver asynchronously (don't block response)
	go func() {
		ctx := context.Background()
		if err := h.relayClient.Push(ctx, fingerprint, payload); err != nil {
			log.Printf("Push notification failed for fingerprint %s: %v", fingerprint, err)
		} else {
			log.Printf("Push notification dispatched to fingerprint %s", fingerprint)
		}
	}()
}

// deliverWebhook delivers webhook asynchronously if configured for the given event.
//
// Does NOT block the response. Spawns goroutine, logs delivery failures.
// Per Knox §7.4: HMAC-SHA256 signature, 3 retries with backoff, SSRF protection.
func (h *Handler) deliverWebhook(keyID string, eventType string, payload interface{}) {
	config := h.GetWebhookConfig(keyID)
	if config == nil {
		return // No webhook configured
	}

	// Check if config subscribes to this event
	subscribed := false
	for _, event := range config.Events {
		if event == eventType {
			subscribed = true
			break
		}
	}
	if !subscribed {
		return // Not subscribed to this event
	}

	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload for %s: %v", eventType, err)
		return
	}

	// Deliver asynchronously (don't block response)
	go func() {
		ctx := context.Background()
		client := webhook.NewClient(config.Secret)
		err := client.Deliver(ctx, config.URL, jsonPayload)
		if err != nil {
			log.Printf("Webhook delivery failed for %s to %s: %v", eventType, config.URL, err)
		} else {
			log.Printf("Webhook delivered: %s to %s", eventType, config.URL)
		}
	}()
}
