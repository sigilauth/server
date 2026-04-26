package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"log"

	"github.com/sigilauth/server/internal/mpa"
	"github.com/sigilauth/server/internal/session"
	"github.com/sigilauth/server/internal/telemetry"
	"github.com/sigilauth/server/internal/webhook"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	sessionStore *session.Store
	mpaStore     *mpa.Store
	telemetry    *telemetry.Telemetry
	serverKey    *ecdsa.PrivateKey
}

// New creates a new handler instance
func New(sessionStore *session.Store, tel *telemetry.Telemetry, serverKey *ecdsa.PrivateKey) *Handler {
	return &Handler{
		sessionStore: sessionStore,
		mpaStore:     mpa.NewStore(),
		telemetry:    tel,
		serverKey:    serverKey,
	}
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
