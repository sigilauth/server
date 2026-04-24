package handlers

import (
	"crypto/ecdsa"

	"github.com/sigilauth/server/internal/mpa"
	"github.com/sigilauth/server/internal/session"
	"github.com/sigilauth/server/internal/telemetry"
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
