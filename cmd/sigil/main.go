package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// Stub binary for B1 - Sigil Auth Server
// This is a minimal implementation to unblock Forge (B11/B14) while full implementation is in progress.
//
// Full implementation will be added as internal packages are completed.

const version = "0.1.0-stub"

type InfoResponse struct {
	ServerID        string            `json:"server_id"`
	ServerName      string            `json:"server_name"`
	Version         string            `json:"version"`
	Mode            string            `json:"mode"`
	Features        map[string]bool   `json:"features"`
}

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
	Uptime  string `json:"uptime"`
}

var startTime = time.Now()

func main() {
	port := getEnv("SIGIL_PORT", "8443")
	mode := getEnv("SIGIL_MODE", "stub")

	mux := http.NewServeMux()

	// Health endpoint (for docker-compose healthchecks)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{
			Status:  "ok",
			Version: version,
			Mode:    mode,
			Uptime:  time.Since(startTime).String(),
		})
	})

	// Info endpoint (no auth required)
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(InfoResponse{
			ServerID:   "sigil-stub-001",
			ServerName: "Sigil Auth Stub",
			Version:    version,
			Mode:       mode,
			Features: map[string]bool{
				"mpa":                 false,
				"secure_decrypt":      false,
				"mnemonic_generation": false,
				"webhooks":            false,
			},
		})
	})

	// Stub endpoints (return 501 Not Implemented)
	stubEndpoints := []string{
		"/challenge",
		"/challenge/",
		"/respond",
		"/mpa/request",
		"/mpa/",
		"/v1/secure/decrypt",
		"/webhooks",
	}

	for _, path := range stubEndpoints {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_IMPLEMENTED",
				"message": "This endpoint is not yet implemented. Stub binary for B11/B14 integration testing.",
			})
		})
	}

	addr := ":" + port
	log.Printf("Sigil Auth Server (STUB) starting on %s", addr)
	log.Printf("Version: %s", version)
	log.Printf("Mode: %s", mode)
	log.Printf("Endpoints: /health, /info (others return 501)")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
