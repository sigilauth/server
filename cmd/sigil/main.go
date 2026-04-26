package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sigilauth/server/internal/apikey"
	"github.com/sigilauth/server/internal/handlers"
	"github.com/sigilauth/server/internal/initwizard"
	"github.com/sigilauth/server/internal/pair"
	"github.com/sigilauth/server/internal/pictogram"
	"github.com/sigilauth/server/internal/ratelimit"
	"github.com/sigilauth/server/internal/session"
	"github.com/sigilauth/server/internal/telemetry"
)

const version = "0.1.0"

func main() {
	// Force output immediately
	fmt.Fprintln(os.Stderr, "=== MAIN() CALLED ===")
	fmt.Fprintln(os.Stdout, "=== STDOUT TEST ===")
	os.Stderr.Sync()
	os.Stdout.Sync()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("=== SIGIL SERVER STARTING ===")

	ctx := context.Background()

	// Initialize telemetry
	log.Println("Initializing telemetry...")
	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-auth-server",
		Enabled:     true,
	})
	log.Println("Telemetry initialized")

	log.Printf("Sigil Auth Server v%s starting...", version)

	// Check if server is initialized
	identityPath := getEnv("SIGIL_IDENTITY_FILE", "/data/server-identity.json")
	log.Printf("Identity path: %s", identityPath)

	log.Println("Loading or initializing server identity...")
	identity, err := loadOrInitialize(identityPath)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	log.Println("Identity loaded successfully")

	log.Printf("Server ID: %s", identity.ServerID)
	log.Printf("Pictogram: %s", identity.PictogramSpeakable)

	// Load pictogram pool for session pictogram derivation
	pictogramPoolPath := getEnv("SIGIL_PICTOGRAM_POOL", "/data/pictogram-pool-v1.json")
	log.Printf("Loading pictogram pool from: %s", pictogramPoolPath)
	if err := pictogram.LoadPool(pictogramPoolPath); err != nil {
		log.Printf("Warning: failed to load pictogram pool: %v", err)
		log.Println("Attempting fallback to api/pictogram-pool-v1.json...")
		if err := pictogram.LoadPool("api/pictogram-pool-v1.json"); err != nil {
			log.Fatalf("Failed to load pictogram pool: %v", err)
		}
	}
	log.Println("Pictogram pool loaded successfully")

	// Load API keys (fail-closed: if no keys loaded, exit)
	apiKeyStore := loadAPIKeys()
	log.Printf("Loaded %d API key(s)", len(apiKeyStore.ListKeys(ctx)))

	// Create rate limiter
	rateLimiter := ratelimit.NewLimiter()

	// Create session store
	sessionStore := session.NewStore()

	// Create pair store for handshake state
	pairStore := pair.NewStore()

	// Create handlers
	h := handlers.New(sessionStore, tel, identity.PrivateKey)
	pairHandler := handlers.NewPairHandler(pairStore, identity.PrivateKey, identity.ServerID)
	envelopeHandler := handlers.NewEnvelopeHandler(identity.PrivateKey)

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version,
		})
	})

	// Pair endpoints (plaintext JSON, no auth required per spec)
	mux.HandleFunc("/pair/init", pairHandler.Init)
	mux.HandleFunc("/pair/complete", pairHandler.Complete)

	// Envelope endpoint (post-pair encrypted communication)
	mux.HandleFunc("/envelope", envelopeHandler.Handle)

	// Info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server_id":                  identity.ServerID,
			"server_public_key":          identity.PublicKey,
			"server_pictogram":           identity.Pictogram,
			"server_pictogram_speakable": identity.PictogramSpeakable,
			"version":                    version,
			"mode":                       "operational",
			"features": map[string]bool{
				"mpa":                 true,
				"secure_decrypt":      true,
				"mnemonic_generation": true,
				"webhooks":            true,
			},
		})
	})

	// Challenge endpoints (protected with auth + rate limiting)
	requireAuth := apikey.RequireAPIKey(apiKeyStore)

	challengeRL := ratelimit.RateLimit(rateLimiter, "/challenge")
	mux.Handle("/challenge", requireAuth(challengeRL(http.HandlerFunc(h.CreateChallenge))))

	respondRL := ratelimit.RateLimit(rateLimiter, "/respond")
	mux.Handle("/respond", requireAuth(respondRL(http.HandlerFunc(h.Respond))))

	challengeStatusRL := ratelimit.RateLimit(rateLimiter, "/v1/auth/challenge/:id/status")
	mux.Handle("/v1/auth/challenge/", requireAuth(challengeStatusRL(http.HandlerFunc(h.GetChallengeStatus))))

	// MPA endpoints (protected with auth + rate limiting)
	mpaRequestRL := ratelimit.RateLimit(rateLimiter, "/mpa/request")
	mux.Handle("/mpa/request", requireAuth(mpaRequestRL(http.HandlerFunc(h.CreateMPARequest))))

	mpaRespondRL := ratelimit.RateLimit(rateLimiter, "/mpa/respond")
	mux.Handle("/mpa/respond", requireAuth(mpaRespondRL(http.HandlerFunc(h.RespondMPA))))

	mpaStatusRL := ratelimit.RateLimit(rateLimiter, "/mpa/status/:id")
	mux.Handle("/mpa/status/", requireAuth(mpaStatusRL(http.HandlerFunc(h.GetMPAStatus))))

	// Secure decrypt endpoints (protected with auth + rate limiting)
	secureDecryptRL := ratelimit.RateLimit(rateLimiter, "/v1/secure/decrypt")
	mux.Handle("/v1/secure/decrypt", requireAuth(secureDecryptRL(http.HandlerFunc(h.SecureDecrypt))))

	decryptStatusRL := ratelimit.RateLimit(rateLimiter, "/v1/secure/decrypt/:id/status")
	mux.Handle("/v1/secure/decrypt/", requireAuth(decryptStatusRL(http.HandlerFunc(h.GetDecryptStatus))))

	// Webhook configuration (protected with auth + rate limiting)
	webhookRL := ratelimit.RateLimit(rateLimiter, "/v1/config/webhooks")
	mux.Handle("/v1/config/webhooks", requireAuth(webhookRL(http.HandlerFunc(h.ConfigureWebhook))))

	// Metrics endpoint
	mux.Handle("/metrics", tel.MetricsHandler())

	// Start periodic cleanup
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			removed := sessionStore.CleanExpired(ctx)
			if removed > 0 {
				log.Printf("Cleaned %d expired challenges", removed)
			}
		}
	}()

	httpPort := os.Getenv("SIGIL_HTTP_PORT")
	if httpPort != "" {
		srv := &http.Server{
			Addr:         ":" + httpPort,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan

			log.Println("Shutting down gracefully...")

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := tel.Shutdown(shutdownCtx); err != nil {
				log.Printf("Telemetry shutdown error: %v", err)
			}

			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Printf("Shutdown error: %v", err)
			}
		}()

		log.Printf("Server listening on http://localhost%s (plain HTTP mode for edge proxy deployment)", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}

		log.Println("Server stopped")
		return
	}

	certFile := getEnv("SIGIL_TLS_CERT", "/data/server.crt")
	keyFile := getEnv("SIGIL_TLS_KEY", "/data/server.key")

	if err := ensureTLSCertificate(certFile, keyFile); err != nil {
		log.Fatalf("Failed to setup TLS certificate: %v", err)
	}

	port := getEnv("SIGIL_PORT", "8443")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down gracefully...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := tel.Shutdown(shutdownCtx); err != nil {
			log.Printf("Telemetry shutdown error: %v", err)
		}

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	log.Printf("Server listening on https://localhost%s", srv.Addr)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("Server stopped")
}

func loadOrInitialize(identityPath string) (*initwizard.ServerIdentity, error) {
	// Mnemonic is always required (for deriving private key)
	mnemonic := os.Getenv("SIGIL_MNEMONIC")
	if mnemonic == "" {
		return nil, fmt.Errorf("server not initialized: set SIGIL_MNEMONIC environment variable")
	}

	// Derive identity from mnemonic (gets PrivateKey)
	identity, err := initwizard.DeriveServerIdentity(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity: %w", err)
	}

	// Try to load existing identity file for verification
	existingIdentity, err := initwizard.LoadFromFile(identityPath)
	if err == nil {
		// File exists - verify it matches the mnemonic-derived identity
		if existingIdentity.ServerID != identity.ServerID {
			return nil, fmt.Errorf("mismatch: mnemonic derives server ID %s, but file has %s",
				identity.ServerID, existingIdentity.ServerID)
		}
		log.Println("Identity file verified against mnemonic")
	} else {
		// File doesn't exist - save the derived identity
		if err := identity.SaveToFile(identityPath); err != nil {
			log.Printf("Warning: failed to save identity: %v", err)
		} else {
			log.Printf("Identity saved to %s", identityPath)
		}
	}

	return identity, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func ensureTLSCertificate(certFile, keyFile string) error {
	// Check if cert and key already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("Using existing TLS certificate: %s", certFile)
			return nil
		}
	}

	log.Printf("Generating self-signed TLS certificate...")

	// Generate self-signed certificate
	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	log.Printf("Self-signed TLS certificate generated: %s", certFile)
	return nil
}

func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sigil Auth"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write cert
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	// Write key
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// loadAPIKeys loads API keys from environment variables.
//
// Supports two formats:
// 1. SIGIL_API_KEYS: comma-separated keyID=key pairs
//    Example: prod=sgk_live_abc...,staging=sgk_live_def...
// 2. SIGIL_API_KEYS_FILE: path to JSON file with {"keyID": "key"} pairs
//
// Fail-closed: if no keys loaded, logs fatal and exits.
func loadAPIKeys() *apikey.Store {
	// Try inline env var first
	inlineKeys := os.Getenv("SIGIL_API_KEYS")
	if inlineKeys != "" {
		keyMap := make(map[string]string)
		pairs := strings.Split(inlineKeys, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) != 2 {
				log.Printf("Warning: invalid key pair format: %s", pair)
				continue
			}
			keyID := strings.TrimSpace(parts[0])
			key := strings.TrimSpace(parts[1])
			if keyID == "" || key == "" {
				log.Printf("Warning: empty keyID or key in pair: %s", pair)
				continue
			}
			keyMap[keyID] = key
		}

		if len(keyMap) > 0 {
			return apikey.LoadFromMap(keyMap)
		}
	}

	// Try file-based loading
	keyFile := os.Getenv("SIGIL_API_KEYS_FILE")
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Failed to read API keys file %s: %v", keyFile, err)
		}

		var keyMap map[string]string
		if err := json.Unmarshal(data, &keyMap); err != nil {
			log.Fatalf("Failed to parse API keys file %s: %v", keyFile, err)
		}

		if len(keyMap) > 0 {
			return apikey.LoadFromMap(keyMap)
		}
	}

	// Fail-closed: no keys loaded
	log.Fatal("No API keys configured. Set SIGIL_API_KEYS or SIGIL_API_KEYS_FILE environment variable.")
	return nil
}
