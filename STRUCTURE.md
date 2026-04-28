# Sigil Server Structure

> Idiomatic Go layout for stateless crypto engine

**Last Updated:** 2026-04-23  
**Module:** `github.com/sigilauth/server`

---

## Directory Layout

```
server/
├── cmd/
│   └── sigil/              # Main application entrypoint
│       └── main.go         # Bootstraps server, loads config, starts HTTP
│
├── internal/               # Private application code (not importable)
│   ├── crypto/             # ECDSA, HKDF, signature verification, ECIES
│   │   ├── ecdsa.go        # P-256 signing/verification, low-S normalization
│   │   ├── hkdf.go         # Key derivation for ECIES
│   │   ├── ecies.go        # Encryption for secure-decrypt + mnemonic
│   │   └── bip.go          # BIP39 mnemonic + BIP32 derivation
│   │
│   ├── session/            # Ephemeral challenge session management
│   │   ├── store.go        # sync.Map-based in-memory store
│   │   ├── challenge.go    # Challenge lifecycle (create, verify, expire)
│   │   └── expiry.go       # Background goroutine for TTL cleanup
│   │
│   ├── mpa/                # Multi-party authorization orchestration
│   │   ├── request.go      # MPA session creation
│   │   ├── group.go        # Group satisfaction tracking
│   │   ├── quorum.go       # Quorum logic + clear notifications
│   │   └── store.go        # Ephemeral MPA state
│   │
│   ├── webhook/            # Webhook delivery to integrator
│   │   ├── client.go       # HTTP client with retries + circuit breaker
│   │   ├── hmac.go         # HMAC-SHA256 signature generation
│   │   └── ssrf.go         # IP blocklist for SSRF protection
│   │
│   ├── relay/              # Push relay client
│   │   ├── client.go       # HTTP client for /push endpoint
│   │   └── signature.go    # Server signature for relay auth
│   │
│   ├── telemetry/          # Observability (logs + metrics)
│   │   ├── logger.go       # Structured JSON logging (slog)
│   │   ├── metrics.go      # Prometheus counters + histograms
│   │   └── trace.go        # OTel span helpers
│   │
│   └── config/             # Configuration management
│       ├── config.go       # Env var parsing
│       └── validate.go     # Config validation rules
│
├── api/
│   ├── gen/                # OpenAPI-generated types (from B0)
│   │   └── (oapi-codegen output)
│   │
│   └── handlers/           # HTTP handlers (after OpenAPI available)
│       ├── challenge.go    # POST /challenge, GET /challenge/{id}/status
│       ├── respond.go      # POST /respond
│       ├── mpa.go          # POST /mpa/request, GET /mpa/{id}/status
│       ├── decrypt.go      # POST /v1/secure/decrypt
│       ├── info.go         # GET /info
│       └── middleware.go   # Auth, rate limiting, telemetry
│
├── pkg/                    # Public libraries (importable by other projects)
│   └── pictogram/          # Pictogram derivation (deterministic from fp)
│       ├── pictogram.go    # Core logic
│       ├── wordlist.go     # 64-emoji canonical list
│       └── speakable.go    # Emoji → speakable name mapping
│
├── test/
│   ├── fixtures/           # Test vectors (keys, mnemonics, signatures)
│   │   ├── keys/
│   │   ├── mnemonics/
│   │   ├── signatures/
│   │   └── pictograms/
│   │
│   └── harness/            # E2E test harness (simulates devices)
│       └── device.go       # Simulated device with P-256 keypair
│
├── go.mod
├── go.sum
├── Dockerfile
└── README.md
```

---

## Package Responsibilities

### cmd/sigil
- **Single concern:** Bootstrap and run the server
- Loads config, initializes dependencies, starts HTTP listener
- No business logic

### internal/crypto
- **Owns:** All cryptographic primitives
- ECDSA P-256 signing/verification with low-S normalization
- HKDF key derivation
- ECIES encryption (ONLY for secure-decrypt + mnemonic delivery per D2)
- BIP39 mnemonic ↔ entropy conversion
- BIP32 hierarchical key derivation
- **Does NOT own:** Challenge lifecycle (that's session/)

### internal/session
- **Owns:** Ephemeral challenge state
- In-memory sync.Map storage (5-min TTL)
- Challenge creation, verification, expiry
- Background cleanup goroutine
- **Does NOT own:** HTTP handlers (that's api/handlers/)

### internal/mpa
- **Owns:** Multi-party authorization state
- Group satisfaction tracking
- Quorum detection
- Clear notification logic
- **Does NOT own:** Push delivery (that's relay/)

### internal/webhook
- **Owns:** Integrator callback delivery
- HTTP POST with HMAC-SHA256 signature
- Retry policy (1s, 5s, 30s)
- Circuit breaker on repeated failures
- SSRF protection (IP blocklist)

### internal/relay
- **Owns:** Communication with push relay service
- POST /push with server signature
- Timeout (3s)
- **Does NOT own:** APNs/FCM logic (that's relay service, different repo)

### internal/telemetry
- **Owns:** Observability
- Structured JSON logs to stdout
- Prometheus metrics registration
- OTel span creation helpers
- Respects `SIGIL_TELEMETRY` env var

### internal/config
- **Owns:** Environment variable parsing
- Validation (required fields, URL formats, port ranges)
- **Does NOT own:** Secret management (mnemonic loaded separately)

### api/gen
- **Owns:** OpenAPI-generated types and client stubs
- Generated by `oapi-codegen` from B0 spec
- **Do NOT hand-edit** — regenerate on spec changes

### api/handlers
- **Owns:** HTTP request/response handling
- Parses requests, calls internal services, formats responses
- Middleware (auth, rate limiting, logging)
- **Does NOT own:** Business logic (delegates to internal/)

### pkg/pictogram
- **Public library** — importable by devices, SDKs, integrators
- Deterministic pictogram derivation from fingerprint
- 64-emoji canonical list
- Speakable name mapping
- **Must remain stable** — breaking changes require major version bump

---

## Dependency Principles

1. **cmd/ depends on everything** — wires up the application
2. **internal/ packages do NOT import each other circularly**
   - crypto is leaf (no internal imports)
   - session imports crypto
   - mpa imports crypto + session
   - handlers import all internal packages
3. **pkg/ is isolated** — no internal/ imports
4. **test/ can import anything** for testing

---

## File Naming Conventions

- `*_test.go` — Unit tests (same package)
- `*_integration_test.go` — Integration tests
- `*_gen.go` — Generated code (do not edit)
- `doc.go` — Package documentation

---

## Next Steps (Awaiting B0)

Once OpenAPI spec is available:
1. Generate types into `api/gen/` via `oapi-codegen`
2. Implement handlers in `api/handlers/` using generated types
3. Wire up routes in `cmd/sigil/main.go`
4. Write tests for each internal package (TDD)

---

## Design Notes

- **Stateless by design:** No database imports anywhere
- **Context propagation:** Every exported function takes `context.Context` as first param
- **Error wrapping:** Use `fmt.Errorf(...: %w, err)` for stack traces
- **No global state:** All state passed via struct receivers or function params
- **Telemetry optional:** Check `cfg.TelemetryLevel` before logging/metering
