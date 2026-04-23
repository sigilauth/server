# Sigil Server Dependencies

> Locked dependencies and rationale for stateless crypto engine

**Last Updated:** 2026-04-23  
**Go Version:** 1.22+ (for `log/slog`)

---

## Production Dependencies

| Package | Version | Purpose | Justification |
|---------|---------|---------|---------------|
| **Standard Library** | | | |
| `crypto/ecdsa` | stdlib | P-256 signing/verification | Core crypto primitive |
| `crypto/rand` | stdlib | CSPRNG for challenges, ephemeral keys | Hardware RNG on supported platforms |
| `crypto/sha256` | stdlib | Hashing for signatures, fingerprints | Required by ECDSA |
| `crypto/aes` | stdlib | AES-256-GCM for ECIES | Specified in Knox threat model §3.1 |
| `crypto/cipher` | stdlib | GCM mode | Part of ECIES implementation |
| `log/slog` | stdlib (Go 1.21+) | Structured JSON logging | Zero-dependency logging |
| `net/http` | stdlib | HTTP server | No external framework needed |
| `encoding/json` | stdlib | JSON encoding | API responses |
| `encoding/base64` | stdlib | Wire format for keys/signatures | Compact representation |
| `encoding/hex` | stdlib | Fingerprint display | Human-readable hashes |
| **External (Crypto)** | | | |
| `golang.org/x/crypto/hkdf` | latest | HKDF-SHA256 key derivation | Specified in Knox §3.1 |
| `github.com/tyler-smith/go-bip39` | latest | BIP39 mnemonic ↔ entropy | Standard BIP39 implementation |
| `github.com/tyler-smith/go-bip32` | latest | BIP32 HD wallet derivation | Mnemonic → server keypair |
| `filippo.io/nistec` | latest | Constant-time P-256 ops | Timing-attack resistant |
| **External (Infra)** | | | |
| `github.com/prometheus/client_golang` | latest | Metrics exposition | `/metrics` endpoint |
| `golang.org/x/time/rate` | latest | Rate limiting | In-memory sliding window |
| `golang.org/x/crypto/bcrypt` | latest | API key hashing | Cost 12 per Knox spec |

---

## Development/Testing Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/stretchr/testify` | Assertions in tests |
| `github.com/leanovate/gopter` | Property-based testing for crypto |
| `github.com/testcontainers/testcontainers-go` | Integration tests (future) |

---

## Explicitly NOT Using

| Package | Why Not |
|---------|---------|
| `gorilla/mux` | stdlib `http.ServeMux` sufficient for MVP |
| `gin-gonic/gin` | No framework needed, stdlib + OpenAPI types |
| `gorm` | No database |
| `redis` | Stateless, no external state |
| `filippo.io/age` | Initially mentioned, but not needed — using stdlib crypto directly |
| `ecies` libraries | Implementing ECIES from primitives per Knox spec |

---

## Rationale: Minimal Dependencies

**Why minimal?**
1. **Security:** Smaller attack surface, fewer supply chain risks
2. **Auditability:** Less code to review for external audit
3. **Stability:** stdlib is stable, no breaking changes
4. **Performance:** No framework overhead
5. **Simplicity:** Stateless service needs little abstraction

**When to add:**
- Crypto: Only if stdlib lacks primitive (e.g., BIP39)
- Infra: Only if reimplementing is error-prone (e.g., Prometheus wire format)
- Dev: Only if speeds up testing meaningfully

---

## Dependency Update Policy

- **Crypto libraries:** Pin to specific versions, update only after review
- **Stdlib:** Use latest stable Go version (currently 1.22)
- **Infrastructure:** Update monthly, test with `go test -race ./...`
- **Vulnerability scanning:** `govulncheck` in CI on every PR

---

## License Compliance

All dependencies are permissively licensed:
- BSD-3-Clause: `filippo.io/nistec`, `golang.org/x/*`
- MIT: `go-bip39`, `go-bip32`, `testify`
- Apache-2.0: `prometheus/client_golang`

**AGPL-3.0 applies to Sigil server code only, not dependencies.**

---

## Installation

```bash
go get golang.org/x/crypto/hkdf
go get golang.org/x/crypto/bcrypt
go get golang.org/x/time/rate
go get github.com/tyler-smith/go-bip39
go get github.com/tyler-smith/go-bip32
go get filippo.io/nistec
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promhttp

# Dev dependencies
go get github.com/stretchr/testify
go get github.com/leanovate/gopter
```

Then:
```bash
go mod tidy
go mod verify
```
