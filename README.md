# Sigil Auth Server

> Stateless Go crypto engine for hardware-backed PKI authentication

**Status:** Scaffolding complete, awaiting OpenAPI spec (B0)  
**Version:** Pre-MVP  
**License:** AGPL-3.0

---

## What This Is

Sigil Auth Server is the core stateless service that:
- Generates cryptographic challenges
- Verifies device signatures using ECDSA P-256
- Orchestrates multi-party authorization (MPA)
- Delivers push notifications via relay service
- Sends webhooks to integrator applications

**Key principles:**
- **Stateless** — No database, ephemeral in-memory sessions only
- **Hardware-backed** — Devices use Secure Enclave/StrongBox/TPM
- **TLS-secured** — Challenges sent plaintext over TLS (D2), not ECIES-encrypted
- **Mnemonic-derived** — Server keypair derived from BIP39 mnemonic

---

## Quick Start

**Prerequisites:**
- Go 1.22+ (for `log/slog`)
- OpenAPI spec from B0 (not yet available)

**Install dependencies:**
```bash
go mod download
go mod verify
```

**Run tests (when implemented):**
```bash
go test -race -cover ./...
```

**Build (when ready):**
```bash
go build -o bin/sigil ./cmd/sigil
```

**Run (when ready):**
```bash
export SIGIL_MNEMONIC_PATH=/path/to/mnemonic.txt
export RELAY_URL=http://relay:8080
./bin/sigil
```

---

## Project Structure

See [STRUCTURE.md](./STRUCTURE.md) for full package layout and responsibilities.

**Key directories:**
- `cmd/sigil/` — Application entrypoint
- `internal/` — Private packages (crypto, session, MPA, webhook, relay, telemetry)
- `api/gen/` — OpenAPI-generated types (awaiting B0)
- `api/handlers/` — HTTP handlers (awaiting B0)
- `pkg/pictogram/` — Public library for pictogram derivation
- `test/` — Test fixtures and harness

---

## Dependencies

See [DEPENDENCIES.md](./DEPENDENCIES.md) for full dependency list and rationale.

**Core dependencies:**
- Standard library crypto (`crypto/ecdsa`, `crypto/aes`, etc.)
- `golang.org/x/crypto` for HKDF and bcrypt
- `github.com/tyler-smith/go-bip39` and `go-bip32` for mnemonic handling
- `filippo.io/nistec` for constant-time P-256 operations
- `github.com/prometheus/client_golang` for metrics

---

## Security

This service implements the security requirements from Knox's threat model.

**Top 5 non-negotiable:**
1. Hardware key extraction infeasible (client responsibility)
2. Biometric gate on every sign (client responsibility)
3. Device self-authentication (server verifies fingerprint from public key)
4. Plaintext challenges over TLS (D2 — no ECIES for challenge wire)
5. Stateless server (no database, ephemeral sessions only)

See [working/go/security-boundaries.md](../working/go/security-boundaries.md) for package-level security requirements.

**Vulnerability reporting:** `security@sigilauth.com`

---

## Testing

**Test-driven development (TDD) is mandatory.**

Every new file must have a corresponding test file committed first (or in the same commit). CI enforces this via TDD audit script.

**Coverage targets:**
- Overall: 90% line, 85% branch
- Crypto packages: 95% line, 90% branch

**Run tests:**
```bash
# Unit tests
go test ./...

# With race detector
go test -race ./...

# With coverage
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Property-based tests (when implemented)
go test -tags=property ./internal/crypto/...
```

---

## Development Workflow

**Current phase:** Scaffolding complete, awaiting B0 (OpenAPI spec)

**Next steps:**
1. @echo ships OpenAPI spec (B0)
2. Generate types: `oapi-codegen -config api/gen/config.yaml api/openapi.yaml > api/gen/types.go`
3. Implement packages in dependency order (see STRUCTURE.md)
4. TDD every package (test first)
5. Achieve coverage targets
6. Pass Knox security checklist

**Do NOT write production code until B0 is available.**

---

## Configuration

Environment variables:

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `SIGIL_PORT` | No | 8443 | HTTPS port |
| `SIGIL_HTTP_PORT` | No | - | HTTP port (edge proxy mode, disables HTTPS) |
| `SIGIL_MNEMONIC_PATH` | Yes (operational) | - | Path to BIP39 mnemonic file |
| `RELAY_URL` | Yes | - | Push relay service URL |
| `WEBHOOK_URL` | No | - | Default integrator webhook URL |
| `SIGIL_TELEMETRY` | No | `full` | Telemetry level: `none`, `metrics`, `full` |
| `SIGIL_TLS_CERT` | No | - | TLS certificate path (or self-signed) |
| `SIGIL_TLS_KEY` | No | - | TLS private key path |
| `SIGIL_MODE` | No | `operational` | Mode: `init` or `operational` |
| **OpenTelemetry (optional)** ||||
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | OTLP endpoint (e.g., `localhost:4317` for gRPC, `http://localhost:4318` for HTTP) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | No | `grpc` | OTLP protocol: `grpc` or `http/protobuf` |
| `OTEL_SERVICE_NAME` | No | `sigil-auth-server` | Service name in traces |
| `OTEL_RESOURCE_ATTRIBUTES` | No | - | Comma-separated key=value resource attributes |

### OpenTelemetry Examples

**Send traces to local OTel collector (gRPC):**
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_SERVICE_NAME=sigil-auth-primary
./sigil
```

**Send traces to Jaeger (HTTP):**
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_SERVICE_NAME=sigil-auth
./sigil
```

**Send traces to Tempo via OTLP gRPC:**
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=tempo:4317
export OTEL_SERVICE_NAME=sigil-server
./sigil
```

**Disable tracing (no endpoint set):**
```bash
unset OTEL_EXPORTER_OTLP_ENDPOINT
./sigil  # Logs "OTEL_EXPORTER_OTLP_ENDPOINT not set, tracing disabled"
```

---

## Architecture Decisions

| Decision | Reference | Summary |
|----------|-----------|---------|
| D1 | DECISIONS.md | Server language is Go |
| D2 | DECISIONS.md | Challenge wire format is plaintext over TLS (NOT ECIES) |
| D5 | DECISIONS.md | TDD required across all components |

See `/Volumes/Expansion/src/sigilauth/working/DECISIONS.md` for full decision log.

---

## Contributing

This is an open-source project under AGPL-3.0.

**Before contributing:**
1. Read [engineering-principles.md](~/.claude/instructions/engineering-principles.md)
2. Read [code-quality.md](~/.claude/instructions/code-quality.md)
3. Read Knox threat model: `working/specs/knox-threat-model.md`
4. Understand TDD requirement (D5)

**Pull requests must:**
- Pass all tests (`go test -race ./...`)
- Meet coverage thresholds (90/85)
- Pass TDD audit (test-first commit order)
- Pass security scan (`govulncheck`)

---

## Documentation

- [STRUCTURE.md](./STRUCTURE.md) — Package layout and responsibilities
- [DEPENDENCIES.md](./DEPENDENCIES.md) — Dependency list and rationale
- [working/go/patterns.md](../working/go/patterns.md) — Approved Go patterns
- [working/go/security-boundaries.md](../working/go/security-boundaries.md) — Security requirements per package
- [working/specs/knox-threat-model.md](../working/specs/knox-threat-model.md) — Full threat model
- [working/specs/taron-service-architecture.md](../working/specs/taron-service-architecture.md) — Service architecture
- [working/specs/beacon-prd.md](../working/specs/beacon-prd.md) — Product requirements

---

## Status

**Current:** Scaffolding phase  
**Blocked by:** B0 (OpenAPI spec from @echo)  
**Owner:** @kai  
**Next milestone:** OpenAPI types generated, crypto package implemented

---

## License

AGPL-3.0 — See [LICENSE](../LICENSE) for details.

API specifications (OpenAPI) are Apache-2.0 to enable compatible implementations without copyleft obligations.
