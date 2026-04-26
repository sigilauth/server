# Changelog

All notable changes to Sigil Auth Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-26

### Added

- **Bearer API key validation now enforced on integrator endpoints.** All integrator-facing endpoints (`/challenge`, `/respond`, `/v1/auth/challenge/{id}`, `/mpa/request`, `/mpa/respond`, `/mpa/status/{id}`, `/v1/secure/decrypt`, `/v1/secure/decrypt/{id}`, `/v1/config/webhooks`) now require a valid Bearer API key in the `Authorization` header. Keys use the format `sgk_live_<64-hex>`.

- API key management system with bcrypt hashing (cost 12) and SHA-256 pre-hashing for secure key storage.

- Environment-based key loading via `SIGIL_API_KEYS` (comma-separated `keyID=key` pairs) or `SIGIL_API_KEYS_FILE` (JSON file path).

- Fail-closed behavior: server exits on startup if no API keys are configured and integrator routes are mounted.

- `cmd/keygen` utility for generating API keys in the correct format.

- Comprehensive API key management documentation (`docs/api-keys.md`) covering generation, loading, rotation, revocation, and best practices.

- OpenAPI 3.1.0 security annotations: all integrator endpoints marked with `security: [{bearerAuth: []}]`.

- Integration tests verifying API key enforcement on all protected endpoints (27 test cases).

- Unit tests for middleware with 100% coverage.

- **Per-API-key rate limiting enforced on integrator endpoints (Knox §4).** Token-bucket rate limiting protects auth-critical endpoints: 100 req/15min for `/challenge` and `/respond`, 50 req/15min for `/mpa/*` and `/v1/secure/*`, 1000 req/hour for status endpoints. Rate limits are per-API-key, enforced via middleware chain. Requests exceeding limits receive `429 Too Many Requests` with `Retry-After` header and JSON error body `{"error":"rate_limited","retry_after_seconds":N}`.

### Security

- Integrator endpoints are now protected by default. Unauthenticated requests return `401 Unauthorized` with `{"error":"invalid_api_key"}`.

- API keys are stored as bcrypt hashes in memory (not plaintext).

- Middleware extracts and validates Bearer tokens, attaching verified `keyID` to request context for handler use.

### Changed

- Webhook configuration handler now uses `keyID` from context instead of raw API key for storage keying.

### Fixed

- Test helpers in `internal/crypto/signature_vectors_test.go` and `internal/webhook/ssrf_test.go` no longer fall back to hardcoded absolute paths. Tests now skip gracefully if project root cannot be found by walking up to `go.mod`.

### Notes

- This is the first production-ready release. API key enforcement is the headline security feature.

- Integrators upgrading from pre-0.1.0 builds must generate and configure API keys before deploying this version.

- See `docs/api-keys.md` for operational guidance.

---

## [Unreleased]

Future changes will be documented here.

[0.1.0]: https://github.com/sigilauth/server/releases/tag/v0.1.0
