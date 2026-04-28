# API Key Management

Sigil Auth Server uses Bearer API keys to authenticate integrator requests. This guide covers key generation, loading, rotation, and revocation.

## Key Format

All Sigil API keys use the format:

```
sgk_live_<64-hex-chars>
```

Example: `sgk_live_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`

Keys are stored as bcrypt hashes (cost 12) with SHA-256 pre-hashing. Plaintext keys are shown **only once** at generation.

---

## Generating Keys

### Using the keygen utility

The simplest way to generate a new API key:

```bash
go run cmd/keygen/main.go production
```

Output:
```
production=sgk_live_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

API key generated for ID: production
Format for SIGIL_API_KEYS: production=sgk_live_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

WARNING: This key is shown only once. Save it now.
```

### Programmatically

```go
import "github.com/sigilauth/server/internal/apikey"

key := apikey.Generate()
fmt.Println(key) // sgk_live_...
```

---

## Loading Keys

Sigil Auth Server supports two methods for loading API keys at startup.

### Method 1: Inline environment variable

Use `SIGIL_API_KEYS` for comma-separated `keyID=key` pairs:

```bash
export SIGIL_API_KEYS="production=sgk_live_abc123...,staging=sgk_live_def456..."
```

**Pros:** Simple, no extra files  
**Cons:** Keys visible in process list, harder to rotate

### Method 2: JSON file

Use `SIGIL_API_KEYS_FILE` to point to a JSON file:

```bash
export SIGIL_API_KEYS_FILE=/secure/api-keys.json
```

File format (`api-keys.json`):
```json
{
  "production": "sgk_live_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "staging": "sgk_live_b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567"
}
```

**Pros:** Easier rotation, not visible in process list  
**Cons:** Requires file management

**Security recommendations:**
- Set file permissions to `0600` (read/write for owner only)
- Store in a secure location (`/etc/secrets/`, mounted secret volume, etc.)
- Rotate keys regularly (every 90 days minimum)

---

## Fail-Closed Behavior

**IMPORTANT:** If no API keys are loaded at startup, the server will exit with a fatal error.

```
2026/04/26 14:00:00 No API keys configured. Set SIGIL_API_KEYS or SIGIL_API_KEYS_FILE environment variable.
exit status 1
```

This is intentional. Integrator endpoints **must not** be exposed without authentication.

---

## Using API Keys

All integrator endpoints require a valid Bearer token in the `Authorization` header:

```bash
curl -X POST https://sigil.example.com/challenge \
  -H "Authorization: Bearer sgk_live_a1b2c3d4..." \
  -H "Content-Type: application/json" \
  -d '{"device_fingerprint":"fp_...", "action_type":"login"}'
```

### Protected endpoints

The following endpoints require API keys:
- `/challenge` (POST)
- `/respond` (POST)
- `/v1/auth/challenge/{id}` (GET)
- `/mpa/request` (POST)
- `/mpa/respond` (POST)
- `/mpa/status/{id}` (GET)
- `/v1/secure/decrypt` (POST)
- `/v1/secure/decrypt/{id}` (GET)
- `/v1/config/webhooks` (POST)

### Unprotected endpoints

The following endpoints do **NOT** require API keys:
- `/health` (GET) — Health check
- `/info` (GET) — Server information
- `/metrics` (GET) — Prometheus metrics

---

## Rotating Keys

To rotate an API key:

1. **Generate a new key:**
   ```bash
   go run cmd/keygen/main.go production
   # production=sgk_live_new_key_here...
   ```

2. **Add the new key** to your configuration **alongside** the old key:
   ```bash
   export SIGIL_API_KEYS="production=sgk_live_old_key...,production-new=sgk_live_new_key..."
   ```
   or in JSON:
   ```json
   {
     "production": "sgk_live_old_key...",
     "production-new": "sgk_live_new_key..."
   }
   ```

3. **Restart the server** to load the new key.

4. **Update all integrators** to use the new key.

5. **Verify** all integrators are using the new key (check server logs for `keyID` in requests).

6. **Remove the old key** from configuration:
   ```bash
   export SIGIL_API_KEYS="production-new=sgk_live_new_key..."
   ```

7. **Restart the server** again to revoke the old key.

**Grace period recommendation:** Run with both keys active for 24-48 hours to allow integrators time to update.

---

## Revoking Keys

To immediately revoke an API key:

1. **Remove the key** from `SIGIL_API_KEYS` or the JSON file.

2. **Restart the server.**

The key becomes invalid immediately on restart. There is no in-memory revocation API (server is stateless).

**Emergency revocation:**
If a key is compromised, restart the server with only the non-compromised keys loaded. The compromised key will be rejected on the next request.

---

## Troubleshooting

### "Missing authorization header"

Request did not include `Authorization` header. Add:
```bash
-H "Authorization: Bearer sgk_live_..."
```

### "Invalid authorization format"

Authorization header is malformed. Must be:
```
Authorization: Bearer sgk_live_<64-hex>
```

Common mistakes:
- Missing "Bearer " prefix
- Extra whitespace
- Wrong token format

### "invalid_api_key"

The provided key is not valid. Possible causes:
- Key not loaded in server configuration
- Key revoked (removed from configuration and server restarted)
- Typo in key
- Using wrong environment's key (e.g., staging key on production server)

Check server logs for the key ID that was attempted.

---

## Best Practices

1. **Generate unique keys per environment** (production, staging, development)
2. **Never commit keys to version control**
3. **Rotate keys every 90 days minimum**
4. **Use short-lived keys for testing** (revoke after test)
5. **Monitor key usage** (check server logs for unexpected `keyID` values)
6. **Use file-based loading in production** (easier rotation, better security)
7. **Set file permissions to 0600** (owner read/write only)
8. **Store keys in secret management systems** (Vault, AWS Secrets Manager, etc.)
9. **Audit key access** (who generated, who rotated, who has access to storage)
10. **Have a revocation runbook** (practice emergency key revocation)

---

## Example Deployment

Docker Compose example:

```yaml
version: '3.8'
services:
  sigil-server:
    image: sigilauth/server:latest
    environment:
      SIGIL_API_KEYS_FILE: /run/secrets/api-keys.json
      SIGIL_MNEMONIC: "${SIGIL_MNEMONIC}"
    secrets:
      - api-keys.json
    ports:
      - "8443:8443"

secrets:
  api-keys.json:
    file: ./secrets/api-keys.json
```

Kubernetes example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sigil-api-keys
type: Opaque
stringData:
  api-keys.json: |
    {
      "production": "sgk_live_..."
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sigil-server
spec:
  template:
    spec:
      containers:
      - name: server
        image: sigilauth/server:latest
        env:
        - name: SIGIL_API_KEYS_FILE
          value: /secrets/api-keys.json
        volumeMounts:
        - name: api-keys
          mountPath: /secrets
          readOnly: true
      volumes:
      - name: api-keys
        secret:
          secretName: sigil-api-keys
```

---

## Security Notes

- **Keys are not encrypted at rest** — they are bcrypt-hashed in memory, but the plaintext file/env var must be protected.
- **Server restart required for rotation** — keys are loaded only at startup.
- **No audit log of key usage** — consider using a reverse proxy (nginx, Envoy) with request logging if you need audit trails.
- **Rate limiting recommended** — the server does not implement rate limiting per-key. Use a reverse proxy or WAF.

---

## Questions?

For security issues, email: `security@sigilauth.com`  
For general questions, file an issue: https://github.com/sigilauth/server/issues
