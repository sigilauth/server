# Sigil Auth Observability Stack

Production-ready observability for Sigil Auth: metrics, logs, traces, and alerting.

## Components

| Service | Purpose | Port | UI |
|---------|---------|------|-----|
| **Prometheus** | Metrics collection + alerting | 9090 | http://localhost:9090 |
| **Grafana** | Dashboards + visualization | 3000 | http://localhost:3000 |
| **Loki** | Log aggregation | 3100 | - |
| **Promtail** | Log shipper | - | - |
| **OTel Collector** | Trace collection | 4317, 4318 | - |
| **Tempo** | Distributed tracing | 3200 | - |

## Quick Start

```bash
# Start observability stack
docker-compose \
  -f docker-compose.yml \
  -f deploy/observability/docker-compose.observability.yml \
  up -d

# Check service health
docker ps | grep sigil

# Access Grafana
open http://localhost:3000
# Default credentials: admin / admin (change on first login)

# Access Prometheus
open http://localhost:9090

# View logs
docker logs -f sigil-promtail
```

## Grafana Dashboards

Three pre-configured dashboards in `/deploy/observability/grafana/dashboards/`:

1. **Operations Overview** — auth success rate, latency p95, push delivery, throughput
2. **MPA Health** — completion rate, duration, outcome distribution
3. **Security Alerts** — signature failures, replay attempts, push degradation

### Importing Dashboards

Dashboards auto-provision on Grafana startup. To manually import:

1. Login to Grafana → Dashboards → Import
2. Upload JSON from `deploy/observability/grafana/dashboards/*.json`
3. Select Prometheus as data source

## Alerting

Prometheus alert rules in `/deploy/observability/prometheus/alerts.yml`:

| Alert | Threshold | Severity |
|-------|-----------|----------|
| SigilDown | >3min downtime | Critical |
| ChallengeSlow | p95 >500ms for 5min | Warning |
| HighSignatureFailures | >1% failure rate | Critical |
| ReplayAttempts | Any detected | Critical |
| PushDeliveryDegraded | <95% delivery | Warning |
| HighMPARejections | >30% rejection rate | Warning |

Configure Alertmanager to route alerts to Slack, PagerDuty, etc.

## Metrics Reference

### Sigil Server

```
# Challenges
sigil_challenges_total{status="created|verified|rejected|replay_blocked|signature_failed"}
sigil_challenges_active
sigil_challenge_latency_seconds{phase="create|verify"}

# MPA
sigil_mpa_requests_total{status="pending|approved|rejected|timeout"}
sigil_mpa_duration_seconds

# HTTP
sigil_http_requests_total{method,path,status}
sigil_http_request_duration_seconds{method,path}

# Device registration
sigil_device_registrations_total{status="success|attestation_failed"}
```

### Push Relay

```
# Push delivery
relay_push_total{provider="apns|fcm",status="sent|failed"}
relay_push_delivery_success_total{provider}
relay_push_delivery_failure_total{provider}

# HTTP
relay_http_requests_total{method,path,status}
relay_http_request_duration_seconds{method,path}
```

## Logs

Loki aggregates JSON-structured logs from Docker stdout.

### Querying in Grafana

```logql
# All sigil logs
{service="sigil"}

# Errors only
{service="sigil"} |= "level=error"

# MPA operations
{service="sigil",operation="mpa"}

# Specific trace
{trace_id="abc123"}
```

### Log Format

Sigil and relay emit JSON logs:

```json
{
  "timestamp": "2026-01-27T14:32:01.123Z",
  "level": "info",
  "message": "Challenge verified",
  "trace_id": "a1b2c3d4",
  "span_id": "e5f6g7h8",
  "component": "auth",
  "operation": "verify_challenge",
  "device_fingerprint": "sha256:abc...",
  "duration_ms": 42
}
```

## Distributed Tracing

OpenTelemetry traces flow: Sigil/Relay → OTel Collector → Tempo → Grafana.

### Viewing Traces in Grafana

1. Explore → Select Tempo data source
2. Query by trace ID or service name
3. Visualize request flow across services

### Trace Context Propagation

Sigil and relay propagate W3C Trace Context headers:

```
traceparent: 00-<trace-id>-<span-id>-01
tracestate: sigil=<correlation-id>
```

## SIGIL_TELEMETRY Opt-Out

Control telemetry granularity via environment variable:

| Value | Metrics | Logs | Traces |
|-------|---------|------|--------|
| `full` (default) | ✅ All | ✅ All | ✅ All |
| `metrics_only` | ✅ All | ❌ Errors only | ❌ None |
| `minimal` | ✅ Health + uptime | ❌ Errors only | ❌ None |
| `none` | ❌ Health only | ❌ Errors only | ❌ None |

**Privacy note:** Even with `SIGIL_TELEMETRY=none`, critical security events (replay attempts, attestation failures) are always logged locally. No telemetry is sent to external services — this is self-hosted observability.

### Setting Telemetry Level

```bash
# docker-compose.yml
services:
  sigil:
    environment:
      SIGIL_TELEMETRY: minimal  # full | metrics_only | minimal | none
```

## Resource Usage

Typical resource consumption (idle state):

| Service | CPU | Memory | Disk |
|---------|-----|--------|------|
| Prometheus | 50m | 200MB | 1GB/day |
| Grafana | 20m | 150MB | 100MB |
| Loki | 30m | 100MB | 500MB/day |
| Promtail | 10m | 50MB | - |
| OTel Collector | 20m | 100MB | - |
| Tempo | 30m | 150MB | 2GB/day |

Total: ~160m CPU, ~750MB RAM, ~3.6GB/day storage.

## Production Considerations

### Retention

- **Metrics:** 30 days (Prometheus)
- **Logs:** 7 days dev, 30 days prod (Loki)
- **Traces:** 7 days (Tempo)

Adjust in respective config files.

### Scaling

For high-volume deployments:

1. **Prometheus:** Use remote write to Cortex/Mimir
2. **Loki:** Deploy with S3/GCS backend instead of local filesystem
3. **Tempo:** Use S3/GCS for trace storage
4. **OTel:** Reduce sampling percentage in `collector.yml`

### Security

- Change Grafana admin password immediately
- Enable TLS for Prometheus, Grafana, Loki (nginx/Caddy reverse proxy)
- Restrict network access to observability ports
- Use Grafana auth (OAuth, LDAP) in production

### Backup

Critical to back up:

- Grafana dashboards: `/var/lib/grafana` volume
- Prometheus config: `/deploy/observability/prometheus/`
- Alert rules: `/deploy/observability/prometheus/alerts.yml`

Metrics/logs/traces are ephemeral — don't back up time-series data.

## Health Monitoring

GitHub Actions workflow polls `/health` endpoints every 5 minutes:

- **File:** `.github/workflows/health-monitor.yml`
- **On failure:** Creates P0 GitHub issue
- **On recovery:** Auto-closes issue

Configure production URLs in workflow matrix.

## Troubleshooting

### Prometheus not scraping targets

```bash
# Check Prometheus targets
open http://localhost:9090/targets

# Verify sigil/relay expose /metrics
curl -k https://localhost:8443/metrics
curl http://localhost:8080/metrics
```

### Grafana can't connect to data sources

```bash
# Check network connectivity
docker exec sigil-grafana ping prometheus
docker exec sigil-grafana ping loki

# Verify services are up
docker ps | grep -E "prometheus|loki|tempo"
```

### Logs not appearing in Loki

```bash
# Check Promtail is scraping
docker logs sigil-promtail

# Verify Loki receiving logs
curl http://localhost:3100/metrics | grep loki_ingester_streams_created_total

# Check log format (must be JSON for parsing)
docker logs sigil | head -1 | jq .
```

### Traces not appearing in Tempo

```bash
# Check OTel Collector receiving traces
docker logs sigil-otel | grep "Trace ID"

# Verify Tempo ingestion
curl http://localhost:3200/metrics | grep tempo_ingester_traces_created_total

# Check trace propagation headers in app
export SIGIL_LOG_LEVEL=debug
docker logs sigil | grep traceparent
```

## References

- [Prometheus documentation](https://prometheus.io/docs/)
- [Grafana documentation](https://grafana.com/docs/)
- [Loki documentation](https://grafana.com/docs/loki/)
- [OpenTelemetry documentation](https://opentelemetry.io/docs/)
- [Tempo documentation](https://grafana.com/docs/tempo/)
