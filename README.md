# wazuh-http-adapter

> A thin HTTP adapter that bridges k6 load tests to Wazuh's syslog ingestion, enabling ingest latency measurement for EPS benchmarking.

Built for my thesis: **Xemarify vs Wazuh EPS performance comparison**

## Problem

Wazuh exposes no HTTP ingest endpoint. k6 can't measure ingest latency directly. Adapter sits in front of Wazuh, exposes `POST /api/v1/events`, forwards via TCP syslog, exposes Prometheus metrics.

## Architecture

```
k6 → POST /api/v1/events → [Adapter] → TCP Syslog → Wazuh Manager
                                ↓
                         :9090/metrics (Prometheus)
                         correlation_id → alerts.json tail → detection latency
```

## Quick Start

### Build & Run (local)

```bash
git clone https://github.com/hildanku/wazuh-http-adapter
cd wazuh-http-adapter

go build -o adapter ./cmd/adapter
./adapter
```

### Pull & Run from GHCR (recommended)

```bash
# Pull latest
docker pull ghcr.io/hildanku/wazuh-http-adapter:main

# Run on Wazuh host — must run on same host as Wazuh manager container
docker stop wazuh-http-adapter 2>/dev/null; docker rm wazuh-http-adapter 2>/dev/null

docker run -d \
  --name wazuh-http-adapter \
  --network host \
  -e WAZUH_HOST=127.0.0.1 \
  -e WAZUH_SYSLOG_PORT=514 \
  -e ALERTS_LOG_PATH=/var/ossec/logs/alerts/alerts.json \
  -v wazuh-manager_wazuh_ossec_logs:/var/ossec/logs:ro \
  ghcr.io/hildanku/wazuh-http-adapter:main
```

> `--network host` required, adapter sends TCP syslog to `127.0.0.1:514` (Wazuh manager).
> Volume name `wazuh-manager_wazuh_ossec_logs` is Docker Compose project-specific. Adjust if different.
> Mount must be `/var/ossec/logs` (not `/var/ossec/logs/alerts`), volume structure includes `alerts/` subdirectory.

### Update Running Container

```bash
docker pull ghcr.io/hildanku/wazuh-http-adapter:main
docker stop wazuh-http-adapter
docker rm wazuh-http-adapter
docker run -d \
  --name wazuh-http-adapter \
  --network host \
  -e WAZUH_HOST=127.0.0.1 \
  -e WAZUH_SYSLOG_PORT=514 \
  -e ALERTS_LOG_PATH=/var/ossec/logs/alerts/alerts.json \
  -v wazuh-manager_wazuh_ossec_logs:/var/ossec/logs:ro \
  ghcr.io/hildanku/wazuh-http-adapter:main
```

### Build & Run (local)

```bash
docker build -t wazuh-http-adapter .

docker run -d \
  --name wazuh-http-adapter \
  --network host \
  -e WAZUH_HOST=127.0.0.1 \
  -e WAZUH_SYSLOG_PORT=514 \
  -e ALERTS_LOG_PATH=/var/ossec/logs/alerts/alerts.json \
  -v wazuh-manager_wazuh_ossec_logs:/var/ossec/logs:ro \
  wazuh-http-adapter
```

### Verify

```bash
# Health check
curl http://localhost:8080/health

# Check metrics
curl http://localhost:9090/metrics | grep wazuh_adapter
```

## Configuration

All config via environment variables.

| Env | Default | Description |
|-----|---------|-------------|
| `ADAPTER_PORT` | `8080` | HTTP listen port |
| `METRICS_PORT` | `9090` | Prometheus metrics port |
| `WAZUH_HOST` | `localhost` | Wazuh manager host |
| `WAZUH_SYSLOG_PORT` | `514` | TCP syslog port |
| `FORWARD_TIMEOUT_SEC` | `5` | TCP write timeout (seconds) |

## API

### `GET /health`

```json
{"status": "ok"}
```

## Prometheus Metrics

Scraped at `:9090/metrics`.

| Metric | Type | Description |
|--------|------|-------------|
| `wazuh_adapter_events_received_total` | Counter | Events received via HTTP |
| `wazuh_adapter_events_forwarded_total` | Counter | Events forwarded to Wazuh |
| `wazuh_adapter_forward_error_total` | Counter | Forward failures |
| `wazuh_adapter_ingest_latency_seconds` | Histogram | HTTP receive → TCP send latency |
| `wazuh_adapter_detection_latency_seconds` | Histogram | HTTP receive → Wazuh alert fired |
| `wazuh_adapter_payload_size_bytes` | Histogram | Incoming payload size |
| `wazuh_adapter_active_connections` | Gauge | Active HTTP connections |

## Baseline Measurement

Adapter introduces overhead. Quantify it before benchmark runs:

```bash
# 1. Stop Wazuh (adapter will log forward errors — expected)
# 2. Start adapter
./adapter

# 3. Run baseline script
chmod +x scripts/baseline.sh
./scripts/baseline.sh --eps 100 --duration 60s

# Output: adapter_baseline_p95 in seconds
# 4. Subtract from thesis measurement table:
#    wazuh_ingest_latency = measured_total - adapter_baseline_p95
```

Overhead documented as explicit limitation in thesis. Valid under "test adapter pattern" — precedented in comparative SIEM benchmarking literature.

## k6 Integration

Adapter accepts same payload shape as Xemarify. Point existing k6 script to adapter host:

```bash
k6 run \
  --env BASE_URL=http://localhost:8080 \
  k6-load-test.js
```

## Metrics Gap vs Xemarify

| Metric | Xemarify | Wazuh (via adapter) |
|--------|----------|---------------------|
| Ingest latency | `ingest_mean_ms` via k6 | `wazuh_adapter_ingest_latency_seconds` (overhead subtracted) |
| Events confirmed received | `events_recv_delta` Prometheus | `wazuh_adapter_events_forwarded_total` |
| Rules evaluated | `engine_rules_eval_delta` | Not available — acknowledged gap |
| Alert delta per run | `engine_alerts_delta` | `totalAlerts` hourly bucket — not comparable |

## Tech Stack

- Go `net/http` stdlib
- `prometheus/client_golang`
- TCP syslog (not UDP — delivery confirmation required)
- `google/uuid` for correlation ID

## Related

- Xemarify test runner: `test/fix/eps-test/xemarify/test-prod-runner-24jun-5xloop-after-fresh-jwt.sh`
- Wazuh test runner: `test/fix/eps-test/wazuh/test-runner-fix-injector.sh`
- EPS tiers tested: 100 / 300 / 600 / 1000
