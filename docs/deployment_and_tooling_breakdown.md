# PacketLens — Deployment, Tooling & Testing Breakdown

## Source Files

| File | Role |
|---|---|
| `deploy/docker-compose.yml` | Full-stack orchestration (7 services) |
| `deploy/.env.example` | All environment variables with safe defaults |
| `deploy/prometheus.yml` | Prometheus scrape configuration |
| `deploy/grafana/` | Grafana provisioning (datasource + dashboard) |
| `Makefile` | Proto code generation + developer tasks |
| `scripts/test_grpc_server.py` | gRPC integration test + benchmark |
| `go.mod` | Go module — all direct and indirect dependencies |

---

## Part 1 — Docker Compose Stack

### Network Architecture Decision

**All 7 services use `network_mode: host`.**

This means every container shares the host's network namespace — no Docker bridge, no NAT, no DNS resolution between containers. All services talk via `localhost`.

**Why `host` mode?**
1. **Sniffer** needs raw socket access to the physical NIC for `libpcap`. Bridge mode would isolate it from real traffic.
2. **Zero-config inter-service communication** — `INFERENCE_ADDR=localhost:50051`, no service discovery needed.
3. **Prometheus scraping** works without container-to-container DNS — just `localhost:8000`, `localhost:9091`.

The trade-off: port conflicts with host services. All ports are configurable via `.env`.

---

### Services

#### 1. `postgres` — Incident Persistence

```yaml
image: postgres:16-alpine
command: postgres -c port=${POSTGRES_PORT:-5433}
```

- Runs on port **5433** by default (not 5432) to avoid conflicting with any host PostgreSQL instance.
- Mounts `init.sql` and `002_materialized_views.sql` into `/docker-entrypoint-initdb.d/` — auto-runs on first start.
- **Healthcheck:** `pg_isready` every 5s, 5 retries — ensures the DB is ready before `api` starts.
- `restart: unless-stopped` — recovers from crashes but respects manual `docker compose stop`.

#### 2. `inference` — Python gRPC + ONNX

```yaml
build:
  context: ..
  dockerfile: services/inference/Dockerfile
restart: always
```

- Build context is the project root (`..`) so the Dockerfile can copy `services/inference/model_store/` artifacts.
- No explicit environment variables — port `50051` (gRPC) and `8000` (Prometheus) are hardcoded defaults in `main.py`.
- `restart: always` — always restarts on crash or container daemon restart.

#### 3. `sniffer` — Go Packet Capture

```yaml
environment:
  - INTERFACE=${INTERFACE:-wlp2s0}
  - POSTGRES_DSN=postgres://...@localhost:${POSTGRES_PORT:-5433}/...
  - ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL:-}
  - ALERT_WEBHOOK_TYPE=${ALERT_WEBHOOK_TYPE:-generic}
  - ALERT_TELEGRAM_CHAT_ID=${ALERT_TELEGRAM_CHAT_ID:-}
cap_add:
  - NET_ADMIN
  - NET_RAW
depends_on:
  - inference
  - postgres
```

- `NET_ADMIN` + `NET_RAW` Linux capabilities — required for `libpcap` to open a raw socket on the NIC. Without these, `pcap.OpenLive()` returns permission denied.
- `INTERFACE` must match the actual NIC name on the host (check with `ip link`).
- Alert variables default to empty — alerting is disabled unless explicitly set in `.env`.
- `depends_on: inference` — sniffer starts after inference, but does not wait for it to be ready; it handles reconnection via exponential backoff internally.

#### 4. `api` — Go REST API

```yaml
environment:
  - POSTGRES_DSN=...
  - API_PORT=${API_PORT:-8080}
  - JWT_SECRET=${JWT_SECRET:-change-me-to-a-random-64-char-hex-string}
  - ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
  - ADMIN_PASSWORD=${ADMIN_PASSWORD:-packetlens-admin}
depends_on:
  postgres:
    condition: service_healthy
```

- `depends_on: condition: service_healthy` — waits for PostgreSQL healthcheck to pass before starting. Prevents "connection refused" on startup.
- `JWT_SECRET` default is a placeholder — **must be changed in production**.

#### 5. `dashboard` — Next.js UI

```yaml
build:
  args:
    NEXT_PUBLIC_API_URL: ${NEXT_PUBLIC_API_URL:-http://localhost:8080/api/v1}
environment:
  - PORT=${DASHBOARD_PORT:-3001}
  - HOSTNAME=0.0.0.0
```

- `NEXT_PUBLIC_API_URL` is a **build-time arg** — Next.js bakes `NEXT_PUBLIC_*` variables into the JavaScript bundle at build time. It cannot be changed at runtime without rebuilding the image.
- Default port is **3001** (not 3000, which is reserved for Grafana).
- `HOSTNAME=0.0.0.0` — makes the Next.js standalone server listen on all interfaces, not just loopback.

#### 6. `prometheus` — Metrics Collection

```yaml
image: prom/prometheus:latest
command:
  - "--storage.tsdb.retention.time=7d"
  - "--web.enable-lifecycle"
```

- Mounts `prometheus.yml` (scrape config) as read-only.
- 7-day metric retention — enough for trend analysis without excessive disk usage.
- `--web.enable-lifecycle` — allows hot-reloading config via `POST /-/reload` without restarting.
- Persistent volume `prometheus_data` — metrics survive container restarts.

#### 7. `grafana` — Visualization

```yaml
environment:
  - GF_AUTH_ANONYMOUS_ENABLED=true
  - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
  - GF_AUTH_DISABLE_LOGIN_FORM=true
```

- **Anonymous access enabled** — the login form is disabled and anyone gets Admin role. Suitable for internal/lab use; disable for production.
- Mounts `grafana/provisioning/` → auto-registers the Prometheus datasource on first start.
- Mounts `grafana/dashboards/` → auto-loads the PacketLens dashboard JSON.
- Persistent volume `grafana_data` — saved dashboards and settings survive restarts.

---

### Volumes

```yaml
volumes:
  postgres_data:    # PostgreSQL data directory
  prometheus_data:  # Prometheus time-series data (7-day retention)
  grafana_data:     # Grafana state (datasources, dashboards, preferences)
```

All named volumes — managed by Docker, survive `docker compose down` (only removed with `docker compose down -v`).

---

### Startup Command

```bash
cd deploy
cp .env.example .env   # first time only — edit values
sudo docker compose up --build -d
```

`sudo` is required because the sniffer container uses `NET_RAW` which Docker needs root to grant.

---

## Part 2 — Prometheus Scrape Config (`prometheus.yml`)

```yaml
global:
  scrape_interval: 1s
  evaluation_interval: 1s

scrape_configs:
  - job_name: 'packetlens-inference'
    static_configs:
      - targets: ['localhost:8000']

  - job_name: 'packetlens-sniffer'
    static_configs:
      - targets: ['localhost:9091']

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

**`scrape_interval: 1s`** — unusually aggressive (default is 15s). This gives near-real-time metric resolution in Grafana, important for monitoring packet rates and inference latency during active attacks. The trade-off is higher Prometheus CPU and storage usage.

All targets use `localhost` — correct because all containers run in `network_mode: host`.

**Metrics endpoints:**
- `localhost:8000/metrics` — Python inference (Prometheus client_python)
- `localhost:9091/metrics` — Go sniffer (prometheus/client_golang)
- `localhost:9090/metrics` — Prometheus self-monitoring

---

## Part 3 — Makefile (Developer Tasks)

All targets are declared `.PHONY` — they don't depend on file timestamps.

| Target | Command | What it does |
|---|---|---|
| `make` / `make all` | `make proto` | Default: generate all proto stubs |
| `make proto` | `make proto-go proto-python` | Regenerate both Go and Python stubs |
| `make proto-go` | `protoc ...` | Generates `gen/go/packetlens/*.go` |
| `make proto-python` | `python -m grpc_tools.protoc ...` | Generates `services/inference/proto/*.py` + `.pyi` |
| `make install-proto-tools` | `go install` + `pip install` | One-time setup of `protoc-gen-go`, `protoc-gen-go-grpc`, `grpcio-tools` |
| `make clean` | `rm -rf gen/go/*.go services/inference/proto/*.py .pyi` | Remove all generated files |
| `make help` | echo | Print all targets |

**When to run `make proto`:**
- Any time `proto/packetlens.proto` is modified
- After a fresh clone (generated files may not be committed)
- Never edit files in `gen/` or `services/inference/proto/` directly — they are always overwritten

**System prerequisite not covered by `make install-proto-tools`:**
```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf
```

---

## Part 4 — gRPC Test Script (`scripts/test_grpc_server.py`)

A standalone integration test and performance benchmark for the inference service.

### Purpose

Validates that the inference server:
1. Accepts the gRPC connection
2. Processes `FeatureVector` messages
3. Returns `Verdict` messages
4. Reports accurate server-side latency

### Usage

```bash
# Default: 100 requests to localhost:50051
python scripts/test_grpc_server.py

# Custom target and load
python scripts/test_grpc_server.py --host localhost --port 50051 --count 1000 --quiet
```

### How It Works

**Step 1 — Generate dummy packets**
```python
rng = np.random.default_rng(seed=42)   # reproducible
features = rng.random(54).astype(np.float32)   # random [0, 1] per feature
```
Reproducible with fixed seed — same input → same benchmark results across runs.

**Step 2 — Connect**
```python
channel = grpc.insecure_channel(f"{host}:{port}", options=[
    ("grpc.max_receive_message_length", 10 * 1024 * 1024),
    ("grpc.max_send_message_length", 10 * 1024 * 1024),
])
grpc.channel_ready_future(channel).result(timeout=5)
```
5-second connection timeout. Fails fast with a helpful error message if the server isn't running.

**Step 3 — Stream requests**
```python
response_stream = stub.Classify(request_stream)
for verdict in response_stream:
    # collect label, confidence, server latency
```
Uses the same bidirectional streaming RPC as the production sniffer. Tests real production code paths, not mocks.

**Step 4 — Report metrics**

| Metric | What it tells you |
|---|---|
| Total / Successful / Errors | Is the server stable? |
| Total time | Wall time for all N requests |
| Avg latency (server-side) | Pure ONNX inference speed |
| P50 / P95 / P99 latency | Tail latency — important for SLAs |
| Requests/second | Effective throughput |
| Label distribution | Is the model classifying (not all ERRORs)? |

**Important:** The latency measured here is `Verdict.inference_time_us` — the **server-side ONNX** time only, not round-trip network latency. This isolates model performance from network conditions.

### Expected Output (healthy server)
```
PacketLens gRPC Server Benchmark
  Target:   localhost:50051
  Requests: 1,000

[1] test_flow_000000: Benign (94.32%) [812µs]
[2] test_flow_000001: Benign (91.15%) [543µs]
...

BENCHMARK RESULTS
  Total Requests:    1,000
  Successful:        1,000
  Errors:            0
  Total Time:        2.34s

Latency (server-side inference):
  Average:    0.712 ms
  P50:        0.689 ms
  P95:        1.203 ms
  P99:        1.891 ms

Throughput:
  Requests/second: 427.4
```

---

## Part 5 — Go Dependencies (`go.mod`)

Module: `github.com/mahmoud375/PacketLens`  
Go version: `1.23.0`

### Direct Dependencies

| Package | Version | Used by | Purpose |
|---|---|---|---|
| `gin-contrib/cors` | v1.7.3 | API | CORS middleware for Gin |
| `gin-gonic/gin` | v1.10.0 | API | HTTP router + middleware framework |
| `google/gopacket` | v1.1.19 | Sniffer | Packet parsing + pcap bindings |
| `jackc/pgx/v5` | v5.5.5 | Sniffer + API | PostgreSQL driver (COPY protocol, connection pool) |
| `prometheus/client_golang` | v1.21.1 | Sniffer | Prometheus metrics exposition |
| `google.golang.org/grpc` | v1.62.0 | Sniffer | gRPC client for inference service |
| `google.golang.org/protobuf` | v1.36.8 | Sniffer | Protocol Buffers runtime |

### Notable Indirect Dependencies

| Package | Why it's here |
|---|---|
| `bytedance/sonic` | Gin's high-performance JSON encoder (replaces `encoding/json`) |
| `golang-jwt/jwt/v5` | JWT signing/validation in API middleware |
| `jackc/puddle/v2` | Connection pool used internally by `pgx/v5` |
| `golang/x/sync` | `errgroup`, `singleflight` used by pgx internally |
| `golang/x/crypto` | TLS, bcrypt (used by pgx for PostgreSQL SCRAM auth) |
