# PacketLens — All Services Breakdown

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PacketLens Architecture                         │
│                                                                         │
│  Network Traffic                                                        │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐  gRPC stream   ┌───────────┐  PostgreSQL COPY             │
│  │ Sniffer  │ ─────────────► │ Inference │ ──────────────► ┌─────────┐ │
│  │  (Go)    │ ◄───────────── │ (Python)  │                 │Postgres │ │
│  └──────────┘   Verdicts     └───────────┘                 └────┬────┘ │
│       │                                                         │       │
│       │ Webhook (Slack/Telegram)                    LISTEN/NOTIFY       │
│       ▼                                                         │       │
│  External Alert                                        ┌────────┴────┐  │
│                                                        │  API (Go)   │  │
│                                                        │  Gin + SSE  │  │
│                                                        └─────┬───────┘  │
│                                                              │ REST/SSE  │
│                                                        ┌─────▼───────┐  │
│                                                        │  Dashboard  │  │
│                                                        │  (Next.js)  │  │
│                                                        └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Service 1 — Sniffer (`services/sniffer/`, Go)

**Role:** Live packet capture → flow aggregation → gRPC to inference → incident persistence → alerting

**Ports:** `:9090` Prometheus metrics  
**Language:** Go  
**Key libraries:** `gopacket/pcap`, `google.golang.org/grpc`, `pgx/v5`, `prometheus/client_golang`

### Internal Packages

#### `internal/capture` — Packet Capture Engine

File: `engine.go`

Wraps `libpcap` via `gopacket`. Opens the NIC in **promiscuous mode**, applies a **BPF filter** (`"ip"` — IP traffic only), and pushes every packet into the `FlowManager`.

```
Default config:
  SnapLen:     65535        (full packet)
  Promiscuous: true         (all traffic on iface)
  BPFFilter:   "ip"         (discard non-IP)
  Timeout:     BlockForever (no read timeout)
```

Uses `NoCopy = true` on the packet source — the buffer is **reused per packet** for performance. Any data that needs to outlive the current iteration must be copied explicitly.

Every 10 seconds: logs `(total packets captured, unique flows)` to stdout.

---

#### `internal/flow` — Flow Tracker + Feature Extractor

Files: `manager.go`, `stats_welford.go`

**The most complex package.** Tracks bidirectional network flows identified by 5-tuple and extracts the exact 54 features required by the ONNX model.

**Flow Key (5-tuple normalization):**
```go
type FlowKey struct {
    SrcIP    [16]byte  // IPv4 and IPv6
    DstIP    [16]byte
    SrcPort  uint16
    DstPort  uint16
    Protocol uint8
}
```
`(A→B)` and `(B→A)` are **canonicalized** to the same key by comparing IP bytes — the "smaller" IP/port is always `Src`. This ensures one `Flow` struct per conversation regardless of which side a packet arrives from.

**Flow Struct — tracked statistics:**

| Field | What it tracks |
|---|---|
| `FwdPackets / BwdPackets` | Directional packet count |
| `FwdBytes / BwdBytes` | Directional byte count |
| `FwdPktLen / BwdPktLen / AllPktLen` | RunningStats (Welford) |
| `FlowIAT / FwdIAT / BwdIAT` | Inter-arrival times (µs) |
| `FwdPSHFlags / SYNCount / URGCount` | TCP flag counts |
| `InitFwdWinBytes / InitBwdWinBytes` | First TCP window per direction |
| `ActivePeriods / IdlePeriods` | Active/idle time segments |
| `FwdActDataPkts / FwdSegSizeMin` | Forward data payload stats |

**Welford online algorithm** (`stats_welford.go`): computes `mean`, `stddev`, `variance`, `min`, `max` in O(1) per packet without storing all values. Critical for unbounded flows.

**`ToFeatures()` — 54-feature vector (exact CIC-IDS order):**

| Index range | Features |
|---|---|
| 0 | `flow_duration` (µs) |
| 1–2 | fwd/bwd packet counts |
| 3–4 | fwd/bwd total bytes |
| 5–6 | fwd pkt len max, stddev |
| 7–9 | bwd pkt len max, mean, stddev |
| 10–11 | flow bytes/s, packets/s |
| 12–15 | flow IAT mean/std/max/min |
| 16–20 | fwd IAT sum/mean/std/max/min |
| 21–25 | bwd IAT sum/mean/std/max/min |
| 26–28 | fwd PSH flags, fwd/bwd header len |
| 29–30 | fwd/bwd packets/s |
| 31–34 | all pkt len max/mean/std/var |
| 35–36 | SYN count, URG count |
| 37–39 | avg pkt size, avg fwd/bwd size |
| 40–41 | init fwd/bwd window bytes |
| 42–43 | fwd active data pkts, fwd seg min |
| 44–47 | active period mean/std/max/min |
| 48–51 | idle period mean/std/max/min |
| 52–53 | flow bytes/s, packets/s (for log1p) |

After computation, any `NaN` or `Inf` values are **zeroed** before sending.

**Manager — concurrent flow table:**

Uses `sync.Map` (lock-free reads on the hot path). Background `cleanupRoutine` ticks every 1 second to flush idle flows (idle timeout: 5 seconds).

**Load-shedding cap:**
```
MaxActiveFlows = 100,000   (~40 MB at 400 bytes/Flow)
```
Under a spoofed-IP DDoS generating 1M unique 5-tuples/second, flow entries are dropped instead of exhausting memory. Uses `atomic.Int64` for the count check — avoids taking the Manager lock on every packet in the hot path.

**Flush triggers (a flow is sent to the channel when):**
1. `FIN` or `RST` TCP flag seen
2. `FlowMaxPackets = 10,000` exceeded
3. Idle timeout (5s without new packet)

Dropped flows (channel full) are counted via `FlowsDropped` Prometheus counter.

---

#### `internal/transport` — gRPC Client + Verdict Handler

File: `grpc.go`

Opens a **bidirectional streaming** gRPC connection to the Python inference service.

**`Client`** — manages the `grpc.ClientConn` and `Classify` stream with mutex protection. Supports `ConnectWithRetry` with exponential backoff (1s → 2s → 4s → … → 30s max).

**`Sender`** — runs two goroutines:

| Goroutine | What it does |
|---|---|
| `sendLoop` | Reads `*Flow` from `flushChan`, calls `flow.ToFeatures()`, sends `FeatureVector` protobuf over the stream |
| `receiveLoop` | Reads `Verdict` messages from the stream; routes non-Benign verdicts to incident + alert channels |

**On every received verdict:**
1. Increments `VerdictsByLabel` Prometheus counter
2. Logs non-Benign verdicts to stdout
3. Parses the `FlowID` string back to a 5-tuple (`srcIP:srcPort→dstIP:dstPort/proto`)
4. Non-blocking send to `incidentChan` if `ShouldLog()` passes
5. Non-blocking send to `alertChan` if `ShouldAlert()` passes

**Protobuf contract (`FeatureVector` → `Verdict`):**
```protobuf
message FeatureVector {
    string flow_id       = 1;
    repeated float features = 2;  // 54 floats
    int64 timestamp_ns   = 3;
}

message Verdict {
    string flow_id         = 1;
    string label           = 2;   // "Benign" / "DDoS-HOIC" / ...
    float  confidence      = 3;   // 0.0 – 1.0
    int64  inference_time_us = 4;
}
```

---

#### `internal/incident` — Batch PostgreSQL Writer

Files: `writer.go`, `store.go`, `model.go`, `config.go`

A **dual-trigger batch writer** that persists incidents without blocking the gRPC receive loop.

**Flush triggers:**
- **Size trigger:** flush when batch reaches `Config.BatchSize`
- **Time trigger:** flush when `Config.FlushInterval` elapses

Whichever fires first wins. On shutdown, the remaining buffer is always flushed with a 10-second timeout context.

**Write mechanism:** Uses `pgx.CopyFrom` (PostgreSQL COPY protocol) — the fastest bulk insert method, bypassing individual INSERT parsing overhead.

```
ipToPrefix() converts net.IP → netip.Prefix
(pgx v5 binary COPY requires netip.Prefix for inet columns)
```

Fields persisted per incident:
`detected_at, src_ip (inet), dst_ip (inet), src_port, dst_port, protocol, attack_type, confidence, inference_us, flow_id, status`

---

#### `internal/alerting` — Webhook Alert Dispatcher

Files: `dispatcher.go`, `ratelimiter.go`, `alert.go`, `config.go`

Async goroutine that consumes from `alertChan` and delivers to external webhooks. Never blocks the gRPC hot path.

**Rate limiting (two layers):**
- **Per-label cooldown:** once an alert fires for `DDoS-HOIC`, suppress subsequent ones for `Config.PerLabelCooldown` duration
- **Global burst ceiling:** at most `Config.GlobalBurstLimit` alerts per `Config.GlobalBurstWindow` across all labels

**Supported webhook formats:**

| Type | Format |
|---|---|
| `slack` | Block Kit JSON with header + section fields |
| `telegram` | Bot API `sendMessage` with HTML parse mode |
| `generic` | Plain JSON `{event, attack_type, confidence, ...}` |

All formats include: `attack_type, src/dst IP:port, protocol, confidence %, inference µs, timestamp`.

---

#### `internal/metrics` — Prometheus Instrumentation

File: `metrics.go`

Exposes `/metrics` on port `:9090`.

| Metric | Type | Meaning |
|---|---|---|
| `packetlens_packets_captured_total` | Counter | Raw packets from pcap |
| `packetlens_active_flows` | Gauge | Current flows in memory |
| `packetlens_flows_flushed_total` | Counter | Flows sent to inference |
| `packetlens_flows_dropped_total` | Counter | Flows dropped (channel full or cap) |
| `packetlens_grpc_send_errors_total` | Counter | gRPC send failures |
| `packetlens_verdicts_received_total` | CounterVec | Verdicts by `{label}` |
| `packetlens_incidents_written_total` | Counter | DB rows written |
| `packetlens_incidents_dropped_total` | Counter | DB channel full drops |
| `packetlens_incident_write_errors_total` | Counter | PostgreSQL CopyFrom failures |
| `packetlens_alerts_sent_total` | Counter | Webhook deliveries |
| `packetlens_alerts_suppressed_total` | Counter | Rate-limited alerts |
| `packetlens_alert_send_errors_total` | Counter | Webhook HTTP failures |
| `packetlens_alerts_dropped_total` | Counter | Alert channel full drops |

---

## Service 2 — Inference (`services/inference/`, Python)

**Role:** Receive feature vectors via gRPC → preprocess → ONNX inference → return verdicts  
**Ports:** `:50051` gRPC, `:8000` Prometheus  
**Language:** Python 3.x  
**Key libraries:** `grpcio`, `onnxruntime`, `scikit-learn`, `prometheus_client`

### Packages

#### `core.py` — `InferenceEngine`

The ONNX model wrapper. Loaded once at startup; shared across all gRPC sessions.

**Startup validation (4 checks):**
1. ONNX model file exists and loads into `ort.InferenceSession`
2. ONNX input shape `n_features` matches `feature_map.json` count
3. `scaler.pkl` loads (warning, not crash, if missing)
4. Scaler feature count matches ONNX `n_features`

Supports both `RobustScaler` (`center_` attribute) and `StandardScaler` (`mean_` attribute) for backward compatibility.

**`_apply_preprocessing(features: np.ndarray) → np.ndarray`**

Exact mirror of `corrected_preprocessing.py`:
1. Clip negative values on heavy-tail features to 0
2. `np.log1p()` on 18 power-law features (same `HEAVY_TAIL_FEATURES` frozenset)
3. `RobustScaler.transform()` using `scaler.pkl`
4. Cast to `float32`

**`predict(features: np.ndarray) → (label, confidence, inference_time_ms)`**
```
Input:  [54,] float32 (raw feature vector from Go sniffer)
  │
  ▼
_apply_preprocessing()
  │
  ▼
session.run(["label", "probabilities"], {"features": [1, 54]})
  │
  ├── outputs[0] → predicted class index (int64)
  └── outputs[1] → softmax probs [1, 33] float32
        │
        ▼
  confidence = max(probs[0])
  label      = label_mapping[pred_idx]
Output: (label: str, confidence: float, time_ms: float)
```

**Prometheus metrics (`:8000`):**

| Metric | Type |
|---|---|
| `packetlens_inference_latency_seconds` | Histogram (buckets: 0.5ms–100ms) |
| `packetlens_verdict_total{label, status}` | Counter |
| `packetlens_requests_per_second` | Gauge |
| `packetlens_requests_total` | Counter |
| `packetlens_active_streams` | Gauge |

---

#### `server.py` — `InferenceService` (gRPC Servicer)

Implements the `InferenceService.Classify` bidirectional streaming RPC.

**Architecture:**
```
grpc.aio server  (AsyncIO event loop)
      │
      └── async for request in stream:
              features = np.array(request.features, dtype=float32)
              label, conf, time = await asyncio.to_thread(engine.predict, features)
              yield Verdict(label=label, confidence=conf, ...)
```

**Key decisions:**

| Decision | Mechanism | Reason |
|---|---|---|
| Non-blocking I/O | `grpc.aio` (AsyncIO) | Handles thousands of concurrent streams |
| CPU-bound isolation | `asyncio.to_thread(engine.predict)` | ONNX `session.run()` blocks — keeps event loop responsive |
| Per-request error isolation | `try/except` → `ERROR` verdict | One bad packet doesn't kill the stream |
| Session persistence | ONNX session loaded once at `__init__` | Avoids ~100ms reload overhead per request |
| Stream tracking | `active_streams` Gauge inc/dec | Enables live connection monitoring |

---

#### `main.py` — Entry Point

**CLI flags:**
```
--port     gRPC port (default: 50051)
--model    path to model.onnx
--labels   path to label_mapping.json
--features path to feature_map.json
--debug    enable DEBUG logging
```

**Startup sequence:**
1. Parse args, configure logging (suppresses gRPC/onnxruntime noise at WARNING)
2. `InferenceEngine(model_path, label_mapping_path, feature_map_path)` — validates all artifacts
3. Register `SIGINT / SIGTERM` handlers → set `asyncio.Event`
4. `asyncio.wait([server_task, shutdown_event.wait()], FIRST_COMPLETED)` — graceful shutdown on signal

---

#### `model_store/` — Versioned Artifacts

| File | Size | Purpose |
|---|---|---|
| `model.onnx` | 19.6 MB | **Production** — ONNX Runtime inference |
| `model.json` | 38.8 MB | Backup — native XGBoost format |
| `training_metadata.json` | ~713 B | Reproducibility record (version, metrics, hyperparams) |

Shared artifacts in `data/processed/`:

| File | Used by |
|---|---|
| `scaler.pkl` | `InferenceEngine._apply_preprocessing()` |
| `label_mapping.json` | `InferenceEngine` — int → attack name |
| `feature_map.json` | `InferenceEngine` validation + `HEAVY_TAIL_FEATURES` mask |

---

## Service 3 — API (`services/api/`, Go)

**Role:** REST API + SSE real-time push for the dashboard  
**Port:** `:8080`  
**Language:** Go  
**Key libraries:** `gin-gonic/gin`, `pgx/v5`, `golang-jwt/jwt`, `gin-contrib/cors`

### Internal Packages

#### `internal/router` — Route Registration

File: `router.go`

```
gin.Engine (Release mode)
  ├── gin.Recovery()          panic → 500, no crash
  ├── gin.Logger()            structured request logging
  └── cors.New(*)             allow all origins (production tightens via env)

/api/v1/ (public)
  ├── GET  /health            → HealthCheck
  └── POST /auth/login        → Login

/api/v1/ (JWT-protected)
  ├── GET  /incidents         → ListIncidents
  ├── GET  /incidents/stream  → StreamIncidents (SSE)
  └── GET  /stats/summary     → GetSummary
```

---

#### `internal/middleware` — JWT Auth

File: `auth.go`

`RequireAuth(jwtSecret)` Gin middleware:
1. Reads `Authorization: Bearer <token>` header
2. Validates HMAC-SHA256 signature with `JWT_SECRET` env var
3. Checks `ExpiresAt` claim
4. Sets `username` and `role` in Gin context
5. Returns `401` if any check fails

---

#### `internal/handler` — HTTP Handlers

**`handler.go`**

| Endpoint | SQL used | Notes |
|---|---|---|
| `GET /incidents` | Dynamic `WHERE 1=1 + AND clauses` | Filters: `?label=`, `?src_ip=`, `?status=`; paginated `LIMIT/OFFSET` |
| `GET /stats/summary` | 3 materialized views | `mv_attack_summary`, `mv_hourly_timeline`, `mv_protocol_breakdown` |
| `GET /health` | `pool.Ping()` | Returns `{status: "healthy"}` or `503` |

**Summary response fields:**
- `total_incidents` (index scan)
- `open_incidents` (partial index `idx_incidents_open`)
- `top_attack_types[]` — from `mv_attack_summary` (top 5, avg confidence)
- `recent_timeline[]` — from `mv_hourly_timeline` (last 24h, hourly buckets)
- `protocol_breakdown[]` — from `mv_protocol_breakdown` (TCP/UDP/ICMP/other)

**`auth_handler.go`**

`POST /api/v1/auth/login`:
1. Bind `{username, password}` JSON
2. Compare against `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars
3. Sign JWT (`HS256`, 24h expiry, issuer: `"packetlens-api"`)
4. Return `{token, expires_at, username, role: "admin"}`

**`sse.go` — `GET /incidents/stream`**

Server-Sent Events endpoint for real-time dashboard updates.

```
SSE Headers: Content-Type: text/event-stream
             Cache-Control: no-cache
             X-Accel-Buffering: no   ← disables nginx proxy buffering

Events:
  event: connected   data: {"status":"connected"}   (on connect)
  event: incident    data: <JSON payload>            (new incident)
  : heartbeat                                         (every 15s — keeps connection alive)
```

On client disconnect (`ctx.Done()`): goroutine exits cleanly, channel unsubscribed.

---

#### `internal/notifier` — PostgreSQL LISTEN/NOTIFY Hub

File: `notifier.go`

The real-time bridge between the database and the SSE clients.

**Architecture:**
```
PostgreSQL trigger (trg_incidents_notify)
        │
        │ pg_notify('incidents_new', row_to_json(NEW))
        ▼
Hub.listenLoop()  ← dedicated pgxpool connection, LISTEN incidents_new
        │
        │ WaitForNotification() (blocking)
        ▼
Hub.broadcast()
        │
        ├─► subscriber channel 1  (SSE client 1)
        ├─► subscriber channel 2  (SSE client 2)
        └─► ...

Each subscriber channel: buffered (64 messages)
Slow subscribers: dropped (non-blocking send) — clients catch up via REST
```

**`RunMigrations()` (called at startup, idempotent):**
1. Creates `notify_new_incident()` PL/pgSQL trigger function
2. Creates `trg_incidents_notify` AFTER INSERT trigger on `incidents`
3. Creates 3 materialized views if they don't exist:
   - `mv_attack_summary` — attack type counts + avg confidence
   - `mv_hourly_timeline` — hourly incident buckets (last 24h)
   - `mv_protocol_breakdown` — incident counts per protocol number

**`StartRefreshLoop(ctx, pool, interval)`:** Refreshes all 3 views `CONCURRENTLY` on a fixed interval (non-blocking — does not lock the table).

**Auto-reconnect:** If the LISTEN connection drops, `Listen()` retries after 3s until context is cancelled.

---

#### `internal/db` — Connection Pool

File: `pool.go`

Creates a `pgxpool.Pool` from the `DATABASE_URL` environment variable with sensible defaults.

---

## Service 4 — Dashboard (`dashboard/`, Next.js)

**Role:** Web UI — real-time incident monitoring, charts, threat analysis  
**Port:** `:3000`  
**Stack:** Next.js 14 (App Router), TypeScript, Tailwind CSS, Recharts

### Directory Layout

```
src/
├── app/
│   ├── layout.tsx            Root layout (fonts, metadata)
│   ├── globals.css           Global Tailwind styles
│   ├── login/                Login page
│   └── (dashboard)/          Protected route group
│       ├── layout.tsx        Dashboard shell (sidebar, nav)
│       └── page.tsx          Main dashboard page
├── components/               Reusable UI components
│   ├── charts/               Recharts wrappers
│   │   ├── AttackTypeChart   Bar chart — top attack types
│   │   ├── TimelineChart     Area chart — hourly incidents
│   │   └── ProtocolChart     Pie chart — protocol breakdown
│   ├── IncidentTable         Paginated, filterable incident list
│   ├── StatCard              KPI widget (total/open incidents)
│   └── LiveIndicator         Animated dot for SSE connection status
├── context/
│   └── AuthContext           JWT storage + login/logout state
├── hooks/
│   ├── useIncidents          REST fetch with pagination + filters
│   ├── useSummary            REST fetch for stats widgets
│   └── useIncidentStream     SSE connection → real-time incident push
└── services/
    └── api.ts                Typed API client (fetch wrapper + JWT inject)
```

**Authentication flow:**
1. `POST /api/v1/auth/login` → JWT stored in `localStorage`
2. `middleware.ts` — Next.js middleware protects all `/dashboard/*` routes; redirects to `/login` if no valid token
3. `api.ts` injects `Authorization: Bearer <token>` on every request

**Real-time update flow:**
```
useIncidentStream()
    │
    ├── new EventSource("/api/v1/incidents/stream")
    │         with Authorization header
    │
    └── on "incident" event:
            parse JSON → prepend to incidents list
            trigger toast notification for non-Benign events
```

---

## Cross-Service Data Flow (End-to-End)

```
1. Packet arrives on NIC
       │
       ▼
2. capture/engine.go → pcap → gopacket.Packet
       │
       ▼
3. flow/manager.go → HandlePacket()
   ├── 5-tuple normalization → FlowKey
   ├── flow.Update() → Welford stats, TCP flags, IAT
   └── ShouldFlush() / idle timeout → flush to channel
       │
       ▼
4. transport/grpc.go → sendLoop()
   └── flow.ToFeatures() → [54]float32
   └── send FeatureVector protobuf over gRPC stream
       │
       ▼
5. inference/server.py → Classify() RPC
   └── asyncio.to_thread(engine.predict, features)
       │
       ▼
6. inference/core.py → InferenceEngine.predict()
   ├── _apply_preprocessing() [log1p + RobustScaler]
   └── ort.InferenceSession.run()
       │
       ▼
7. Verdict returned over gRPC stream
       │
       ▼
8. transport/grpc.go → receiveLoop()
   ├── metrics.VerdictsByLabel.Inc()
   ├── [if not Benign] → incidentChan (non-blocking)
   └── [if not Benign + threshold] → alertChan (non-blocking)
       │
       ├──────────────────────────────────────────────────────┐
       ▼                                                      ▼
9. incident/writer.go                             alerting/dispatcher.go
   └── batch accumulate                           └── rate limit check
   └── pgx.CopyFrom → PostgreSQL                 └── format Slack/Telegram/generic
                                                  └── HTTP POST to webhook
       │
       ▼
10. PostgreSQL trigger fires pg_notify('incidents_new', row_to_json(NEW))
       │
       ▼
11. api/notifier.go → Hub.listenLoop()
    └── WaitForNotification() → hub.broadcast(JSON)
       │
       ▼
12. sse.go → StreamIncidents()
    └── fmt.Fprintf("event: incident\ndata: %s\n\n", payload)
       │
       ▼
13. dashboard/hooks/useIncidentStream
    └── EventSource "incident" event → prepend to list → re-render
```

---

## Environment Variables Summary

| Service | Variable | Required | Purpose |
|---|---|---|---|
| Sniffer | `INTERFACE` | Yes | NIC to sniff (e.g. `eth0`) |
| Sniffer | `INFERENCE_ADDR` | Yes | `host:50051` |
| Sniffer | `DATABASE_URL` | Optional | Incident persistence |
| Sniffer | `WEBHOOK_URL` | Optional | Alert destination |
| Sniffer | `WEBHOOK_TYPE` | Optional | `slack`/`telegram`/`generic` |
| API | `DATABASE_URL` | Yes | pgxpool connection |
| API | `JWT_SECRET` | Yes | HMAC signing key |
| API | `ADMIN_USERNAME` | Yes | Dashboard login |
| API | `ADMIN_PASSWORD` | Yes | Dashboard login |
| Dashboard | `NEXT_PUBLIC_API_URL` | Yes | `http://api:8080` |

---

## Dockerfile Summary

Each service ships with its own Dockerfile:

| Service | Base | Notes |
|---|---|---|
| `sniffer/Dockerfile` | `golang:alpine` | Needs `libpcap-dev` at build, `libpcap` at runtime |
| `api/Dockerfile` | `golang:alpine` | Minimal — only Go stdlib + deps |
| `inference/Dockerfile` | `python:3.11-slim` | Installs `onnxruntime`, `grpcio`, `scikit-learn` |
| `dashboard/Dockerfile` | `node:20-alpine` | `npm run build` + `next start` |
