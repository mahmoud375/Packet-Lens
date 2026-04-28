# PacketLens — Proto Contract & Database Schema

## Source Files

| File | Role |
|---|---|
| `proto/packetlens.proto` | Single source of truth for the gRPC contract |
| `gen/go/packetlens/` | Auto-generated Go stubs (do not edit) |
| `services/inference/proto/` | Auto-generated Python stubs (do not edit) |
| `deploy/postgres/init.sql` | Incidents table DDL — runs on first container start |
| `deploy/postgres/002_materialized_views.sql` | Materialized views + pg_notify trigger |

---

## Part 1 — gRPC Contract (`packetlens.proto`)

### Message 1 — `FeatureVector` (Go → Python)

```protobuf
message FeatureVector {
  string flow_id      = 1;   // "192.168.1.1:443→10.0.0.5:12345/6"
  repeated float features = 2;   // 54 float32 values
  int64 timestamp_ns  = 3;   // capture time (Unix nanoseconds)
}
```

| Field | Meaning |
|---|---|
| `flow_id` | 5-tuple string from `FlowKey.String()`. Echoed back in `Verdict` to correlate response → flow |
| `features` | 54 float32 values in CIC-IDS order, produced by `flow.ToFeatures()` |
| `timestamp_ns` | `flow.LastSeen.UnixNano()` — last packet timestamp of the flow |

`repeated float` uses packed encoding in proto3 — efficient for 54 floats (~220 bytes/message).

---

### Message 2 — `Verdict` (Python → Go)

```protobuf
message Verdict {
  string flow_id           = 1;   // echoed from FeatureVector
  string label             = 2;   // "Benign" / "DDoS-HOIC" / "ERROR"
  float  confidence        = 3;   // 0.0 – 1.0
  int64  inference_time_us = 4;   // server-side ONNX latency (µs)
}
```

| Field | Meaning |
|---|---|
| `flow_id` | Echoed back — Go uses this to match verdict to original flow |
| `label` | Attack class from `label_mapping.json`. `"ERROR"` = per-request failure (stream stays alive) |
| `confidence` | `max(softmax_probabilities)` — used for `ShouldLog()` / `ShouldAlert()` thresholding |
| `inference_time_us` | ONNX wall time — tracked in Prometheus histogram |

---

### Service

```protobuf
service InferenceService {
  rpc Classify(stream FeatureVector) returns (stream Verdict);
}
```

Bidirectional streaming — one long-lived connection per sniffer session. Both sides send independently.

**Why streaming instead of unary RPCs?**

| | Unary | Bidirectional Stream |
|---|---|---|
| Connection overhead | Per request | Once per session |
| At 1000 flows/sec | 1000 TCP handshakes/sec | 0 extra handshakes |
| Error isolation | Per-call | Per-message |

---

### Code Generation (`make proto`)

**Go:**
```bash
protoc --proto_path=proto --go_out=gen/go --go-grpc_out=gen/go proto/packetlens.proto
```
Produces `packetlens.pb.go` (message structs) + `packetlens_grpc.pb.go` (client/server interfaces).

**Python:**
```bash
python -m grpc_tools.protoc --proto_path=proto \
  --python_out=services/inference/proto \
  --pyi_out=services/inference/proto \
  --grpc_python_out=services/inference/proto proto/packetlens.proto
```
Then a `sed` fixes absolute imports → relative imports in the grpc stub (required for package import).

---

## Part 2 — Database Schema

### Table: `incidents`

The only table. Every non-Benign verdict above the confidence threshold is persisted here via `pgx.CopyFrom`.

| Column | Type | Notes |
|---|---|---|
| `id` | `BIGSERIAL PK` | Auto-increment — supports billions of rows |
| `detected_at` | `TIMESTAMPTZ NOT NULL DEFAULT NOW()` | When the verdict arrived at the Go sniffer |
| `src_ip` | `INET NOT NULL` | Native PostgreSQL inet — stores IPv4/IPv6 compactly |
| `dst_ip` | `INET NOT NULL` | |
| `src_port` | `INTEGER NOT NULL` | |
| `dst_port` | `INTEGER NOT NULL` | |
| `protocol` | `SMALLINT NOT NULL` | 6=TCP, 17=UDP, 1=ICMP |
| `attack_type` | `TEXT NOT NULL` | e.g. `DDoS-HOIC`, `BruteForce-SSH` |
| `confidence` | `REAL NOT NULL` | [0.0, 1.0] |
| `inference_us` | `INTEGER NOT NULL` | ONNX latency in microseconds |
| `flow_id` | `TEXT NOT NULL` | Original 5-tuple string from flow manager |
| `status` | `TEXT NOT NULL DEFAULT 'open'` | Lifecycle state |
| `blocked_at` | `TIMESTAMPTZ NULL` | When src_ip was blocklisted (Phase 4) |
| `notes` | `TEXT NULL` | Analyst notes (Phase 3 Management API) |

**Constraints:**
```sql
CHECK (status IN ('open', 'acknowledged', 'blocked', 'false_positive'))
CHECK (confidence >= 0.0 AND confidence <= 1.0)
CHECK (protocol >= 0 AND protocol <= 255)
CHECK (src_port >= 0 AND src_port <= 65535)
CHECK (dst_port >= 0 AND dst_port <= 65535)
```

**Incident lifecycle:**
```
open → acknowledged → blocked
  └──────────────→ false_positive
```

---

### Indexes

| Index | Definition | Query it serves |
|---|---|---|
| `idx_incidents_detected_at` | `(detected_at DESC)` | Latest incidents first |
| `idx_incidents_src_ip` | `(src_ip)` | Analyst: "all incidents from this IP" |
| `idx_incidents_attack_type` | `(attack_type)` | Group by attack type |
| `idx_incidents_status` | `(status)` | Filter by lifecycle state |
| `idx_incidents_open` ⭐ | `(detected_at DESC) WHERE status = 'open'` | Most common dashboard query |

`idx_incidents_open` is a **partial index** — it only contains rows where `status = 'open'`. It is far smaller than a full index and PostgreSQL uses it automatically for `WHERE status = 'open'` queries, avoiding scanning closed/false_positive rows entirely.

---

### Materialized Views

Pre-computed aggregations. Dashboard reads are O(1) instead of O(n) full-table scans. Each has a `UNIQUE INDEX` to enable `REFRESH CONCURRENTLY` (no read lock during refresh).

#### `mv_attack_summary`
```sql
SELECT attack_type, COUNT(*) AS count, AVG(confidence)::real AS avg_confidence
FROM incidents GROUP BY attack_type ORDER BY count DESC;
```
→ `GET /api/v1/stats/summary` → `top_attack_types[]`

#### `mv_hourly_timeline`
```sql
SELECT date_trunc('hour', detected_at) AS hour, COUNT(*) AS count
FROM incidents WHERE detected_at >= NOW() - INTERVAL '24 hours'
GROUP BY hour ORDER BY hour ASC;
```
→ `GET /api/v1/stats/summary` → `recent_timeline[]`

#### `mv_protocol_breakdown`
```sql
SELECT protocol, COUNT(*) AS count
FROM incidents GROUP BY protocol ORDER BY count DESC;
```
→ `GET /api/v1/stats/summary` → `protocol_breakdown[]`

**Refresh:** `notifier.StartRefreshLoop()` in the Go API calls `REFRESH MATERIALIZED VIEW CONCURRENTLY` on all 3 on a fixed interval. No reads blocked during refresh.

---

### pg_notify Trigger (Real-Time SSE Pipeline)

```sql
CREATE OR REPLACE FUNCTION notify_new_incident() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('incidents_new', row_to_json(NEW)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incidents_notify
    AFTER INSERT ON incidents
    FOR EACH ROW EXECUTE FUNCTION notify_new_incident();
```

**Flow:**
```
INSERT into incidents
    │
    ▼
trg_incidents_notify fires
    │
    ▼
pg_notify('incidents_new', row_to_json(NEW))
    │
    ▼
Go API Hub.listenLoop() → WaitForNotification() unblocks
    │
    ▼
hub.broadcast(JSON) → all SSE subscriber channels
    │
    ▼
StreamIncidents() → "event: incident\ndata: {...}\n\n"
    │
    ▼
Dashboard EventSource receives it in < 5ms
```

Why push instead of polling: no added latency, no wasted queries when idle.

---

### Initialization Order

Docker runs `/docker-entrypoint-initdb.d/` scripts alphabetically on first start:
```
001_schema.sql   ← creates incidents table + indexes
002_views.sql    ← creates materialized views + trigger
```
Order matters — views depend on the table existing first.
