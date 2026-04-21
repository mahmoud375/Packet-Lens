-- =============================================================================
-- PacketLens NIPS v2.0 — Materialized Views & Real-Time Notifications
-- =============================================================================
-- Runs on first PostgreSQL initialization (after init.sql).
-- Creates pre-computed dashboard aggregations and a NOTIFY trigger
-- for real-time SSE streaming.
-- =============================================================================

-- ─── Materialized View: Top Attack Types ────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_attack_summary AS
SELECT
    attack_type,
    COUNT(*)              AS count,
    AVG(confidence)::real AS avg_confidence
FROM incidents
GROUP BY attack_type
ORDER BY count DESC;

CREATE UNIQUE INDEX IF NOT EXISTS uidx_mv_attack_summary_type
    ON mv_attack_summary (attack_type);

-- ─── Materialized View: Hourly Timeline (last 24h) ─────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_hourly_timeline AS
SELECT
    date_trunc('hour', detected_at) AS hour,
    COUNT(*)                        AS count
FROM incidents
WHERE detected_at >= NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour ASC;

CREATE UNIQUE INDEX IF NOT EXISTS uidx_mv_hourly_timeline_hour
    ON mv_hourly_timeline (hour);

-- ─── Materialized View: Protocol Breakdown ──────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_protocol_breakdown AS
SELECT
    protocol,
    COUNT(*) AS count
FROM incidents
GROUP BY protocol
ORDER BY count DESC;

CREATE UNIQUE INDEX IF NOT EXISTS uidx_mv_protocol_breakdown_proto
    ON mv_protocol_breakdown (protocol);

-- ─── NOTIFY Trigger: Broadcast New Incidents via pg_notify ──────────────────
-- The Go API LISTENs on 'incidents_new' and fans out to SSE clients.

CREATE OR REPLACE FUNCTION notify_new_incident() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('incidents_new', row_to_json(NEW)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incidents_notify ON incidents;
CREATE TRIGGER trg_incidents_notify
    AFTER INSERT ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION notify_new_incident();
