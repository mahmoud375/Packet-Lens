-- =============================================================================
-- PacketLens NIPS v2.0 — Incident Schema
-- =============================================================================
--
-- This script runs automatically on first PostgreSQL container startup via
-- Docker's /docker-entrypoint-initdb.d/ mechanism.
--
-- Schema: public (default)
-- Table:  incidents — stores high-confidence attack verdicts from the ONNX
--         inference pipeline for SOC review and automated mitigation.
-- =============================================================================

CREATE TABLE IF NOT EXISTS incidents (
    id           BIGSERIAL    PRIMARY KEY,
    detected_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    src_ip       INET         NOT NULL,
    dst_ip       INET         NOT NULL,
    src_port     INTEGER      NOT NULL,
    dst_port     INTEGER      NOT NULL,
    protocol     SMALLINT     NOT NULL,
    attack_type  TEXT         NOT NULL,
    confidence   REAL         NOT NULL,
    inference_us INTEGER      NOT NULL,
    flow_id      TEXT         NOT NULL,

    -- Incident lifecycle management (Phase 3: Management API)
    status       TEXT         NOT NULL DEFAULT 'open',
    blocked_at   TIMESTAMPTZ,
    notes        TEXT,

    -- Constraints
    CONSTRAINT chk_status CHECK (status IN ('open', 'acknowledged', 'blocked', 'false_positive')),
    CONSTRAINT chk_confidence CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CONSTRAINT chk_protocol CHECK (protocol >= 0 AND protocol <= 255),
    CONSTRAINT chk_port_src CHECK (src_port >= 0 AND src_port <= 65535),
    CONSTRAINT chk_port_dst CHECK (dst_port >= 0 AND dst_port <= 65535)
);

-- =============================================================================
-- Indices for common query patterns
-- =============================================================================

-- Dashboard: "show me the latest incidents"
CREATE INDEX IF NOT EXISTS idx_incidents_detected_at
    ON incidents (detected_at DESC);

-- Analyst: "show me all incidents from this source IP"
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip
    ON incidents (src_ip);

-- Dashboard: "show me incidents grouped by attack type"
CREATE INDEX IF NOT EXISTS idx_incidents_attack_type
    ON incidents (attack_type);

-- Lifecycle: "show me all open/acknowledged incidents"
CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);

-- Fast path: the most common dashboard query is "open incidents, newest first"
-- A partial index avoids scanning closed/false_positive rows entirely.
CREATE INDEX IF NOT EXISTS idx_incidents_open
    ON incidents (detected_at DESC)
    WHERE status = 'open';

-- =============================================================================
-- Comments for documentation
-- =============================================================================

COMMENT ON TABLE incidents IS 'High-confidence attack verdicts from the PacketLens ONNX inference pipeline.';
COMMENT ON COLUMN incidents.detected_at IS 'Timestamp when the verdict was received by the Go sniffer.';
COMMENT ON COLUMN incidents.src_ip IS 'Source IP address of the attacking flow (from FlowKey).';
COMMENT ON COLUMN incidents.dst_ip IS 'Destination IP address of the target (from FlowKey).';
COMMENT ON COLUMN incidents.protocol IS 'IP protocol number (6=TCP, 17=UDP, 1=ICMP).';
COMMENT ON COLUMN incidents.attack_type IS 'ML model prediction label (e.g., DDoS-HOIC, BruteForce-SSH).';
COMMENT ON COLUMN incidents.confidence IS 'Model confidence score [0.0, 1.0].';
COMMENT ON COLUMN incidents.inference_us IS 'Server-side ONNX inference latency in microseconds.';
COMMENT ON COLUMN incidents.flow_id IS 'Original 5-tuple string identifier from the Go flow manager.';
COMMENT ON COLUMN incidents.status IS 'Incident lifecycle state: open → acknowledged → blocked | false_positive.';
COMMENT ON COLUMN incidents.blocked_at IS 'Timestamp when the source IP was added to the nftables blocklist (Phase 4).';
COMMENT ON COLUMN incidents.notes IS 'Free-text analyst notes (set via Management API, Phase 3).';
