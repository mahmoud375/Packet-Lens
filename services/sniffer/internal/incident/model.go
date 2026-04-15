// Package incident provides persistent storage for high-confidence attack
// verdicts produced by the PacketLens inference pipeline.
//
// The package implements an asynchronous, channel-based writer that batches
// incidents into PostgreSQL without blocking the gRPC receive loop.
package incident

import (
	"net"
	"time"
)

// Incident represents a single high-confidence attack verdict that has been
// promoted from a transient gRPC Verdict message to a persistent, queryable
// database record.
//
// Fields are populated from two sources:
//   - The Verdict protobuf (Label, Confidence, InferenceTimeUs, FlowId)
//   - The flow.FlowKey lookup (SrcIP, DstIP, SrcPort, DstPort, Protocol)
type Incident struct {
	// ID is the database-generated primary key (BIGSERIAL).
	// Zero value when the incident has not yet been persisted.
	ID int64 `json:"id"`

	// DetectedAt is the timestamp when the verdict was received by the
	// Go sniffer's receiveLoop. This uses the sniffer's wall clock, not
	// the inference server's clock, to avoid cross-service clock skew.
	DetectedAt time.Time `json:"detected_at"`

	// Network 5-tuple from flow.FlowKey
	SrcIP    net.IP `json:"src_ip"`
	DstIP    net.IP `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`

	// ML verdict fields from the Verdict protobuf
	AttackType  string  `json:"attack_type"`
	Confidence  float32 `json:"confidence"`
	InferenceUs int64   `json:"inference_us"`
	FlowID      string  `json:"flow_id"`

	// Incident lifecycle (managed via the Management API in Phase 3)
	Status    string     `json:"status"`     // open | acknowledged | blocked | false_positive
	BlockedAt *time.Time `json:"blocked_at"` // nil until the IP is added to the nftables blocklist
	Notes     string     `json:"notes"`      // Free-text analyst notes
}

// IncidentStatus constants for the incident lifecycle state machine.
const (
	StatusOpen          = "open"
	StatusAcknowledged  = "acknowledged"
	StatusBlocked       = "blocked"
	StatusFalsePositive = "false_positive"
)
