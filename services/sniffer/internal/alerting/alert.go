package alerting

import (
	"fmt"
	"net"
	"time"
)

// Alert represents a single high-confidence threat notification ready for
// dispatch to a webhook. Built from the gRPC verdict + parsed FlowKey.
type Alert struct {
	// Timestamp when the verdict was received
	DetectedAt time.Time `json:"detected_at"`

	// 5-tuple context
	SrcIP    net.IP `json:"src_ip"`
	DstIP    net.IP `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`

	// Inference result
	AttackType  string  `json:"attack_type"`
	Confidence  float32 `json:"confidence"`
	InferenceUs int64   `json:"inference_us"`

	// Original flow identifier
	FlowID string `json:"flow_id"`
}

// ProtocolName returns a human-readable protocol name.
func (a Alert) ProtocolName() string {
	switch a.Protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("IP/%d", a.Protocol)
	}
}

// Summary returns a single-line human-readable description of the alert.
func (a Alert) Summary() string {
	return fmt.Sprintf("🚨 %s detected from %s:%d → %s:%d (%s) — %.1f%% confidence",
		a.AttackType,
		a.SrcIP, a.SrcPort,
		a.DstIP, a.DstPort,
		a.ProtocolName(),
		a.Confidence*100,
	)
}
