// Package alerting provides an async, rate-limited webhook notification
// dispatcher for the PacketLens NIPS pipeline. It sends rich push alerts
// (Slack, Telegram, or generic webhook) for high-confidence threats without
// blocking the gRPC inference hot path.
package alerting

import "time"

// Config holds all tunables for the alerting subsystem.
type Config struct {
	// ──────────────────────────────────────────────────────────────────────
	// Webhook
	// ──────────────────────────────────────────────────────────────────────

	// WebhookURL is the HTTP POST endpoint for alerts.
	// Supports Slack incoming webhooks, Telegram bot API, or any generic
	// endpoint that accepts JSON. Leave empty to disable alerting.
	WebhookURL string

	// WebhookType selects the payload format for the webhook.
	// Supported values: "slack", "telegram", "generic" (default).
	WebhookType string

	// TelegramChatID is the chat/group ID for Telegram alerts.
	// Only used when WebhookType is "telegram".
	TelegramChatID string

	// ──────────────────────────────────────────────────────────────────────
	// Rate Limiting
	// ──────────────────────────────────────────────────────────────────────

	// PerLabelCooldown is the minimum interval between alerts for the same
	// attack label (e.g., "DoS-Heartbleed"). During a DDoS storm, this
	// prevents thousands of identical alerts.
	// Default: 60s
	PerLabelCooldown time.Duration

	// GlobalBurstLimit is the maximum number of alerts allowed within
	// GlobalBurstWindow. Once this ceiling is hit, ALL alerts are
	// suppressed until the window resets — a circuit breaker.
	// Default: 10 alerts per 60 seconds.
	GlobalBurstLimit int
	GlobalBurstWindow time.Duration

	// ──────────────────────────────────────────────────────────────────────
	// Channel & HTTP
	// ──────────────────────────────────────────────────────────────────────

	// ChannelSize is the capacity of the buffered alert channel.
	// When full, new alerts are dropped (non-blocking) and a Prometheus
	// counter is incremented.
	// Default: 10000 (absorb DDoS-triggered alert storms)
	ChannelSize int

	// HTTPTimeout is the maximum time allowed for each webhook POST.
	// Slow endpoints must not stall the dispatcher.
	// Default: 5s
	HTTPTimeout time.Duration

	// ConfidenceFloor is the minimum confidence for triggering an alert.
	// Typically higher than the incident persistence floor.
	// Default: 0.90
	ConfidenceFloor float32

	// ExcludeLabels is a set of verdict labels that never trigger alerts.
	ExcludeLabels map[string]struct{}
}

// DefaultConfig returns a Config with production-safe defaults.
func DefaultConfig() Config {
	return Config{
		WebhookType:       "generic",
		PerLabelCooldown:  60 * time.Second,
		GlobalBurstLimit:  10,
		GlobalBurstWindow: 60 * time.Second,
		ChannelSize:       10_000,
		HTTPTimeout:       5 * time.Second,
		ConfidenceFloor:   0.90,
		ExcludeLabels: map[string]struct{}{
			"Benign": {},
		},
	}
}

// ShouldAlert returns true if the given verdict should trigger an alert.
func (c *Config) ShouldAlert(label string, confidence float32) bool {
	if confidence < c.ConfidenceFloor {
		return false
	}
	if _, excluded := c.ExcludeLabels[label]; excluded {
		return false
	}
	return true
}
