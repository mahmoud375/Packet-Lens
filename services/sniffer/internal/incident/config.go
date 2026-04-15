package incident

import "time"

// Config holds all tunables for the incident persistence layer.
//
// These values control which verdicts are promoted to incidents, how they
// are batched, and how the writer goroutine behaves under load.
type Config struct {
	// ──────────────────────────────────────────────────────────────────────
	// Database
	// ──────────────────────────────────────────────────────────────────────

	// PostgresDSN is the connection string for the PostgreSQL database.
	// Format: "postgres://user:password@host:port/dbname?sslmode=disable"
	PostgresDSN string

	// MaxPoolConns is the maximum number of connections in the pgxpool.
	// The writer goroutine is single-threaded, so 4 connections is generous.
	// Default: 4
	MaxPoolConns int32

	// ──────────────────────────────────────────────────────────────────────
	// Filtering
	// ──────────────────────────────────────────────────────────────────────

	// ConfidenceFloor is the minimum confidence score required for a verdict
	// to be promoted to a persistent incident. Verdicts below this threshold
	// are silently discarded.
	// Default: 0.85
	ConfidenceFloor float32

	// ExcludeLabels is a set of verdict labels that should never be logged,
	// regardless of confidence. Typically contains "Benign".
	ExcludeLabels map[string]struct{}

	// ──────────────────────────────────────────────────────────────────────
	// Batching
	// ──────────────────────────────────────────────────────────────────────

	// BatchSize is the number of incidents accumulated before a batch flush
	// is triggered. Larger batches improve INSERT throughput but increase
	// the latency between detection and database visibility.
	// Default: 50
	BatchSize int

	// FlushInterval is the maximum time between batch flushes. Even if the
	// batch buffer is not full, incidents will be flushed after this duration
	// to ensure timely visibility in the Management UI.
	// Default: 1s
	FlushInterval time.Duration

	// ChannelSize is the capacity of the buffered incidentChan. When the
	// channel is full, new incidents are dropped (non-blocking send) and a
	// Prometheus counter is incremented.
	// Default: 5000
	ChannelSize int
}

// DefaultConfig returns a Config with production-safe defaults.
func DefaultConfig() Config {
	return Config{
		MaxPoolConns:    4,
		ConfidenceFloor: 0.85,
		ExcludeLabels: map[string]struct{}{
			"Benign": {},
		},
		BatchSize:     50,
		FlushInterval: 1 * time.Second,
		ChannelSize:   5000,
	}
}

// ShouldLog returns true if the given verdict passes the filter criteria
// and should be promoted to a persistent incident.
func (c *Config) ShouldLog(label string, confidence float32) bool {
	if confidence < c.ConfidenceFloor {
		return false
	}
	if _, excluded := c.ExcludeLabels[label]; excluded {
		return false
	}
	return true
}
