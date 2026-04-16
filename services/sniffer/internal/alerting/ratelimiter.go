package alerting

import (
	"sync"
	"time"
)

// RateLimiter enforces two constraints:
//
//  1. Per-label cooldown: only 1 alert per attack type per PerLabelCooldown
//     window. Prevents alert storms during sustained attacks.
//
//  2. Global burst ceiling: a maximum of GlobalBurstLimit alerts within
//     GlobalBurstWindow. Acts as a circuit breaker to protect webhook APIs.
type RateLimiter struct {
	mu sync.Mutex

	// Per-label cooldown
	perLabelCooldown time.Duration
	lastAlertByLabel map[string]time.Time

	// Global burst circuit breaker
	burstLimit  int
	burstWindow time.Duration
	burstTimes  []time.Time // sliding window of recent alert timestamps
}

// NewRateLimiter creates a RateLimiter with the given configuration.
func NewRateLimiter(cfg Config) *RateLimiter {
	return &RateLimiter{
		perLabelCooldown: cfg.PerLabelCooldown,
		lastAlertByLabel: make(map[string]time.Time),
		burstLimit:       cfg.GlobalBurstLimit,
		burstWindow:      cfg.GlobalBurstWindow,
		burstTimes:       make([]time.Time, 0, cfg.GlobalBurstLimit),
	}
}

// Allow checks whether an alert for the given label should be sent.
// Returns true if the alert passes both the per-label cooldown and the
// global burst ceiling. If allowed, internal state is updated atomically.
func (rl *RateLimiter) Allow(label string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// ── Check 1: Global burst circuit breaker ────────────────────────
	// Prune timestamps outside the window
	cutoff := now.Add(-rl.burstWindow)
	pruned := rl.burstTimes[:0]
	for _, t := range rl.burstTimes {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	rl.burstTimes = pruned

	if len(rl.burstTimes) >= rl.burstLimit {
		return false // circuit breaker tripped
	}

	// ── Check 2: Per-label cooldown ──────────────────────────────────
	if lastTime, ok := rl.lastAlertByLabel[label]; ok {
		if now.Sub(lastTime) < rl.perLabelCooldown {
			return false // still in cooldown for this label
		}
	}

	// ── Allowed: update state ────────────────────────────────────────
	rl.lastAlertByLabel[label] = now
	rl.burstTimes = append(rl.burstTimes, now)

	return true
}

// Stats returns the current number of tracked labels and burst count.
// Useful for debugging and Prometheus metrics.
func (rl *RateLimiter) Stats() (trackedLabels int, recentBursts int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Prune stale burst entries for accurate count
	now := time.Now()
	cutoff := now.Add(-rl.burstWindow)
	active := 0
	for _, t := range rl.burstTimes {
		if t.After(cutoff) {
			active++
		}
	}

	return len(rl.lastAlertByLabel), active
}
