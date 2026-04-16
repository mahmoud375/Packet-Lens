// Package metrics provides Prometheus instrumentation for the PacketLens sniffer.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// PacketsCaptured tracks total packets captured.
	PacketsCaptured = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "packets_captured_total",
		Help:      "Total number of packets captured",
	})

	// ActiveFlows tracks current number of active flows being tracked.
	ActiveFlows = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "packetlens",
		Name:      "active_flows",
		Help:      "Current number of active network flows",
	})

	// FlowsFlushed tracks total flows flushed to the inference service.
	FlowsFlushed = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "flows_flushed_total",
		Help:      "Total number of flows flushed for inference",
	})

	// FlowsDropped tracks flows dropped due to channel full.
	FlowsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "flows_dropped_total",
		Help:      "Total number of flows dropped (channel full)",
	})

	// GRPCSendErrors tracks gRPC send errors.
	GRPCSendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "grpc_send_errors_total",
		Help:      "Total number of gRPC send errors",
	})

	// VerdictsByLabel tracks verdicts received from inference server.
	VerdictsByLabel = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "verdicts_received_total",
		Help:      "Verdicts received by label",
	}, []string{"label"})

	// ──────────────────────────────────────────────────────────────
	// Phase 1: Incident Persistence Metrics
	// ──────────────────────────────────────────────────────────────

	// IncidentsWritten tracks total incidents successfully persisted to PostgreSQL.
	IncidentsWritten = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "incidents_written_total",
		Help:      "Total number of incidents successfully written to PostgreSQL",
	})

	// IncidentsDropped tracks incidents dropped due to full channel (non-blocking send).
	IncidentsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "incidents_dropped_total",
		Help:      "Total number of incidents dropped because the writer channel was full",
	})

	// IncidentWriteErrors tracks PostgreSQL batch write failures.
	IncidentWriteErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "incident_write_errors_total",
		Help:      "Total number of PostgreSQL batch write failures",
	})

	// ──────────────────────────────────────────────────────────────
	// Phase 2: Alerting Metrics
	// ──────────────────────────────────────────────────────────────

	// AlertsSent tracks total alerts successfully delivered to webhook.
	AlertsSent = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "alerts_sent_total",
		Help:      "Total number of alerts successfully sent to the webhook",
	})

	// AlertsSuppressed tracks alerts suppressed by the rate limiter.
	AlertsSuppressed = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "alerts_suppressed_total",
		Help:      "Total number of alerts suppressed by per-label cooldown or global burst ceiling",
	})

	// AlertSendErrors tracks webhook delivery failures (HTTP errors, timeouts).
	AlertSendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "alert_send_errors_total",
		Help:      "Total number of webhook delivery failures",
	})

	// AlertsDropped tracks alerts dropped due to full channel (non-blocking send).
	AlertsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "packetlens",
		Name:      "alerts_dropped_total",
		Help:      "Total number of alerts dropped because the dispatcher channel was full",
	})

	once sync.Once
)

// StartServer starts the Prometheus metrics HTTP server on the given port.
// This function is safe to call multiple times; only the first call starts the server.
func StartServer(port string) {
	once.Do(func() {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			if err := http.ListenAndServe(":"+port, nil); err != nil {
				// Log error but don't crash - metrics are optional
				println("[Metrics] Failed to start server:", err.Error())
			}
		}()
	})
}
