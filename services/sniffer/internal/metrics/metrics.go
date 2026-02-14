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
