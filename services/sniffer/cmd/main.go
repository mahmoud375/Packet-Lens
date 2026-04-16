// PacketLens Sniffer - Network traffic capture and feature extraction
//
// This service captures network packets, aggregates them into flows,
// computes the 54 CIC-IDS features, and sends them to the Python
// inference service via gRPC for real-time intrusion detection.
//
// Usage:
//
//	go run ./services/sniffer/cmd -iface eth0 -server localhost:50051
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mahmoud375/PacketLens/services/sniffer/internal/alerting"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/capture"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/flow"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/incident"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/metrics"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/transport"
)

// Version information (set via ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Parse command-line flags
	var (
		iface  = flag.String("iface", "", "Network interface to capture (required)")
		server = flag.String("server", "localhost:50051", "gRPC inference server address")
		bpf    = flag.String("bpf", "ip", "BPF filter expression")
		list   = flag.Bool("list", false, "List available interfaces and exit")
		vers   = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	// Version flag
	if *vers {
		fmt.Printf("PacketLens Sniffer %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// List interfaces
	if *list {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			log.Fatalf("Failed to list interfaces: %v", err)
		}
		fmt.Println("Available network interfaces:")
		for _, name := range ifaces {
			fmt.Printf("  - %s\n", name)
		}
		os.Exit(0)
	}

	// Validate required flags
	if *iface == "" {
		log.Fatal("Error: -iface flag is required. Use -list to see available interfaces.")
	}

	// Setup logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Printf("PacketLens Sniffer %s starting...", version)
	log.Printf("  Interface: %s", *iface)
	log.Printf("  Server:    %s", *server)
	log.Printf("  BPF:       %s", *bpf)

	// Start Prometheus metrics server on port 9091
	metrics.StartServer("9091")
	log.Println("📊 Prometheus metrics available on :9091/metrics")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Create flow flush channel (buffered to prevent blocking)
	flushChan := make(chan *flow.Flow, 1000)

	// Initialize flow manager
	flowManager := flow.NewManager(flushChan)
	flowManager.Start()

	// Initialize gRPC client
	grpcClient := transport.NewClient(*server)
	if err := grpcClient.ConnectWithRetry(ctx, 5); err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer grpcClient.Close()

	// ─── Phase 1: Incident Persistence Layer ─────────────────────────────
	incidentCfg := incident.DefaultConfig()
	incidentCfg.PostgresDSN = os.Getenv("POSTGRES_DSN")

	var incidentStore *incident.Store
	var incidentChan chan incident.Incident
	var incidentWriter *incident.Writer

	if incidentCfg.PostgresDSN != "" {
		var storeErr error
		incidentStore, storeErr = incident.NewStore(ctx, incidentCfg)
		if storeErr != nil {
			log.Printf("[WARNING] Incident store unavailable: %v (continuing without persistence)", storeErr)
		} else {
			defer incidentStore.Close()
			incidentChan = make(chan incident.Incident, incidentCfg.ChannelSize)
			incidentWriter = incident.NewWriter(incidentStore, incidentChan)
			incidentWriter.Start(ctx)
			log.Println("📝 Incident persistence enabled (PostgreSQL)")
		}
	} else {
		log.Println("[INFO] POSTGRES_DSN not set — incident persistence disabled")
	}

	// ─── Phase 2: Alerting Subsystem ───────────────────────────────────
	alertCfg := alerting.DefaultConfig()
	alertCfg.WebhookURL = os.Getenv("ALERT_WEBHOOK_URL")
	alertCfg.WebhookType = os.Getenv("ALERT_WEBHOOK_TYPE")
	alertCfg.TelegramChatID = os.Getenv("ALERT_TELEGRAM_CHAT_ID")

	if alertCfg.WebhookType == "" {
		alertCfg.WebhookType = "generic"
	}

	var alertChan chan alerting.Alert
	var alertDispatcher *alerting.Dispatcher

	if alertCfg.WebhookURL != "" {
		alertChan = make(chan alerting.Alert, alertCfg.ChannelSize)
		alertDispatcher = alerting.NewDispatcher(alertChan, alertCfg)
		alertDispatcher.Start(ctx)
		log.Printf("🔔 Alerting enabled (type=%s)", alertCfg.WebhookType)
	} else {
		log.Println("[INFO] ALERT_WEBHOOK_URL not set — alerting disabled")
	}

	// Start gRPC sender
	sender := transport.NewSender(grpcClient, flushChan, incidentChan, incidentCfg, alertChan, alertCfg)
	sender.Start(ctx)

	// Initialize capture engine
	captureConfig := capture.Config{
		Interface:   *iface,
		SnapLen:     65535,
		Promiscuous: true,
		BPFFilter:   *bpf,
	}
	engine := capture.NewEngine(captureConfig, flowManager)

	// Run capture (blocks until context cancelled)
	log.Println("Starting packet capture...")
	if err := engine.Run(ctx); err != nil {
		log.Printf("Capture error: %v", err)
	}

	// Graceful shutdown
	log.Println("Shutting down...")
	flowManager.Stop()
	sender.Wait()

	// Wait for the incident writer to flush its final batch
	if incidentWriter != nil {
		incidentWriter.Wait()
		log.Println("📝 Incident writer shut down cleanly")
	}

	// Wait for the alert dispatcher to finish sending
	if alertDispatcher != nil {
		alertDispatcher.Wait()
		log.Println("🔔 Alert dispatcher shut down cleanly")
	}

	// Print final statistics
	pkts, flows := flowManager.Stats()
	sent, errors := sender.Stats()
	log.Printf("Final stats: %d packets, %d flows, %d sent, %d errors",
		pkts, flows, sent, errors)

	log.Println("PacketLens Sniffer stopped.")
}
