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

	"github.com/mahmoud375/PacketLens/services/sniffer/internal/capture"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/flow"
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

	// Start gRPC sender
	sender := transport.NewSender(grpcClient, flushChan)
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

	// Print final statistics
	pkts, flows := flowManager.Stats()
	sent, errors := sender.Stats()
	log.Printf("Final stats: %d packets, %d flows, %d sent, %d errors",
		pkts, flows, sent, errors)

	log.Println("PacketLens Sniffer stopped.")
}
