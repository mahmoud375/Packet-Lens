// Package capture provides the packet capture engine using gopacket/pcap.
package capture

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/mahmoud375/PacketLens/services/sniffer/internal/flow"
)

// Engine wraps pcap capture with flow aggregation.
type Engine struct {
	iface       string
	snapLen     int32
	promisc     bool
	timeout     time.Duration
	bpfFilter   string
	flowManager *flow.Manager
}

// Config holds capture engine configuration.
type Config struct {
	Interface   string
	SnapLen     int32
	Promiscuous bool
	Timeout     time.Duration
	BPFFilter   string
}

// DefaultConfig returns sensible defaults for packet capture.
func DefaultConfig(iface string) Config {
	return Config{
		Interface:   iface,
		SnapLen:     65535,             // Capture full packets
		Promiscuous: true,              // Capture all traffic on interface
		Timeout:     pcap.BlockForever, // Don't timeout reads
		BPFFilter:   "ip",              // Only IP traffic
	}
}

// NewEngine creates a new capture engine.
func NewEngine(cfg Config, flowManager *flow.Manager) *Engine {
	return &Engine{
		iface:       cfg.Interface,
		snapLen:     cfg.SnapLen,
		promisc:     cfg.Promiscuous,
		timeout:     cfg.Timeout,
		bpfFilter:   cfg.BPFFilter,
		flowManager: flowManager,
	}
}

// Run starts packet capture and blocks until context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	// Open the interface for live capture
	handle, err := pcap.OpenLive(e.iface, e.snapLen, e.promisc, e.timeout)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", e.iface, err)
	}
	defer handle.Close()

	// Apply BPF filter if specified
	if e.bpfFilter != "" {
		if err := handle.SetBPFFilter(e.bpfFilter); err != nil {
			return fmt.Errorf("failed to set BPF filter '%s': %w", e.bpfFilter, err)
		}
		log.Printf("[Capture] BPF filter applied: %s", e.bpfFilter)
	}

	log.Printf("[Capture] Started on interface: %s (snaplen=%d, promisc=%v)",
		e.iface, e.snapLen, e.promisc)

	// Create packet source with NoCopy for performance
	// NoCopy means the packet data buffer is reused - we must copy data if we need to keep it
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.DecodeStreamsAsDatagrams = true

	// Statistics tracking
	var packetCount int64
	lastReport := time.Now()

	// Process packets until context is cancelled
	packets := packetSource.Packets()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[Capture] Shutdown requested, processed %d packets", packetCount)
			return nil

		case packet, ok := <-packets:
			if !ok {
				log.Println("[Capture] Packet source closed")
				return nil
			}

			packetCount++
			e.flowManager.HandlePacket(packet)

			// Periodic statistics (every 10 seconds)
			if time.Since(lastReport) > 10*time.Second {
				pkts, flows := e.flowManager.Stats()
				log.Printf("[Capture] Stats: %d packets captured, %d packets processed, %d unique flows",
					packetCount, pkts, flows)
				lastReport = time.Now()
			}
		}
	}
}

// ListInterfaces returns available network interfaces.
func ListInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var names []string
	for _, dev := range devices {
		names = append(names, dev.Name)
	}
	return names, nil
}
