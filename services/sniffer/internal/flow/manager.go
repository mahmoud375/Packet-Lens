// Package flow implements concurrent network flow tracking and feature extraction
// for the CIC-IDS 54-feature model.
package flow

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Constants for flow management
const (
	// FlowIdleTimeout defines how long a flow can be inactive before flushing
	FlowIdleTimeout = 5 * time.Second

	// FlowMaxPackets limits packets per flow to prevent memory explosion
	FlowMaxPackets = 10000

	// CleanupInterval defines how often to check for idle flows
	CleanupInterval = 1 * time.Second

	// ActiveIdleThreshold for active/idle period detection (1 second)
	ActiveIdleThreshold = 1 * time.Second
)

// Direction represents packet direction in a flow
type Direction int

const (
	Forward Direction = iota
	Backward
)

// FlowKey uniquely identifies a bidirectional network flow using 5-tuple.
// We normalize the key so that (A→B) and (B→A) map to the same flow.
type FlowKey struct {
	SrcIP    [16]byte // Supports both IPv4 and IPv6
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// String returns a human-readable representation of the flow key.
func (k FlowKey) String() string {
	srcIP := net.IP(k.SrcIP[:])
	dstIP := net.IP(k.DstIP[:])
	return fmt.Sprintf("%s:%d→%s:%d/%d", srcIP, k.SrcPort, dstIP, k.DstPort, k.Protocol)
}

// Flow represents an active network flow with all statistics needed for
// the 54-feature CIC-IDS model.
type Flow struct {
	Key       FlowKey
	FirstSeen time.Time
	LastSeen  time.Time

	// Packet counts
	FwdPackets int64
	BwdPackets int64

	// Byte counts
	FwdBytes int64
	BwdBytes int64

	// Per-packet length statistics
	FwdPktLen *RunningStats
	BwdPktLen *RunningStats
	AllPktLen *RunningStats

	// Inter-Arrival Time statistics
	FlowIAT *RunningStats
	FwdIAT  *RunningStats
	BwdIAT  *RunningStats

	// Last packet times for IAT calculation
	LastFwdTime time.Time
	LastBwdTime time.Time

	// Header lengths
	FwdHeaderLen int64
	BwdHeaderLen int64

	// TCP flags
	FwdPSHFlags int64
	SYNCount    int64
	URGCount    int64
	FINSeen     bool
	RSTSeen     bool

	// Window sizes (first packet only)
	InitFwdWinBytes int64
	InitBwdWinBytes int64
	InitWinSet      bool

	// Forward active data packets (packets with payload)
	FwdActDataPkts int64

	// Minimum forward segment size
	FwdSegSizeMin int64
	FwdSegMinSet  bool

	// Active/Idle period tracking
	ActivePeriods  *RunningStats
	IdlePeriods    *RunningStats
	LastActive     time.Time
	InActivePeriod bool

	// Mutex for thread safety
	mu sync.Mutex
}

// NewFlow creates a new flow with initialized statistics.
func NewFlow(key FlowKey, timestamp time.Time) *Flow {
	return &Flow{
		Key:           key,
		FirstSeen:     timestamp,
		LastSeen:      timestamp,
		FwdPktLen:     NewStats(),
		BwdPktLen:     NewStats(),
		AllPktLen:     NewStats(),
		FlowIAT:       NewStats(),
		FwdIAT:        NewStats(),
		BwdIAT:        NewStats(),
		ActivePeriods: NewStats(),
		IdlePeriods:   NewStats(),
		LastActive:    timestamp,
		FwdSegSizeMin: math.MaxInt64,
	}
}

// Update adds a packet to the flow and updates all statistics.
func (f *Flow) Update(
	timestamp time.Time,
	payloadLen int,
	headerLen int,
	direction Direction,
	tcpFlags *layers.TCP,
	windowSize uint16,
) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Update timing
	if timestamp.After(f.LastSeen) {
		// Calculate flow IAT
		iat := timestamp.Sub(f.LastSeen).Seconds() * 1e6 // microseconds
		f.FlowIAT.Update(iat)

		// Active/Idle period tracking
		if timestamp.Sub(f.LastSeen) > ActiveIdleThreshold {
			// This is an idle period
			if f.InActivePeriod {
				activeDuration := f.LastSeen.Sub(f.LastActive).Seconds() * 1e6
				f.ActivePeriods.Update(activeDuration)
				f.InActivePeriod = false
			}
			idleDuration := timestamp.Sub(f.LastSeen).Seconds() * 1e6
			f.IdlePeriods.Update(idleDuration)
			f.LastActive = timestamp
		} else {
			f.InActivePeriod = true
		}

		f.LastSeen = timestamp
	}

	// Update packet length stats
	pktLen := float64(payloadLen)
	f.AllPktLen.Update(pktLen)

	// Direction-specific updates
	if direction == Forward {
		f.FwdPackets++
		f.FwdBytes += int64(payloadLen)
		f.FwdPktLen.Update(pktLen)
		f.FwdHeaderLen += int64(headerLen)

		// Forward IAT
		if !f.LastFwdTime.IsZero() {
			fwdIAT := timestamp.Sub(f.LastFwdTime).Seconds() * 1e6
			f.FwdIAT.Update(fwdIAT)
		}
		f.LastFwdTime = timestamp

		// Forward active data packets
		if payloadLen > 0 {
			f.FwdActDataPkts++
		}

		// Minimum forward segment size
		if payloadLen > 0 && int64(payloadLen) < f.FwdSegSizeMin {
			f.FwdSegSizeMin = int64(payloadLen)
			f.FwdSegMinSet = true
		}
	} else {
		f.BwdPackets++
		f.BwdBytes += int64(payloadLen)
		f.BwdPktLen.Update(pktLen)
		f.BwdHeaderLen += int64(headerLen)

		// Backward IAT
		if !f.LastBwdTime.IsZero() {
			bwdIAT := timestamp.Sub(f.LastBwdTime).Seconds() * 1e6
			f.BwdIAT.Update(bwdIAT)
		}
		f.LastBwdTime = timestamp
	}

	// TCP flag counting
	if tcpFlags != nil {
		if tcpFlags.PSH && direction == Forward {
			f.FwdPSHFlags++
		}
		if tcpFlags.SYN {
			f.SYNCount++
		}
		if tcpFlags.URG {
			f.URGCount++
		}
		if tcpFlags.FIN {
			f.FINSeen = true
		}
		if tcpFlags.RST {
			f.RSTSeen = true
		}

		// Initial window sizes (first packet of each direction)
		if !f.InitWinSet {
			if direction == Forward {
				f.InitFwdWinBytes = int64(windowSize)
			} else {
				f.InitBwdWinBytes = int64(windowSize)
			}
			f.InitWinSet = true
		}
	}
}

// ShouldFlush returns true if the flow should be flushed due to termination.
func (f *Flow) ShouldFlush() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	totalPackets := f.FwdPackets + f.BwdPackets
	return f.FINSeen || f.RSTSeen || totalPackets >= FlowMaxPackets
}

// IsIdle returns true if the flow has been inactive for the idle timeout.
func (f *Flow) IsIdle(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return now.Sub(f.LastSeen) > FlowIdleTimeout
}

// ToFeatures converts the flow to a 54-element float32 slice matching
// the CIC-IDS feature order in feature_map.json.
func (f *Flow) ToFeatures() []float32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Calculate derived values
	duration := f.LastSeen.Sub(f.FirstSeen).Seconds() * 1e6 // microseconds
	if duration <= 0 {
		duration = 1 // Prevent division by zero
	}

	totalPackets := f.FwdPackets + f.BwdPackets
	totalBytes := f.FwdBytes + f.BwdBytes

	// Build feature vector (54 features in exact order)
	features := make([]float32, 54)

	// 0: flow_duration (microseconds)
	features[0] = float32(duration)

	// 1-2: Packet counts
	features[1] = float32(f.FwdPackets)
	features[2] = float32(f.BwdPackets)

	// 3-4: Total bytes
	features[3] = float32(f.FwdBytes)
	features[4] = float32(f.BwdBytes)

	// 5-6: Forward packet length stats
	features[5] = float32(f.FwdPktLen.Max())
	features[6] = float32(f.FwdPktLen.StdDev())

	// 7-9: Backward packet length stats
	features[7] = float32(f.BwdPktLen.Max())
	features[8] = float32(f.BwdPktLen.Mean())
	features[9] = float32(f.BwdPktLen.StdDev())

	// 10-11: Flow rates
	features[10] = float32(float64(totalBytes) / duration * 1e6)   // bytes/s
	features[11] = float32(float64(totalPackets) / duration * 1e6) // packets/s

	// 12-15: Flow IAT stats
	features[12] = float32(f.FlowIAT.Mean())
	features[13] = float32(f.FlowIAT.StdDev())
	features[14] = float32(f.FlowIAT.Max())
	features[15] = float32(f.FlowIAT.Min())

	// 16-20: Forward IAT stats
	features[16] = float32(f.FwdIAT.Sum())
	features[17] = float32(f.FwdIAT.Mean())
	features[18] = float32(f.FwdIAT.StdDev())
	features[19] = float32(f.FwdIAT.Max())
	features[20] = float32(f.FwdIAT.Min())

	// 21-25: Backward IAT stats
	features[21] = float32(f.BwdIAT.Sum())
	features[22] = float32(f.BwdIAT.Mean())
	features[23] = float32(f.BwdIAT.StdDev())
	features[24] = float32(f.BwdIAT.Max())
	features[25] = float32(f.BwdIAT.Min())

	// 26-27: Flags and headers
	features[26] = float32(f.FwdPSHFlags)
	features[27] = float32(f.FwdHeaderLen)
	features[28] = float32(f.BwdHeaderLen)

	// 29-30: Per-direction rates
	features[29] = float32(float64(f.FwdPackets) / duration * 1e6) // fwd packets/s
	features[30] = float32(float64(f.BwdPackets) / duration * 1e6) // bwd packets/s

	// 31-34: Combined packet length stats
	features[31] = float32(f.AllPktLen.Max())
	features[32] = float32(f.AllPktLen.Mean())
	features[33] = float32(f.AllPktLen.StdDev())
	features[34] = float32(f.AllPktLen.Variance())

	// 35-36: Flag counts
	features[35] = float32(f.SYNCount)
	features[36] = float32(f.URGCount)

	// 37-39: Average sizes
	if totalPackets > 0 {
		features[37] = float32(float64(totalBytes) / float64(totalPackets))
	}
	if f.FwdPackets > 0 {
		features[38] = float32(float64(f.FwdBytes) / float64(f.FwdPackets))
	}
	if f.BwdPackets > 0 {
		features[39] = float32(float64(f.BwdBytes) / float64(f.BwdPackets))
	}

	// 40-41: Initial window bytes
	features[40] = float32(f.InitFwdWinBytes)
	features[41] = float32(f.InitBwdWinBytes)

	// 42-43: Forward segment stats
	features[42] = float32(f.FwdActDataPkts)
	if f.FwdSegMinSet {
		features[43] = float32(f.FwdSegSizeMin)
	}

	// 44-47: Active period stats
	features[44] = float32(f.ActivePeriods.Mean())
	features[45] = float32(f.ActivePeriods.StdDev())
	features[46] = float32(f.ActivePeriods.Max())
	features[47] = float32(f.ActivePeriods.Min())

	// 48-51: Idle period stats
	features[48] = float32(f.IdlePeriods.Mean())
	features[49] = float32(f.IdlePeriods.StdDev())
	features[50] = float32(f.IdlePeriods.Max())
	features[51] = float32(f.IdlePeriods.Min())

	// 52-53: Computed rates (same as 10-11 but with log1p applied in preprocessing)
	features[52] = float32(float64(totalBytes) / duration * 1e6)
	features[53] = float32(float64(totalPackets) / duration * 1e6)

	// Handle NaN/Inf
	for i := range features {
		if math.IsNaN(float64(features[i])) || math.IsInf(float64(features[i]), 0) {
			features[i] = 0
		}
	}

	return features
}

// Manager handles concurrent flow tracking and aggregation.
type Manager struct {
	flows       sync.Map // map[FlowKey]*Flow
	flushChan   chan *Flow
	stopChan    chan struct{}
	wg          sync.WaitGroup
	packetCount int64
	flowCount   int64
	mu          sync.Mutex
}

// NewManager creates a new flow manager.
func NewManager(flushChan chan *Flow) *Manager {
	return &Manager{
		flushChan: flushChan,
		stopChan:  make(chan struct{}),
	}
}

// Start begins the background cleanup routine.
func (m *Manager) Start() {
	m.wg.Add(1)
	go m.cleanupRoutine()
	log.Println("[FlowManager] Started cleanup routine")
}

// Stop signals the manager to shutdown gracefully.
func (m *Manager) Stop() {
	close(m.stopChan)
	m.wg.Wait()

	// Flush remaining flows
	m.flows.Range(func(key, value interface{}) bool {
		flow := value.(*Flow)
		select {
		case m.flushChan <- flow:
		default:
			log.Printf("[FlowManager] Flush channel full, dropping flow: %s", flow.Key)
		}
		return true
	})

	log.Println("[FlowManager] Stopped")
}

// HandlePacket processes a captured packet and updates flow state.
func (m *Manager) HandlePacket(packet gopacket.Packet) {
	// Extract timestamp
	metadata := packet.Metadata()
	timestamp := metadata.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Parse network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return // Not an IP packet
	}

	var srcIP, dstIP [16]byte
	var protocol uint8

	switch nl := networkLayer.(type) {
	case *layers.IPv4:
		copy(srcIP[:], nl.SrcIP.To16())
		copy(dstIP[:], nl.DstIP.To16())
		protocol = uint8(nl.Protocol)
	case *layers.IPv6:
		copy(srcIP[:], nl.SrcIP)
		copy(dstIP[:], nl.DstIP)
		protocol = uint8(nl.NextHeader)
	default:
		return
	}

	// Parse transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return // No transport layer
	}

	var srcPort, dstPort uint16
	var tcpFlags *layers.TCP
	var windowSize uint16
	var headerLen int

	switch tl := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		tcpFlags = tl
		windowSize = tl.Window
		headerLen = int(tl.DataOffset) * 4
	case *layers.UDP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		headerLen = 8
	default:
		return
	}

	// Calculate payload length
	payloadLen := 0
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payloadLen = len(appLayer.Payload())
	} else if transportLayer != nil {
		payloadLen = len(transportLayer.LayerPayload())
	}

	// Create flow key (normalize direction for bidirectional matching)
	key, direction := normalizeFlowKey(srcIP, dstIP, srcPort, dstPort, protocol)

	// Get or create flow
	flowI, loaded := m.flows.LoadOrStore(key, NewFlow(key, timestamp))
	flow := flowI.(*Flow)

	if !loaded {
		m.mu.Lock()
		m.flowCount++
		m.mu.Unlock()
	}

	// Update flow statistics
	flow.Update(timestamp, payloadLen, headerLen, direction, tcpFlags, windowSize)

	m.mu.Lock()
	m.packetCount++
	m.mu.Unlock()

	// Check for immediate flush conditions
	if flow.ShouldFlush() {
		m.flows.Delete(key)
		select {
		case m.flushChan <- flow:
		default:
			log.Printf("[FlowManager] Flush channel full, dropping flow: %s", key)
		}
	}
}

// cleanupRoutine periodically checks for idle flows and flushes them.
func (m *Manager) cleanupRoutine() {
	defer m.wg.Done()

	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			var flushed int

			m.flows.Range(func(key, value interface{}) bool {
				flow := value.(*Flow)
				if flow.IsIdle(now) {
					m.flows.Delete(key)
					select {
					case m.flushChan <- flow:
						flushed++
					default:
						log.Printf("[FlowManager] Flush channel full during cleanup")
					}
				}
				return true
			})

			if flushed > 0 {
				log.Printf("[FlowManager] Flushed %d idle flows", flushed)
			}
		}
	}
}

// Stats returns current flow manager statistics.
func (m *Manager) Stats() (packets int64, flows int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.packetCount, m.flowCount
}

// normalizeFlowKey creates a consistent key regardless of packet direction.
// Returns the key and the direction relative to the key's "forward" direction.
func normalizeFlowKey(
	srcIP, dstIP [16]byte,
	srcPort, dstPort uint16,
	protocol uint8,
) (FlowKey, Direction) {
	// Compare IPs, then ports to determine canonical direction
	srcBytes := binary.BigEndian.Uint64(srcIP[:8])
	dstBytes := binary.BigEndian.Uint64(dstIP[:8])

	if srcBytes < dstBytes || (srcBytes == dstBytes && srcPort < dstPort) {
		// Source is "smaller" - this is forward direction
		return FlowKey{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
		}, Forward
	}

	// Destination is "smaller" - this is backward direction
	return FlowKey{
		SrcIP:    dstIP,
		DstIP:    srcIP,
		SrcPort:  dstPort,
		DstPort:  srcPort,
		Protocol: protocol,
	}, Backward
}
