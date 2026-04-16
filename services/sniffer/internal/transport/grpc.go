// Package transport provides the gRPC client for sending flow features to
// the Python inference service.
package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/mahmoud375/PacketLens/gen/go/packetlens"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/flow"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/incident"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/metrics"
)

// Client wraps the gRPC connection to the inference service.
type Client struct {
	conn   *grpc.ClientConn
	client pb.InferenceServiceClient
	stream pb.InferenceService_ClassifyClient

	addr      string
	reconnect bool
	mu        sync.Mutex
}

// NewClient creates a new gRPC client.
func NewClient(serverAddr string) *Client {
	return &Client{
		addr:      serverAddr,
		reconnect: true,
	}
}

// Connect establishes the gRPC connection and opens the bidirectional stream.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close existing connection if any
	if c.conn != nil {
		c.conn.Close()
	}

	// Dial the server
	log.Printf("[gRPC] Connecting to %s...", c.addr)

	conn, err := grpc.DialContext(ctx, c.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10*1024*1024),
			grpc.MaxCallSendMsgSize(10*1024*1024),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.addr, err)
	}

	c.conn = conn
	c.client = pb.NewInferenceServiceClient(conn)

	// Open bidirectional stream
	stream, err := c.client.Classify(ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open Classify stream: %w", err)
	}

	c.stream = stream
	log.Printf("[gRPC] Connected to %s", c.addr)

	return nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reconnect = false

	if c.stream != nil {
		c.stream.CloseSend()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SendFlow sends a flow's features to the inference service.
func (c *Client) SendFlow(f *flow.Flow) error {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream not connected")
	}

	// Convert flow to feature vector
	features := f.ToFeatures()

	// Create protobuf message
	msg := &pb.FeatureVector{
		FlowId:      f.Key.String(),
		Features:    features,
		TimestampNs: f.LastSeen.UnixNano(),
	}

	// Send to stream
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("failed to send feature vector: %w", err)
	}

	return nil
}

// Sender manages the send loop for flows.
type Sender struct {
	client   *Client
	flowChan <-chan *flow.Flow
	wg       sync.WaitGroup

	// Phase 1: Incident persistence
	incidentChan chan<- incident.Incident // nil if persistence is disabled
	incidentCfg  incident.Config

	// Statistics
	sentCount  int64
	errorCount int64
	mu         sync.Mutex
}

// NewSender creates a new sender that reads from the flow channel.
// incidentChan may be nil if incident persistence is not configured.
func NewSender(client *Client, flowChan <-chan *flow.Flow, incidentChan chan<- incident.Incident, incidentCfg incident.Config) *Sender {
	return &Sender{
		client:       client,
		flowChan:     flowChan,
		incidentChan: incidentChan,
		incidentCfg:  incidentCfg,
	}
}

// Start begins the send loop in a goroutine.
func (s *Sender) Start(ctx context.Context) {
	s.wg.Add(2)
	go s.sendLoop(ctx)
	go s.receiveLoop(ctx)
}

// sendLoop reads flows from the channel and sends them to the server.
func (s *Sender) sendLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Sender] Send loop shutting down")
			return

		case flow, ok := <-s.flowChan:
			if !ok {
				log.Println("[Sender] Flow channel closed")
				return
			}

			if err := s.client.SendFlow(flow); err != nil {
				s.mu.Lock()
				s.errorCount++
				s.mu.Unlock()
				log.Printf("[Sender] Error sending flow: %v", err)
				continue
			}

			s.mu.Lock()
			s.sentCount++
			count := s.sentCount
			s.mu.Unlock()

			// Log every 100 flows
			if count%100 == 0 {
				log.Printf("[Sender] Sent %d flows", count)
			}
		}
	}
}

// receiveLoop reads verdicts from the server.
func (s *Sender) receiveLoop(ctx context.Context) {
	defer s.wg.Done()

	s.client.mu.Lock()
	stream := s.client.stream
	s.client.mu.Unlock()

	if stream == nil {
		log.Println("[Sender] No stream for receive loop")
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Sender] Receive loop shutting down")
			return
		default:
		}

		verdict, err := stream.Recv()
		if err != nil {
			log.Printf("[Sender] Receive error (stream closed?): %v", err)
			return
		}

		// Track verdict label in Prometheus
		metrics.VerdictsByLabel.WithLabelValues(verdict.Label).Inc()

		// Log verdicts for non-benign traffic
		if verdict.Label != "Benign" {
			log.Printf("[ALERT] Flow %s classified as %s (%.2f%% confidence, %dµs)",
				verdict.FlowId,
				verdict.Label,
				verdict.Confidence*100,
				verdict.InferenceTimeUs)
		}

		// ─── Phase 1: Async incident logging ────────────────────────
		// Only log if: (a) persistence is enabled, and (b) the verdict
		// passes the confidence floor + label exclusion filter.
		if s.incidentChan != nil && s.incidentCfg.ShouldLog(verdict.Label, verdict.Confidence) {
			srcIP, dstIP, srcPort, dstPort, protocol, parseErr := parseFlowID(verdict.FlowId)
			if parseErr != nil {
				log.Printf("[Sender] Failed to parse flow ID for incident: %v", parseErr)
			} else {
				inc := incident.Incident{
					DetectedAt:  time.Now(),
					SrcIP:       srcIP,
					DstIP:       dstIP,
					SrcPort:     srcPort,
					DstPort:     dstPort,
					Protocol:    protocol,
					AttackType:  verdict.Label,
					Confidence:  verdict.Confidence,
					InferenceUs: verdict.InferenceTimeUs,
					FlowID:      verdict.FlowId,
					Status:      incident.StatusOpen,
				}

				// Non-blocking send: if the writer can't keep up, drop
				// the incident and count the loss in Prometheus.
				select {
				case s.incidentChan <- inc:
				default:
					metrics.IncidentsDropped.Inc()
				}
			}
		}
	}
}

// parseFlowID extracts the 5-tuple from a FlowKey.String() representation.
// Format: "srcIP:srcPort→dstIP:dstPort/protocol"
// Example: "192.168.1.1:443→10.0.0.5:12345/6"
func parseFlowID(flowID string) (srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, protocol uint8, err error) {
	// Split on "→" (U+2192) to separate src and dst+proto parts
	srcPart, dstProto, found := strings.Cut(flowID, "→")
	if !found {
		return nil, nil, 0, 0, 0, fmt.Errorf("missing → separator in flow ID: %s", flowID)
	}

	// Split dst+proto on "/" to extract protocol number
	dstPart, protoStr, found := strings.Cut(dstProto, "/")
	if !found {
		return nil, nil, 0, 0, 0, fmt.Errorf("missing / separator in flow ID: %s", flowID)
	}

	proto, parseErr := strconv.ParseUint(protoStr, 10, 8)
	if parseErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid protocol in flow ID: %w", parseErr)
	}

	// Parse src: split on last ":" to handle IPv6 addresses correctly
	lastColon := strings.LastIndex(srcPart, ":")
	if lastColon < 0 {
		return nil, nil, 0, 0, 0, fmt.Errorf("missing port separator in src: %s", srcPart)
	}
	srcIPStr := srcPart[:lastColon]
	srcPortVal, parseErr := strconv.ParseUint(srcPart[lastColon+1:], 10, 16)
	if parseErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid src port: %w", parseErr)
	}

	// Parse dst: split on last ":" to handle IPv6 addresses correctly
	lastColon = strings.LastIndex(dstPart, ":")
	if lastColon < 0 {
		return nil, nil, 0, 0, 0, fmt.Errorf("missing port separator in dst: %s", dstPart)
	}
	dstIPStr := dstPart[:lastColon]
	dstPortVal, parseErr := strconv.ParseUint(dstPart[lastColon+1:], 10, 16)
	if parseErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid dst port: %w", parseErr)
	}

	srcIP = net.ParseIP(srcIPStr)
	if srcIP == nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid src IP: %s", srcIPStr)
	}

	dstIP = net.ParseIP(dstIPStr)
	if dstIP == nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid dst IP: %s", dstIPStr)
	}

	return srcIP, dstIP, uint16(srcPortVal), uint16(dstPortVal), uint8(proto), nil
}

// Wait blocks until both loops complete.
func (s *Sender) Wait() {
	s.wg.Wait()
}

// Stats returns current sender statistics.
func (s *Sender) Stats() (sent int64, errors int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sentCount, s.errorCount
}

// ConnectWithRetry attempts to connect with exponential backoff.
func (c *Client) ConnectWithRetry(ctx context.Context, maxRetries int) error {
	backoff := time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := c.Connect(ctx); err != nil {
			log.Printf("[gRPC] Connection attempt %d failed: %v", attempt+1, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
				continue
			}
		}
		return nil
	}

	return fmt.Errorf("failed to connect after %d attempts", maxRetries)
}
