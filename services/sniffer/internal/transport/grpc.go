// Package transport provides the gRPC client for sending flow features to
// the Python inference service.
package transport

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/mahmoud375/PacketLens/gen/go/packetlens"
	"github.com/mahmoud375/PacketLens/services/sniffer/internal/flow"
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

	// Statistics
	sentCount  int64
	errorCount int64
	mu         sync.Mutex
}

// NewSender creates a new sender that reads from the flow channel.
func NewSender(client *Client, flowChan <-chan *flow.Flow) *Sender {
	return &Sender{
		client:   client,
		flowChan: flowChan,
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

		// Log verdicts for non-benign traffic or periodically
		if verdict.Label != "Benign" {
			log.Printf("[ALERT] Flow %s classified as %s (%.2f%% confidence, %dµs)",
				verdict.FlowId,
				verdict.Label,
				verdict.Confidence*100,
				verdict.InferenceTimeUs)
		}
	}
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
