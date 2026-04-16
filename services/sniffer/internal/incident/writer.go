package incident

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mahmoud375/PacketLens/services/sniffer/internal/metrics"
)

// incidentColumns defines the INSERT column order for CopyFrom.
// Must match the init.sql schema exactly (excluding id which is BIGSERIAL).
var incidentColumns = []string{
	"detected_at",
	"src_ip",
	"dst_ip",
	"src_port",
	"dst_port",
	"protocol",
	"attack_type",
	"confidence",
	"inference_us",
	"flow_id",
	"status",
}

// Writer is a single-goroutine, channel-driven batch writer that persists
// incidents to PostgreSQL without ever blocking the gRPC receive loop.
//
// It implements a dual-trigger flush strategy:
//   - Size trigger: flush when the batch buffer reaches Config.BatchSize.
//   - Time trigger: flush when Config.FlushInterval elapses since the last flush.
//
// Whichever condition is met first triggers the flush. This ensures low-latency
// visibility in the Management UI (time trigger) while maintaining high throughput
// under burst conditions (size trigger).
type Writer struct {
	store *Store
	ch    <-chan Incident
	wg    sync.WaitGroup
}

// NewWriter creates an IncidentWriter that reads from the given channel
// and batch-writes to the Store's PostgreSQL instance.
func NewWriter(store *Store, ch <-chan Incident) *Writer {
	return &Writer{
		store: store,
		ch:    ch,
	}
}

// Start launches the writer goroutine. Call Wait() during shutdown to
// ensure the final batch is flushed before the process exits.
func (w *Writer) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.run(ctx)
}

// Wait blocks until the writer goroutine has completed, including its
// final batch flush. Must be called during graceful shutdown.
func (w *Writer) Wait() {
	w.wg.Wait()
}

// run is the main loop. It drains the incident channel, accumulates a batch,
// and flushes on either the size or time trigger.
func (w *Writer) run(ctx context.Context) {
	defer w.wg.Done()

	cfg := w.store.Config()
	batch := make([]Incident, 0, cfg.BatchSize)

	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()

	log.Printf("[IncidentWriter] Started (batch_size=%d, flush_interval=%s)",
		cfg.BatchSize, cfg.FlushInterval)

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown: flush whatever is in the batch buffer.
			// Use a fresh context with a timeout since the parent ctx is cancelled.
			w.flushBatch(batch, "shutdown")
			log.Printf("[IncidentWriter] Shut down, flushed %d remaining incidents", len(batch))
			return

		case inc, ok := <-w.ch:
			if !ok {
				// Channel closed — flush and exit.
				w.flushBatch(batch, "channel_closed")
				log.Println("[IncidentWriter] Channel closed, writer exiting")
				return
			}

			batch = append(batch, inc)

			// Size trigger: flush when batch is full.
			if len(batch) >= cfg.BatchSize {
				w.flushBatch(batch, "size")
				batch = batch[:0] // reuse underlying array
				ticker.Reset(cfg.FlushInterval)
			}

		case <-ticker.C:
			// Time trigger: flush even if batch isn't full.
			if len(batch) > 0 {
				w.flushBatch(batch, "timer")
				batch = batch[:0]
			}
		}
	}
}

// flushBatch writes a batch of incidents to PostgreSQL using COPY protocol.
// On failure, it logs the error and increments a Prometheus counter but does
// NOT crash — the writer goroutine continues draining the channel.
func (w *Writer) flushBatch(batch []Incident, trigger string) {
	if len(batch) == 0 {
		return
	}

	// Use a dedicated timeout context for the write operation.
	// This is independent of the parent context so we can flush during shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()

	if err := w.writeBatch(ctx, batch); err != nil {
		log.Printf("[IncidentWriter] Batch insert failed (trigger=%s, rows=%d): %v",
			trigger, len(batch), err)
		metrics.IncidentWriteErrors.Inc()
		return
	}

	elapsed := time.Since(start)
	count := float64(len(batch))
	metrics.IncidentsWritten.Add(count)

	log.Printf("[IncidentWriter] Flushed %d incidents (trigger=%s, latency=%s)",
		len(batch), trigger, elapsed.Round(time.Millisecond))
}

// writeBatch executes the actual COPY FROM for a batch of incidents.
func (w *Writer) writeBatch(ctx context.Context, batch []Incident) error {
	rows := make([][]any, len(batch))
	for i, inc := range batch {
		rows[i] = []any{
			inc.DetectedAt,
			ipToPrefix(inc.SrcIP),
			ipToPrefix(inc.DstIP),
			int32(inc.SrcPort),
			int32(inc.DstPort),
			int16(inc.Protocol),
			inc.AttackType,
			inc.Confidence,
			int32(inc.InferenceUs),
			inc.FlowID,
			inc.Status,
		}
	}

	conn, err := w.store.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Release()

	_, err = conn.CopyFrom(
		ctx,
		pgx.Identifier{"incidents"},
		incidentColumns,
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("CopyFrom failed: %w", err)
	}

	return nil
}

// ipToPrefix converts a net.IP to a netip.Prefix, which is the Go type
// that pgx v5 uses for PostgreSQL's inet column type in binary COPY mode.
func ipToPrefix(ip net.IP) netip.Prefix {
	if ip == nil {
		return netip.Prefix{}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}
	}
	// Unmap converts IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) back to
	// true IPv4 so PostgreSQL stores them as compact 4-byte inet values.
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen())
}
