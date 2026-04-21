// Package notifier provides a PostgreSQL LISTEN/NOTIFY hub that fans out
// new incident notifications to all connected SSE clients.
package notifier

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hub manages a set of SSE subscribers and broadcasts pg_notify payloads.
type Hub struct {
	pool        *pgxpool.Pool
	mu          sync.RWMutex
	subscribers map[chan []byte]struct{}
}

// NewHub creates a new notification hub.
func NewHub(pool *pgxpool.Pool) *Hub {
	return &Hub{
		pool:        pool,
		subscribers: make(map[chan []byte]struct{}),
	}
}

// Subscribe registers a new SSE client and returns a channel for events.
// The channel is buffered to prevent slow clients from blocking broadcasts.
func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	log.Printf("[Notifier] Client subscribed (total: %d)", h.Len())
	return ch
}

// Unsubscribe removes a client and closes its channel.
func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	close(ch)
	h.mu.Unlock()
	log.Printf("[Notifier] Client unsubscribed (total: %d)", h.Len())
}

// Len returns the current subscriber count.
func (h *Hub) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscribers)
}

// broadcast sends data to all subscribers. Drops messages for slow clients.
func (h *Hub) broadcast(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- data:
		default:
			// Channel full — skip to prevent blocking.
			// Client will catch up via REST endpoint.
			log.Println("[Notifier] Dropped message for slow subscriber")
		}
	}
}

// Listen connects to PostgreSQL and listens for incident notifications.
// It reconnects automatically on connection failure. Blocks until ctx is cancelled.
func (h *Hub) Listen(ctx context.Context) {
	for {
		if err := h.listenLoop(ctx); err != nil {
			if ctx.Err() != nil {
				return // Shutting down
			}
			log.Printf("[Notifier] LISTEN error: %v — reconnecting in 3s", err)
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}

// listenLoop acquires a dedicated connection and blocks on WaitForNotification.
func (h *Hub) listenLoop(ctx context.Context) error {
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN incidents_new"); err != nil {
		return err
	}
	log.Println("[Notifier] LISTEN incidents_new — waiting for notifications")

	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}

		// Validate the payload is valid JSON before broadcasting
		if json.Valid([]byte(notification.Payload)) {
			h.broadcast([]byte(notification.Payload))
		} else {
			log.Printf("[Notifier] Invalid JSON payload from pg_notify: %.100s", notification.Payload)
		}
	}
}

// RunMigrations ensures materialized views and NOTIFY triggers exist.
// Idempotent — safe to call on every startup.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrations := []struct {
		name string
		sql  string
	}{
		{"notify_function", `
			CREATE OR REPLACE FUNCTION notify_new_incident() RETURNS trigger AS $$
			BEGIN
				PERFORM pg_notify('incidents_new', row_to_json(NEW)::text);
				RETURN NEW;
			END;
			$$ LANGUAGE plpgsql;
		`},
		{"notify_trigger_drop", `DROP TRIGGER IF EXISTS trg_incidents_notify ON incidents;`},
		{"notify_trigger_create", `
			CREATE TRIGGER trg_incidents_notify
				AFTER INSERT ON incidents
				FOR EACH ROW
				EXECUTE FUNCTION notify_new_incident();
		`},
	}

	for _, m := range migrations {
		if _, err := pool.Exec(ctx, m.sql); err != nil {
			log.Printf("[Migration] %s failed: %v", m.name, err)
			return err
		}
		log.Printf("[Migration] ✓ %s", m.name)
	}

	// Create materialized views if they don't exist
	views := []struct {
		name    string
		create  string
		index   string
	}{
		{
			"mv_attack_summary",
			`CREATE MATERIALIZED VIEW mv_attack_summary AS
			 SELECT attack_type, COUNT(*) AS count, AVG(confidence)::real AS avg_confidence
			 FROM incidents GROUP BY attack_type ORDER BY count DESC`,
			`CREATE UNIQUE INDEX uidx_mv_attack_summary_type ON mv_attack_summary (attack_type)`,
		},
		{
			"mv_hourly_timeline",
			`CREATE MATERIALIZED VIEW mv_hourly_timeline AS
			 SELECT date_trunc('hour', detected_at) AS hour, COUNT(*) AS count
			 FROM incidents WHERE detected_at >= NOW() - INTERVAL '24 hours'
			 GROUP BY hour ORDER BY hour ASC`,
			`CREATE UNIQUE INDEX uidx_mv_hourly_timeline_hour ON mv_hourly_timeline (hour)`,
		},
		{
			"mv_protocol_breakdown",
			`CREATE MATERIALIZED VIEW mv_protocol_breakdown AS
			 SELECT protocol, COUNT(*) AS count
			 FROM incidents GROUP BY protocol ORDER BY count DESC`,
			`CREATE UNIQUE INDEX uidx_mv_protocol_breakdown_proto ON mv_protocol_breakdown (protocol)`,
		},
	}

	for _, v := range views {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM pg_matviews WHERE matviewname = $1)", v.name,
		).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := pool.Exec(ctx, v.create); err != nil {
				log.Printf("[Migration] CREATE %s failed: %v", v.name, err)
				return err
			}
			if _, err := pool.Exec(ctx, v.index); err != nil {
				log.Printf("[Migration] INDEX on %s failed: %v", v.name, err)
				return err
			}
			log.Printf("[Migration] ✓ Created %s", v.name)
		} else {
			log.Printf("[Migration] ✓ %s already exists", v.name)
		}
	}

	return nil
}

// RefreshViews refreshes all materialized views concurrently (non-blocking).
func RefreshViews(ctx context.Context, pool *pgxpool.Pool) {
	views := []string{"mv_attack_summary", "mv_hourly_timeline", "mv_protocol_breakdown"}
	for _, v := range views {
		if _, err := pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY "+v); err != nil {
			log.Printf("[Refresh] %s failed: %v", v, err)
		}
	}
}

// StartRefreshLoop refreshes materialized views on a fixed interval.
func StartRefreshLoop(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) {
	// Initial refresh
	RefreshViews(ctx, pool)
	log.Printf("[Refresh] Materialized views refreshing every %s", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			RefreshViews(ctx, pool)
		}
	}
}
