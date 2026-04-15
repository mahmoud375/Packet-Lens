package incident

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store manages the PostgreSQL connection pool and provides methods for
// persisting and querying incidents.
//
// The Store is safe for concurrent use. It is typically created once in
// main.go and shared between the IncidentWriter goroutine (writes) and
// the Management API handlers (reads, updates).
type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

// NewStore creates a new Store by establishing a connection pool to PostgreSQL.
//
// The function validates connectivity with a Ping before returning. If the
// database is unreachable, it returns an error — the caller decides whether
// to retry or exit.
func NewStore(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.PostgresDSN == "" {
		return nil, fmt.Errorf("incident.NewStore: PostgresDSN is required")
	}

	// Parse the DSN into a pool config so we can tune pool parameters.
	poolCfg, err := pgxpool.ParseConfig(cfg.PostgresDSN)
	if err != nil {
		return nil, fmt.Errorf("incident.NewStore: invalid DSN: %w", err)
	}

	// Constrain pool size. The writer goroutine is single-threaded,
	// and the Management API adds a few more readers.
	if cfg.MaxPoolConns > 0 {
		poolCfg.MaxConns = cfg.MaxPoolConns
	}

	// Set reasonable connection timeouts.
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second

	// Create the pool.
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("incident.NewStore: failed to create pool: %w", err)
	}

	// Validate connectivity immediately.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("incident.NewStore: database ping failed: %w", err)
	}

	log.Printf("[IncidentStore] Connected to PostgreSQL (max_conns=%d)", poolCfg.MaxConns)

	return &Store{
		pool: pool,
		cfg:  cfg,
	}, nil
}

// Ping verifies the database connection is still alive.
// Used by the health check endpoint (Phase 3) and startup validation.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases all connections in the pool.
// Must be called during graceful shutdown.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
		log.Println("[IncidentStore] Connection pool closed")
	}
}

// Pool returns the underlying pgxpool.Pool for direct access.
// This is used by the IncidentWriter for batch inserts (CopyFrom) and
// by the Management API for queries. Exposing the pool allows these
// consumers to use the most efficient pgx primitives without abstraction overhead.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Config returns the store's configuration.
func (s *Store) Config() Config {
	return s.cfg
}
