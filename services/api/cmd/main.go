// PacketLens REST API Service — Read-only HTTP layer for the dashboard.
//
// This microservice exposes incident data from PostgreSQL to the Next.js
// frontend. It is a strictly READ-ONLY service with no write capabilities.
//
// v2.0: Added materialized view migrations, LISTEN/NOTIFY hub for SSE,
//       and background view refresh loop.
//
// Usage:
//
//	POSTGRES_DSN=postgres://... go run ./services/api/cmd
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mahmoud375/PacketLens/services/api/internal/db"
	"github.com/mahmoud375/PacketLens/services/api/internal/handler"
	"github.com/mahmoud375/PacketLens/services/api/internal/notifier"
	"github.com/mahmoud375/PacketLens/services/api/internal/router"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Println("PacketLens API starting...")

	// ── Configuration ────────────────────────────────────────────────
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("POSTGRES_DSN is required")
	}

	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	// ── Database ─────────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer pool.Close()
	log.Println("📦 Connected to PostgreSQL")

	// ── Migrations (materialized views + NOTIFY trigger) ─────────────
	if err := notifier.RunMigrations(ctx, pool); err != nil {
		log.Printf("[WARNING] Migrations incomplete: %v (dashboard may show stale data)", err)
	}

	// ── Notification Hub ─────────────────────────────────────────────
	hub := notifier.NewHub(pool)
	go hub.Listen(ctx)
	log.Println("📡 LISTEN/NOTIFY hub started")

	// ── Materialized View Refresh Loop ───────────────────────────────
	go notifier.StartRefreshLoop(ctx, pool, 30*time.Second)

	// ── Handlers ─────────────────────────────────────────────────────
	h := handler.New(pool, hub)

	// ── Router ───────────────────────────────────────────────────────
	r := router.Setup(h)

	// ── HTTP Server ──────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // Disabled for SSE (long-lived connections)
		IdleTimeout:  60 * time.Second,
	}

	// Start in goroutine for graceful shutdown
	go func() {
		log.Printf("🚀 API listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// ── Graceful Shutdown ────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down API server...")
	cancel() // Stop notifier + refresh loop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("PacketLens API stopped.")
}
