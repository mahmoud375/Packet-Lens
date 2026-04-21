package handler

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// StreamIncidents is an SSE endpoint that pushes new incidents to clients
// in real-time via the PostgreSQL NOTIFY → Hub broadcast pipeline.
//
// Protocol:
//   - event: connected  → initial handshake
//   - event: incident   → new incident JSON payload
//   - : heartbeat       → keep-alive comment (every 15s)
func (h *Handler) StreamIncidents(c *gin.Context) {
	// ── SSE Headers ──────────────────────────────────────────────────
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // Disable nginx/proxy buffering

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
		return
	}

	// ── Subscribe to the notification hub ────────────────────────────
	if h.hub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "notification hub not initialized"})
		return
	}

	ch := h.hub.Subscribe()
	defer h.hub.Unsubscribe(ch)

	// ── Send initial connection event ────────────────────────────────
	fmt.Fprintf(c.Writer, "event: connected\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()

	// ── Heartbeat to detect dead connections ─────────────────────────
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	ctx := c.Request.Context()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected — goroutine exits cleanly
			log.Println("[SSE] Client disconnected")
			return

		case data, ok := <-ch:
			if !ok {
				// Channel closed (hub shutting down)
				return
			}
			fmt.Fprintf(c.Writer, "event: incident\ndata: %s\n\n", data)
			flusher.Flush()

		case <-heartbeat.C:
			// SSE comment line — keeps the connection alive
			fmt.Fprintf(c.Writer, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}
