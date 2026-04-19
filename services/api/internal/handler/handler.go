// Package handler provides the HTTP handlers for the PacketLens REST API.
package handler

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler holds the database pool and provides HTTP handler methods.
type Handler struct {
	pool *pgxpool.Pool
}

// New creates a new Handler with the given database pool.
func New(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// ─── Response Types ──────────────────────────────────────────────────────────

// Incident represents a single incident row for JSON serialization.
type Incident struct {
	ID          int64      `json:"id"`
	DetectedAt  time.Time  `json:"detected_at"`
	SrcIP       string     `json:"src_ip"`
	DstIP       string     `json:"dst_ip"`
	SrcPort     int        `json:"src_port"`
	DstPort     int        `json:"dst_port"`
	Protocol    int        `json:"protocol"`
	AttackType  string     `json:"attack_type"`
	Confidence  float32    `json:"confidence"`
	InferenceUs int        `json:"inference_us"`
	FlowID      string     `json:"flow_id"`
	Status      string     `json:"status"`
	BlockedAt   *time.Time `json:"blocked_at,omitempty"`
	Notes       *string    `json:"notes,omitempty"`
}

// PaginatedResponse wraps a list of items with pagination metadata.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Limit      int         `json:"limit"`
	Offset     int         `json:"offset"`
	HasMore    bool        `json:"has_more"`
}

// SummaryResponse is the aggregated stats response for dashboard widgets.
type SummaryResponse struct {
	TotalIncidents  int64              `json:"total_incidents"`
	OpenIncidents   int64              `json:"open_incidents"`
	TopAttackTypes  []AttackTypeStat   `json:"top_attack_types"`
	RecentTimeline  []TimelineBucket   `json:"recent_timeline"`
	ProtocolBreakdown []ProtocolStat   `json:"protocol_breakdown"`
}

// AttackTypeStat represents the count of incidents per attack type.
type AttackTypeStat struct {
	AttackType string  `json:"attack_type"`
	Count      int64   `json:"count"`
	AvgConf    float32 `json:"avg_confidence"`
}

// TimelineBucket represents the incident count per hour for the timeline chart.
type TimelineBucket struct {
	Hour  time.Time `json:"hour"`
	Count int64     `json:"count"`
}

// ProtocolStat represents the incident count per protocol.
type ProtocolStat struct {
	Protocol     int    `json:"protocol"`
	ProtocolName string `json:"protocol_name"`
	Count        int64  `json:"count"`
}

// ─── GET /api/v1/incidents ───────────────────────────────────────────────────

// ListIncidents returns paginated, filterable incident data.
func (h *Handler) ListIncidents(c *gin.Context) {
	// Parse pagination
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Parse filters
	labelFilter := c.Query("label")
	srcIPFilter := c.Query("src_ip")
	statusFilter := c.Query("status")

	// Build dynamic query
	query := `SELECT id, detected_at, src_ip::text, dst_ip::text, src_port, dst_port,
	                  protocol, attack_type, confidence, inference_us, flow_id,
	                  status, blocked_at, notes
	           FROM incidents WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM incidents WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if labelFilter != "" {
		clause := fmt.Sprintf(" AND attack_type = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, labelFilter)
		argIdx++
	}
	if srcIPFilter != "" {
		clause := fmt.Sprintf(" AND src_ip = $%d::inet", argIdx)
		query += clause
		countQuery += clause
		args = append(args, srcIPFilter)
		argIdx++
	}
	if statusFilter != "" {
		clause := fmt.Sprintf(" AND status = $%d", argIdx)
		query += clause
		countQuery += clause
		args = append(args, statusFilter)
		argIdx++
	}

	// Get total count (for pagination metadata)
	var total int64
	if err := h.pool.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total); err != nil {
		log.Printf("[API] Count query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	// Add ordering and pagination
	query += fmt.Sprintf(" ORDER BY detected_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	// Execute
	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		log.Printf("[API] Query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	incidents := make([]Incident, 0, limit)
	for rows.Next() {
		var inc Incident
		if err := rows.Scan(
			&inc.ID, &inc.DetectedAt, &inc.SrcIP, &inc.DstIP,
			&inc.SrcPort, &inc.DstPort, &inc.Protocol, &inc.AttackType,
			&inc.Confidence, &inc.InferenceUs, &inc.FlowID,
			&inc.Status, &inc.BlockedAt, &inc.Notes,
		); err != nil {
			log.Printf("[API] Row scan error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan error"})
			return
		}
		incidents = append(incidents, inc)
	}

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:    incidents,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+limit) < total,
	})
}

// ─── GET /api/v1/stats/summary ──────────────────────────────────────────────

// GetSummary returns aggregated statistics for the dashboard.
func (h *Handler) GetSummary(c *gin.Context) {
	ctx := c.Request.Context()
	var summary SummaryResponse

	// 1. Total incidents
	err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents`).Scan(&summary.TotalIncidents)
	if err != nil {
		log.Printf("[API] Total count error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	// 2. Open incidents
	err = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE status = 'open'`).Scan(&summary.OpenIncidents)
	if err != nil {
		log.Printf("[API] Open count error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	// 3. Top 5 attack types by count + average confidence
	rows, err := h.pool.Query(ctx, `
		SELECT attack_type, COUNT(*) as cnt, AVG(confidence)::real as avg_conf
		FROM incidents
		GROUP BY attack_type
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err != nil {
		log.Printf("[API] Top attack types error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	summary.TopAttackTypes = make([]AttackTypeStat, 0, 5)
	for rows.Next() {
		var stat AttackTypeStat
		if err := rows.Scan(&stat.AttackType, &stat.Count, &stat.AvgConf); err != nil {
			log.Printf("[API] Attack type scan error: %v", err)
			continue
		}
		summary.TopAttackTypes = append(summary.TopAttackTypes, stat)
	}

	// 4. Recent timeline: incidents per hour for the last 24 hours
	timeRows, err := h.pool.Query(ctx, `
		SELECT date_trunc('hour', detected_at) AS hour, COUNT(*) AS cnt
		FROM incidents
		WHERE detected_at >= NOW() - INTERVAL '24 hours'
		GROUP BY hour
		ORDER BY hour ASC
	`)
	if err != nil {
		log.Printf("[API] Timeline error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer timeRows.Close()

	summary.RecentTimeline = make([]TimelineBucket, 0, 24)
	for timeRows.Next() {
		var bucket TimelineBucket
		if err := timeRows.Scan(&bucket.Hour, &bucket.Count); err != nil {
			log.Printf("[API] Timeline scan error: %v", err)
			continue
		}
		summary.RecentTimeline = append(summary.RecentTimeline, bucket)
	}

	// 5. Protocol breakdown
	protoRows, err := h.pool.Query(ctx, `
		SELECT protocol, COUNT(*) AS cnt
		FROM incidents
		GROUP BY protocol
		ORDER BY cnt DESC
	`)
	if err != nil {
		log.Printf("[API] Protocol breakdown error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer protoRows.Close()

	summary.ProtocolBreakdown = make([]ProtocolStat, 0, 4)
	for protoRows.Next() {
		var stat ProtocolStat
		if err := protoRows.Scan(&stat.Protocol, &stat.Count); err != nil {
			log.Printf("[API] Protocol scan error: %v", err)
			continue
		}
		stat.ProtocolName = protocolName(stat.Protocol)
		summary.ProtocolBreakdown = append(summary.ProtocolBreakdown, stat)
	}

	c.JSON(http.StatusOK, summary)
}

// ─── GET /api/v1/health ─────────────────────────────────────────────────────

// HealthCheck verifies database connectivity.
func (h *Handler) HealthCheck(c *gin.Context) {
	if err := h.pool.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "packetlens-api",
	})
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func protocolName(p int) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("IP/%d", p)
	}
}
