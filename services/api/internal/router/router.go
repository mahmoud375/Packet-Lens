// Package router sets up the Gin engine with middleware and routes.
package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mahmoud375/PacketLens/services/api/internal/handler"
)

// Setup creates and configures the Gin router with CORS middleware.
func Setup(h *handler.Handler) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// CORS: allow all origins for development (Next.js frontend on port 3000)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	// ── API v1 ───────────────────────────────────────────────────────
	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", h.HealthCheck)
		v1.GET("/incidents", h.ListIncidents)
		v1.GET("/stats/summary", h.GetSummary)
	}

	return r
}
