// Package router sets up the Gin engine with middleware and routes.
package router

import (
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mahmoud375/PacketLens/services/api/internal/handler"
	"github.com/mahmoud375/PacketLens/services/api/internal/middleware"
)

// Setup creates and configures the Gin router with CORS and JWT middleware.
func Setup(h *handler.Handler) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// CORS: allow all origins (tightened in production via env)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	// ── API v1 ───────────────────────────────────────────────────────
	v1 := r.Group("/api/v1")

	// Public routes (no auth required)
	v1.GET("/health", h.HealthCheck)
	v1.POST("/auth/login", h.Login)

	// Protected routes (JWT required)
	jwtSecret := os.Getenv("JWT_SECRET")
	protected := v1.Group("")
	protected.Use(middleware.RequireAuth(jwtSecret))
	{
		protected.GET("/incidents", h.ListIncidents)
		protected.GET("/incidents/stream", h.StreamIncidents)
		protected.GET("/stats/summary", h.GetSummary)
	}

	return r
}
