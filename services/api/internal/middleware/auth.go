// Package middleware provides Gin middleware for the PacketLens API.
package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the JWT payload structure.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// RequireAuth returns a Gin middleware that validates JWT tokens.
//
// Token lookup order (critical for EventSource/SSE compatibility):
//  1. Authorization: Bearer <token> header
//  2. ?token=<token> query parameter (fallback for EventSource which
//     does not support custom headers)
//
// On success, sets "username" and "role" in the Gin context.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	secretBytes := []byte(jwtSecret)

	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authentication token",
			})
			return
		}

		// Parse and validate
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secretBytes, nil
		})

		if err != nil || !token.Valid {
			log.Printf("[Auth] Invalid token: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		// Inject user info into context for downstream handlers
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// extractToken retrieves the JWT from the request.
// Priority: Authorization header > query parameter.
func extractToken(c *gin.Context) string {
	// 1. Check Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}

	// 2. Fallback: query parameter (required for EventSource/SSE)
	if token := c.Query("token"); token != "" {
		return token
	}

	return ""
}
