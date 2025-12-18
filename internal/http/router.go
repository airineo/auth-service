package http

import (
	"os"
	"strings"
	"time"

	"auth-service/internal/auth"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func NewRouter(authSvc *auth.Service) *gin.Engine {
	r := gin.Default()

	origins := os.Getenv("CORS_ORIGINS")
	if origins == "" {
		origins = "http://localhost:3000,http://localhost:5173,http://localhost:19006"
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(origins, ","),
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	h := NewHandlers(authSvc)

	r.POST("/auth/login", h.Login)
	r.POST("/auth/register", h.Register)
	r.POST("/auth/refresh", h.Refresh)

	protected := r.Group("/")
	protected.Use(AuthMiddleware(authSvc))
	{
		protected.GET("/auth/me", h.Me)
		protected.POST("/auth/logout", h.Logout)
	}

	return r
}
