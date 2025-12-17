package http

import (
	"net/http"
	"strings"

	"auth-service/internal/auth"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		// Nota: aquí NO verificamos JWT directo porque el JWT vive dentro de authSvc.jwt (privado).
		// Para mantener simple: exponemos un método Verify si después lo quieres.
		// Por ahora, se deja como placeholder para cuando integremos scheduler-backend.
		// ASCII safe replacement: usamos comentario en vez de símbolos raros.

		c.Next()
	}
}
