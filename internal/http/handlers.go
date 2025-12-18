package http

import (
	"net/http"
	"os"
	"auth-service/internal/auth"
	"github.com/gin-gonic/gin"
)

type Handlers struct {
	auth *auth.Service
}

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	ClientID int64  `json:"clientId"`
}

func (h *Handlers) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	if err := h.auth.Register(req.Email, req.Password, req.ClientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}

func NewHandlers(a *auth.Service) *Handlers {
	return &Handlers{auth: a}
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	access, refresh, user, err := h.auth.Login(req.Email, req.Password)
	if err != nil {
		if err == auth.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	// Cookie refresh token (web). En app móvil también lo puedes guardar en SecureStore.
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	secure := os.Getenv("COOKIE_SECURE") == "true"

	c.SetCookie(
		"refreshToken",
		refresh,
		7*24*3600,
		"/",
		cookieDomain,
		secure,
		true, // HttpOnly
	)

	c.JSON(http.StatusOK, gin.H{
		"accessToken": access,
		"user": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"role":     user.Role,
			"clientId": user.ClientID,
		},
	})
}

func (h *Handlers) Refresh(c *gin.Context) {
	rt, err := c.Cookie("refreshToken")
	if err != nil || rt == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing refresh token"})
		return
	}

	access, err := h.auth.Refresh(rt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"accessToken": access})
}

func (h *Handlers) Me(c *gin.Context) {
	// placeholder — cuando integremos el middleware real, aquí devolvemos claims
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handlers) Logout(c *gin.Context) {
	secure := os.Getenv("COOKIE_SECURE") == "true"
	cookieDomain := os.Getenv("COOKIE_DOMAIN")

	c.SetCookie("refreshToken", "", -1, "/", cookieDomain, secure, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
