package auth

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewJWTFromEnv() *JWT {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-secret-change-me" // local
	}

	accMin, _ := strconv.Atoi(os.Getenv("ACCESS_TOKEN_MINUTES"))
	if accMin == 0 {
		accMin = 10
	}
	refDays, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_DAYS"))
	if refDays == 0 {
		refDays = 7
	}

	return &JWT{
		secret:     []byte(secret),
		accessTTL:  time.Duration(accMin) * time.Minute,
		refreshTTL: time.Duration(refDays) * 24 * time.Hour,
	}
}

func (j *JWT) IssueAccess(u *User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"typ":      "access",
		"sub":      u.ID,
		"email":    u.Email,
		"role":     u.Role,
		"clientId": u.ClientID,
		"iat":      now.Unix(),
		"exp":      now.Add(j.accessTTL).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(j.secret)
}

func (j *JWT) IssueRefresh(u *User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"typ":      "refresh",
		"sub":      u.ID,
		"email":    u.Email,
		"role":     u.Role,
		"clientId": u.ClientID,
		"iat":      now.Unix(),
		"exp":      now.Add(j.refreshTTL).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(j.secret)
}

func (j *JWT) Verify(token string) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return j.secret, nil
	})
	if err != nil || !parsed.Valid {
		return nil, err
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	return claims, nil
}
