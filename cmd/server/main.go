package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"auth-service/internal/auth"
	"auth-service/internal/http"
)

func main() {
	_ = godotenv.Load()

	// Defaults seguros para local si .env está vacío
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	// 1) Store (in-memory demo) — luego lo migras a Postgres sin tocar handlers
	store := auth.NewMemoryStoreFromEnv()

	// 2) Auth service (login/refresh)
	authSvc := auth.NewService(store, auth.NewJWTFromEnv())

	// 3) Router HTTP (Gin)
	r := http.NewRouter(authSvc)

	log.Printf("✅ auth-service corriendo en http://localhost%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("❌ error iniciando servidor: %v", err)
	}
}
