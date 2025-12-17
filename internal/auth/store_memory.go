package auth

import (
	"os"
)

type Store interface {
	FindByEmail(email string) (*User, error)
}

type memoryStore struct {
	users map[string]User
}

func NewMemoryStoreFromEnv() Store {
	email := os.Getenv("DEMO_EMAIL")
	pass := os.Getenv("DEMO_PASSWORD")

	// Defaults de demo si env viene vacío (local)
	if email == "" {
		email = "demo@book-urself.mx"
	}
	if pass == "" {
		pass = "Secret123!"
	}

	hash, _ := HashPassword(pass)

	return &memoryStore{
		users: map[string]User{
			email: {
				ID:           1,
				Email:        email,
				PasswordHash: hash,
				Role:         "user",
				ClientID:     1,
			},
		},
	}
}

func (m *memoryStore) FindByEmail(email string) (*User, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	uu := u
	return &uu, nil
}
