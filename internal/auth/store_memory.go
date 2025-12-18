package auth

import (
	"errors"
	"os"
)

type Store interface {
	FindByEmail(email string) (*User, error)
	Create(user *User) error
}

type memoryStore struct {
	users map[string]User
}

func (m *memoryStore) Create(u *User) error {
	if _, exists := m.users[u.Email]; exists {
		return errors.New("email already exists")
	}
	m.users[u.Email] = *u
	return nil
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
