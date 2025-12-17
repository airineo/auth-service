package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")

type Service struct {
	store Store
	jwt   *JWT
}

func NewService(store Store, jwt *JWT) *Service {
	return &Service{store: store, jwt: jwt}
}

func (s *Service) Login(email, password string) (access, refresh string, user *User, err error) {
	u, err := s.store.FindByEmail(email)
	if err != nil {
		return "", "", nil, err
	}
	if u == nil || !CheckPassword(u.PasswordHash, password) {
		return "", "", nil, ErrInvalidCredentials
	}

	access, err = s.jwt.IssueAccess(u)
	if err != nil {
		return "", "", nil, err
	}
	refresh, err = s.jwt.IssueRefresh(u)
	if err != nil {
		return "", "", nil, err
	}

	return access, refresh, u, nil
}

func (s *Service) Refresh(refreshToken string) (string, error) {
	claims, err := s.jwt.Verify(refreshToken)
	if err != nil {
		return "", err
	}
	if claims["typ"] != "refresh" {
		return "", errors.New("not a refresh token")
	}

	// Reconstruimos un usuario mínimo desde claims (suficiente para emitir access)
	u := &User{
		Email:    toStr(claims["email"]),
		Role:     toStr(claims["role"]),
		ClientID: toInt64(claims["clientId"]),
		ID:       toInt64(claims["sub"]),
	}

	return s.jwt.IssueAccess(u)
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	default:
		return 0
	}
}
