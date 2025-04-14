package core

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	id      string
	account Account
	roles   []string
	exp     time.Time
	iss     time.Time
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) Account() Account {
	return s.account
}

func (s *Session) ExpiresAt() time.Time {
	return s.exp
}

func (s *Session) IssuedAt() time.Time {
	return s.iss
}

func (s *Session) Roles() []string {
	return s.roles
}

func NewSession(account Account, roles []string, ttl time.Duration) *Session {
	issued := time.Now()
	return &Session{
		id:      uuid.New().String(),
		account: account,
		exp:     issued.Add(ttl),
		iss:     issued,
		roles:   roles,
	}
}
