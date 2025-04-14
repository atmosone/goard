package goard

import "time"

type Admin struct {
	Account  Account
	Login    string
	Password string
}

type Credentials struct {
	id       int64
	login    string
	passhash string
	roles    []string
}

func (c *Credentials) ID() int64 {
	return c.id
}

func (c *Credentials) Login() string {
	return c.login
}

func (c *Credentials) Roles() []string {
	return c.roles
}

type Session struct {
	id          string
	account     Account
	credentials *Credentials
	exp         time.Time
	iss         time.Time
	admin       bool
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

func (s *Session) IsAdmin() bool {
	return s.admin
}

func (s *Session) Roles() []string {
	return s.credentials.roles
}
