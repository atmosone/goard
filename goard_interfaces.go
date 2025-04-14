package goard

import (
	"context"
	"encoding/json"
	"net/http"
)

type App interface {
	CreateAccount(ctx context.Context, account json.RawMessage) (Account, error)
	AccountByID(ctx context.Context, id int64) (Account, error)
	DeleteAccount(ctx context.Context, id int64) error
}

type Account interface {
	GetID() int64
}

type Store interface {
	CreateSession(context.Context, *Session) error
	InvokeSession(context.Context, string) (*Session, error)
	RevokeSession(context.Context, string) error
	ForEach(context.Context, func(s *Session) error) error
	Reset(context.Context) error
	Count(context.Context) int
}

type Database interface {
	Migrate(context.Context) error
	CredentialsByLogin(context.Context, string) (*Credentials, error)
	CreateCredentials(context.Context, *Credentials) error
	CredentialsByID(context.Context, int64) (*Credentials, error)
	DeleteCredentials(context.Context, int64) error
	UpdateCredentials(context.Context, *Credentials) error
}

type Transport interface {
	SignIn(*http.Request) (login, password string, err error)
	SignUp(*http.Request) (account json.RawMessage, login, password string, err error)
	SetRole(*http.Request) (account int64, role string, err error)
	UnsetRole(*http.Request) (account int64, role string, err error)
}

type Container interface {
	GetSession(*http.Request) string
	SetSession(http.ResponseWriter, *Session)
}

type Validator interface {
	Validate(ctx context.Context, login, password string) bool
}

type Hasher interface {
	Hash(ctx context.Context, password string) (hash string, err error)
	Compare(ctx context.Context, hash, password string) bool
}
