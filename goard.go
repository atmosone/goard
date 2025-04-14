/* Package goard implements simple authorization/authentication framework for your Go App with session HTTP cookies */
package goard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	DEFAULT_TTL     = 8 * time.Hour
	DEFAULT_CLEANUP = 5 * time.Minute
	DEFAULT_COST    = 10
)

var (
	ErrMethod       = errors.New("method not allowed")
	ErrAccessDenied = errors.New("access denied")
	ErrRoleConflict = errors.New("role already exists")

	ErrCredentialsConflict = errors.New("credentials already exists")
	ErrCredentialsNotFound = errors.New("credentials not found")
	ErrCredentialsMismatch = errors.New("credentials mismatch")

	ErrBadCredentials  = errors.New("bad credentials")
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

type Config struct {
	// App - is application interface which uses Goard API
	App App
	// Admin - is full access Goard superuser
	Admin Admin
	// Transpor - is Goard transport interface
	Transport Transport
	// Transpor - is Goard Session container interface
	Container Container
	// Database - is your Go App users database interface
	Database Database
	// Store - is Goard session store interface
	Store Store
	// Validator - is Goard credentials validator interface
	Validator Validator
	// Hasher - is a hash function provider interface fo password encryption
	Hasher Hasher
	// TTL - is time to life for one personal Goard session
	TTL time.Duration
	// CI - is cleanup interval for session store scan expired Goard sessions
	CI time.Duration
}

func New(config *Config) *Goard {
	if config.Database == nil {
		return nil
	}

	if config.Hasher == nil {
		config.Hasher = NewBcryptHasher(DEFAULT_COST)
	}

	if config.Container == nil {
		return nil
	}

	if config.Transport == nil {
		config.Transport = NewJSONTransport()
	}

	if config.Validator == nil {
		config.Validator = NewDefaultValidator()
	}

	if config.Store == nil {
		config.Store = NewStore()
	}

	if config.TTL.Milliseconds() == 0 {
		config.TTL = DEFAULT_TTL
	}

	if config.CI.Milliseconds() == 0 {
		config.CI = DEFAULT_CLEANUP
	}

	g := &Goard{
		app:       config.App,
		admin:     config.Admin,
		database:  config.Database,
		container: config.Container,
		transport: config.Transport,
		hasher:    config.Hasher,
		validator: config.Validator,
		store:     config.Store,
		ttl:       config.TTL,
		ci:        config.CI,
	}

	return g
}

func (g *Goard) Open() error {
	if err := g.database.Migrate(context.Background()); err != nil {
		return err
	}

	go g.cleanup(context.Background())
	return nil
}

func (g *Goard) SignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	login, password, err := g.transport.SignIn(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session, err := g.signin(ctx, login, password)
	if err != nil {
		if errors.Is(err, ErrBadCredentials) {
			w.WriteHeader(http.StatusBadRequest)
		} else if errors.Is(err, ErrCredentialsNotFound) {
			w.WriteHeader(http.StatusForbidden)
		} else if errors.Is(err, ErrCredentialsMismatch) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	g.container.SetSession(w, session)
	w.WriteHeader(http.StatusOK)
}

func (g *Goard) SignUp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	account, login, password, err := g.transport.SignUp(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := g.signup(ctx, account, login, password); err != nil {
		if errors.Is(err, ErrBadCredentials) {
			w.WriteHeader(http.StatusBadRequest)
		} else if errors.Is(err, ErrCredentialsConflict) {
			w.WriteHeader(http.StatusConflict)
		} else if errors.Is(err, ErrCredentialsMismatch) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
}

func (g *Goard) SignOut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := g.container.GetSession(r)
	if session == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := g.signout(ctx, session); err != nil {
		fmt.Println(err)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func (g *Goard) Guard(next http.Handler, filter func(*Session) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sessionID := g.container.GetSession(r)
		if sessionID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		session, err := g.session(ctx, sessionID)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				w.WriteHeader(http.StatusUnauthorized)
			} else if errors.Is(err, ErrSessionExpired) {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		if ok := filter(session); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *Goard) SetRole(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	sessionID := g.container.GetSession(r)
	if sessionID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	account, role, err := g.transport.SetRole(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := g.setRole(ctx, sessionID, account, role); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			w.WriteHeader(http.StatusForbidden)
		} else if errors.Is(err, ErrRoleConflict) {
			w.WriteHeader(http.StatusConflict)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (g *Goard) UnsetRole(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	sessionID := g.container.GetSession(r)
	if sessionID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	account, role, err := g.transport.UnsetRole(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := g.unsetRole(ctx, sessionID, account, role); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}
