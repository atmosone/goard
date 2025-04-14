package goard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

type Goard struct {
	app       App
	store     Store
	database  Database
	transport Transport
	container Container
	validator Validator
	hasher    Hasher
	admin     Admin
	ttl       time.Duration
	ci        time.Duration
}

func (g *Goard) signinAsAdmin(ctx context.Context) (*Session, error) {
	now := time.Now()
	session := &Session{
		id:      uuid.New().String(),
		account: g.admin.Account,
		credentials: &Credentials{
			id:    0,
			login: g.admin.Login,
			roles: []string{"admin"},
		},
		exp: now.Add(g.ttl),
		iss: now,
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if err := g.store.CreateSession(ctx, session); err != nil {
			return nil, err
		}
	}

	return session, nil
}

func (g *Goard) signin(ctx context.Context, login, password string) (*Session, error) {
	var err error

	if login == "" || password == "" {
		return nil, ErrBadCredentials
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if err = g.store.ForEach(ctx, func(s *Session) error {
			if s.credentials.login != login {
				return nil
			}

			if err := g.store.RevokeSession(ctx, s.id); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return nil, err
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if login == g.admin.Login && password == g.admin.Password {
			return g.signinAsAdmin(ctx)
		}
	}

	var credentials *Credentials

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if credentials, err = g.database.CredentialsByLogin(ctx, login); err != nil {
			return nil, err
		}
	}

	var account Account

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if account, err = g.app.AccountByID(ctx, credentials.id); err != nil {
			return nil, err
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if ok := g.hasher.Compare(ctx, credentials.passhash, password); !ok {
			return nil, ErrCredentialsMismatch
		}
	}

	now := time.Now()
	session := &Session{
		id:          uuid.New().String(),
		account:     account,
		credentials: credentials,
		exp:         now.Add(g.ttl),
		iss:         now,
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if err = g.store.CreateSession(ctx, session); err != nil {
			return nil, err
		}
	}

	return session, nil
}

func (g *Goard) signup(ctx context.Context, account json.RawMessage, login, password string) error {
	var err error

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if ok := g.validator.Validate(ctx, login, password); !ok {
			return ErrBadCredentials
		}
	}

	var acc Account

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if acc, err = g.app.CreateAccount(ctx, account); err != nil {
			return err
		}
	}

	// Rollback application account
	defer func() {
		if err != nil {
			if err := g.app.DeleteAccount(context.Background(), acc.GetID()); err != nil {
				fmt.Println(err)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if _, err = g.database.CredentialsByID(ctx, acc.GetID()); err != nil {
			if !errors.Is(err, ErrCredentialsNotFound) {
				return err
			}
		} else {
			return ErrCredentialsConflict
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if _, err := g.database.CredentialsByLogin(ctx, login); err != nil {
			if !errors.Is(err, ErrCredentialsNotFound) {
				return err
			}
		} else {
			return ErrCredentialsConflict
		}
	}

	var passhash string

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if passhash, err = g.hasher.Hash(ctx, password); err != nil {
			return err
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if err = g.database.CreateCredentials(ctx, &Credentials{
			id:       acc.GetID(),
			login:    login,
			passhash: passhash,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (g *Goard) signout(ctx context.Context, sessionID string) error {
	if g.store.Count(ctx) == 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return g.store.RevokeSession(ctx, sessionID)
	}
}

func (g *Goard) session(ctx context.Context, sessionID string) (*Session, error) {
	if g.store.Count(ctx) == 0 {
		return nil, ErrSessionNotFound
	}

	now := time.Now()
	session, err := g.store.InvokeSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.exp.Unix() > now.Unix() {
		return session, nil
	}

	go func() {
		if err := g.store.RevokeSession(context.Background(), sessionID); err != nil {
			fmt.Println(err)
		}
	}()

	return nil, ErrSessionExpired
}

func (g *Goard) cleanup(ctx context.Context) {
	ticker := time.NewTicker(g.ci)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case now := <-ticker.C:
			go func(t time.Time) {
				ctx, cancel := context.WithDeadline(ctx,
					t.Add(time.Duration(g.ci.Milliseconds()-100)),
				)
				defer cancel()

				if g.store.Count(ctx) == 0 {
					return
				}

				if err := g.store.ForEach(ctx, func(s *Session) error {
					if s.exp.Unix() > t.Unix() {
						return nil
					}

					if err := g.store.RevokeSession(ctx, s.ID()); err != nil {
						return err
					}

					return nil
				}); err != nil {
					log.Fatal(err)
				}
			}(now)
		}
	}
}

func (g *Goard) setRole(ctx context.Context, id string, account int64, role string) error {
	session, err := g.store.InvokeSession(ctx, id)
	if err != nil {
		return err
	}

	if !session.admin {
		return ErrAccessDenied
	}

	credentials, err := g.database.CredentialsByID(ctx, account)
	if err != nil {
		return err
	}

	for i := range credentials.roles {
		if credentials.roles[i] == role {
			return ErrRoleConflict
		}
	}

	credentials.roles = append(credentials.roles, role)

	if err := g.database.UpdateCredentials(ctx, credentials); err != nil {
		return err
	}

	if err := g.store.ForEach(ctx, func(s *Session) error {
		if s.credentials.id == credentials.id {
			if err := g.store.CreateSession(ctx, &Session{
				id:          s.id,
				account:     s.account,
				credentials: credentials,
				exp:         s.exp,
				iss:         s.iss,
				admin:       s.admin,
			}); err != nil {
				return err
			}
		}

		return err
	}); err != nil {
		return err
	}

	return nil
}

func (g *Goard) unsetRole(ctx context.Context, id string, account int64, role string) error {
	session, err := g.store.InvokeSession(ctx, id)
	if err != nil {
		return err
	}

	if !session.admin {
		return ErrAccessDenied
	}

	credentials, err := g.database.CredentialsByID(ctx, account)
	if err != nil {
		return err
	}

	roles := make([]string, 0, len(credentials.roles))
	for i := range credentials.roles {
		if credentials.roles[i] != role {
			roles = append(roles, credentials.roles[i])
		}
	}

	credentials.roles = roles

	if err := g.database.UpdateCredentials(ctx, credentials); err != nil {
		return err
	}

	if err := g.store.ForEach(ctx, func(s *Session) error {
		if s.credentials.id == credentials.id {
			if err := g.store.CreateSession(ctx, &Session{
				id:          s.id,
				account:     s.account,
				credentials: credentials,
				exp:         s.exp,
				iss:         s.iss,
				admin:       s.admin,
			}); err != nil {
				return err
			}
		}

		return err
	}); err != nil {
		return err
	}

	return nil
}
