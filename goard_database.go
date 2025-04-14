package goard

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type postgresDatabase struct {
	db *sql.DB
}

func (p *postgresDatabase) Migrate(ctx context.Context) error {
	const query = `
	BEGIN;

	CREATE TABLE IF NOT EXISTS 
		goard_roles (
			role_id SERIAL PRIMARY KEY,
			role_name VARCHAR(60) NOT NULL
		)
	;

	CREATE TABLE IF NOT EXISTS 
		goard_creds (
			creds_id BIGINT NOT NULL UNIQUE,
			creds_login VARCHAR(60) NOT NULL UNIQUE,
			creds_passhash VARCHAR(120) NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)
	;

	CREATE TABLE IF NOT EXISTS 
		goard_permissions (
			creds_id BIGINT NOT NULL REFERENCES goard_creds(creds_id),
			role_id INTEGER NOT NULL REFERENCES goard_roles(role_id),
			created_at TIMESTAMPTZ NOT NULL
		)
	;

	COMMIT;`

	if _, err := p.db.ExecContext(ctx, query); err != nil {
		return err
	}

	return nil
}

func (p *postgresDatabase) createRoleIfNotExists(ctx context.Context, tx *sql.Tx, role string) (int32, error) {
	var id int32

	if err := tx.QueryRowContext(ctx,
		`SELECT role_id FROM goard_roles WHERE role_name = $1;`,
		role,
	).Scan(&id); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
	}

	if err := tx.QueryRowContext(ctx,
		`INSERT INTO goard_roles (role_name) VALUES ($1) RETURNING role_id;`,
		role,
	).Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
}

func (p *postgresDatabase) rolesByCredentialsID(ctx context.Context, tx *sql.Tx, credsID int64) ([]string, error) {
	const query = `
	SELECT
		goard_roles.role_name
	FROM
		goard_permissions
	JOIN 
		goard_roles 
	ON 
		goard_permissions.role_id = goard_roles.role_id
	WHERE
		goard_permissions.creds_id = $1;`

	rows, err := tx.QueryContext(ctx, query, credsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []string{}

	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (p *postgresDatabase) createPermission(ctx context.Context, tx *sql.Tx, credsID int64, roleID int32) error {
	var ok int

	if err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM goard_permissions WHERE creds_id = $1 AND role_id = $2;`,
		credsID, roleID,
	).Scan(&ok); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goard_permissions (creds_id, role_id) VALUES ($1, $2);`,
		credsID, roleID,
	); err != nil {
		return err
	}

	return nil
}

func (p *postgresDatabase) deletePermission(ctx context.Context, tx *sql.Tx, credsID int64, role string) error {
	const query = `
	DELETE FROM
	    goard_permissions
	USING
	    goard_roles
	WHERE
	    goard_permissions.creds_id = $1
	AND
	    goard_permissions.role_id = goard_roles.role_id
	AND
	    goard_roles.role_name = $2;`

	if _, err := tx.ExecContext(ctx, query, credsID, role); err != nil {
		return err
	}

	return nil
}

// CreateCredentials implements Database.
func (p *postgresDatabase) CreateCredentials(ctx context.Context, credentials *Credentials) error {
	const query = `
	INSERT INTO 
		goard_creds (
			creds_id,
			creds_login,
			creds_passhash
		) 
	VALUES 
		($1, $2, $3) 
	RETURNING
		creds_id;`
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var credsID int64
	if err := tx.QueryRowContext(ctx, query,
		credentials.id,
		credentials.login,
		credentials.passhash,
	).Scan(&credsID); err != nil {
		return err
	}

	for i := range credentials.roles {
		roleID, err := p.createRoleIfNotExists(ctx, tx, credentials.roles[i])
		if err != nil {
			return err
		}
		if err = p.createPermission(ctx, tx, credsID, roleID); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil
	}

	return nil
}

// CredentialsByID implements Database.
func (p *postgresDatabase) CredentialsByID(ctx context.Context, credsID int64) (*Credentials, error) {
	const query = `
	SELECT
		creds_id,
		creds_login,
		creds_passhash
	FROM
		goard_creds
	WHERE
		creds_id = $1;`
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	creds := &Credentials{}
	if err = tx.QueryRowContext(ctx, query, credsID).Scan(
		&creds.id,
		creds.login,
		creds.passhash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCredentialsNotFound
		}
		return nil, err
	}

	if creds.roles, err = p.rolesByCredentialsID(ctx, tx, credsID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return creds, nil
}

// CredentialsByLogin implements Database.
func (p *postgresDatabase) CredentialsByLogin(ctx context.Context, login string) (*Credentials, error) {
	const query = `
	SELECT
		creds_id,
		creds_login,
		creds_passhash
	FROM
		goard_creds
	WHERE
		creds_login = $1;`
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	creds := &Credentials{}
	if err = tx.QueryRowContext(ctx, query, login).Scan(
		&creds.id,
		creds.login,
		creds.passhash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCredentialsNotFound
		}
		return nil, err
	}

	if creds.roles, err = p.rolesByCredentialsID(ctx, tx, creds.id); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return creds, nil
}

// DeleteCredentials implements Database.
func (p *postgresDatabase) DeleteCredentials(ctx context.Context, credsID int64) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(ctx,
		`DELETE FROM goard_permissions WHERE creds_id = $1;`,
		credsID,
	); err != nil {
		return err
	}

	if _, err = tx.ExecContext(ctx,
		`DELETE FROM goard_creds WHERE creds_id = $1;`,
		credsID,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// UpdateCredentials implements Database.
func (p *postgresDatabase) UpdateCredentials(ctx context.Context, credentials *Credentials) error {
	const query = `
	UPDATE
		goard_creds
	SET
		creds_login = $1,
		creds_passhash = $2,
		creds_updated_at = $3
	WHERE
		creds_id = $4
	;`

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, query,
		credentials.login,
		credentials.passhash,
		time.Now(),
	); err != nil {
		return err
	}

	prev, err := p.rolesByCredentialsID(ctx, tx, credentials.id)
	if err != nil {
		return err
	}

	toDelete, toAdd := diffSlices(prev, credentials.roles)

	for i := range toDelete {
		if err = p.deletePermission(ctx, tx, credentials.id, toDelete[i]); err != nil {
			return err
		}
	}

	for i := range toAdd {
		roleID, err := p.createRoleIfNotExists(ctx, tx, toAdd[i])
		if err != nil {
			return err
		}
		if err = p.createPermission(ctx, tx, credentials.id, roleID); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}

func diffSlices(old, new []string) (toDelete, toAdd []string) {
	// Создаем мапы для быстрого поиска
	oldMap := make(map[string]struct{}, len(old))
	newMap := make(map[string]struct{}, len(new))

	// Заполняем мапу старого слайса
	for _, item := range old {
		oldMap[item] = struct{}{}
	}

	// Заполняем мапу нового слайса
	for _, item := range new {
		newMap[item] = struct{}{}
	}

	// Находим элементы для удаления (есть в old, но нет в new)
	for _, item := range old {
		if _, exists := newMap[item]; !exists {
			toDelete = append(toDelete, item)
		}
	}

	// Находим элементы для добавления (есть в new, но нет в old)
	for _, item := range new {
		if _, exists := oldMap[item]; !exists {
			toAdd = append(toAdd, item)
		}
	}

	return toDelete, toAdd
}

func NewPostgresDatabase(db *sql.DB) Database {
	return &postgresDatabase{
		db: db,
	}
}
