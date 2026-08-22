package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const sessionTouchInterval = 5 * time.Minute

type Repository struct {
	pool *pgxpool.Pool
}

var _ adminauth.Repository = (*Repository)(nil)

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (repository *Repository) CreateUser(ctx context.Context, username, normalized, passwordHash string, at time.Time) (adminauth.User, error) {
	wantNormalized, err := adminauth.NormalizeUsername(username)
	if err != nil || wantNormalized != normalized || !validPasswordHash(passwordHash) || repository == nil || repository.pool == nil {
		return adminauth.User{}, adminauth.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	user, err := scanUser(tx.QueryRow(ctx, `INSERT INTO admin_users
		(username, username_normalized, password_hash, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', $4, $4)
		RETURNING id::text, username, status, password_version, last_login_at`, username, normalized, passwordHash, at))
	if err != nil {
		if isUniqueViolation(err) {
			return adminauth.User{}, adminauth.ErrAlreadyExists
		}
		if isConstraintViolation(err) {
			return adminauth.User{}, adminauth.ErrInvalidInput
		}
		return adminauth.User{}, databaseError(ctx)
	}
	if err := insertSecurityEvent(ctx, tx, user.ID, "account_created", "local_cli", at); err != nil {
		return adminauth.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	return user, nil
}

func (repository *Repository) FindUserByNormalizedUsername(ctx context.Context, normalized string) (adminauth.User, string, error) {
	if _, err := adminauth.NormalizeUsername(normalized); err != nil || normalized != lowerASCII(normalized) || repository == nil || repository.pool == nil {
		return adminauth.User{}, "", adminauth.ErrInvalidInput
	}
	var passwordHash string
	user, err := scanUserAndPassword(repository.pool.QueryRow(ctx, `SELECT id::text, username, status, password_version, last_login_at, password_hash
		FROM admin_users WHERE username_normalized = $1`, normalized), &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.User{}, "", adminauth.ErrNotFound
	}
	if err != nil {
		return adminauth.User{}, "", databaseError(ctx)
	}
	return user, passwordHash, nil
}

func (repository *Repository) CreateSession(ctx context.Context, record adminauth.SessionRecord) error {
	if !validUUID(string(record.User.ID)) || record.PasswordVersion <= 0 || !record.ExpiresAt.After(record.CreatedAt) || record.LastUsedAt.Before(record.CreatedAt) || repository == nil || repository.pool == nil {
		return adminauth.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return databaseError(ctx)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `INSERT INTO admin_sessions
		(token_hash, csrf_hash, admin_user_id, password_version, created_at, last_used_at, expires_at)
		SELECT $1, $2, id, password_version, $4, $5, $6 FROM admin_users
		WHERE id = $3 AND status = 'active' AND password_version = $7`,
		record.TokenHash[:], record.CSRFHash[:], record.User.ID, record.CreatedAt, record.LastUsedAt, record.ExpiresAt, record.PasswordVersion)
	if err != nil {
		if isConstraintViolation(err) || isUniqueViolation(err) {
			return adminauth.ErrInvalidInput
		}
		return databaseError(ctx)
	}
	if result.RowsAffected() != 1 {
		return adminauth.ErrAuthenticationFailed
	}
	if _, err := tx.Exec(ctx, "UPDATE admin_users SET last_login_at = $2, updated_at = $2 WHERE id = $1", record.User.ID, record.CreatedAt); err != nil {
		return databaseError(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return databaseError(ctx)
	}
	return nil
}

func (repository *Repository) FindSession(ctx context.Context, tokenHash [32]byte, now time.Time) (adminauth.SessionRecord, error) {
	if repository == nil || repository.pool == nil {
		return adminauth.SessionRecord{}, adminauth.ErrInvalidInput
	}
	row := repository.pool.QueryRow(ctx, `SELECT u.id::text, u.username, u.status, u.password_version, u.last_login_at, u.password_hash,
		s.csrf_hash, s.password_version, s.created_at, s.last_used_at, s.expires_at, s.revoked_at
		FROM admin_sessions s JOIN admin_users u ON u.id = s.admin_user_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2
		  AND s.last_used_at > $2::timestamptz - interval '1 hour'
		  AND s.password_version = u.password_version AND u.status = 'active'`, tokenHash[:], now)
	var record adminauth.SessionRecord
	record.TokenHash = tokenHash
	var csrf []byte
	err := row.Scan(&record.User.ID, &record.User.Username, &record.User.Status, &record.User.PasswordVersion,
		&record.User.LastLoginAt, &record.PasswordHash, &csrf, &record.PasswordVersion,
		&record.CreatedAt, &record.LastUsedAt, &record.ExpiresAt, &record.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.SessionRecord{}, adminauth.ErrAuthenticationFailed
	}
	if err != nil {
		return adminauth.SessionRecord{}, databaseError(ctx)
	}
	if len(csrf) != len(record.CSRFHash) {
		return adminauth.SessionRecord{}, databaseError(ctx)
	}
	copy(record.CSRFHash[:], csrf)
	return record, nil
}

func (repository *Repository) TouchSession(ctx context.Context, tokenHash [32]byte, at time.Time) error {
	if repository == nil || repository.pool == nil {
		return adminauth.ErrInvalidInput
	}
	var exists bool
	err := repository.pool.QueryRow(ctx, `WITH touched AS (
		UPDATE admin_sessions SET last_used_at = $2
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
		  AND last_used_at <= $2::timestamptz - interval '5 minutes'
		RETURNING token_hash
	)
	SELECT EXISTS (SELECT 1 FROM admin_sessions WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2)`, tokenHash[:], at).Scan(&exists)
	if err != nil {
		return databaseError(ctx)
	}
	if !exists {
		return adminauth.ErrAuthenticationFailed
	}
	return nil
}

func (repository *Repository) RevokeSession(ctx context.Context, tokenHash [32]byte, at time.Time) error {
	if repository == nil || repository.pool == nil {
		return adminauth.ErrInvalidInput
	}
	result, err := repository.pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at = $2
		WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash[:], at)
	if err != nil {
		return databaseError(ctx)
	}
	if result.RowsAffected() != 1 {
		return adminauth.ErrAuthenticationFailed
	}
	return nil
}

func (repository *Repository) ChangePassword(ctx context.Context, id adminauth.ID, expectedVersion int64, passwordHash string, at time.Time) (adminauth.User, error) {
	if !validUUID(string(id)) || expectedVersion <= 0 || !validPasswordHash(passwordHash) || repository == nil || repository.pool == nil {
		return adminauth.User{}, adminauth.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	user, err := scanUser(tx.QueryRow(ctx, `UPDATE admin_users SET password_hash = $3,
		password_version = password_version + 1, updated_at = $4
		WHERE id = $1 AND password_version = $2 AND status = 'active'
		RETURNING id::text, username, status, password_version, last_login_at`, id, expectedVersion, passwordHash, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.User{}, adminauth.ErrAuthenticationFailed
	}
	if err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	if _, err := tx.Exec(ctx, "UPDATE admin_sessions SET revoked_at = $2 WHERE admin_user_id = $1 AND revoked_at IS NULL", id, at); err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	if err := insertSecurityEvent(ctx, tx, id, "password_changed", "admin_web", at); err != nil {
		return adminauth.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return adminauth.User{}, databaseError(ctx)
	}
	return user, nil
}

func (repository *Repository) ResetPassword(ctx context.Context, normalized, passwordHash string, at time.Time) error {
	if _, err := adminauth.NormalizeUsername(normalized); err != nil || normalized != lowerASCII(normalized) || !validPasswordHash(passwordHash) || repository == nil || repository.pool == nil {
		return adminauth.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return databaseError(ctx)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id adminauth.ID
	err = tx.QueryRow(ctx, `UPDATE admin_users SET password_hash = $2,
		password_version = password_version + 1, updated_at = $3
		WHERE username_normalized = $1 RETURNING id::text`, normalized, passwordHash, at).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminauth.ErrNotFound
	}
	if err != nil {
		return databaseError(ctx)
	}
	if _, err := tx.Exec(ctx, "UPDATE admin_sessions SET revoked_at = $2 WHERE admin_user_id = $1 AND revoked_at IS NULL", id, at); err != nil {
		return databaseError(ctx)
	}
	if err := insertSecurityEvent(ctx, tx, id, "password_reset", "local_cli", at); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return databaseError(ctx)
	}
	return nil
}

func insertSecurityEvent(ctx context.Context, tx pgx.Tx, id adminauth.ID, action, actor string, at time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO admin_security_events (admin_user_id, action, actor_type, created_at)
		VALUES ($1, $2, $3, $4)`, id, action, actor, at); err != nil {
		if isConstraintViolation(err) {
			return adminauth.ErrInvalidInput
		}
		return databaseError(ctx)
	}
	return nil
}

type scanner interface {
	Scan(...any) error
}

func scanUser(row scanner) (adminauth.User, error) {
	var user adminauth.User
	err := row.Scan(&user.ID, &user.Username, &user.Status, &user.PasswordVersion, &user.LastLoginAt)
	return user, err
}

func scanUserAndPassword(row scanner, passwordHash *string) (adminauth.User, error) {
	var user adminauth.User
	err := row.Scan(&user.ID, &user.Username, &user.Status, &user.PasswordVersion, &user.LastLoginAt, passwordHash)
	return user, err
}

func validPasswordHash(value string) bool {
	return len(value) >= 1 && len(value) <= 1024
}

func validUUID(value string) bool {
	var parsed pgtype.UUID
	return parsed.Scan(value) == nil && parsed.Valid
}

func lowerASCII(value string) string {
	contents := []byte(value)
	for index, character := range contents {
		if character >= 'A' && character <= 'Z' {
			contents[index] = character + ('a' - 'A')
		}
	}
	return string(contents)
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func isConstraintViolation(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	switch postgresError.Code {
	case "22001", "23502", "23503", "23514", "22P02":
		return true
	default:
		return false
	}
}

func databaseError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return adminauth.ErrUnavailable
}
