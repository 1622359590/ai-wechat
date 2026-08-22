package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepositoryCreatesAndFindsAdministrator(t *testing.T) {
	pool := adminTestPool(t)
	repository := NewRepository(pool)
	ctx := context.Background()
	now := time.Date(2026, 8, 22, 1, 2, 3, 0, time.UTC)

	created, err := repository.CreateUser(ctx, "Admin_01", "admin_01", "synthetic-password-hash", now)
	if err != nil {
		t.Fatalf("CreateUser(): %v", err)
	}
	if created.Username != "Admin_01" || created.Status != adminauth.StatusActive || created.PasswordVersion != 1 {
		t.Fatalf("CreateUser() = %+v", created)
	}
	found, passwordHash, err := repository.FindUserByNormalizedUsername(ctx, "admin_01")
	if err != nil {
		t.Fatalf("FindUserByNormalizedUsername(): %v", err)
	}
	if found != created || passwordHash != "synthetic-password-hash" {
		t.Fatalf("FindUserByNormalizedUsername() = %+v, %q", found, passwordHash)
	}
	if _, err := repository.CreateUser(ctx, "ADMIN_01", "admin_01", "different-hash", now); !errors.Is(err, adminauth.ErrAlreadyExists) {
		t.Fatalf("CreateUser(duplicate) error = %v, want ErrAlreadyExists", err)
	}
	if _, _, err := repository.FindUserByNormalizedUsername(ctx, "missing_admin"); !errors.Is(err, adminauth.ErrNotFound) {
		t.Fatalf("FindUserByNormalizedUsername(missing) error = %v, want ErrNotFound", err)
	}

	var eventAction, actorType string
	if err := pool.QueryRow(ctx, `SELECT action, actor_type FROM admin_security_events WHERE admin_user_id = $1`, created.ID).Scan(&eventAction, &actorType); err != nil {
		t.Fatalf("read account event: %v", err)
	}
	if eventAction != "account_created" || actorType != "local_cli" {
		t.Fatalf("account event = %q, %q", eventAction, actorType)
	}
}

func TestRepositorySessionLifecycle(t *testing.T) {
	pool := adminTestPool(t)
	repository := NewRepository(pool)
	ctx := context.Background()
	now := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
	user := createAdminUser(t, repository, now)
	record := adminauth.SessionRecord{
		User:            user,
		TokenHash:       digestWithLast(1),
		CSRFHash:        digestWithLast(2),
		PasswordVersion: user.PasswordVersion,
		CreatedAt:       now,
		LastUsedAt:      now,
		ExpiresAt:       now.Add(8 * time.Hour),
	}
	if err := repository.CreateSession(ctx, record); err != nil {
		t.Fatalf("CreateSession(): %v", err)
	}

	found, err := repository.FindSession(ctx, record.TokenHash, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("FindSession(): %v", err)
	}
	if found.User.ID != user.ID || found.User.Username != user.Username || found.User.LastLoginAt == nil || !found.User.LastLoginAt.Equal(now) || found.CSRFHash != record.CSRFHash || !found.ExpiresAt.Equal(record.ExpiresAt) {
		t.Fatalf("FindSession() = %+v", found)
	}
	rotatedCSRF := digestWithLast(3)
	if err := repository.RotateCSRF(ctx, record.TokenHash, rotatedCSRF, now.Add(31*time.Minute)); err != nil {
		t.Fatalf("RotateCSRF(): %v", err)
	}
	rotated, err := repository.FindSession(ctx, record.TokenHash, now.Add(31*time.Minute))
	if err != nil || rotated.CSRFHash != rotatedCSRF {
		t.Fatalf("FindSession(rotated CSRF) = %+v/%v", rotated, err)
	}
	if _, err := repository.FindSession(ctx, record.TokenHash, now.Add(time.Hour)); !errors.Is(err, adminauth.ErrAuthenticationFailed) {
		t.Fatalf("FindSession(idle boundary) error = %v, want ErrAuthenticationFailed", err)
	}

	if err := repository.TouchSession(ctx, record.TokenHash, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("TouchSession(coalesced): %v", err)
	}
	if got := sessionLastUsedAt(t, pool, record.TokenHash); !got.Equal(now) {
		t.Fatalf("coalesced last_used_at = %v, want %v", got, now)
	}
	if err := repository.TouchSession(ctx, record.TokenHash, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("TouchSession(update): %v", err)
	}
	if got := sessionLastUsedAt(t, pool, record.TokenHash); !got.Equal(now.Add(6 * time.Minute)) {
		t.Fatalf("updated last_used_at = %v", got)
	}

	if err := repository.RevokeSession(ctx, record.TokenHash, now.Add(7*time.Minute)); err != nil {
		t.Fatalf("RevokeSession(): %v", err)
	}
	if _, err := repository.FindSession(ctx, record.TokenHash, now.Add(8*time.Minute)); !errors.Is(err, adminauth.ErrAuthenticationFailed) {
		t.Fatalf("FindSession(revoked) error = %v, want ErrAuthenticationFailed", err)
	}
	if _, err := repository.FindSession(ctx, digestWithLast(99), now); !errors.Is(err, adminauth.ErrAuthenticationFailed) {
		t.Fatalf("FindSession(unknown) error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestRepositoryPasswordChangesInvalidateSessions(t *testing.T) {
	pool := adminTestPool(t)
	repository := NewRepository(pool)
	ctx := context.Background()
	now := time.Date(2026, 8, 22, 3, 0, 0, 0, time.UTC)
	user := createAdminUser(t, repository, now)
	first := newSessionRecord(user, digestWithLast(10), digestWithLast(11), now)
	second := newSessionRecord(user, digestWithLast(12), digestWithLast(13), now)
	if err := repository.CreateSession(ctx, first); err != nil {
		t.Fatalf("CreateSession(first): %v", err)
	}
	if err := repository.CreateSession(ctx, second); err != nil {
		t.Fatalf("CreateSession(second): %v", err)
	}

	changed, err := repository.ChangePassword(ctx, user.ID, user.PasswordVersion, "changed-password-hash", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ChangePassword(): %v", err)
	}
	if changed.PasswordVersion != 2 {
		t.Fatalf("ChangePassword() version = %d, want 2", changed.PasswordVersion)
	}
	for _, token := range [][32]byte{first.TokenHash, second.TokenHash} {
		if _, err := repository.FindSession(ctx, token, now.Add(2*time.Minute)); !errors.Is(err, adminauth.ErrAuthenticationFailed) {
			t.Fatalf("FindSession(after change) error = %v, want ErrAuthenticationFailed", err)
		}
	}
	if _, err := repository.ChangePassword(ctx, user.ID, user.PasswordVersion, "stale-change", now.Add(2*time.Minute)); !errors.Is(err, adminauth.ErrAuthenticationFailed) {
		t.Fatalf("ChangePassword(stale version) error = %v, want ErrAuthenticationFailed", err)
	}

	if err := repository.ResetPassword(ctx, "admin_01", "reset-password-hash", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("ResetPassword(): %v", err)
	}
	found, passwordHash, err := repository.FindUserByNormalizedUsername(ctx, "admin_01")
	if err != nil {
		t.Fatalf("FindUserByNormalizedUsername(): %v", err)
	}
	if found.PasswordVersion != 3 || passwordHash != "reset-password-hash" {
		t.Fatalf("reset user = %+v, hash=%q", found, passwordHash)
	}
	if err := repository.ResetPassword(ctx, "missing_admin", "hash", now); !errors.Is(err, adminauth.ErrNotFound) {
		t.Fatalf("ResetPassword(missing) error = %v, want ErrNotFound", err)
	}

	rows, err := pool.Query(ctx, `SELECT action, actor_type FROM admin_security_events
		WHERE admin_user_id = $1 ORDER BY id`, user.ID)
	if err != nil {
		t.Fatalf("query security events: %v", err)
	}
	defer rows.Close()
	var events [][2]string
	for rows.Next() {
		var event [2]string
		if err := rows.Scan(&event[0], &event[1]); err != nil {
			t.Fatalf("scan security event: %v", err)
		}
		events = append(events, event)
	}
	want := [][2]string{{"account_created", "local_cli"}, {"password_changed", "admin_web"}, {"password_reset", "local_cli"}}
	if len(events) != len(want) {
		t.Fatalf("security events = %v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("security event %d = %v, want %v", index, events[index], want[index])
		}
	}
}

func adminTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatalf("reset test database: %v", err)
	}
	if err := devicepostgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return pool
}

func createAdminUser(t *testing.T, repository *Repository, now time.Time) adminauth.User {
	t.Helper()
	user, err := repository.CreateUser(context.Background(), "Admin_01", "admin_01", "synthetic-password-hash", now)
	if err != nil {
		t.Fatalf("CreateUser(): %v", err)
	}
	return user
}

func newSessionRecord(user adminauth.User, tokenHash, csrfHash [32]byte, now time.Time) adminauth.SessionRecord {
	return adminauth.SessionRecord{
		User:            user,
		TokenHash:       tokenHash,
		CSRFHash:        csrfHash,
		PasswordVersion: user.PasswordVersion,
		CreatedAt:       now,
		LastUsedAt:      now,
		ExpiresAt:       now.Add(8 * time.Hour),
	}
}

func sessionLastUsedAt(t *testing.T, pool *pgxpool.Pool, tokenHash [32]byte) time.Time {
	t.Helper()
	var result time.Time
	if err := pool.QueryRow(context.Background(), "SELECT last_used_at FROM admin_sessions WHERE token_hash = $1", tokenHash[:]).Scan(&result); err != nil {
		t.Fatalf("read session last_used_at: %v", err)
	}
	return result
}

func digestWithLast(last byte) [32]byte {
	var result [32]byte
	result[len(result)-1] = last
	return result
}
