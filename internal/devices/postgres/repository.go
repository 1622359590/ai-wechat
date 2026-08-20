package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxListLimit  = 1000
	maxLabelRunes = 120
)

type Repository struct {
	pool *pgxpool.Pool
}

var _ devices.Repository = (*Repository)(nil)

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (repository *Repository) Authorize(ctx context.Context, fingerprint devices.Fingerprint, now time.Time) (devices.Device, error) {
	row := repository.pool.QueryRow(ctx, `SELECT id::text, tenant_id::text, label, status, auth_expires_at, last_authenticated_at
		FROM devices
		WHERE credential_fingerprint = $1
		  AND status = 'active'
		  AND (auth_expires_at IS NULL OR auth_expires_at > $2)`, fingerprint.Bytes(), now)
	device, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.Device{}, devices.ErrNotAuthorized
	}
	if err != nil {
		return devices.Device{}, databaseError(ctx, "authorize device")
	}
	return device, nil
}

func (repository *Repository) TouchAuthenticated(ctx context.Context, id devices.ID, at time.Time) error {
	if !validUUID(string(id)) {
		return devices.ErrInvalidInput
	}
	var exists bool
	err := repository.pool.QueryRow(ctx, `WITH updated AS (
		UPDATE devices
		SET last_authenticated_at = $2::timestamptz, updated_at = $2::timestamptz
		WHERE id = $1
		  AND (last_authenticated_at IS NULL OR last_authenticated_at <= $2::timestamptz - interval '1 hour')
		RETURNING id
	)
	SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)`, id, at).Scan(&exists)
	if err != nil {
		return databaseError(ctx, "touch device authentication")
	}
	if !exists {
		return devices.ErrNotFound
	}
	return nil
}

func (repository *Repository) Add(ctx context.Context, input devices.AddDevice) (devices.Device, error) {
	if !validUUID(input.TenantID) || utf8.RuneCountInString(input.Label) > maxLabelRunes || !validStatus(input.Status) {
		return devices.Device{}, devices.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return devices.Device{}, databaseError(ctx, "begin device add")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, credential_fingerprint, label, status, auth_expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, tenant_id::text, label, status, auth_expires_at, last_authenticated_at`,
		input.TenantID, input.Fingerprint.Bytes(), input.Label, input.Status, input.AuthExpiresAt)
	device, err := scanDevice(row)
	if err != nil {
		if isUniqueViolation(err) {
			return devices.Device{}, devices.ErrAlreadyExists
		}
		if isConstraintViolation(err) {
			return devices.Device{}, devices.ErrInvalidInput
		}
		return devices.Device{}, databaseError(ctx, "insert device")
	}
	if err := insertAdminEvent(ctx, tx, device.ID, "created", "local_cli", "manual_add", time.Now()); err != nil {
		return devices.Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devices.Device{}, databaseError(ctx, "commit device add")
	}
	return device, nil
}

func (repository *Repository) List(ctx context.Context, limit int) ([]devices.Device, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, devices.ErrInvalidInput
	}
	rows, err := repository.pool.Query(ctx, `SELECT id::text, tenant_id::text, label, status, auth_expires_at, last_authenticated_at
		FROM devices ORDER BY created_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, databaseError(ctx, "list devices")
	}
	defer rows.Close()

	result := make([]devices.Device, 0)
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, databaseError(ctx, "read device list")
		}
		result = append(result, device)
	}
	if rows.Err() != nil {
		return nil, databaseError(ctx, "read device list")
	}
	return result, nil
}

func (repository *Repository) SetStatus(ctx context.Context, id devices.ID, status devices.Status, reason string, at time.Time) error {
	if !validUUID(string(id)) || !validStatus(status) {
		return devices.ErrInvalidInput
	}
	action := "enabled"
	wantReason := "manual_enable"
	if status == devices.StatusDisabled {
		action = "disabled"
		wantReason = "manual_disable"
	}
	if reason != wantReason {
		return devices.ErrInvalidInput
	}
	return repository.adminUpdate(ctx, id, action, reason, at,
		"UPDATE devices SET status = $2, updated_at = $3 WHERE id = $1 RETURNING id", status)
}

func (repository *Repository) SetExpiry(ctx context.Context, id devices.ID, expiresAt *time.Time, reason string, at time.Time) error {
	if !validUUID(string(id)) || reason != "manual_expiry" {
		return devices.ErrInvalidInput
	}
	return repository.adminUpdate(ctx, id, "expiry_changed", reason, at,
		"UPDATE devices SET auth_expires_at = $2, updated_at = $3 WHERE id = $1 RETURNING id", expiresAt)
}

type ImportRecord struct {
	Fingerprint   devices.Fingerprint
	Status        devices.Status
	AuthExpiresAt *time.Time
}

type ImportSummary struct {
	Total      int
	Imported   int
	Duplicates int
}

func (repository *Repository) PreviewImport(ctx context.Context, records []ImportRecord) (ImportSummary, error) {
	summary := ImportSummary{Total: len(records)}
	if !validImportRecords(records) {
		return summary, devices.ErrInvalidInput
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return summary, databaseError(ctx, "begin device import preview")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	seen := make(map[devices.Fingerprint]struct{}, len(records))
	for _, record := range records {
		if _, duplicate := seen[record.Fingerprint]; duplicate {
			summary.Duplicates++
			continue
		}
		seen[record.Fingerprint] = struct{}{}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM devices WHERE credential_fingerprint = $1)", record.Fingerprint.Bytes()).Scan(&exists); err != nil {
			return summary, databaseError(ctx, "preview device import")
		}
		if exists {
			summary.Duplicates++
		} else {
			summary.Imported++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return summary, databaseError(ctx, "complete device import preview")
	}
	return summary, nil
}

func (repository *Repository) ImportDevices(ctx context.Context, records []ImportRecord, at time.Time) (ImportSummary, error) {
	summary := ImportSummary{Total: len(records)}
	if !validImportRecords(records) {
		return summary, devices.ErrInvalidInput
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return summary, databaseError(ctx, "begin device import")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, record := range records {
		var deviceID devices.ID
		err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, credential_fingerprint, status, auth_expires_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (credential_fingerprint) DO NOTHING
			RETURNING id::text`, devices.DefaultTenantID, record.Fingerprint.Bytes(), record.Status, record.AuthExpiresAt).Scan(&deviceID)
		if errors.Is(err, pgx.ErrNoRows) {
			summary.Duplicates++
			continue
		}
		if err != nil {
			return summary, databaseError(ctx, "insert imported device")
		}
		if err := insertAdminEvent(ctx, tx, deviceID, "created", "migration", "legacy_import", at); err != nil {
			return summary, err
		}
		summary.Imported++
	}
	if err := tx.Commit(ctx); err != nil {
		return summary, databaseError(ctx, "commit device import")
	}
	return summary, nil
}

func validImportRecords(records []ImportRecord) bool {
	for _, record := range records {
		if !validStatus(record.Status) {
			return false
		}
	}
	return true
}

func (repository *Repository) adminUpdate(ctx context.Context, id devices.ID, action, reason string, at time.Time, query string, value any) error {
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return databaseError(ctx, "begin device update")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var updatedID string
	if err := tx.QueryRow(ctx, query, id, value, at).Scan(&updatedID); errors.Is(err, pgx.ErrNoRows) {
		return devices.ErrNotFound
	} else if err != nil {
		return databaseError(ctx, "update device")
	}
	if err := insertAdminEvent(ctx, tx, id, action, "local_cli", reason, at); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return databaseError(ctx, "commit device update")
	}
	return nil
}

func insertAdminEvent(ctx context.Context, tx pgx.Tx, id devices.ID, action, actor, reason string, at time.Time) error {
	var eventID int64
	if err := tx.QueryRow(ctx, `INSERT INTO device_admin_events (device_id, action, actor_type, reason_code, created_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`, id, action, actor, reason, at).Scan(&eventID); err != nil {
		if isConstraintViolation(err) {
			return devices.ErrInvalidInput
		}
		return databaseError(ctx, "record device admin event")
	}
	payload := fmt.Sprintf("%d:%s", eventID, id)
	if _, err := tx.Exec(ctx, "SELECT pg_notify('device_admin_events', $1)", payload); err != nil {
		return databaseError(ctx, "publish device admin event")
	}
	return nil
}

type scanner interface {
	Scan(...any) error
}

func scanDevice(row scanner) (devices.Device, error) {
	var device devices.Device
	err := row.Scan(&device.ID, &device.TenantID, &device.Label, &device.Status, &device.AuthExpiresAt, &device.LastAuthenticatedAt)
	return device, err
}

func validStatus(status devices.Status) bool {
	return status == devices.StatusActive || status == devices.StatusDisabled
}

func validUUID(value string) bool {
	var parsed pgtype.UUID
	return parsed.Scan(value) == nil && parsed.Valid
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

func databaseError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(operation + " failed")
}
