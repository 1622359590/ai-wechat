package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepositoryAuthorize(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)

	tests := []struct {
		name        string
		fingerprint devices.Fingerprint
		status      devices.Status
		expires     *time.Time
		wantError   error
	}{
		{name: "active without expiry", fingerprint: testFingerprint(1), status: devices.StatusActive},
		{name: "active before expiry", fingerprint: testFingerprint(2), status: devices.StatusActive, expires: &future},
		{name: "exact expiry", fingerprint: testFingerprint(3), status: devices.StatusActive, expires: &now, wantError: devices.ErrNotAuthorized},
		{name: "disabled", fingerprint: testFingerprint(4), status: devices.StatusDisabled, wantError: devices.ErrNotAuthorized},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			created, err := repository.Add(ctx, devices.AddDevice{
				Fingerprint:   testCase.fingerprint,
				TenantID:      devices.DefaultTenantID,
				Label:         "synthetic-" + testCase.name,
				Status:        testCase.status,
				AuthExpiresAt: testCase.expires,
			})
			if err != nil {
				t.Fatalf("Add(): %v", err)
			}

			got, err := repository.Authorize(ctx, testCase.fingerprint, now)
			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("Authorize() error = %v, want %v", err, testCase.wantError)
			}
			if testCase.wantError == nil && got.ID != created.ID {
				t.Fatalf("Authorize() device ID = %q, want %q", got.ID, created.ID)
			}
		})
	}

	if _, err := repository.Authorize(ctx, testFingerprint(99), now); !errors.Is(err, devices.ErrNotAuthorized) {
		t.Fatalf("Authorize(unknown) error = %v, want ErrNotAuthorized", err)
	}
}

func TestRepositoryLegacyImportIsIdempotentAndPreservesExistingDevices(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	now := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	records := []ImportRecord{
		{Fingerprint: testFingerprint(71), Status: devices.StatusActive, AuthExpiresAt: &expires},
		{Fingerprint: testFingerprint(72), Status: devices.StatusDisabled},
	}
	summary, err := repository.ImportDevices(ctx, records, now)
	if err != nil {
		t.Fatalf("Import(): %v", err)
	}
	if summary.Imported != 2 || summary.Duplicates != 0 {
		t.Fatalf("first import summary = %#v", summary)
	}
	if _, err := repository.Authorize(ctx, testFingerprint(71), now); err != nil {
		t.Fatalf("authorize imported active device: %v", err)
	}
	if _, err := repository.Authorize(ctx, testFingerprint(72), now); !errors.Is(err, devices.ErrNotAuthorized) {
		t.Fatalf("authorize imported disabled device: %v", err)
	}

	replacementExpiry := now.Add(48 * time.Hour)
	summary, err = repository.ImportDevices(ctx, []ImportRecord{{
		Fingerprint: testFingerprint(71), Status: devices.StatusDisabled, AuthExpiresAt: &replacementExpiry,
	}}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("duplicate Import(): %v", err)
	}
	if summary.Imported != 0 || summary.Duplicates != 1 {
		t.Fatalf("duplicate import summary = %#v", summary)
	}
	device, err := repository.Authorize(ctx, testFingerprint(71), now)
	if err != nil {
		t.Fatalf("duplicate import changed active status: %v", err)
	}
	if device.AuthExpiresAt == nil || !device.AuthExpiresAt.Equal(expires) {
		t.Fatalf("duplicate import changed expiry to %v", device.AuthExpiresAt)
	}

	var migrationEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM device_admin_events
		WHERE actor_type = 'migration' AND reason_code = 'legacy_import'`).Scan(&migrationEvents); err != nil {
		t.Fatalf("count migration events: %v", err)
	}
	if migrationEvents != 2 {
		t.Fatalf("migration event count = %d, want 2", migrationEvents)
	}
}

func TestRepositoryLegacyImportPreviewAndInvalidBatchAreReadOnly(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	now := time.Date(2026, 8, 20, 16, 0, 0, 0, time.UTC)
	if _, err := repository.ImportDevices(ctx, []ImportRecord{{Fingerprint: testFingerprint(73), Status: devices.StatusActive}}, now); err != nil {
		t.Fatalf("seed Import(): %v", err)
	}
	preview, err := repository.PreviewImport(ctx, []ImportRecord{
		{Fingerprint: testFingerprint(73), Status: devices.StatusActive},
		{Fingerprint: testFingerprint(74), Status: devices.StatusDisabled},
		{Fingerprint: testFingerprint(74), Status: devices.StatusDisabled},
	})
	if err != nil || preview.Imported != 1 || preview.Duplicates != 2 {
		t.Fatalf("Preview() = %#v, error %v", preview, err)
	}
	if _, err := repository.Authorize(ctx, testFingerprint(74), now); !errors.Is(err, devices.ErrNotAuthorized) {
		t.Fatal("Preview() wrote a device")
	}
	_, err = repository.ImportDevices(ctx, []ImportRecord{
		{Fingerprint: testFingerprint(75), Status: devices.StatusActive},
		{Fingerprint: testFingerprint(76), Status: devices.Status("invalid")},
	}, now)
	if !errors.Is(err, devices.ErrInvalidInput) {
		t.Fatalf("invalid Import() error = %v, want ErrInvalidInput", err)
	}
	if _, err := repository.Authorize(ctx, testFingerprint(75), now); !errors.Is(err, devices.ErrNotAuthorized) {
		t.Fatal("invalid batch partially wrote a device")
	}
}

func TestOpenUsesBoundedPoolSettings(t *testing.T) {
	ctx := context.Background()
	pool, err := Open(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer pool.Close()
	config := pool.Config()
	if config.MaxConns != 10 || config.MinConns != 1 {
		t.Fatalf("pool connections = max %d/min %d, want 10/1", config.MaxConns, config.MinConns)
	}
	if config.MaxConnLifetime != 30*time.Minute || config.MaxConnIdleTime != 5*time.Minute {
		t.Fatalf("pool durations = lifetime %v/idle %v", config.MaxConnLifetime, config.MaxConnIdleTime)
	}
}

func TestRepositoryAddDuplicateAndListValidation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	input := devices.AddDevice{
		Fingerprint: testFingerprint(10),
		TenantID:    devices.DefaultTenantID,
		Label:       "synthetic-device",
		Status:      devices.StatusActive,
	}
	created, err := repository.Add(ctx, input)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}
	if created.ID == "" || created.TenantID != input.TenantID || created.Label != input.Label || created.Status != input.Status {
		t.Fatalf("Add() returned incomplete device: %#v", created)
	}
	if _, err := repository.Add(ctx, input); !errors.Is(err, devices.ErrAlreadyExists) {
		t.Fatalf("duplicate Add() error = %v, want ErrAlreadyExists", err)
	}

	for _, limit := range []int{-1, 0, 1001} {
		if _, err := repository.List(ctx, limit); !errors.Is(err, devices.ErrInvalidInput) {
			t.Fatalf("List(%d) error = %v, want ErrInvalidInput", limit, err)
		}
	}
	listed, err := repository.List(ctx, 1000)
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("List() = %#v, want created device", listed)
	}
}

func TestRepositoryAdministrativeChangesAreAuditedAtomically(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	created, err := repository.Add(ctx, devices.AddDevice{
		Fingerprint: testFingerprint(20),
		TenantID:    devices.DefaultTenantID,
		Label:       "synthetic-admin",
		Status:      devices.StatusActive,
	})
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}
	now := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	if err := repository.SetStatus(ctx, created.ID, devices.StatusDisabled, "manual_disable", now); err != nil {
		t.Fatalf("SetStatus(disabled): %v", err)
	}
	if err := repository.SetStatus(ctx, created.ID, devices.StatusActive, "manual_enable", now.Add(time.Minute)); err != nil {
		t.Fatalf("SetStatus(active): %v", err)
	}
	if err := repository.SetExpiry(ctx, created.ID, &expires, "manual_expiry", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("SetExpiry(): %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT action, actor_type, reason_code
		FROM device_admin_events WHERE device_id = $1 ORDER BY id`, created.ID)
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, actor, reason string
		if err := rows.Scan(&action, &actor, &reason); err != nil {
			t.Fatalf("scan audit event: %v", err)
		}
		got = append(got, action+":"+actor+":"+reason)
	}
	want := []string{
		"created:local_cli:manual_add",
		"disabled:local_cli:manual_disable",
		"enabled:local_cli:manual_enable",
		"expiry_changed:local_cli:manual_expiry",
	}
	if len(got) != len(want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("audit event %d = %q, want %q", index, got[index], want[index])
		}
	}

	if err := repository.SetStatus(ctx, created.ID, devices.StatusDisabled, "invalid_reason", now); !errors.Is(err, devices.ErrInvalidInput) {
		t.Fatalf("SetStatus(invalid reason) error = %v, want ErrInvalidInput", err)
	}
	authorized, err := repository.Authorize(ctx, testFingerprint(20), now)
	if err != nil || authorized.Status != devices.StatusActive {
		t.Fatalf("invalid status transaction changed device: device=%#v error=%v", authorized, err)
	}
	if err := repository.SetStatus(ctx, devices.ID("00000000-0000-0000-0000-000000000099"), devices.StatusDisabled, "manual_disable", now); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("SetStatus(unknown) error = %v, want ErrNotFound", err)
	}
}

func TestRepositoryManagedActorAndEventList(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	var adminUserID string
	if err := pool.QueryRow(ctx, `INSERT INTO admin_users
		(username, username_normalized, password_hash) VALUES ('Admin_Events', 'admin_events', 'synthetic-hash')
		RETURNING id::text`).Scan(&adminUserID); err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	repository := NewRepository(pool)
	actor := devices.AdminActor{Type: "admin_web", AdminUserID: adminUserID}
	now := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	created, err := repository.AddManaged(ctx, devices.AddDevice{
		Fingerprint: testFingerprint(24),
		TenantID:    devices.DefaultTenantID,
		Label:       "managed-device",
		Status:      devices.StatusActive,
	}, actor, "manual_add", now)
	if err != nil {
		t.Fatalf("AddManaged(): %v", err)
	}
	if err := repository.SetStatusManaged(ctx, created.ID, devices.StatusDisabled, actor, "manual_disable", now.Add(time.Minute)); err != nil {
		t.Fatalf("SetStatusManaged(): %v", err)
	}
	if err := repository.SetExpiry(ctx, created.ID, nil, "manual_expiry", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("SetExpiry(local CLI): %v", err)
	}
	events, err := repository.ListAdminEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminEvents(): %v", err)
	}
	if len(events) != 3 || events[0].Action != "expiry_changed" || events[1].Action != "disabled" || events[2].Action != "created" {
		t.Fatalf("ListAdminEvents order = %#v", events)
	}
	if events[0].ActorType != "local_cli" || events[0].AdminUserID != "" {
		t.Fatalf("local CLI event = %#v", events[0])
	}
	for _, event := range events[1:] {
		if event.DeviceID != created.ID || event.ActorType != "admin_web" || event.AdminUserID != adminUserID {
			t.Fatalf("managed event = %#v", event)
		}
	}
	for _, invalid := range []devices.AdminActor{
		{Type: "admin_web"},
		{Type: "local_cli", AdminUserID: adminUserID},
		{Type: "unexpected"},
	} {
		if _, err := repository.AddManaged(ctx, devices.AddDevice{
			Fingerprint: testFingerprint(25), TenantID: devices.DefaultTenantID, Status: devices.StatusActive,
		}, invalid, "manual_add", now); !errors.Is(err, devices.ErrInvalidInput) {
			t.Fatalf("AddManaged(invalid actor %#v) error = %v", invalid, err)
		}
	}
	if _, err := repository.ListAdminEvents(ctx, 0); !errors.Is(err, devices.ErrInvalidInput) {
		t.Fatalf("ListAdminEvents(0) error = %v", err)
	}
}

func TestRepositoryTouchAuthenticatedCoalescesWithinOneHour(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	repository := NewRepository(pool)
	created, err := repository.Add(ctx, devices.AddDevice{
		Fingerprint: testFingerprint(30),
		TenantID:    devices.DefaultTenantID,
		Label:       "synthetic-touch",
		Status:      devices.StatusActive,
	})
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}
	first := time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)
	if err := repository.TouchAuthenticated(ctx, created.ID, first); err != nil {
		t.Fatalf("first TouchAuthenticated(): %v", err)
	}
	if err := repository.TouchAuthenticated(ctx, created.ID, first.Add(30*time.Minute)); err != nil {
		t.Fatalf("coalesced TouchAuthenticated(): %v", err)
	}
	if got := lastAuthenticatedAt(t, pool, created.ID); !got.Equal(first) {
		t.Fatalf("timestamp after coalesced touch = %v, want %v", got, first)
	}
	second := first.Add(time.Hour)
	if err := repository.TouchAuthenticated(ctx, created.ID, second); err != nil {
		t.Fatalf("hourly TouchAuthenticated(): %v", err)
	}
	if got := lastAuthenticatedAt(t, pool, created.ID); !got.Equal(second) {
		t.Fatalf("timestamp after hourly touch = %v, want %v", got, second)
	}
}

func testFingerprint(last byte) devices.Fingerprint {
	var fingerprint devices.Fingerprint
	fingerprint[len(fingerprint)-1] = last
	return fingerprint
}

func lastAuthenticatedAt(t *testing.T, pool *pgxpool.Pool, id devices.ID) time.Time {
	t.Helper()
	var value time.Time
	if err := pool.QueryRow(context.Background(), "SELECT last_authenticated_at FROM devices WHERE id = $1", id).Scan(&value); err != nil {
		t.Fatalf("read last_authenticated_at: %v", err)
	}
	return value
}
