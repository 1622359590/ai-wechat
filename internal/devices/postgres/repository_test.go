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
