package postgres

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(context.Background(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatalf("reset test database: %v", err)
	}
	return pool
}

func TestMigrateInstallsSchemaOnce(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first Migrate(): %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate(): %v", err)
	}

	var versions int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if versions != 1 {
		t.Fatalf("migration count = %d, want 1", versions)
	}
	for _, table := range []string{"devices", "device_admin_events"} {
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
			t.Fatalf("look up table %q: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}
}

func TestMigrateSerializesConcurrentCalls(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const callers = 8
	var wait sync.WaitGroup
	errors := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- Migrate(ctx, pool)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Migrate(): %v", err)
		}
	}

	var versions int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if versions != 1 {
		t.Fatalf("migration count = %d, want 1", versions)
	}
}

func TestMigrateInstallsDeviceConstraints(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}

	validFingerprint := make([]byte, 32)
	insertDevice := `INSERT INTO devices (tenant_id, credential_fingerprint, credential_version, label, status)
		VALUES ('00000000-0000-0000-0000-000000000001', $1, $2, $3, $4) RETURNING id`
	var deviceID string
	if err := pool.QueryRow(ctx, insertDevice, validFingerprint, 1, "synthetic", "active").Scan(&deviceID); err != nil {
		t.Fatalf("insert valid device: %v", err)
	}

	deviceCases := []struct {
		name        string
		fingerprint []byte
		version     int
		label       string
		status      string
	}{
		{name: "fingerprint length", fingerprint: make([]byte, 31), version: 1, status: "active"},
		{name: "credential version", fingerprint: bytesWithLast(1), version: 2, status: "active"},
		{name: "label length", fingerprint: bytesWithLast(2), version: 1, label: strings.Repeat("x", 121), status: "active"},
		{name: "device status", fingerprint: bytesWithLast(3), version: 1, status: "paused"},
		{name: "unique fingerprint", fingerprint: validFingerprint, version: 1, status: "active"},
	}
	for _, testCase := range deviceCases {
		t.Run(testCase.name, func(t *testing.T) {
			var ignored string
			if err := pool.QueryRow(ctx, insertDevice, testCase.fingerprint, testCase.version, testCase.label, testCase.status).Scan(&ignored); err == nil {
				t.Fatal("invalid device row was accepted")
			}
		})
	}

	insertEvent := `INSERT INTO device_admin_events (device_id, action, actor_type, reason_code, created_at)
		VALUES ($1, $2, $3, $4, now())`
	eventCases := []struct {
		name       string
		action     string
		actorType  string
		reasonCode string
	}{
		{name: "action", action: "removed", actorType: "local_cli", reasonCode: "manual_disable"},
		{name: "actor type", action: "disabled", actorType: "http", reasonCode: "manual_disable"},
		{name: "reason code", action: "disabled", actorType: "local_cli", reasonCode: "other"},
	}
	for _, testCase := range eventCases {
		t.Run("event "+testCase.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, insertEvent, deviceID, testCase.action, testCase.actorType, testCase.reasonCode); err == nil {
				t.Fatal("invalid admin event was accepted")
			}
		})
	}
}

func TestMigrateRejectsNewerDatabaseVersion(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES (999)"); err != nil {
		t.Fatalf("seed newer version: %v", err)
	}
	if err := Migrate(ctx, pool); err == nil {
		t.Fatal("Migrate() accepted a database newer than the binary")
	}
}

func TestMigrateRollsBackFailingMigration(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	broken := fstest.MapFS{
		"migrations/0001_broken.sql": &fstest.MapFile{Data: []byte("CREATE TABLE rollback_probe (id bigint); SELECT missing_function();")},
	}

	if err := migrate(ctx, pool, fs.FS(broken)); err == nil {
		t.Fatal("migrate() succeeded with a broken migration")
	}
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('rollback_probe') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("look up rollback probe: %v", err)
	}
	if exists {
		t.Fatal("failed migration left a partially created table")
	}
}

func bytesWithLast(last byte) []byte {
	value := make([]byte, 32)
	value[len(value)-1] = last
	return value
}
