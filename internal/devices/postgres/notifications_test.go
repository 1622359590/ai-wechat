package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestListenAdminEventsDeduplicatesAndRejectsMalformedPayloads(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}

	received := make(chan devices.ID, 4)
	listener, err := NewAdminEventListener(ctx, testDSN(t), func(deviceID devices.ID) { received <- deviceID })
	if err != nil {
		t.Fatalf("NewAdminEventListener(): %v", err)
	}
	runResult := make(chan error, 1)
	go func() { runResult <- listener.Run(ctx) }()

	firstID := devices.ID("00000000-0000-0000-0000-000000000051")
	secondID := devices.ID("00000000-0000-0000-0000-000000000052")
	for _, payload := range []string{
		"3:" + string(firstID),
		"2:" + string(secondID),
		"3:" + string(firstID),
		"malformed",
	} {
		if _, err := pool.Exec(ctx, "SELECT pg_notify('device_admin_events', $1)", payload); err != nil {
			t.Fatalf("publish notification: %v", err)
		}
	}

	got := map[devices.ID]int{}
	for len(got) < 2 {
		select {
		case deviceID := <-received:
			got[deviceID]++
		case <-time.After(3 * time.Second):
			t.Fatalf("callbacks = %v, want two device IDs", got)
		}
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case duplicate := <-received:
		t.Fatalf("duplicate callback for %q", duplicate)
	default:
	}
	if got[firstID] != 1 || got[secondID] != 1 {
		t.Fatalf("callbacks = %v, want each device once", got)
	}
	if listener.MalformedCount() != 1 {
		t.Fatalf("malformed count = %d, want 1", listener.MalformedCount())
	}

	cancel()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run() after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
}

func TestListenAdminEventsCatchesUpAfterReconnect(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}

	received := make(chan devices.ID, 2)
	listener, err := NewAdminEventListener(ctx, testDSN(t), func(deviceID devices.ID) { received <- deviceID })
	if err != nil {
		t.Fatalf("NewAdminEventListener(): %v", err)
	}
	runResult := make(chan error, 1)
	go func() { runResult <- listener.Run(ctx) }()

	pid := listener.backendPID()
	var terminated bool
	if err := pool.QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate listener backend = %v/%v", terminated, err)
	}

	deviceID := devices.ID("00000000-0000-0000-0000-000000000053")
	if _, err := pool.Exec(ctx, `INSERT INTO devices (id, tenant_id, credential_fingerprint, status)
		VALUES ($1, $2, $3, 'active')`, deviceID, devices.DefaultTenantID, bytesWithLast(53)); err != nil {
		t.Fatalf("insert synthetic device: %v", err)
	}
	var eventID int64
	if err := pool.QueryRow(ctx, `INSERT INTO device_admin_events (device_id, action, actor_type, reason_code, created_at)
		VALUES ($1, 'disabled', 'local_cli', 'manual_disable', now()) RETURNING id`, deviceID).Scan(&eventID); err != nil {
		t.Fatalf("insert gap event: %v", err)
	}

	select {
	case got := <-received:
		if got != deviceID {
			t.Fatalf("catch-up device ID = %q, want %q", got, deviceID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("listener did not catch up event %d", eventID)
	}
	cancel()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run() after reconnect cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not stop after reconnect test")
	}
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set")
	}
	return dsn
}

func TestListenAdminEventsConstructorFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := NewAdminEventListener(ctx, "postgres://127.0.0.1:1/unavailable?sslmode=disable", func(devices.ID) {}); err == nil {
		t.Fatal("NewAdminEventListener() accepted unavailable database")
	}
}
