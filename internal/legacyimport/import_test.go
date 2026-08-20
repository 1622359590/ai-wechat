package legacyimport

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestExecuteImportsValidatedActiveAndDisabledRecords(t *testing.T) {
	now := importNow()
	expires := now.Add(24 * time.Hour)
	database := openImportSource(t, []string{"credential", "status", "auth_expires_at"}, [][]driver.Value{
		{[]byte("synthetic-one"), "active", nil},
		{[]byte("synthetic-two"), "disabled", expires},
	})
	target := &fakeImportTarget{importSummary: Summary{Imported: 2}}

	summary, err := Execute(context.Background(), database, "private synthetic query", importFingerprinter(t), target, false, now)
	if err != nil {
		t.Fatalf("Execute(): %v", err)
	}
	if summary.Total != 2 || summary.Imported != 2 || summary.Duplicates != 0 || summary.Rejected != 0 {
		t.Fatalf("summary = %#v", summary)
	}
	if len(target.imported) != 2 || target.imported[0].Status != devices.StatusActive || target.imported[1].Status != devices.StatusDisabled {
		t.Fatalf("imported records = %#v", target.imported)
	}
	if target.imported[1].AuthExpiresAt == nil || !target.imported[1].AuthExpiresAt.Equal(expires) {
		t.Fatalf("disabled expiry = %v", target.imported[1].AuthExpiresAt)
	}
}

func TestExecuteDryRunUsesPreviewAndReportsDuplicates(t *testing.T) {
	database := openImportSource(t, []string{"credential", "status", "auth_expires_at"}, [][]driver.Value{
		{[]byte("synthetic-one"), "active", nil},
		{[]byte("synthetic-two"), "active", nil},
	})
	target := &fakeImportTarget{previewSummary: Summary{Imported: 1, Duplicates: 1}}
	summary, err := Execute(context.Background(), database, "private synthetic query", importFingerprinter(t), target, true, importNow())
	if err != nil {
		t.Fatalf("Execute(dry-run): %v", err)
	}
	if !summary.DryRun || summary.Total != 2 || summary.Imported != 1 || summary.Duplicates != 1 {
		t.Fatalf("dry-run summary = %#v", summary)
	}
	if target.importCalls != 0 || target.previewCalls != 1 {
		t.Fatalf("target import/preview calls = %d/%d, want 0/1", target.importCalls, target.previewCalls)
	}
}

func TestExecuteRejectsEntireBatchBeforeTargetWrite(t *testing.T) {
	tests := []struct {
		name    string
		columns []string
		rows    [][]driver.Value
	}{
		{name: "wrong columns", columns: []string{"device", "status", "auth_expires_at"}, rows: [][]driver.Value{{[]byte("synthetic"), "active", nil}}},
		{name: "empty credential", columns: validImportColumns(), rows: [][]driver.Value{{[]byte{}, "active", nil}}},
		{name: "invalid status", columns: validImportColumns(), rows: [][]driver.Value{{[]byte("synthetic"), "paused", nil}}},
		{name: "invalid expiry", columns: validImportColumns(), rows: [][]driver.Value{{[]byte("synthetic"), "active", "tomorrow"}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			database := openImportSource(t, testCase.columns, testCase.rows)
			target := &fakeImportTarget{}
			summary, err := Execute(context.Background(), database, "private synthetic query", importFingerprinter(t), target, false, importNow())
			if !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("Execute() error = %v, want ErrInvalidSource", err)
			}
			if target.importCalls != 0 || target.previewCalls != 0 {
				t.Fatal("invalid batch reached target")
			}
			if testCase.name != "wrong columns" && summary.Rejected != 1 {
				t.Fatalf("rejected count = %d, want 1", summary.Rejected)
			}
		})
	}
}

func TestExecuteHonorsContextCancellation(t *testing.T) {
	database := openImportSource(t, validImportColumns(), [][]driver.Value{{[]byte("synthetic"), "active", nil}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, database, "private synthetic query", importFingerprinter(t), &fakeImportTarget{}, false, importNow())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
}

func importFingerprinter(t *testing.T) *devices.Fingerprinter {
	t.Helper()
	fingerprinter, err := devices.NewFingerprinter(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatalf("NewFingerprinter(): %v", err)
	}
	return fingerprinter
}

func importNow() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

func validImportColumns() []string {
	return []string{"credential", "status", "auth_expires_at"}
}

type fakeImportTarget struct {
	importSummary  Summary
	previewSummary Summary
	imported       []Record
	importCalls    int
	previewCalls   int
}

func (target *fakeImportTarget) Import(_ context.Context, records []Record, _ time.Time) (Summary, error) {
	target.importCalls++
	target.imported = append([]Record(nil), records...)
	return target.importSummary, nil
}
func (target *fakeImportTarget) Preview(_ context.Context, _ []Record) (Summary, error) {
	target.previewCalls++
	return target.previewSummary, nil
}

var (
	importDriverOnce  sync.Once
	importDriverState struct {
		sync.Mutex
		columns []string
		rows    [][]driver.Value
	}
)

func openImportSource(t *testing.T, columns []string, rows [][]driver.Value) *sql.DB {
	t.Helper()
	importDriverOnce.Do(func() { sql.Register("legacyimport-test", importTestDriver{}) })
	importDriverState.Lock()
	importDriverState.columns = append([]string(nil), columns...)
	importDriverState.rows = append([][]driver.Value(nil), rows...)
	importDriverState.Unlock()
	database, err := sql.Open("legacyimport-test", "")
	if err != nil {
		t.Fatalf("open test source: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

type importTestDriver struct{}

func (importTestDriver) Open(string) (driver.Conn, error) { return importTestConnection{}, nil }

type importTestConnection struct{}

func (importTestConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}
func (importTestConnection) Close() error { return nil }
func (importTestConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transaction unsupported")
}
func (importTestConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	importDriverState.Lock()
	defer importDriverState.Unlock()
	columns := append([]string(nil), importDriverState.columns...)
	rows := make([][]driver.Value, len(importDriverState.rows))
	for index := range importDriverState.rows {
		rows[index] = append([]driver.Value(nil), importDriverState.rows[index]...)
	}
	return &importTestRows{columns: columns, rows: rows}, nil
}

type importTestRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (rows *importTestRows) Columns() []string { return rows.columns }
func (*importTestRows) Close() error           { return nil }
func (rows *importTestRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.rows) {
		return io.EOF
	}
	copy(destination, rows.rows[rows.index])
	rows.index++
	return nil
}
