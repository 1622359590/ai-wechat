package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/legacyimport"
	"github.com/go-sql-driver/mysql"
)

func TestRunRequiresAllFilesAndPrintsAggregateSummaryOnly(t *testing.T) {
	args := []string{
		"--legacy-dsn-file", "/synthetic/legacy",
		"--database-dsn-file", "/synthetic/database",
		"--pepper-file", "/synthetic/pepper",
		"--query-file", "/synthetic/query",
		"--dry-run",
	}
	var captured importConfig
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), args, &stdout, &stderr, func(_ context.Context, config importConfig) (legacyimport.Summary, error) {
		captured = config
		return legacyimport.Summary{Total: 5, Imported: 3, Duplicates: 1, Rejected: 1, DryRun: true}, nil
	})
	if exitCode != 0 || stderr.Len() != 0 || !captured.dryRun {
		t.Fatalf("run() exit/stderr/dry = %d/%q/%v", exitCode, stderr.String(), captured.dryRun)
	}
	want := "total=5 imported=3 duplicates=1 rejected=1 dry_run=true\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want aggregate summary", stdout.String())
	}
	for _, forbidden := range []string{"credential", "fingerprint", "synthetic/query", "synthetic/legacy"} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatalf("output exposed %q", forbidden)
		}
	}
}

func TestHardenedMySQLDSNSetsTimeoutsAndTimeParsing(t *testing.T) {
	formatted, err := hardenedMySQLDSN("synthetic:password@tcp(127.0.0.1:3306)/legacy")
	if err != nil {
		t.Fatalf("hardenedMySQLDSN(): %v", err)
	}
	config, err := mysql.ParseDSN(formatted)
	if err != nil {
		t.Fatalf("parse hardened DSN: %v", err)
	}
	if config.Timeout != 5*time.Second || config.ReadTimeout != 10*time.Second || config.WriteTimeout != 10*time.Second || !config.ParseTime {
		t.Fatalf("hardened DSN settings = timeout %v/read %v/write %v/parseTime %v", config.Timeout, config.ReadTimeout, config.WriteTimeout, config.ParseTime)
	}
}

func TestRunRejectsMissingFilesAndSanitizesFailure(t *testing.T) {
	valid := []string{"--legacy-dsn-file", "/l", "--database-dsn-file", "/d", "--pepper-file", "/p", "--query-file", "/q"}
	for removed := 0; removed < len(valid); removed += 2 {
		args := append([]string(nil), valid[:removed]...)
		args = append(args, valid[removed+2:]...)
		var stdout, stderr bytes.Buffer
		if exitCode := run(context.Background(), args, &stdout, &stderr, func(context.Context, importConfig) (legacyimport.Summary, error) {
			return legacyimport.Summary{}, nil
		}); exitCode != 2 {
			t.Fatalf("missing flag %q exit = %d, want 2", valid[removed], exitCode)
		}
	}

	marker := "sensitive-synthetic-marker"
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), valid, &stdout, &stderr, func(context.Context, importConfig) (legacyimport.Summary, error) {
		return legacyimport.Summary{Total: 1, Rejected: 1}, errors.New("source leaked " + marker)
	})
	if exitCode != 1 || strings.Contains(stdout.String()+stderr.String(), marker) {
		t.Fatalf("failure exit/output = %d/%q/%q", exitCode, stdout.String(), stderr.String())
	}
	if stdout.String() != "total=1 imported=0 duplicates=0 rejected=1 dry_run=false\n" {
		t.Fatalf("failure summary = %q", stdout.String())
	}
}

func TestExecuteProductionRejectsAnyUnsafeInputFile(t *testing.T) {
	directory := t.TempDir()
	files := map[string]string{
		"legacy":   writeImportFile(t, directory, "legacy.txt", []byte("synthetic:dsn@tcp(localhost)/legacy"), 0o600),
		"database": writeImportFile(t, directory, "database.txt", []byte("postgres://synthetic-host/device"), 0o600),
		"pepper":   writeImportFile(t, directory, "pepper.bin", bytes.Repeat([]byte{0x61}, 32), 0o600),
		"query":    writeImportFile(t, directory, "query.sql", []byte("SELECT synthetic"), 0o600),
	}
	for name, path := range files {
		t.Run(name, func(t *testing.T) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatalf("chmod unsafe fixture: %v", err)
			}
			_, err := executeProduction(context.Background(), importConfig{
				legacyDSNFile: files["legacy"], databaseDSNFile: files["database"], pepperFile: files["pepper"], queryFile: files["query"],
			})
			if err == nil {
				t.Fatal("unsafe input file was accepted")
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatalf("restore fixture mode: %v", err)
			}
		})
	}
}

func writeImportFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write import fixture: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod import fixture: %v", err)
	}
	return path
}
