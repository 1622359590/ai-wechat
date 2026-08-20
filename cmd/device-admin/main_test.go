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

	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestRunCoversDeviceAdminSubcommands(t *testing.T) {
	common := []string{"--database-dsn-file", "/synthetic/database", "--pepper-file", "/synthetic/pepper"}
	tests := []struct {
		name     string
		args     []string
		stdin    string
		wantCall string
	}{
		{name: "migrate", args: append([]string{"migrate"}, common...), wantCall: "migrate"},
		{name: "add", args: append(append([]string{"add"}, common...), "--label", "sales-one", "--status", "active", "--expiry", "never"), stdin: "synthetic-credential\n", wantCall: "add"},
		{name: "list", args: append([]string{"list"}, common...), wantCall: "list"},
		{name: "enable", args: append(append([]string{"enable"}, common...), "--id", string(cliDeviceID)), wantCall: "enable"},
		{name: "disable", args: append(append([]string{"disable"}, common...), "--id", string(cliDeviceID)), wantCall: "disable"},
		{name: "set expiry", args: append(append([]string{"set-expiry"}, common...), "--id", string(cliDeviceID), "--expiry", "2026-08-21T12:00:00Z"), wantCall: "set-expiry"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			operations := &fakeAdminOperations{}
			var stdout, stderr bytes.Buffer
			exitCode := run(context.Background(), testCase.args, strings.NewReader(testCase.stdin), &stdout, &stderr,
				func(context.Context, string, string) (adminOperations, func(), error) {
					return operations, func() {}, nil
				})
			if exitCode != 0 || stderr.Len() != 0 {
				t.Fatalf("run() exit/stderr = %d/%q", exitCode, stderr.String())
			}
			if operations.call != testCase.wantCall {
				t.Fatalf("operation call = %q, want %q", operations.call, testCase.wantCall)
			}
			if strings.Contains(stdout.String(), "synthetic-credential") {
				t.Fatal("stdout exposed credential")
			}
			if testCase.wantCall == "list" && (!strings.Contains(stdout.String(), string(cliDeviceID)) || !strings.Contains(stdout.String(), "sales-one")) {
				t.Fatalf("list output omitted safe fields: %q", stdout.String())
			}
		})
	}
}

func TestRunRejectsMissingFlagsAndUnsafeCredentialInput(t *testing.T) {
	open := func(context.Context, string, string) (adminOperations, func(), error) {
		return &fakeAdminOperations{}, func() {}, nil
	}
	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{name: "missing files", args: []string{"list"}},
		{name: "empty credential", args: []string{"add", "--database-dsn-file", "/synthetic/database", "--pepper-file", "/synthetic/pepper"}, stdin: "\n"},
		{name: "multiple credential lines", args: []string{"add", "--database-dsn-file", "/synthetic/database", "--pepper-file", "/synthetic/pepper"}, stdin: "first\nsecond\n"},
		{name: "credential without newline", args: []string{"add", "--database-dsn-file", "/synthetic/database", "--pepper-file", "/synthetic/pepper"}, stdin: "synthetic"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exitCode := run(context.Background(), testCase.args, strings.NewReader(testCase.stdin), &stdout, &stderr, open); exitCode != 2 {
				t.Fatalf("run() exit = %d, want 2", exitCode)
			}
			if marker := strings.TrimSpace(testCase.stdin); marker != "" && strings.Contains(stderr.String(), marker) {
				t.Fatal("stderr exposed credential input")
			}
		})
	}
}

func TestOpenProductionAdminRejectsUnsafeSecretFiles(t *testing.T) {
	directory := t.TempDir()
	dsnPath := filepath.Join(directory, "database.txt")
	pepperPath := filepath.Join(directory, "pepper.bin")
	if err := os.WriteFile(dsnPath, []byte("postgres://synthetic-host/device"), 0o644); err != nil {
		t.Fatalf("write DSN: %v", err)
	}
	if err := os.WriteFile(pepperPath, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatalf("write pepper: %v", err)
	}
	if _, closeRuntime, err := openProductionAdmin(context.Background(), dsnPath, pepperPath); err == nil {
		closeRuntime()
		t.Fatal("unsafe secret file was accepted")
	}
}

func TestRunSanitizesOperationErrors(t *testing.T) {
	credential := "sensitive-synthetic-credential"
	operations := &fakeAdminOperations{err: errors.New("operation leaked " + credential)}
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"add", "--database-dsn-file", "/synthetic/database", "--pepper-file", "/synthetic/pepper"}, strings.NewReader(credential+"\n"), &stdout, &stderr,
		func(context.Context, string, string) (adminOperations, func(), error) {
			return operations, func() {}, nil
		})
	if exitCode != 1 {
		t.Fatalf("run() exit = %d, want 1", exitCode)
	}
	if strings.Contains(stdout.String()+stderr.String(), credential) {
		t.Fatal("CLI output exposed credential")
	}
}

const cliDeviceID devices.ID = "00000000-0000-0000-0000-000000000072"

type fakeAdminOperations struct {
	call string
	err  error
}

func (operations *fakeAdminOperations) Migrate(context.Context) error {
	operations.call = "migrate"
	return operations.err
}
func (operations *fakeAdminOperations) Add(context.Context, string, string, devices.Status, string) (devices.Device, error) {
	operations.call = "add"
	return devices.Device{ID: cliDeviceID, Label: "sales-one", Status: devices.StatusActive}, operations.err
}
func (operations *fakeAdminOperations) List(context.Context) ([]devices.Device, error) {
	operations.call = "list"
	expires := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	last := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	return []devices.Device{{ID: cliDeviceID, Label: "sales-one", Status: devices.StatusActive, AuthExpiresAt: &expires, LastAuthenticatedAt: &last}}, operations.err
}
func (operations *fakeAdminOperations) Enable(context.Context, devices.ID) error {
	operations.call = "enable"
	return operations.err
}
func (operations *fakeAdminOperations) Disable(context.Context, devices.ID) error {
	operations.call = "disable"
	return operations.err
}
func (operations *fakeAdminOperations) SetExpiry(context.Context, devices.ID, string) error {
	operations.call = "set-expiry"
	return operations.err
}
