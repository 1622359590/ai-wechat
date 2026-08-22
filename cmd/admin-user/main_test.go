package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/1622359590/ai-wechat/internal/adminauth"
)

func TestRunCreatesAndResetsAdministratorWithoutExposingPassword(t *testing.T) {
	for _, test := range []struct {
		command  string
		wantCall string
		wantText string
	}{
		{command: "create", wantCall: "create", wantText: "administrator created id=00000000-0000-0000-0000-000000000111\n"},
		{command: "reset-password", wantCall: "reset", wantText: "administrator password reset\n"},
	} {
		t.Run(test.command, func(t *testing.T) {
			operations := &fakeUserOperations{}
			var stdout, stderr bytes.Buffer
			exitCode := run(context.Background(), []string{test.command, "--database-dsn-file", "/synthetic/database", "--username", "Admin_01"}, &stdout, &stderr,
				func(context.Context, string) (userOperations, func(), error) { return operations, func() {}, nil },
				func() ([]byte, []byte, error) {
					return []byte("correct horse battery"), []byte("correct horse battery"), nil
				})
			if exitCode != 0 || stdout.String() != test.wantText || stderr.Len() != 0 || operations.call != test.wantCall {
				t.Fatalf("run() = exit %d stdout %q stderr %q call %q", exitCode, stdout.String(), stderr.String(), operations.call)
			}
			if operations.username != "Admin_01" || !allZeroBytes(operations.password) || strings.Contains(stdout.String()+stderr.String(), "correct horse") {
				t.Fatalf("unsafe command state/output: username=%q password=%v", operations.username, operations.password)
			}
		})
	}
}

func TestRunRejectsPasswordMismatchAndSanitizesOperationErrors(t *testing.T) {
	secret := "synthetic password value"
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"create", "--database-dsn-file", "/synthetic/database", "--username", "Admin_01"}, &stdout, &stderr,
		func(context.Context, string) (userOperations, func(), error) {
			return &fakeUserOperations{err: errors.New("database leaked " + secret)}, func() {}, nil
		}, func() ([]byte, []byte, error) { return []byte(secret), []byte(secret), nil })
	if exitCode != 1 || stderr.String() != "operation failed\n" || strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatalf("operation failure = exit %d stdout %q stderr %q", exitCode, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(context.Background(), []string{"create", "--database-dsn-file", "/synthetic/database", "--username", "Admin_01"}, &stdout, &stderr,
		func(context.Context, string) (userOperations, func(), error) {
			return &fakeUserOperations{}, func() {}, nil
		},
		func() ([]byte, []byte, error) { return []byte(secret), []byte("different password"), nil })
	if exitCode != 2 || stderr.String() != "invalid password input\n" {
		t.Fatalf("mismatch = exit %d stderr %q", exitCode, stderr.String())
	}
}

func TestReadTerminalPasswordsRejectsNonTerminalInput(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(): %v", err)
	}
	defer read.Close()
	defer write.Close()
	if _, _, err := readTerminalPasswords(read, &bytes.Buffer{}); err == nil {
		t.Fatal("readTerminalPasswords() accepted non-terminal input")
	}
}

func TestRunRejectsUnknownCommandsAndMissingArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"create", "--username", "Admin_01"}, {"create", "--database-dsn-file", "/synthetic/database"}} {
		var stdout, stderr bytes.Buffer
		if exitCode := run(context.Background(), args, &stdout, &stderr, nil, nil); exitCode != 2 || stderr.String() != "invalid arguments\n" {
			t.Fatalf("run(%v) = exit %d stderr %q", args, exitCode, stderr.String())
		}
	}
}

type fakeUserOperations struct {
	call     string
	username string
	password []byte
	err      error
}

func (operations *fakeUserOperations) Create(_ context.Context, username string, password []byte) (adminauth.User, error) {
	operations.call, operations.username, operations.password = "create", username, password
	defer clear(password)
	return adminauth.User{ID: "00000000-0000-0000-0000-000000000111", Username: username}, operations.err
}

func (operations *fakeUserOperations) Reset(_ context.Context, username string, password []byte) error {
	operations.call, operations.username, operations.password = "reset", username, password
	defer clear(password)
	return operations.err
}

func allZeroBytes(contents []byte) bool {
	for _, value := range contents {
		if value != 0 {
			return false
		}
	}
	return true
}
