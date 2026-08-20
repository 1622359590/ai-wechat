package securefile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestReadExactRejectsUnsafeFilesAndWrongLength(t *testing.T) {
	temporary := t.TempDir()
	valid := writeSecureTestFile(t, temporary, "valid.bin", bytes.Repeat([]byte{0x31}, 32), 0o600)

	tests := []struct {
		name string
		path string
	}{
		{name: "relative", path: "relative.bin"},
		{name: "directory", path: temporary},
		{name: "unsafe mode", path: writeSecureTestFile(t, temporary, "unsafe.bin", bytes.Repeat([]byte{1}, 32), 0o644)},
		{name: "short", path: writeSecureTestFile(t, temporary, "short.bin", bytes.Repeat([]byte{1}, 31), 0o600)},
		{name: "long", path: writeSecureTestFile(t, temporary, "long.bin", bytes.Repeat([]byte{1}, 33), 0o600)},
	}
	if runtime.GOOS != "windows" {
		symlink := filepath.Join(temporary, "secret-link")
		if err := os.Symlink(valid, symlink); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		tests = append(tests, struct{ name, path string }{name: "symlink", path: symlink})

		fifo := filepath.Join(temporary, "secret-fifo")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatalf("create FIFO: %v", err)
		}
		tests = append(tests, struct{ name, path string }{name: "FIFO", path: fifo})
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ReadExact(testCase.path, 32); err == nil {
				t.Fatal("unsafe exact file was accepted")
			} else if strings.Contains(err.Error(), temporary) {
				t.Fatalf("error exposed file path: %v", err)
			}
		})
	}
}

func TestReadExactAcceptsPrivateModesAndReturnsIndependentBytes(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		path := writeSecureTestFile(t, t.TempDir(), "secret.bin", bytes.Repeat([]byte{0x42}, 32), mode)
		first, err := ReadExact(path, 32)
		if err != nil {
			t.Fatalf("ReadExact(mode=%o): %v", mode, err)
		}
		first[0] = 0
		second, err := ReadExact(path, 32)
		if err != nil {
			t.Fatalf("second ReadExact(mode=%o): %v", mode, err)
		}
		if second[0] != 0x42 {
			t.Fatal("returned mutation affected a later read")
		}
	}
}

func TestReadTextRejectsUnsafeContentAndAcceptsOnePrivateLine(t *testing.T) {
	temporary := t.TempDir()
	tests := []struct {
		name     string
		contents []byte
		maximum  int
	}{
		{name: "empty", contents: nil, maximum: 64},
		{name: "NUL", contents: []byte("synthetic\x00dsn"), maximum: 64},
		{name: "CR", contents: []byte("synthetic\rdsn"), maximum: 64},
		{name: "LF", contents: []byte("synthetic\ndsn"), maximum: 64},
		{name: "oversize", contents: []byte("synthetic-dsn"), maximum: 4},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			path := writeSecureTestFile(t, temporary, testCase.name+".txt", testCase.contents, 0o600)
			if _, err := ReadText(path, testCase.maximum); err == nil {
				t.Fatal("unsafe text file was accepted")
			} else if len(testCase.contents) > 0 && strings.Contains(err.Error(), string(testCase.contents)) {
				t.Fatalf("error exposed file content: %v", err)
			}
		})
	}

	want := "postgres://synthetic-host/device?sslmode=require"
	path := writeSecureTestFile(t, temporary, "valid.txt", []byte(want), 0o400)
	got, err := ReadText(path, 1024)
	if err != nil {
		t.Fatalf("ReadText(): %v", err)
	}
	if got != want {
		t.Fatalf("ReadText() returned changed text")
	}
}

func writeSecureTestFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write secure fixture: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod secure fixture: %v", err)
	}
	return path
}
