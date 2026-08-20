package pairing

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreCreatesPrivateStateWithoutPlaintextCredential(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential.json")
	store := newStore(path)
	credential := "synthetic-credential"
	fingerprint := sha256.Sum256([]byte(credential))
	createdAt := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)

	if err := store.create(fingerprint, createdAt); err != nil {
		t.Fatalf("create state: %v", err)
	}
	got, err := store.load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got != fingerprint {
		t.Fatal("loaded fingerprint differs from the enrolled fingerprint")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("state permissions = %o, want %o", got, want)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if bytes.Contains(body, []byte(credential)) {
		t.Fatal("state contains the plaintext credential")
	}
}

func TestStoreNeverOverwritesExistingFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	store := newStore(path)
	first := sha256.Sum256([]byte("synthetic-first"))
	second := sha256.Sum256([]byte("synthetic-second"))
	if err := store.create(first, time.Unix(1, 0)); err != nil {
		t.Fatalf("create first state: %v", err)
	}
	if err := store.create(second, time.Unix(2, 0)); !errors.Is(err, errStateExists) {
		t.Fatalf("second create error = %v, want errStateExists", err)
	}
	got, err := store.load()
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if got != first {
		t.Fatal("second create overwrote the first fingerprint")
	}
}

func TestStoreConcurrentFirstCreateHasSingleWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	store := newStore(path)
	fingerprints := [][32]byte{
		sha256.Sum256([]byte("synthetic-a")),
		sha256.Sum256([]byte("synthetic-b")),
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, len(fingerprints))
	var group sync.WaitGroup
	for _, fingerprint := range fingerprints {
		fingerprint := fingerprint
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errorsChannel <- store.create(fingerprint, time.Unix(1, 0))
		}()
	}
	close(start)
	group.Wait()
	close(errorsChannel)

	successes := 0
	exists := 0
	for err := range errorsChannel {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errStateExists):
			exists++
		default:
			t.Fatalf("create state: %v", err)
		}
	}
	if successes != 1 || exists != 1 {
		t.Fatalf("successes/exists = %d/%d, want 1/1", successes, exists)
	}
	got, err := store.load()
	if err != nil {
		t.Fatalf("load winning state: %v", err)
	}
	if got != fingerprints[0] && got != fingerprints[1] {
		t.Fatal("stored fingerprint is not one of the contenders")
	}
}

func TestStoreRejectsMalformedOrUnsafeState(t *testing.T) {
	tests := []struct {
		name string
		body string
		mode os.FileMode
	}{
		{name: "malformed", body: "{", mode: 0o600},
		{name: "wrong-version", body: `{"version":2,"credential_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":"2026-08-20T01:02:03Z"}`, mode: 0o600},
		{name: "unsafe-mode", body: `{"version":1,"credential_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":"2026-08-20T01:02:03Z"}`, mode: 0o644},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credential.json")
			if err := os.WriteFile(path, []byte(test.body), test.mode); err != nil {
				t.Fatalf("write state: %v", err)
			}
			if _, err := newStore(path).load(); !errors.Is(err, errInvalidState) {
				t.Fatalf("load error = %v, want errInvalidState", err)
			}
		})
	}
}
