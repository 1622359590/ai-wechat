package pairing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var (
	errStateNotFound = errors.New("pairing state not found")
	errStateExists   = errors.New("pairing state already exists")
	errInvalidState  = errors.New("pairing state is invalid")
)

type stateFile struct {
	Version          int    `json:"version"`
	CredentialSHA256 string `json:"credential_sha256"`
	CreatedAt        string `json:"created_at"`
}

type store struct {
	path string
}

func newStore(path string) *store {
	return &store{path: path}
}

func (stateStore *store) load() ([32]byte, error) {
	var fingerprint [32]byte
	info, err := os.Stat(stateStore.path)
	if errors.Is(err, os.ErrNotExist) {
		return fingerprint, errStateNotFound
	}
	if err != nil {
		return fingerprint, fmt.Errorf("stat pairing state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fingerprint, errInvalidState
	}
	body, err := os.ReadFile(stateStore.path)
	if err != nil {
		return fingerprint, fmt.Errorf("read pairing state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state stateFile
	if err := decoder.Decode(&state); err != nil {
		return fingerprint, errInvalidState
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fingerprint, errInvalidState
	}
	decoded, err := hex.DecodeString(state.CredentialSHA256)
	if state.Version != 1 || err != nil || len(decoded) != len(fingerprint) {
		return fingerprint, errInvalidState
	}
	if _, err := time.Parse(time.RFC3339Nano, state.CreatedAt); err != nil {
		return fingerprint, errInvalidState
	}
	copy(fingerprint[:], decoded)
	return fingerprint, nil
}

func (stateStore *store) create(fingerprint [32]byte, createdAt time.Time) error {
	directory := filepath.Dir(stateStore.path)
	state := stateFile{
		Version:          1,
		CredentialSHA256: hex.EncodeToString(fingerprint[:]),
		CreatedAt:        createdAt.UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal pairing state: %w", err)
	}
	body = append(body, '\n')

	temporary, err := os.CreateTemp(directory, ".pairing-state-*")
	if err != nil {
		return fmt.Errorf("create temporary pairing state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeTemporary := func() error {
		if temporary == nil {
			return nil
		}
		err := temporary.Close()
		temporary = nil
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = closeTemporary()
		return fmt.Errorf("set pairing state permissions: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		_ = closeTemporary()
		return fmt.Errorf("write pairing state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = closeTemporary()
		return fmt.Errorf("sync pairing state: %w", err)
	}
	if err := closeTemporary(); err != nil {
		return fmt.Errorf("close pairing state: %w", err)
	}
	if err := os.Link(temporaryPath, stateStore.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errStateExists
		}
		return fmt.Errorf("publish pairing state: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open pairing state directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync pairing state directory: %w", err)
	}
	return nil
}
