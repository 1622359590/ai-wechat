package adminauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"
)

func TestServiceLoginStoresOnlyTokenDigests(t *testing.T) {
	now := time.Date(2026, 8, 22, 5, 0, 0, 0, time.UTC)
	service, repository := newTestService(t, &now)
	password := []byte("correct horse battery")

	result, err := service.Login(context.Background(), "ADMIN_01", password, net.ParseIP("192.0.2.20"))
	if err != nil {
		t.Fatalf("Login(): %v", err)
	}
	if result.User.Username != "Admin_01" || result.ExpiresAt != now.Add(8*time.Hour) {
		t.Fatalf("Login() = %+v", result)
	}
	if !allZero(password) {
		t.Fatal("Login() did not clear the caller password buffer")
	}
	if len(repository.sessions) != 1 {
		t.Fatalf("stored sessions = %d, want 1", len(repository.sessions))
	}
	record := repository.sessions[tokenDigest(t, result.SessionToken)]
	if record.CSRFHash != tokenDigest(t, result.CSRFToken) {
		t.Fatal("CreateSession() did not receive CSRF digest")
	}
	if record.CreatedAt != now || record.LastUsedAt != now || record.ExpiresAt != result.ExpiresAt {
		t.Fatalf("stored Session = %+v", record)
	}
}

func TestServiceLoginUsesUniformAuthenticationFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		username string
		password string
		disable  bool
	}{
		{name: "unknown", username: "missing_admin", password: "correct horse battery"},
		{name: "wrong password", username: "admin_01", password: "wrong password value"},
		{name: "disabled", username: "admin_01", password: "correct horse battery", disable: true},
		{name: "invalid username", username: "bad user", password: "correct horse battery"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 22, 5, 30, 0, 0, time.UTC)
			service, repository := newTestService(t, &now)
			if test.disable {
				user := repository.users["admin_01"]
				user.Status = StatusDisabled
				repository.users["admin_01"] = user
			}
			if _, err := service.Login(context.Background(), test.username, []byte(test.password), net.ParseIP("192.0.2.21")); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("Login() error = %v, want ErrAuthenticationFailed", err)
			}
		})
	}
}

func TestServiceAuthenticatesCSRFAndLogout(t *testing.T) {
	now := time.Date(2026, 8, 22, 6, 0, 0, 0, time.UTC)
	service, _ := newTestService(t, &now)
	login, err := service.Login(context.Background(), "admin_01", []byte("correct horse battery"), net.ParseIP("192.0.2.22"))
	if err != nil {
		t.Fatalf("Login(): %v", err)
	}
	user, err := service.Authenticate(context.Background(), login.SessionToken)
	if err != nil || user.ID != login.User.ID {
		t.Fatalf("Authenticate() = %+v, %v", user, err)
	}
	if err := service.VerifyCSRF(context.Background(), login.SessionToken, login.CSRFToken); err != nil {
		t.Fatalf("VerifyCSRF(correct): %v", err)
	}
	wrongCSRF := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32))
	if err := service.VerifyCSRF(context.Background(), login.SessionToken, wrongCSRF); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("VerifyCSRF(wrong) error = %v, want ErrAuthenticationFailed", err)
	}
	if err := service.Logout(context.Background(), login.SessionToken); err != nil {
		t.Fatalf("Logout(): %v", err)
	}
	if _, err := service.Authenticate(context.Background(), login.SessionToken); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate(after logout) error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestServiceRejectsIdleAndAbsoluteSessionExpiry(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Hour, 8 * time.Hour} {
		t.Run(elapsed.String(), func(t *testing.T) {
			now := time.Date(2026, 8, 22, 7, 0, 0, 0, time.UTC)
			service, _ := newTestService(t, &now)
			login, err := service.Login(context.Background(), "admin_01", []byte("correct horse battery"), net.ParseIP("192.0.2.23"))
			if err != nil {
				t.Fatalf("Login(): %v", err)
			}
			now = now.Add(elapsed)
			if _, err := service.Authenticate(context.Background(), login.SessionToken); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("Authenticate(after %s) error = %v", elapsed, err)
			}
		})
	}
}

func TestServiceChangePasswordRotatesSession(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	service, repository := newTestService(t, &now)
	first, err := service.Login(context.Background(), "admin_01", []byte("correct horse battery"), net.ParseIP("192.0.2.24"))
	if err != nil {
		t.Fatalf("Login(): %v", err)
	}
	now = now.Add(time.Minute)
	current := []byte("correct horse battery")
	replacement := []byte("new correct password")
	rotated, err := service.ChangePassword(context.Background(), first.SessionToken, current, replacement)
	if err != nil {
		t.Fatalf("ChangePassword(): %v", err)
	}
	if !allZero(current) || !allZero(replacement) {
		t.Fatal("ChangePassword() did not clear password buffers")
	}
	if rotated.SessionToken == first.SessionToken || rotated.User.PasswordVersion != 2 {
		t.Fatalf("ChangePassword() = %+v", rotated)
	}
	if _, err := service.Authenticate(context.Background(), first.SessionToken); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate(old Session) error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), rotated.SessionToken); err != nil {
		t.Fatalf("Authenticate(rotated Session): %v", err)
	}
	verified, err := repository.hasher.Verify(repository.passwordHashes["admin_01"], []byte("new correct password"))
	if err != nil || !verified {
		t.Fatalf("stored changed password verification = %v, %v", verified, err)
	}
}

func newTestService(t *testing.T, now *time.Time) (*Service, *memoryRepository) {
	t.Helper()
	hasherRandom := bytes.NewReader(bytes.Repeat([]byte{0x61}, 16*8))
	hasher, err := NewPasswordHasher(testPasswordParams(), hasherRandom)
	if err != nil {
		t.Fatalf("NewPasswordHasher(): %v", err)
	}
	passwordHash, err := hasher.Hash([]byte("correct horse battery"))
	if err != nil {
		t.Fatalf("Hash(seed password): %v", err)
	}
	repository := &memoryRepository{
		users: map[string]User{
			"admin_01": {ID: "00000000-0000-0000-0000-000000000701", Username: "Admin_01", Status: StatusActive, PasswordVersion: 1},
		},
		passwordHashes: map[string]string{"admin_01": passwordHash},
		sessions:       make(map[[32]byte]SessionRecord),
		hasher:         hasher,
	}
	limiter, err := NewLoginLimiter(bytes.NewReader(bytes.Repeat([]byte{0x62}, 32)))
	if err != nil {
		t.Fatalf("NewLoginLimiter(): %v", err)
	}
	serviceEntropy := make([]byte, 32*32)
	for block := range 32 {
		for index := range 32 {
			serviceEntropy[block*32+index] = byte(block + index)
		}
	}
	serviceRandom := bytes.NewReader(serviceEntropy)
	service, err := NewService(repository, hasher, limiter, func() time.Time { return *now }, serviceRandom)
	if err != nil {
		t.Fatalf("NewService(): %v", err)
	}
	return service, repository
}

type memoryRepository struct {
	users          map[string]User
	passwordHashes map[string]string
	sessions       map[[32]byte]SessionRecord
	hasher         *PasswordHasher
}

func (repository *memoryRepository) CreateUser(context.Context, string, string, string, time.Time) (User, error) {
	return User{}, ErrUnavailable
}

func (repository *memoryRepository) FindUserByNormalizedUsername(_ context.Context, normalized string) (User, string, error) {
	if validated, err := NormalizeUsername(normalized); err != nil || validated != normalized {
		return User{}, "", ErrInvalidInput
	}
	user, exists := repository.users[normalized]
	if !exists {
		return User{}, "", ErrNotFound
	}
	return user, repository.passwordHashes[normalized], nil
}

func (repository *memoryRepository) CreateSession(_ context.Context, record SessionRecord) error {
	user := repository.users[normalizeKnownUsername(record.User.Username)]
	if user.Status != StatusActive || user.PasswordVersion != record.PasswordVersion {
		return ErrAuthenticationFailed
	}
	user.LastLoginAt = timePointer(record.CreatedAt)
	repository.users[normalizeKnownUsername(user.Username)] = user
	record.User = user
	repository.sessions[record.TokenHash] = record
	return nil
}

func (repository *memoryRepository) FindSession(_ context.Context, tokenHash [32]byte, now time.Time) (SessionRecord, error) {
	record, exists := repository.sessions[tokenHash]
	if !exists || record.RevokedAt != nil || !record.ExpiresAt.After(now) || !record.LastUsedAt.After(now.Add(-time.Hour)) {
		return SessionRecord{}, ErrAuthenticationFailed
	}
	user := repository.users[normalizeKnownUsername(record.User.Username)]
	if user.Status != StatusActive || user.PasswordVersion != record.PasswordVersion {
		return SessionRecord{}, ErrAuthenticationFailed
	}
	record.User = user
	record.PasswordHash = repository.passwordHashes[normalizeKnownUsername(user.Username)]
	return record, nil
}

func (repository *memoryRepository) TouchSession(_ context.Context, tokenHash [32]byte, at time.Time) error {
	record, exists := repository.sessions[tokenHash]
	if !exists || record.RevokedAt != nil {
		return ErrAuthenticationFailed
	}
	if !record.LastUsedAt.After(at.Add(-5 * time.Minute)) {
		record.LastUsedAt = at
		repository.sessions[tokenHash] = record
	}
	return nil
}

func (repository *memoryRepository) RevokeSession(_ context.Context, tokenHash [32]byte, at time.Time) error {
	record, exists := repository.sessions[tokenHash]
	if !exists || record.RevokedAt != nil {
		return ErrAuthenticationFailed
	}
	record.RevokedAt = timePointer(at)
	repository.sessions[tokenHash] = record
	return nil
}

func (repository *memoryRepository) ChangePassword(_ context.Context, id ID, expectedVersion int64, passwordHash string, at time.Time) (User, error) {
	user := repository.users["admin_01"]
	if user.ID != id || user.PasswordVersion != expectedVersion {
		return User{}, ErrAuthenticationFailed
	}
	user.PasswordVersion++
	repository.users["admin_01"] = user
	repository.passwordHashes["admin_01"] = passwordHash
	for tokenHash, record := range repository.sessions {
		if record.User.ID == id && record.RevokedAt == nil {
			record.RevokedAt = timePointer(at)
			repository.sessions[tokenHash] = record
		}
	}
	return user, nil
}

func (repository *memoryRepository) ResetPassword(context.Context, string, string, time.Time) error {
	return ErrUnavailable
}

func tokenDigest(t *testing.T, token string) [32]byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode token: length=%d error=%v", len(decoded), err)
	}
	return sha256.Sum256(decoded)
}

func allZero(contents []byte) bool {
	for _, value := range contents {
		if value != 0 {
			return false
		}
	}
	return true
}

func normalizeKnownUsername(value string) string {
	normalized, _ := NormalizeUsername(value)
	return normalized
}

func timePointer(value time.Time) *time.Time {
	return &value
}
