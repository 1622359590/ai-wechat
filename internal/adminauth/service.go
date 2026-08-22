package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	sessionTokenBytes = 32
	sessionLifetime   = 8 * time.Hour
)

type LoginResult struct {
	User         User
	SessionToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

type Service struct {
	repository Repository
	hasher     *PasswordHasher
	limiter    *LoginLimiter
	now        func() time.Time
	random     io.Reader
	randomMu   sync.Mutex
	dummyHash  string
}

func NewService(repository Repository, hasher *PasswordHasher, limiter *LoginLimiter, now func() time.Time, random io.Reader) (*Service, error) {
	if repository == nil || hasher == nil || limiter == nil {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	dummyPassword := []byte("synthetic administrator password")
	dummyHash, err := hasher.Hash(dummyPassword)
	clear(dummyPassword)
	if err != nil {
		return nil, err
	}
	return &Service{
		repository: repository,
		hasher:     hasher,
		limiter:    limiter,
		now:        now,
		random:     random,
		dummyHash:  dummyHash,
	}, nil
}

func (service *Service) Login(ctx context.Context, username string, password []byte, ip net.IP) (LoginResult, error) {
	defer clear(password)
	now := service.now().UTC()
	normalized, normalizationErr := NormalizeUsername(username)
	limiterUsername := normalized
	if normalizationErr != nil {
		limiterUsername = "invalid_username"
	}
	if err := service.limiter.Allow(limiterUsername, ip, now); err != nil {
		return LoginResult{}, err
	}

	var user User
	var passwordHash string
	repositoryErr := ErrNotFound
	if normalizationErr == nil {
		user, passwordHash, repositoryErr = service.repository.FindUserByNormalizedUsername(ctx, normalized)
	}
	hashToVerify := passwordHash
	if repositoryErr != nil {
		hashToVerify = service.dummyHash
	}
	passwordToVerify, passwordValid := usablePassword(password)
	verified, verifyErr := service.hasher.Verify(hashToVerify, passwordToVerify)
	if !passwordValid {
		clear(passwordToVerify)
	}

	if repositoryErr != nil && !errors.Is(repositoryErr, ErrNotFound) {
		return LoginResult{}, repositoryErr
	}
	if normalizationErr != nil || repositoryErr != nil || verifyErr != nil || !passwordValid || !verified || user.Status != StatusActive {
		return LoginResult{}, ErrAuthenticationFailed
	}
	result, err := service.createSession(ctx, user, now)
	if err != nil {
		return LoginResult{}, err
	}
	service.limiter.Success(normalized, ip)
	return result, nil
}

func (service *Service) Authenticate(ctx context.Context, sessionToken string) (User, error) {
	tokenHash, err := digestToken(sessionToken)
	if err != nil {
		return User{}, ErrAuthenticationFailed
	}
	now := service.now().UTC()
	record, err := service.repository.FindSession(ctx, tokenHash, now)
	if err != nil {
		return User{}, authenticationStorageError(err)
	}
	if err := service.repository.TouchSession(ctx, tokenHash, now); err != nil {
		return User{}, authenticationStorageError(err)
	}
	return record.User, nil
}

func (service *Service) VerifyCSRF(ctx context.Context, sessionToken, csrfToken string) error {
	tokenHash, err := digestToken(sessionToken)
	if err != nil {
		return ErrAuthenticationFailed
	}
	csrfHash, err := digestToken(csrfToken)
	if err != nil {
		return ErrAuthenticationFailed
	}
	record, err := service.repository.FindSession(ctx, tokenHash, service.now().UTC())
	if err != nil {
		return authenticationStorageError(err)
	}
	if subtle.ConstantTimeCompare(record.CSRFHash[:], csrfHash[:]) != 1 {
		return ErrAuthenticationFailed
	}
	return nil
}

func (service *Service) Logout(ctx context.Context, sessionToken string) error {
	tokenHash, err := digestToken(sessionToken)
	if err != nil {
		return ErrAuthenticationFailed
	}
	if err := service.repository.RevokeSession(ctx, tokenHash, service.now().UTC()); err != nil {
		return authenticationStorageError(err)
	}
	return nil
}

func (service *Service) ChangePassword(ctx context.Context, sessionToken string, currentPassword, newPassword []byte) (LoginResult, error) {
	defer clear(currentPassword)
	defer clear(newPassword)
	tokenHash, err := digestToken(sessionToken)
	if err != nil {
		return LoginResult{}, ErrAuthenticationFailed
	}
	now := service.now().UTC()
	record, err := service.repository.FindSession(ctx, tokenHash, now)
	if err != nil {
		return LoginResult{}, authenticationStorageError(err)
	}
	verified, err := service.hasher.Verify(record.PasswordHash, currentPassword)
	if err != nil || !verified {
		return LoginResult{}, ErrAuthenticationFailed
	}
	newHash, err := service.hasher.Hash(newPassword)
	if err != nil {
		return LoginResult{}, err
	}
	user, err := service.repository.ChangePassword(ctx, record.User.ID, record.PasswordVersion, newHash, now)
	if err != nil {
		return LoginResult{}, authenticationStorageError(err)
	}
	return service.createSession(ctx, user, now)
}

func (service *Service) createSession(ctx context.Context, user User, now time.Time) (LoginResult, error) {
	sessionToken, tokenHash, err := service.newToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrfToken, csrfHash, err := service.newToken()
	if err != nil {
		return LoginResult{}, err
	}
	expiresAt := now.Add(sessionLifetime)
	record := SessionRecord{
		User:            user,
		TokenHash:       tokenHash,
		CSRFHash:        csrfHash,
		PasswordVersion: user.PasswordVersion,
		CreatedAt:       now,
		LastUsedAt:      now,
		ExpiresAt:       expiresAt,
	}
	if err := service.repository.CreateSession(ctx, record); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{User: user, SessionToken: sessionToken, CSRFToken: csrfToken, ExpiresAt: expiresAt}, nil
}

func (service *Service) newToken() (string, [32]byte, error) {
	raw := make([]byte, sessionTokenBytes)
	service.randomMu.Lock()
	_, err := io.ReadFull(service.random, raw)
	service.randomMu.Unlock()
	if err != nil {
		clear(raw)
		return "", [32]byte{}, errorsWithoutDetails("generate administrator session")
	}
	digest := sha256.Sum256(raw)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return encoded, digest, nil
}

func digestToken(encoded string) ([32]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != sessionTokenBytes {
		clear(raw)
		return [32]byte{}, ErrAuthenticationFailed
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return digest, nil
}

func usablePassword(password []byte) ([]byte, bool) {
	if validPassword(password) {
		return password, true
	}
	dummy := []byte("invalid-password-value")
	return dummy, false
}

func authenticationStorageError(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return ErrAuthenticationFailed
}
