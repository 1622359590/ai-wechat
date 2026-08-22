package adminauth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound             = errors.New("administrator record not found")
	ErrAlreadyExists        = errors.New("administrator record already exists")
	ErrAuthenticationFailed = errors.New("administrator authentication failed")
	ErrUnavailable          = errors.New("administrator storage is unavailable")
)

type SessionRecord struct {
	User            User
	PasswordHash    string
	TokenHash       [32]byte
	CSRFHash        [32]byte
	PasswordVersion int64
	CreatedAt       time.Time
	LastUsedAt      time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

type Repository interface {
	CreateUser(context.Context, string, string, string, time.Time) (User, error)
	FindUserByNormalizedUsername(context.Context, string) (User, string, error)
	CreateSession(context.Context, SessionRecord) error
	FindSession(context.Context, [32]byte, time.Time) (SessionRecord, error)
	TouchSession(context.Context, [32]byte, time.Time) error
	RevokeSession(context.Context, [32]byte, time.Time) error
	ChangePassword(context.Context, ID, int64, string, time.Time) (User, error)
	ResetPassword(context.Context, string, string, time.Time) error
}
