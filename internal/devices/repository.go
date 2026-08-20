package devices

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotAuthorized = errors.New("device not authorized")
	ErrAlreadyExists = errors.New("device already exists")
	ErrNotFound      = errors.New("device not found")
	ErrInvalidInput  = errors.New("invalid device input")
)

type AddDevice struct {
	Fingerprint   Fingerprint
	TenantID      string
	Label         string
	Status        Status
	AuthExpiresAt *time.Time
}

type Repository interface {
	Authorize(context.Context, Fingerprint, time.Time) (Device, error)
	TouchAuthenticated(context.Context, ID, time.Time) error
	Add(context.Context, AddDevice) (Device, error)
	List(context.Context, int) ([]Device, error)
	SetStatus(context.Context, ID, Status, string, time.Time) error
	SetExpiry(context.Context, ID, *time.Time, string, time.Time) error
}
