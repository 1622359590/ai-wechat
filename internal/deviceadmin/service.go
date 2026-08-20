package deviceadmin

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
)

const (
	maximumCredentialBytes = 4096
	maximumLabelRunes      = 120
	listLimit              = 1000
)

var (
	ErrInvalidInput    = errors.New("device administration input is invalid")
	ErrOperationFailed = errors.New("device administration operation failed")
)

type Service struct {
	repository    devices.Repository
	fingerprinter *devices.Fingerprinter
	now           func() time.Time
}

func New(repository devices.Repository, fingerprinter *devices.Fingerprinter, now func() time.Time) (*Service, error) {
	if repository == nil || fingerprinter == nil {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, fingerprinter: fingerprinter, now: now}, nil
}

func (service *Service) Add(ctx context.Context, credential, label string, status devices.Status, expiryText string) (devices.Device, error) {
	if credential == "" || len(credential) > maximumCredentialBytes || !utf8.ValidString(credential) ||
		utf8.RuneCountInString(label) > maximumLabelRunes || (status != devices.StatusActive && status != devices.StatusDisabled) {
		return devices.Device{}, ErrInvalidInput
	}
	expiresAt, err := parseExpiry(expiryText)
	if err != nil {
		return devices.Device{}, err
	}
	device, err := service.repository.Add(ctx, devices.AddDevice{
		Fingerprint:   service.fingerprinter.Sum(credential),
		TenantID:      devices.DefaultTenantID,
		Label:         label,
		Status:        status,
		AuthExpiresAt: expiresAt,
	})
	if err != nil {
		return devices.Device{}, sanitizeRepositoryError(err)
	}
	return device, nil
}

func (service *Service) List(ctx context.Context) ([]devices.Device, error) {
	result, err := service.repository.List(ctx, listLimit)
	if err != nil {
		return nil, sanitizeRepositoryError(err)
	}
	return result, nil
}

func (service *Service) Enable(ctx context.Context, id devices.ID) error {
	return sanitizeRepositoryError(service.repository.SetStatus(ctx, id, devices.StatusActive, "manual_enable", service.now()))
}

func (service *Service) Disable(ctx context.Context, id devices.ID) error {
	return sanitizeRepositoryError(service.repository.SetStatus(ctx, id, devices.StatusDisabled, "manual_disable", service.now()))
}

func (service *Service) SetExpiry(ctx context.Context, id devices.ID, expiryText string) error {
	expiresAt, err := parseExpiry(expiryText)
	if err != nil {
		return err
	}
	return sanitizeRepositoryError(service.repository.SetExpiry(ctx, id, expiresAt, "manual_expiry", service.now()))
}

func parseExpiry(value string) (*time.Time, error) {
	if value == "never" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return &parsed, nil
}

func sanitizeRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	for _, stable := range []error{devices.ErrAlreadyExists, devices.ErrNotFound, devices.ErrInvalidInput} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrOperationFailed
}
