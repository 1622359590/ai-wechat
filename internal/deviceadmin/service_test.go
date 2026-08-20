package deviceadmin

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestServiceAddUsesDefaultTenantAndReturnsNoCredentialMaterial(t *testing.T) {
	repository := &adminFakeRepository{}
	service := newAdminTestService(t, repository)
	expires := "2026-08-21T12:00:00Z"
	device, err := service.Add(context.Background(), "sensitive-synthetic-credential", "sales-one", devices.StatusActive, expires)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}
	if repository.added.TenantID != devices.DefaultTenantID || repository.added.Label != "sales-one" || repository.added.Status != devices.StatusActive {
		t.Fatalf("repository Add input = %#v", repository.added)
	}
	if repository.added.AuthExpiresAt == nil || repository.added.AuthExpiresAt.Format(time.RFC3339) != expires {
		t.Fatalf("repository expiry = %v", repository.added.AuthExpiresAt)
	}
	if repository.added.Fingerprint == (devices.Fingerprint{}) {
		t.Fatal("Add() did not fingerprint the credential")
	}
	if strings.Contains(device.Label, "credential") {
		t.Fatal("returned device exposed credential material")
	}
}

func TestServiceListUsesFixedLimit(t *testing.T) {
	repository := &adminFakeRepository{listResult: []devices.Device{{ID: adminDeviceID, Label: "synthetic"}}}
	service := newAdminTestService(t, repository)
	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if repository.listLimit != 1000 || len(listed) != 1 || listed[0].ID != adminDeviceID {
		t.Fatalf("List() limit/result = %d/%v", repository.listLimit, listed)
	}
}

func TestServiceEnableDisableAndExpiryUseFixedReasons(t *testing.T) {
	repository := &adminFakeRepository{}
	service := newAdminTestService(t, repository)
	ctx := context.Background()
	if err := service.Enable(ctx, adminDeviceID); err != nil {
		t.Fatalf("Enable(): %v", err)
	}
	if repository.status != devices.StatusActive || repository.reason != "manual_enable" || !repository.at.Equal(adminNow()) {
		t.Fatalf("Enable() = status %q, reason %q, at %v", repository.status, repository.reason, repository.at)
	}
	if err := service.Disable(ctx, adminDeviceID); err != nil {
		t.Fatalf("Disable(): %v", err)
	}
	if repository.status != devices.StatusDisabled || repository.reason != "manual_disable" {
		t.Fatalf("Disable() = status %q, reason %q", repository.status, repository.reason)
	}

	if err := service.SetExpiry(ctx, adminDeviceID, "2026-08-22T12:00:00Z"); err != nil {
		t.Fatalf("SetExpiry(RFC3339): %v", err)
	}
	if repository.expiry == nil || repository.expiry.Format(time.RFC3339) != "2026-08-22T12:00:00Z" || repository.reason != "manual_expiry" {
		t.Fatalf("SetExpiry() = expiry %v, reason %q", repository.expiry, repository.reason)
	}
	if err := service.SetExpiry(ctx, adminDeviceID, "never"); err != nil {
		t.Fatalf("SetExpiry(never): %v", err)
	}
	if repository.expiry != nil {
		t.Fatalf("SetExpiry(never) = %v, want nil", repository.expiry)
	}
	if err := service.SetExpiry(ctx, adminDeviceID, "tomorrow"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("SetExpiry(invalid) error = %v, want ErrInvalidInput", err)
	}
}

func TestServiceErrorsDoNotExposeCredentialOrFingerprint(t *testing.T) {
	credential := "sensitive-synthetic-credential"
	repository := &adminFakeRepository{addErr: errors.New("repository leaked " + credential)}
	service := newAdminTestService(t, repository)
	_, err := service.Add(context.Background(), credential, "synthetic", devices.StatusActive, "never")
	if err == nil {
		t.Fatal("Add() unexpectedly succeeded")
	}
	fingerprintText := service.fingerprinter.Sum(credential).Bytes()
	if strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), string(fingerprintText)) {
		t.Fatalf("service error exposed credential material: %v", err)
	}
}

const adminDeviceID devices.ID = "00000000-0000-0000-0000-000000000071"

func newAdminTestService(t *testing.T, repository devices.Repository) *Service {
	t.Helper()
	fingerprinter, err := devices.NewFingerprinter(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatalf("NewFingerprinter(): %v", err)
	}
	service, err := New(repository, fingerprinter, adminNow)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return service
}

func adminNow() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

type adminFakeRepository struct {
	added      devices.AddDevice
	addErr     error
	listResult []devices.Device
	listLimit  int
	status     devices.Status
	expiry     *time.Time
	reason     string
	at         time.Time
}

func (repository *adminFakeRepository) Authorize(context.Context, devices.Fingerprint, time.Time) (devices.Device, error) {
	return devices.Device{}, errors.New("not implemented in fake")
}
func (*adminFakeRepository) TouchAuthenticated(context.Context, devices.ID, time.Time) error {
	return errors.New("not implemented in fake")
}
func (repository *adminFakeRepository) Add(_ context.Context, input devices.AddDevice) (devices.Device, error) {
	repository.added = input
	if repository.addErr != nil {
		return devices.Device{}, repository.addErr
	}
	return devices.Device{ID: adminDeviceID, TenantID: input.TenantID, Label: input.Label, Status: input.Status, AuthExpiresAt: input.AuthExpiresAt}, nil
}
func (repository *adminFakeRepository) List(_ context.Context, limit int) ([]devices.Device, error) {
	repository.listLimit = limit
	return repository.listResult, nil
}
func (repository *adminFakeRepository) SetStatus(_ context.Context, _ devices.ID, status devices.Status, reason string, at time.Time) error {
	repository.status, repository.reason, repository.at = status, reason, at
	return nil
}
func (repository *adminFakeRepository) SetExpiry(_ context.Context, _ devices.ID, expiry *time.Time, reason string, at time.Time) error {
	repository.expiry, repository.reason, repository.at = expiry, reason, at
	return nil
}
