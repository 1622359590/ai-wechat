package deviceauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/1622359590/ai-wechat/internal/gateway"
)

const syntheticDeviceID devices.ID = "00000000-0000-0000-0000-000000000010"

func TestAuthenticatorAcceptsLegacyAuthTypesZeroAndOne(t *testing.T) {
	for _, authType := range []int32{0, 1} {
		t.Run(string(rune('0'+authType)), func(t *testing.T) {
			repository := newFakeRepository(t, "synthetic-device", devices.Device{ID: syntheticDeviceID, Status: devices.StatusActive})
			authenticator := newTestAuthenticator(t, repository, &fakeLimiter{}, bytes.Repeat([]byte{byte(authType + 1)}, 32))
			if _, err := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
				AuthType: authType, Credential: "synthetic-device", PeerIP: net.ParseIP("192.0.2.10"),
			}); err != nil {
				t.Fatalf("Authenticate(AuthType=%d): %v", authType, err)
			}
		})
	}
}

func TestAuthenticatorRejectsOtherAuthTypesAndInvalidCredential(t *testing.T) {
	tests := []struct {
		name       string
		authType   int32
		credential string
	}{
		{name: "negative auth type", authType: -1, credential: "synthetic-device"},
		{name: "unsupported auth type", authType: 2, credential: "synthetic-device"},
		{name: "empty credential", authType: 1},
		{name: "oversized credential", authType: 1, credential: strings.Repeat("x", maxCredentialBytes+1)},
		{name: "invalid UTF-8", authType: 1, credential: string([]byte{0xff})},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := &fakeRepository{}
			authenticator := newTestAuthenticator(t, repository, &fakeLimiter{}, bytes.Repeat([]byte{1}, 32))
			_, err := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
				AuthType: testCase.authType, Credential: testCase.credential, PeerIP: net.ParseIP("192.0.2.10"),
			})
			if !errors.Is(err, errInvalidAuthRequest) {
				t.Fatalf("Authenticate() error = %v, want errInvalidAuthRequest", err)
			}
			if repository.authorizeCalls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.authorizeCalls)
			}
		})
	}
	if !utf8.ValidString("synthetic-device") {
		t.Fatal("synthetic fixture unexpectedly invalid")
	}
}

func TestAuthenticatorCollapsesUnknownDisabledAndExpired(t *testing.T) {
	now := fixedNow()
	past := now.Add(-time.Second)
	tests := []struct {
		name       string
		credential string
		device     devices.Device
	}{
		{name: "unknown", credential: "unknown"},
		{name: "disabled", credential: "disabled", device: devices.Device{ID: syntheticDeviceID, Status: devices.StatusDisabled}},
		{name: "expired", credential: "expired", device: devices.Device{ID: syntheticDeviceID, Status: devices.StatusActive, AuthExpiresAt: &past}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newFakeRepository(t, testCase.credential, testCase.device)
			limiter := &fakeLimiter{}
			authenticator := newTestAuthenticator(t, repository, limiter, bytes.Repeat([]byte{1}, 32))
			_, err := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
				AuthType: 1, Credential: testCase.credential, PeerIP: net.ParseIP("192.0.2.10"),
			})
			if !errors.Is(err, errAuthenticationRejected) {
				t.Fatalf("Authenticate() error = %v, want errAuthenticationRejected", err)
			}
			if limiter.failures != 1 || limiter.successes != 0 {
				t.Fatalf("limiter failures/successes = %d/%d, want 1/0", limiter.failures, limiter.successes)
			}
		})
	}
}

func TestAuthenticatorReturnsInternalDeviceIDAndRandomOneHourToken(t *testing.T) {
	repository := newFakeRepository(t, "synthetic-device", devices.Device{ID: syntheticDeviceID, Status: devices.StatusActive})
	limiter := &fakeLimiter{}
	random := bytes.Repeat([]byte{0xab}, sessionTokenBytes)
	authenticator := newTestAuthenticator(t, repository, limiter, random)

	result, err := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
		AuthType: 1, Credential: "synthetic-device", PeerIP: net.ParseIP("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	if result.DeviceID != syntheticDeviceID {
		t.Fatalf("DeviceID = %q, want %q", result.DeviceID, syntheticDeviceID)
	}
	if result.AccessToken != strings.Repeat("ab", sessionTokenBytes) || len(result.AccessToken) != 64 {
		t.Fatalf("AccessToken has unexpected value or length")
	}
	if want := fixedNow().Add(time.Hour); !result.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", result.ExpiresAt, want)
	}
	if len(repository.touched) != 1 || repository.touched[0] != syntheticDeviceID {
		t.Fatalf("touched devices = %v, want internal device ID", repository.touched)
	}
	if limiter.successes != 1 || limiter.failures != 0 {
		t.Fatalf("limiter successes/failures = %d/%d, want 1/0", limiter.successes, limiter.failures)
	}
}

func TestAuthenticatorFailsClosedWhenRepositoryFails(t *testing.T) {
	tests := []struct {
		name       string
		authorize  error
		touch      error
		wantFailed int
	}{
		{name: "authorize backend", authorize: errors.New("synthetic backend failure")},
		{name: "touch backend", touch: errors.New("synthetic backend failure")},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newFakeRepository(t, "synthetic-device", devices.Device{ID: syntheticDeviceID, Status: devices.StatusActive})
			repository.authorizeErr = testCase.authorize
			repository.touchErr = testCase.touch
			limiter := &fakeLimiter{}
			authenticator := newTestAuthenticator(t, repository, limiter, bytes.Repeat([]byte{1}, 32))
			if _, err := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
				AuthType: 1, Credential: "synthetic-device", PeerIP: net.ParseIP("192.0.2.10"),
			}); !errors.Is(err, errAuthenticationUnavailable) {
				t.Fatalf("Authenticate() error = %v, want errAuthenticationUnavailable", err)
			}
			if limiter.failures != testCase.wantFailed || limiter.successes != 0 {
				t.Fatalf("limiter failures/successes = %d/%d, want %d/0", limiter.failures, limiter.successes, testCase.wantFailed)
			}
		})
	}
}

func TestAuthenticatorDoesNotExposeCredentialOrFingerprintInErrors(t *testing.T) {
	credential := "sensitive-synthetic-device-marker"
	repository := &fakeRepository{authorizeErr: errors.New("repository rejected " + credential)}
	fingerprinter := testFingerprinter(t)
	fingerprintHex := hex.EncodeToString(fingerprinter.Sum(credential).Bytes())
	authenticator, err := New(repository, fingerprinter, &fakeLimiter{}, fixedNow, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	_, authErr := authenticator.Authenticate(context.Background(), gateway.AuthRequest{
		AuthType: 1, Credential: credential, PeerIP: net.ParseIP("192.0.2.10"),
	})
	if authErr == nil {
		t.Fatal("Authenticate() unexpectedly succeeded")
	}
	if strings.Contains(authErr.Error(), credential) || strings.Contains(authErr.Error(), fingerprintHex) {
		t.Fatalf("authentication error exposed credential material: %q", authErr)
	}
}

func newTestAuthenticator(t *testing.T, repository devices.Repository, limiter AttemptLimiter, random []byte) *Authenticator {
	t.Helper()
	authenticator, err := New(repository, testFingerprinter(t), limiter, fixedNow, bytes.NewReader(random))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return authenticator
}

func testFingerprinter(t *testing.T) *devices.Fingerprinter {
	t.Helper()
	fingerprinter, err := devices.NewFingerprinter(bytes.Repeat([]byte{0x3a}, 32))
	if err != nil {
		t.Fatalf("NewFingerprinter(): %v", err)
	}
	return fingerprinter
}

func fixedNow() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

type fakeLimiter struct {
	allowErr  error
	failures  int
	successes int
}

func (limiter *fakeLimiter) Allow(net.IP, devices.Fingerprint, time.Time) error {
	return limiter.allowErr
}
func (limiter *fakeLimiter) Failure(devices.Fingerprint, time.Time) { limiter.failures++ }
func (limiter *fakeLimiter) Success(devices.Fingerprint)            { limiter.successes++ }

type fakeRepository struct {
	records        map[devices.Fingerprint]devices.Device
	authorizeErr   error
	touchErr       error
	authorizeCalls int
	touched        []devices.ID
}

func newFakeRepository(t *testing.T, credential string, device devices.Device) *fakeRepository {
	t.Helper()
	repository := &fakeRepository{records: make(map[devices.Fingerprint]devices.Device)}
	if device.ID != "" {
		repository.records[testFingerprinter(t).Sum(credential)] = device
	}
	return repository
}

func (repository *fakeRepository) Authorize(_ context.Context, fingerprint devices.Fingerprint, now time.Time) (devices.Device, error) {
	repository.authorizeCalls++
	if repository.authorizeErr != nil {
		return devices.Device{}, repository.authorizeErr
	}
	device, exists := repository.records[fingerprint]
	if !exists || device.Status != devices.StatusActive || (device.AuthExpiresAt != nil && !device.AuthExpiresAt.After(now)) {
		return devices.Device{}, devices.ErrNotAuthorized
	}
	return device, nil
}

func (repository *fakeRepository) TouchAuthenticated(_ context.Context, id devices.ID, _ time.Time) error {
	if repository.touchErr != nil {
		return repository.touchErr
	}
	repository.touched = append(repository.touched, id)
	return nil
}

func (*fakeRepository) Add(context.Context, devices.AddDevice) (devices.Device, error) {
	return devices.Device{}, errors.New("not implemented in fake")
}
func (*fakeRepository) List(context.Context, int) ([]devices.Device, error) {
	return nil, errors.New("not implemented in fake")
}
func (*fakeRepository) SetStatus(context.Context, devices.ID, devices.Status, string, time.Time) error {
	return errors.New("not implemented in fake")
}
func (*fakeRepository) SetExpiry(context.Context, devices.ID, *time.Time, string, time.Time) error {
	return errors.New("not implemented in fake")
}
