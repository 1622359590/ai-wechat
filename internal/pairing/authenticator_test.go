package pairing

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/gateway"
)

func TestNewRejectsExistingInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid state: %v", err)
	}
	if _, err := New(Config{StateFile: path}); !errors.Is(err, errInvalidState) {
		t.Fatalf("New error = %v, want errInvalidState", err)
	}
}

func TestAuthenticatorRejectsWhenEnrollmentIsDisabledAndStateIsAbsent(t *testing.T) {
	authenticator := newTestAuthenticator(t, false, nil)
	_, err := authenticator.Authenticate(context.Background(), validAuthRequest())
	if !errors.Is(err, errEnrollmentDisabled) {
		t.Fatalf("authenticate error = %v, want errEnrollmentDisabled", err)
	}
}

func TestAuthenticatorValidatesRequestBeforeEnrollment(t *testing.T) {
	tests := []struct {
		name    string
		request gateway.AuthRequest
		want    error
	}{
		{name: "auth-type", request: gateway.AuthRequest{AuthType: 2, Credential: "synthetic-credential", PeerIP: net.ParseIP("192.0.2.10")}, want: errInvalidAuthRequest},
		{name: "empty", request: gateway.AuthRequest{AuthType: 1, PeerIP: net.ParseIP("192.0.2.10")}, want: errInvalidAuthRequest},
		{name: "oversized", request: gateway.AuthRequest{AuthType: 1, Credential: strings.Repeat("x", maxCredentialBytes+1), PeerIP: net.ParseIP("192.0.2.10")}, want: errInvalidAuthRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := newTestAuthenticator(t, true, mustCIDR(t, "192.0.2.0/24"))
			if _, err := authenticator.Authenticate(context.Background(), test.request); !errors.Is(err, test.want) {
				t.Fatalf("authenticate error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthenticatorRejectsEnrollmentOutsideAllowedCIDR(t *testing.T) {
	authenticator := newTestAuthenticator(t, true, mustCIDR(t, "192.0.2.0/24"))
	request := validAuthRequest()
	request.PeerIP = net.ParseIP("198.51.100.10")
	if _, err := authenticator.Authenticate(context.Background(), request); !errors.Is(err, errSourceRejected) {
		t.Fatalf("authenticate error = %v, want errSourceRejected", err)
	}
}

func TestAuthenticatorEnrollsOnceAndIssuesRandomSessionToken(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "credential.json")
	authenticator, err := New(Config{
		StateFile:    path,
		Enrollment:   true,
		AllowedCIDRs: []*net.IPNet{mustCIDR(t, "192.0.2.0/24")},
		Now:          func() time.Time { return now },
		Random:       bytes.NewReader(bytes.Repeat([]byte{0xab}, sessionTokenBytes)),
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	result, err := authenticator.Authenticate(context.Background(), validAuthRequest())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got, want := result.AccessToken, strings.Repeat("ab", sessionTokenBytes); got != want {
		t.Fatalf("AccessToken = %q, want %q", got, want)
	}
	if got, want := result.ExpiresAt, now.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", got, want)
	}
	if result.DeviceID != "" {
		t.Fatalf("legacy pairing DeviceID = %q, want empty", result.DeviceID)
	}
	if _, err := newStore(path).load(); err != nil {
		t.Fatalf("load enrolled state: %v", err)
	}
}

func TestAuthenticatorReloadsLockedStateAndRejectsDifferentCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	first := newAuthenticatorAtPath(t, path, true, []*net.IPNet{mustCIDR(t, "192.0.2.0/24")}, bytes.Repeat([]byte{1}, sessionTokenBytes))
	if _, err := first.Authenticate(context.Background(), validAuthRequest()); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	locked := newAuthenticatorAtPath(t, path, false, nil, bytes.Repeat([]byte{2}, sessionTokenBytes*2))
	request := validAuthRequest()
	request.PeerIP = net.ParseIP("203.0.113.9")
	result, err := locked.Authenticate(context.Background(), request)
	if err != nil {
		t.Fatalf("authenticate enrolled device from changed network: %v", err)
	}
	if got, want := result.AccessToken, strings.Repeat("02", sessionTokenBytes); got != want {
		t.Fatalf("AccessToken = %q, want %q", got, want)
	}
	request.Credential = "synthetic-other"
	if _, err := locked.Authenticate(context.Background(), request); !errors.Is(err, errCredentialRejected) {
		t.Fatalf("different credential error = %v, want errCredentialRejected", err)
	}
}

func newTestAuthenticator(t *testing.T, enrollment bool, allowed *net.IPNet) *Authenticator {
	t.Helper()
	var allowedCIDRs []*net.IPNet
	if allowed != nil {
		allowedCIDRs = []*net.IPNet{allowed}
	}
	return newAuthenticatorAtPath(t, filepath.Join(t.TempDir(), "credential.json"), enrollment, allowedCIDRs, bytes.Repeat([]byte{1}, sessionTokenBytes*4))
}

func newAuthenticatorAtPath(t *testing.T, path string, enrollment bool, allowedCIDRs []*net.IPNet, random []byte) *Authenticator {
	t.Helper()
	authenticator, err := New(Config{
		StateFile:    path,
		Enrollment:   enrollment,
		AllowedCIDRs: allowedCIDRs,
		Now:          func() time.Time { return time.Unix(1, 0).UTC() },
		Random:       bytes.NewReader(random),
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	return authenticator
}

func validAuthRequest() gateway.AuthRequest {
	return gateway.AuthRequest{
		AuthType:   1,
		Credential: "synthetic-credential",
		PeerIP:     net.ParseIP("192.0.2.10"),
	}
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("parse CIDR: %v", err)
	}
	return network
}
