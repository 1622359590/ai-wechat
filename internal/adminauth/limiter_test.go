package adminauth

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestLoginLimiterAppliesBurstAndRefill(t *testing.T) {
	t.Parallel()
	limiter, err := NewLoginLimiter(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)))
	if err != nil {
		t.Fatalf("NewLoginLimiter(): %v", err)
	}
	now := time.Date(2026, 8, 22, 4, 0, 0, 0, time.UTC)
	ip := net.ParseIP("192.0.2.10")
	for attempt := 1; attempt <= 3; attempt++ {
		if err := limiter.Allow("admin_01", ip, now); err != nil {
			t.Fatalf("Allow(attempt %d): %v", attempt, err)
		}
	}
	if err := limiter.Allow("admin_01", ip, now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Allow(burst exceeded) error = %v, want ErrRateLimited", err)
	}
	if err := limiter.Allow("admin_01", ip, now.Add(12*time.Second)); err != nil {
		t.Fatalf("Allow(after refill): %v", err)
	}
}

func TestLoginLimiterSeparatesKeysAndResetsSuccess(t *testing.T) {
	t.Parallel()
	limiter, err := NewLoginLimiter(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatalf("NewLoginLimiter(): %v", err)
	}
	now := time.Date(2026, 8, 22, 4, 30, 0, 0, time.UTC)
	firstIP := net.ParseIP("192.0.2.11")
	secondIP := net.ParseIP("192.0.2.12")
	for range 3 {
		if err := limiter.Allow("admin_01", firstIP, now); err != nil {
			t.Fatalf("Allow(first key): %v", err)
		}
	}
	if err := limiter.Allow("admin_02", firstIP, now); err != nil {
		t.Fatalf("Allow(other username): %v", err)
	}
	if err := limiter.Allow("admin_01", secondIP, now); err != nil {
		t.Fatalf("Allow(other IP): %v", err)
	}
	limiter.Success("admin_01", firstIP)
	if err := limiter.Allow("admin_01", firstIP, now); err != nil {
		t.Fatalf("Allow(after success): %v", err)
	}
}

func TestLoginLimiterRejectsInvalidIdentity(t *testing.T) {
	t.Parallel()
	if _, err := NewLoginLimiter(bytes.NewReader([]byte("short"))); err == nil {
		t.Fatal("NewLoginLimiter() accepted insufficient randomness")
	}
	limiter, err := NewLoginLimiter(bytes.NewReader(bytes.Repeat([]byte{0x53}, 32)))
	if err != nil {
		t.Fatalf("NewLoginLimiter(): %v", err)
	}
	if err := limiter.Allow("", net.ParseIP("192.0.2.13"), time.Now()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Allow(empty username) error = %v", err)
	}
	if err := limiter.Allow("admin_01", nil, time.Now()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Allow(nil IP) error = %v", err)
	}
}
