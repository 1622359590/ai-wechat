package ratelimit

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestAuthLimiterInitialBurstRefillAndIPIsolation(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestAuth(t, clock)
	fingerprint := limiterFingerprint(1)
	firstIP := net.ParseIP("192.0.2.10")

	for attempt := 0; attempt < 5; attempt++ {
		if err := limiter.Allow(firstIP, fingerprint, clock.Now()); err != nil {
			t.Fatalf("initial attempt %d: %v", attempt, err)
		}
	}
	if err := limiter.Allow(firstIP, fingerprint, clock.Now()); !errors.Is(err, ErrLimited) {
		t.Fatalf("sixth attempt error = %v, want ErrLimited", err)
	}
	if err := limiter.Allow(net.ParseIP("198.51.100.10"), fingerprint, clock.Now()); err != nil {
		t.Fatalf("isolated IP attempt: %v", err)
	}
	clock.Advance(3 * time.Second)
	if err := limiter.Allow(firstIP, fingerprint, clock.Now()); err != nil {
		t.Fatalf("refilled attempt: %v", err)
	}
}

func TestAuthLimiterBackoffCapsAndSuccessResets(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestAuth(t, clock)
	ip := net.ParseIP("192.0.2.20")
	fingerprint := limiterFingerprint(2)

	for failure := 0; failure < 12; failure++ {
		if err := limiter.Allow(ip, fingerprint, clock.Now()); err != nil {
			t.Fatalf("allow before failure %d: %v", failure, err)
		}
		limiter.Failure(fingerprint, clock.Now())
		if err := limiter.Allow(ip, fingerprint, clock.Now()); !errors.Is(err, ErrLimited) {
			t.Fatalf("immediate retry %d error = %v, want ErrLimited", failure, err)
		}
		state := limiter.backoffs[limiter.credentialIdentifier(fingerprint)]
		delay := state.blockedUntil.Sub(clock.Now())
		wantDelay := time.Second << failure
		if wantDelay > 15*time.Minute {
			wantDelay = 15 * time.Minute
		}
		if delay != wantDelay {
			t.Fatalf("backoff %d = %v, want %v", failure, delay, wantDelay)
		}
		clock.Advance(delay)
		clock.Advance(time.Minute)
	}

	limiter.Success(fingerprint)
	if _, exists := limiter.backoffs[limiter.credentialIdentifier(fingerprint)]; exists {
		t.Fatal("Success() did not clear credential backoff")
	}
}

func TestAuthLimiterCleansStaleKeyedStateWithoutRawIdentifiers(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestAuth(t, clock)
	ip := net.ParseIP("192.0.2.30")
	fingerprint := limiterFingerprint(3)
	if err := limiter.Allow(ip, fingerprint, clock.Now()); err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	limiter.Failure(fingerprint, clock.Now())

	if len(limiter.buckets) != 1 || len(limiter.backoffs) != 1 {
		t.Fatalf("state sizes = %d/%d, want 1/1", len(limiter.buckets), len(limiter.backoffs))
	}
	for identifier := range limiter.buckets {
		if len(identifier) != 16 {
			t.Fatalf("IP identifier length = %d, want 16", len(identifier))
		}
		if bytes.Contains(identifier[:], ip.To4()) {
			t.Fatal("IP identifier contains raw IP bytes")
		}
	}
	for identifier := range limiter.backoffs {
		if len(identifier) != 16 {
			t.Fatalf("credential identifier length = %d, want 16", len(identifier))
		}
		if bytes.Contains(identifier[:], fingerprint.Bytes()) {
			t.Fatal("credential identifier contains raw fingerprint bytes")
		}
	}

	clock.Advance(staleEntryTTL + time.Second)
	if err := limiter.Allow(net.ParseIP("198.51.100.30"), limiterFingerprint(4), clock.Now()); err != nil {
		t.Fatalf("Allow() after stale interval: %v", err)
	}
	if len(limiter.buckets) != 1 || len(limiter.backoffs) != 0 {
		t.Fatalf("stale cleanup sizes = %d/%d, want 1/0", len(limiter.buckets), len(limiter.backoffs))
	}
}

func TestAuthLimiterRequiresExactCopiedKey(t *testing.T) {
	clock := newFakeClock()
	for _, size := range []int{0, 31, 33} {
		if _, err := NewAuth(Config{AttemptsPerMinute: 20, Burst: 5, MaximumBackoff: 15 * time.Minute, Now: clock.Now, Key: make([]byte, size)}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("NewAuth(key bytes=%d) error = %v, want ErrInvalidInput", size, err)
		}
	}
	key := bytes.Repeat([]byte{0x4a}, 32)
	limiter, err := NewAuth(Config{AttemptsPerMinute: 20, Burst: 5, MaximumBackoff: 15 * time.Minute, Now: clock.Now, Key: key})
	if err != nil {
		t.Fatalf("NewAuth(): %v", err)
	}
	before := limiter.ipIdentifier(net.ParseIP("192.0.2.40"))
	key[0] ^= 0xff
	after := limiter.ipIdentifier(net.ParseIP("192.0.2.40"))
	if before != after {
		t.Fatal("limiter retained caller-owned key storage")
	}
}

func newTestAuth(t *testing.T, clock *fakeClock) *Auth {
	t.Helper()
	limiter, err := NewAuth(Config{
		AttemptsPerMinute: 20,
		Burst:             5,
		MaximumBackoff:    15 * time.Minute,
		Now:               clock.Now,
		Key:               bytes.Repeat([]byte{0x3b}, 32),
	})
	if err != nil {
		t.Fatalf("NewAuth(): %v", err)
	}
	return limiter
}

func limiterFingerprint(last byte) devices.Fingerprint {
	var fingerprint devices.Fingerprint
	fingerprint[len(fingerprint)-1] = last
	return fingerprint
}

type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
}

func (clock *fakeClock) Now() time.Time                 { return clock.now }
func (clock *fakeClock) Advance(duration time.Duration) { clock.now = clock.now.Add(duration) }
