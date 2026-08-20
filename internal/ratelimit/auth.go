package ratelimit

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
)

const staleEntryTTL = 30 * time.Minute

var (
	ErrLimited      = errors.New("authentication attempt is limited")
	ErrInvalidInput = errors.New("authentication limiter input is invalid")
)

type Config struct {
	AttemptsPerMinute float64
	Burst             int
	MaximumBackoff    time.Duration
	Now               func() time.Time
	Key               []byte
}

type identifier [16]byte

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type backoffState struct {
	failures     uint
	blockedUntil time.Time
	lastSeen     time.Time
}

type Auth struct {
	mu                sync.Mutex
	attemptsPerSecond float64
	burst             float64
	maximumBackoff    time.Duration
	now               func() time.Time
	key               [32]byte
	buckets           map[identifier]tokenBucket
	backoffs          map[identifier]backoffState
}

func NewAuth(config Config) (*Auth, error) {
	if config.AttemptsPerMinute <= 0 || math.IsNaN(config.AttemptsPerMinute) || math.IsInf(config.AttemptsPerMinute, 0) ||
		config.Burst <= 0 || config.MaximumBackoff <= 0 || len(config.Key) != sha256.Size {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	limiter := &Auth{
		attemptsPerSecond: config.AttemptsPerMinute / 60,
		burst:             float64(config.Burst),
		maximumBackoff:    config.MaximumBackoff,
		now:               config.Now,
		buckets:           make(map[identifier]tokenBucket),
		backoffs:          make(map[identifier]backoffState),
	}
	copy(limiter.key[:], config.Key)
	return limiter, nil
}

func (limiter *Auth) Allow(ip net.IP, fingerprint devices.Fingerprint, at time.Time) error {
	canonicalIP := canonicalIP(ip)
	if canonicalIP == nil {
		return ErrInvalidInput
	}
	if at.IsZero() {
		at = limiter.now()
	}
	ipID := limiter.identifier("ip", canonicalIP)
	credentialID := limiter.credentialIdentifier(fingerprint)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.cleanup(at)

	bucket, exists := limiter.buckets[ipID]
	if !exists {
		bucket = tokenBucket{tokens: limiter.burst, last: at}
	}
	if at.After(bucket.last) {
		bucket.tokens += at.Sub(bucket.last).Seconds() * limiter.attemptsPerSecond
		if bucket.tokens > limiter.burst {
			bucket.tokens = limiter.burst
		}
		bucket.last = at
	}
	bucket.lastSeen = at
	if bucket.tokens < 1 {
		limiter.buckets[ipID] = bucket
		return ErrLimited
	}
	bucket.tokens--
	limiter.buckets[ipID] = bucket

	if state, exists := limiter.backoffs[credentialID]; exists {
		state.lastSeen = at
		limiter.backoffs[credentialID] = state
		if at.Before(state.blockedUntil) {
			return ErrLimited
		}
	}
	return nil
}

func (limiter *Auth) Failure(fingerprint devices.Fingerprint, at time.Time) {
	if at.IsZero() {
		at = limiter.now()
	}
	credentialID := limiter.credentialIdentifier(fingerprint)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state := limiter.backoffs[credentialID]
	state.failures++
	delay := time.Second
	for count := uint(1); count < state.failures && delay < limiter.maximumBackoff; count++ {
		if delay > limiter.maximumBackoff/2 {
			delay = limiter.maximumBackoff
			break
		}
		delay *= 2
	}
	if delay > limiter.maximumBackoff {
		delay = limiter.maximumBackoff
	}
	state.blockedUntil = at.Add(delay)
	state.lastSeen = at
	limiter.backoffs[credentialID] = state
}

func (limiter *Auth) Success(fingerprint devices.Fingerprint) {
	credentialID := limiter.credentialIdentifier(fingerprint)
	limiter.mu.Lock()
	delete(limiter.backoffs, credentialID)
	limiter.mu.Unlock()
}

func (limiter *Auth) ipIdentifier(ip net.IP) identifier {
	return limiter.identifier("ip", canonicalIP(ip))
}

func (limiter *Auth) credentialIdentifier(fingerprint devices.Fingerprint) identifier {
	return limiter.identifier("credential", fingerprint.Bytes())
}

func (limiter *Auth) identifier(domain string, value []byte) identifier {
	digest := hmac.New(sha256.New, limiter.key[:])
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	var result identifier
	copy(result[:], digest.Sum(nil))
	return result
}

func (limiter *Auth) cleanup(at time.Time) {
	cutoff := at.Add(-staleEntryTTL)
	for key, bucket := range limiter.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.buckets, key)
		}
	}
	for key, state := range limiter.backoffs {
		if state.lastSeen.Before(cutoff) && !state.blockedUntil.After(at) {
			delete(limiter.backoffs, key)
		}
	}
}

func canonicalIP(ip net.IP) []byte {
	if ip == nil {
		return nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return append([]byte(nil), ipv4...)
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		return append([]byte(nil), ipv6...)
	}
	return nil
}
