package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var ErrRateLimited = errors.New("administrator login rate limited")

const (
	loginBurst           = 3.0
	loginRefillPerSecond = 5.0 / 60.0
	loginBucketLifetime  = 30 * time.Minute
	maximumLoginBuckets  = 10_000
)

type loginBucket struct {
	tokens   float64
	refilled time.Time
	lastSeen time.Time
}

// LoginLimiter is an in-memory token bucket keyed by an HMAC of username and IP.
// It deliberately retains neither value in plaintext.
type LoginLimiter struct {
	mu      sync.Mutex
	key     [32]byte
	buckets map[[32]byte]loginBucket
}

func NewLoginLimiter(random io.Reader) (*LoginLimiter, error) {
	if random == nil {
		random = rand.Reader
	}
	limiter := &LoginLimiter{buckets: make(map[[32]byte]loginBucket)}
	if _, err := io.ReadFull(random, limiter.key[:]); err != nil {
		return nil, errorsWithoutDetails("initialize login limiter")
	}
	return limiter, nil
}

func (limiter *LoginLimiter) Allow(username string, ip net.IP, now time.Time) error {
	if limiter == nil {
		return ErrInvalidInput
	}
	normalized, err := NormalizeUsername(username)
	address := ip.To16()
	if err != nil || address == nil || now.IsZero() {
		return ErrInvalidInput
	}
	key := limiter.identityKey(normalized, address)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.cleanup(now)
	bucket, exists := limiter.buckets[key]
	if !exists {
		if len(limiter.buckets) >= maximumLoginBuckets {
			limiter.evictOldest()
		}
		bucket = loginBucket{tokens: loginBurst, refilled: now}
	}
	if now.After(bucket.refilled) {
		bucket.tokens += now.Sub(bucket.refilled).Seconds() * loginRefillPerSecond
		if bucket.tokens > loginBurst {
			bucket.tokens = loginBurst
		}
		bucket.refilled = now
	}
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		limiter.buckets[key] = bucket
		return ErrRateLimited
	}
	bucket.tokens--
	limiter.buckets[key] = bucket
	return nil
}

func (limiter *LoginLimiter) Success(username string, ip net.IP) {
	if limiter == nil {
		return
	}
	normalized, err := NormalizeUsername(username)
	address := ip.To16()
	if err != nil || address == nil {
		return
	}
	key := limiter.identityKey(normalized, address)
	limiter.mu.Lock()
	delete(limiter.buckets, key)
	limiter.mu.Unlock()
}

func (limiter *LoginLimiter) identityKey(username string, address net.IP) [32]byte {
	mac := hmac.New(sha256.New, limiter.key[:])
	_, _ = mac.Write([]byte(username))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(address)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (limiter *LoginLimiter) cleanup(now time.Time) {
	cutoff := now.Add(-loginBucketLifetime)
	for key, bucket := range limiter.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.buckets, key)
		}
	}
}

func (limiter *LoginLimiter) evictOldest() {
	var oldestKey [32]byte
	var oldestTime time.Time
	first := true
	for key, bucket := range limiter.buckets {
		if first || bucket.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = bucket.lastSeen
			first = false
		}
	}
	if !first {
		delete(limiter.buckets, oldestKey)
	}
}
