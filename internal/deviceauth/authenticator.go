package deviceauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/1622359590/ai-wechat/internal/gateway"
)

const (
	maxCredentialBytes = 4096
	sessionTokenBytes  = 32
	deviceTokenTTL     = time.Hour
)

var (
	errInvalidAuthRequest        = errors.New("device authentication request is invalid")
	errAuthenticationRejected    = errors.New("device authentication is rejected")
	errAuthenticationLimited     = errors.New("device authentication is temporarily limited")
	errAuthenticationUnavailable = errors.New("device authentication is unavailable")
)

type AttemptLimiter interface {
	Allow(net.IP, devices.Fingerprint, time.Time) error
	Failure(devices.Fingerprint, time.Time)
	Success(devices.Fingerprint)
}

type Authenticator struct {
	repository    devices.Repository
	fingerprinter *devices.Fingerprinter
	limiter       AttemptLimiter
	now           func() time.Time
	random        io.Reader
}

func New(repository devices.Repository, fingerprinter *devices.Fingerprinter, limiter AttemptLimiter, now func() time.Time, random io.Reader) (*Authenticator, error) {
	if repository == nil {
		return nil, errors.New("device repository is required")
	}
	if fingerprinter == nil {
		return nil, errors.New("device fingerprinter is required")
	}
	if limiter == nil {
		return nil, errors.New("device authentication limiter is required")
	}
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &Authenticator{
		repository:    repository,
		fingerprinter: fingerprinter,
		limiter:       limiter,
		now:           now,
		random:        random,
	}, nil
}

func (authenticator *Authenticator) Authenticate(ctx context.Context, request gateway.AuthRequest) (gateway.AuthResult, error) {
	if err := ctx.Err(); err != nil {
		return gateway.AuthResult{}, err
	}
	if (request.AuthType != 0 && request.AuthType != 1) ||
		request.Credential == "" || len(request.Credential) > maxCredentialBytes ||
		!utf8.ValidString(request.Credential) {
		return gateway.AuthResult{}, errInvalidAuthRequest
	}

	now := authenticator.now()
	fingerprint := authenticator.fingerprinter.Sum(request.Credential)
	if err := authenticator.limiter.Allow(request.PeerIP, fingerprint, now); err != nil {
		return gateway.AuthResult{}, errAuthenticationLimited
	}

	device, err := authenticator.repository.Authorize(ctx, fingerprint, now)
	if errors.Is(err, devices.ErrNotAuthorized) {
		authenticator.limiter.Failure(fingerprint, now)
		return gateway.AuthResult{}, errAuthenticationRejected
	}
	if err != nil {
		return gateway.AuthResult{}, authenticationUnavailable(ctx)
	}

	rawToken := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(authenticator.random, rawToken); err != nil {
		return gateway.AuthResult{}, authenticationUnavailable(ctx)
	}
	if err := authenticator.repository.TouchAuthenticated(ctx, device.ID, now); err != nil {
		return gateway.AuthResult{}, authenticationUnavailable(ctx)
	}
	authenticator.limiter.Success(fingerprint)

	return gateway.AuthResult{
		AccessToken: hex.EncodeToString(rawToken),
		ExpiresAt:   now.Add(deviceTokenTTL),
		DeviceID:    device.ID,
	}, nil
}

func authenticationUnavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errAuthenticationUnavailable
}
