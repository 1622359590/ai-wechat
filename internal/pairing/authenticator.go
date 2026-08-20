package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/1622359590/ai-wechat/internal/gateway"
)

const (
	maxCredentialBytes = 4096
	sessionTokenBytes  = 32
	deviceTokenTTL     = time.Hour
)

var (
	errEnrollmentDisabled = errors.New("device enrollment is disabled")
	errInvalidAuthRequest = errors.New("device authentication request is invalid")
	errSourceRejected     = errors.New("device enrollment source is rejected")
	errCredentialRejected = errors.New("device credential is rejected")
)

type Config struct {
	StateFile    string
	Enrollment   bool
	AllowedCIDRs []*net.IPNet
	Now          func() time.Time
	Random       io.Reader
}

type Authenticator struct {
	store        *store
	enrollment   bool
	allowedCIDRs []*net.IPNet
	now          func() time.Time
	random       io.Reader
}

func New(config Config) (*Authenticator, error) {
	if config.StateFile == "" {
		return nil, errors.New("pairing state file is required")
	}
	if config.Enrollment && len(config.AllowedCIDRs) == 0 {
		return nil, errors.New("pairing enrollment requires an allowed CIDR")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	allowedCIDRs := make([]*net.IPNet, 0, len(config.AllowedCIDRs))
	for _, network := range config.AllowedCIDRs {
		if network == nil {
			return nil, errors.New("pairing allowed CIDR is invalid")
		}
		ip := append(net.IP(nil), network.IP...)
		mask := append(net.IPMask(nil), network.Mask...)
		allowedCIDRs = append(allowedCIDRs, &net.IPNet{IP: ip, Mask: mask})
	}
	return &Authenticator{
		store:        newStore(config.StateFile),
		enrollment:   config.Enrollment,
		allowedCIDRs: allowedCIDRs,
		now:          config.Now,
		random:       config.Random,
	}, nil
}

func (authenticator *Authenticator) Authenticate(ctx context.Context, request gateway.AuthRequest) (gateway.AuthResult, error) {
	if err := ctx.Err(); err != nil {
		return gateway.AuthResult{}, err
	}
	if request.AuthType != 1 || request.Credential == "" || len(request.Credential) > maxCredentialBytes {
		return gateway.AuthResult{}, errInvalidAuthRequest
	}
	fingerprint := sha256.Sum256([]byte(request.Credential))
	stored, err := authenticator.store.load()
	switch {
	case err == nil:
		if !equalFingerprint(stored, fingerprint) {
			return gateway.AuthResult{}, errCredentialRejected
		}
	case errors.Is(err, errStateNotFound):
		if !authenticator.enrollment {
			return gateway.AuthResult{}, errEnrollmentDisabled
		}
		if !authenticator.sourceAllowed(request.PeerIP) {
			return gateway.AuthResult{}, errSourceRejected
		}
		if err := authenticator.store.create(fingerprint, authenticator.now()); err != nil {
			if !errors.Is(err, errStateExists) {
				return gateway.AuthResult{}, fmt.Errorf("create pairing state: %w", err)
			}
			stored, err = authenticator.store.load()
			if err != nil {
				return gateway.AuthResult{}, fmt.Errorf("reload pairing state: %w", err)
			}
			if !equalFingerprint(stored, fingerprint) {
				return gateway.AuthResult{}, errCredentialRejected
			}
		}
	default:
		return gateway.AuthResult{}, fmt.Errorf("load pairing state: %w", err)
	}

	rawToken := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(authenticator.random, rawToken); err != nil {
		return gateway.AuthResult{}, fmt.Errorf("generate session token: %w", err)
	}
	return gateway.AuthResult{
		AccessToken: hex.EncodeToString(rawToken),
		ExpiresAt:   authenticator.now().Add(deviceTokenTTL),
	}, nil
}

func (authenticator *Authenticator) sourceAllowed(peerIP net.IP) bool {
	if peerIP == nil {
		return false
	}
	for _, network := range authenticator.allowedCIDRs {
		if network.Contains(peerIP) {
			return true
		}
	}
	return false
}

func equalFingerprint(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
