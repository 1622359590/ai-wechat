// Package gateway applies per-connection authentication and message routing.
package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/1622359590/ai-wechat/internal/protocol"
	"google.golang.org/protobuf/types/dynamicpb"
)

type AuthRequest struct {
	AuthType   int32
	Credential string
	PeerIP     net.IP
}

type AuthResult struct {
	AccessToken string
	ExpiresAt   time.Time
}

var (
	ErrAuthenticationRequired = errors.New("authentication is required")
	ErrAuthenticationFailed   = errors.New("authentication failed")
	ErrAccessTokenInvalid     = errors.New("access token is invalid")
	ErrAccessTokenExpired     = errors.New("access token is expired")
	ErrUnexpectedMessage      = errors.New("message is not accepted from a device")
)

type Authenticator interface {
	Authenticate(context.Context, AuthRequest) (AuthResult, error)
}

type Responder interface {
	OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error)
}

type Session struct {
	authenticated atomic.Bool
	peerIP        net.IP
	accessToken   string
	expiresAt     time.Time
}

func NewSession(peerIP net.IP) *Session {
	return &Session{peerIP: append(net.IP(nil), peerIP...)}
}

func (session *Session) Authenticated() bool {
	return session.authenticated.Load()
}

func (session *Session) authenticate(result AuthResult) {
	session.accessToken = result.AccessToken
	session.expiresAt = result.ExpiresAt
	session.authenticated.Store(true)
}

func (session *Session) validateAccessToken(accessToken string, now time.Time) error {
	if !session.expiresAt.After(now) {
		return ErrAccessTokenExpired
	}
	if accessToken == "" || subtle.ConstantTimeCompare([]byte(accessToken), []byte(session.accessToken)) != 1 {
		return ErrAccessTokenInvalid
	}
	return nil
}

type Handler struct {
	codec         *protocol.Codec
	authenticator Authenticator
	responder     Responder
}

func NewHandler(codec *protocol.Codec, authenticator Authenticator, responder Responder) *Handler {
	return &Handler{codec: codec, authenticator: authenticator, responder: responder}
}

func (handler *Handler) Handle(ctx context.Context, session *Session, body []byte) ([]byte, error) {
	decoded, err := handler.codec.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("decode device message: %w", err)
	}

	if decoded.MsgType == 1010 {
		if session.Authenticated() {
			return nil, fmt.Errorf("%w: repeated authentication", ErrUnexpectedMessage)
		}
		fields := decoded.Payload.Descriptor().Fields()
		request := AuthRequest{
			AuthType:   int32(decoded.Payload.Get(fields.ByName("AuthType")).Enum()),
			Credential: decoded.Payload.Get(fields.ByName("Credential")).String(),
			PeerIP:     append(net.IP(nil), session.peerIP...),
		}
		result, err := handler.authenticator.Authenticate(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
		}
		response, err := handler.codec.EncodeDeviceAuth(result.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("encode device auth response: %w", err)
		}
		session.authenticate(result)
		return response, nil
	}
	if !session.Authenticated() {
		return nil, ErrAuthenticationRequired
	}
	if err := session.validateAccessToken(decoded.AccessToken, time.Now()); err != nil {
		return nil, err
	}

	switch decoded.MsgType {
	case 1001:
		return nil, nil
	case 1024:
		reply, err := handler.responder.OnFriendTalk(ctx, decoded.Payload)
		if err != nil {
			return nil, fmt.Errorf("handle friend talk: %w", err)
		}
		if reply == nil {
			return nil, nil
		}
		body, err := handler.codec.EncodeTalkToFriend(*reply)
		if err != nil {
			return nil, fmt.Errorf("encode friend reply: %w", err)
		}
		return body, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnexpectedMessage, decoded.MsgType)
	}
}

type DenyAllAuthenticator struct{}

func (DenyAllAuthenticator) Authenticate(context.Context, AuthRequest) (AuthResult, error) {
	return AuthResult{}, errors.New("no authentication backend configured")
}

type NoopResponder struct{}

func (NoopResponder) OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error) {
	return nil, nil
}
