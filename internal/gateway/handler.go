// Package gateway applies per-connection authentication and message routing.
package gateway

import (
	"context"
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
	ErrUnexpectedMessage      = errors.New("message is not accepted from a device")
)

type Authenticator interface {
	Authenticate(context.Context, *dynamicpb.Message) error
}

type Responder interface {
	OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error)
}

type Session struct {
	authenticated atomic.Bool
}

func NewSession() *Session {
	return new(Session)
}

func (session *Session) Authenticated() bool {
	return session.authenticated.Load()
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
		if err := handler.authenticator.Authenticate(ctx, decoded.Payload); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
		}
		session.authenticated.Store(true)
		return nil, nil
	}
	if !session.Authenticated() {
		return nil, ErrAuthenticationRequired
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

func (DenyAllAuthenticator) Authenticate(context.Context, *dynamicpb.Message) error {
	return errors.New("no authentication backend configured")
}

type NoopResponder struct{}

func (NoopResponder) OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error) {
	return nil, nil
}
