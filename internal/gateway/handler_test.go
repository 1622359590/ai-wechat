package gateway_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/1622359590/ai-wechat/internal/gateway"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestHandlerRequiresSuccessfulAuthentication(t *testing.T) {
	codec := loadCodec(t)
	heartbeat := fixtureBody(t, "heart-beat-normal")
	auth := fixtureBody(t, "device-auth-normal")

	denyHandler := gateway.NewHandler(codec, gateway.DenyAllAuthenticator{}, gateway.NoopResponder{})
	session := gateway.NewSession(net.ParseIP("192.0.2.10"))
	if _, err := denyHandler.Handle(context.Background(), session, heartbeat); !errors.Is(err, gateway.ErrAuthenticationRequired) {
		t.Fatalf("pre-auth heartbeat error = %v, want ErrAuthenticationRequired", err)
	}
	if _, err := denyHandler.Handle(context.Background(), session, auth); !errors.Is(err, gateway.ErrAuthenticationFailed) {
		t.Fatalf("deny auth error = %v, want ErrAuthenticationFailed", err)
	}
	if session.Authenticated() {
		t.Fatal("denied session became authenticated")
	}

	accept := &acceptAuthenticator{}
	handler := gateway.NewHandler(codec, accept, gateway.NoopResponder{})
	session = gateway.NewSession(net.ParseIP("192.0.2.10"))
	response, err := handler.Handle(context.Background(), session, auth)
	if err != nil || len(response) == 0 {
		t.Fatalf("authenticate response length/error = %d/%v", len(response), err)
	}
	if !session.Authenticated() || accept.calls != 1 {
		t.Fatalf("authenticated=%v calls=%d, want true/1", session.Authenticated(), accept.calls)
	}
	if deviceID, ok := session.DeviceID(); !ok || deviceID != acceptDeviceID {
		t.Fatalf("session DeviceID = %q/%v, want %q/true", deviceID, ok, acceptDeviceID)
	}
	if deviceID, ok := session.TakePendingActivation(); !ok || deviceID != acceptDeviceID {
		t.Fatalf("first pending activation = %q/%v, want %q/true", deviceID, ok, acceptDeviceID)
	}
	if deviceID, ok := session.TakePendingActivation(); ok || deviceID != "" {
		t.Fatalf("second pending activation = %q/%v, want empty/false", deviceID, ok)
	}
	decoded, err := codec.Decode(response)
	if err != nil || decoded.MsgType != 1011 {
		t.Fatalf("decode auth response type/error = %d/%v", decoded.MsgType, err)
	}
	if accept.request.AuthType != 1 || accept.request.Credential != "synthetic-credential" || !accept.request.PeerIP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatal("authenticator did not receive the decoded request and peer IP")
	}
	if response, err := handler.Handle(context.Background(), session, heartbeat); err != nil || len(response) != 0 {
		t.Fatalf("heartbeat response length/error = %d/%v", len(response), err)
	}
}

func TestHandlerRejectsAuthenticationAfterSessionIsAuthenticated(t *testing.T) {
	codec := loadCodec(t)
	authenticator := &acceptAuthenticator{}
	handler := gateway.NewHandler(codec, authenticator, gateway.NoopResponder{})
	session := gateway.NewSession(net.ParseIP("192.0.2.10"))
	auth := fixtureBody(t, "device-auth-normal")

	if _, err := handler.Handle(context.Background(), session, auth); err != nil {
		t.Fatalf("initial authentication: %v", err)
	}
	if _, err := handler.Handle(context.Background(), session, auth); !errors.Is(err, gateway.ErrUnexpectedMessage) {
		t.Fatalf("repeated authentication error = %v, want ErrUnexpectedMessage", err)
	}
	if authenticator.calls != 1 {
		t.Fatalf("authenticator calls = %d, want 1", authenticator.calls)
	}
}

func TestHandlerRoutesFriendTalkAndEncodesReply(t *testing.T) {
	codec := loadCodec(t)
	responder := &replyResponder{}
	handler := gateway.NewHandler(codec, &acceptAuthenticator{}, responder)
	session := gateway.NewSession(net.ParseIP("192.0.2.10"))

	if _, err := handler.Handle(context.Background(), session, fixtureBody(t, "device-auth-normal")); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	response, err := handler.Handle(context.Background(), session, fixtureBody(t, "friend-talk-normal"))
	if err != nil {
		t.Fatalf("friend talk: %v", err)
	}
	if responder.calls != 1 {
		t.Fatalf("responder calls = %d, want 1", responder.calls)
	}
	decoded, err := codec.Decode(response)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if decoded.MsgType != 1070 {
		t.Fatalf("reply MsgType = %d, want 1070", decoded.MsgType)
	}
}

func TestHandlerRejectsMissingWrongAndExpiredAccessTokens(t *testing.T) {
	codec := loadCodec(t)
	tests := []struct {
		name          string
		authenticator *acceptAuthenticator
		heartbeat     []byte
		want          error
	}{
		{name: "missing", authenticator: &acceptAuthenticator{}, heartbeat: transportWithAccessToken(t, codec, fixtureBody(t, "heart-beat-normal"), ""), want: gateway.ErrAccessTokenInvalid},
		{name: "wrong", authenticator: &acceptAuthenticator{}, heartbeat: transportWithAccessToken(t, codec, fixtureBody(t, "heart-beat-normal"), "synthetic-wrong"), want: gateway.ErrAccessTokenInvalid},
		{name: "expired", authenticator: &acceptAuthenticator{expiresAt: time.Unix(1, 0)}, heartbeat: fixtureBody(t, "heart-beat-normal"), want: gateway.ErrAccessTokenExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := gateway.NewHandler(codec, test.authenticator, gateway.NoopResponder{})
			session := gateway.NewSession(net.ParseIP("192.0.2.10"))
			if _, err := handler.Handle(context.Background(), session, fixtureBody(t, "device-auth-normal")); err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if _, err := handler.Handle(context.Background(), session, test.heartbeat); !errors.Is(err, test.want) {
				t.Fatalf("heartbeat error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHandlerDoesNotAuthenticateWhenAuthResponseCannotBeEncoded(t *testing.T) {
	codec := loadCodec(t)
	handler := gateway.NewHandler(codec, &acceptAuthenticator{forceEmptyToken: true}, gateway.NoopResponder{})
	session := gateway.NewSession(net.ParseIP("192.0.2.10"))
	if _, err := handler.Handle(context.Background(), session, fixtureBody(t, "device-auth-normal")); !errors.Is(err, protocol.ErrInvalidAuthResult) {
		t.Fatalf("authenticate error = %v, want ErrInvalidAuthResult", err)
	}
	if session.Authenticated() {
		t.Fatal("session became authenticated without an encodable response")
	}
	if _, ok := session.TakePendingActivation(); ok {
		t.Fatal("session exposed activation without an encodable response")
	}
}

func TestSessionLeavesLegacyPairingWithoutDeviceActivation(t *testing.T) {
	codec := loadCodec(t)
	handler := gateway.NewHandler(codec, &acceptAuthenticator{legacyNoDeviceID: true}, gateway.NoopResponder{})
	session := gateway.NewSession(net.ParseIP("192.0.2.10"))
	if _, err := handler.Handle(context.Background(), session, fixtureBody(t, "device-auth-normal")); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if deviceID, ok := session.DeviceID(); ok || deviceID != "" {
		t.Fatalf("legacy DeviceID = %q/%v, want empty/false", deviceID, ok)
	}
	if _, ok := session.TakePendingActivation(); ok {
		t.Fatal("legacy session exposed a pending activation")
	}
}

const acceptDeviceID devices.ID = "00000000-0000-0000-0000-000000000020"

type acceptAuthenticator struct {
	calls            int
	request          gateway.AuthRequest
	accessToken      string
	expiresAt        time.Time
	forceEmptyToken  bool
	legacyNoDeviceID bool
}

func (authenticator *acceptAuthenticator) Authenticate(_ context.Context, request gateway.AuthRequest) (gateway.AuthResult, error) {
	authenticator.calls++
	authenticator.request = request
	if request.Credential != "synthetic-credential" {
		return gateway.AuthResult{}, errors.New("unexpected synthetic credential")
	}
	accessToken := authenticator.accessToken
	if accessToken == "" && !authenticator.forceEmptyToken {
		accessToken = "synthetic-token"
	}
	expiresAt := authenticator.expiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}
	deviceID := acceptDeviceID
	if authenticator.legacyNoDeviceID {
		deviceID = ""
	}
	return gateway.AuthResult{AccessToken: accessToken, ExpiresAt: expiresAt, DeviceID: deviceID}, nil
}

func transportWithAccessToken(t *testing.T, codec *protocol.Codec, body []byte, accessToken string) []byte {
	t.Helper()
	decoded, err := codec.Decode(body)
	if err != nil {
		t.Fatalf("decode transport: %v", err)
	}
	field := decoded.Transport.Descriptor().Fields().ByName(protoreflect.Name("AccessToken"))
	if field == nil {
		t.Fatal("transport AccessToken field not found")
	}
	decoded.Transport.Set(field, protoreflect.ValueOfString(accessToken))
	result, err := (proto.MarshalOptions{Deterministic: true}).Marshal(decoded.Transport)
	if err != nil {
		t.Fatalf("marshal transport: %v", err)
	}
	return result
}

type replyResponder struct {
	calls int
}

func loadCodec(t *testing.T) *protocol.Codec {
	t.Helper()
	files, err := schema.Load()
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	codec, err := protocol.NewCodec(files)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	return codec
}

func fixtureBody(t *testing.T, caseName string) []byte {
	t.Helper()
	body, err := os.ReadFile("../../proto/testdata/synthetic_frames.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures []struct {
		Case     string `json:"case"`
		FrameHex string `json:"frame_hex"`
	}
	if err := json.Unmarshal(body, &fixtures); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	for _, fixture := range fixtures {
		if fixture.Case != caseName {
			continue
		}
		frame, err := hex.DecodeString(fixture.FrameHex)
		if err != nil || len(frame) < 4 {
			t.Fatalf("decode %s frame: %v", caseName, err)
		}
		return frame[4:]
	}
	t.Fatalf("fixture %s not found", caseName)
	return nil
}

func (responder *replyResponder) OnFriendTalk(_ context.Context, _ *dynamicpb.Message) (*protocol.Reply, error) {
	responder.calls++
	return &protocol.Reply{
		ID: 900, RefMessageID: 1, AccessToken: "synthetic-token",
		WeChatID: "synthetic-wechat", FriendID: "synthetic-friend",
		ContentType: 1, Content: []byte("synthetic-reply"), MsgID: 901,
	}, nil
}
