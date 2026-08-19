package gateway_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/1622359590/ai-wechat/internal/gateway"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestHandlerRequiresSuccessfulAuthentication(t *testing.T) {
	codec := loadCodec(t)
	heartbeat := fixtureBody(t, "heart-beat-normal")
	auth := fixtureBody(t, "device-auth-normal")

	denyHandler := gateway.NewHandler(codec, gateway.DenyAllAuthenticator{}, gateway.NoopResponder{})
	session := gateway.NewSession()
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
	session = gateway.NewSession()
	if response, err := handler.Handle(context.Background(), session, auth); err != nil || len(response) != 0 {
		t.Fatalf("authenticate response length/error = %d/%v", len(response), err)
	}
	if !session.Authenticated() || accept.calls != 1 {
		t.Fatalf("authenticated=%v calls=%d, want true/1", session.Authenticated(), accept.calls)
	}
	if response, err := handler.Handle(context.Background(), session, heartbeat); err != nil || len(response) != 0 {
		t.Fatalf("heartbeat response length/error = %d/%v", len(response), err)
	}
}

func TestHandlerRejectsAuthenticationAfterSessionIsAuthenticated(t *testing.T) {
	codec := loadCodec(t)
	authenticator := &acceptAuthenticator{}
	handler := gateway.NewHandler(codec, authenticator, gateway.NoopResponder{})
	session := gateway.NewSession()
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
	session := gateway.NewSession()

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

type acceptAuthenticator struct {
	calls int
}

func (authenticator *acceptAuthenticator) Authenticate(_ context.Context, message *dynamicpb.Message) error {
	authenticator.calls++
	credential := message.Descriptor().Fields().ByName("Credential")
	if message.Get(credential).String() != "synthetic-credential" {
		return errors.New("unexpected synthetic credential")
	}
	return nil
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
