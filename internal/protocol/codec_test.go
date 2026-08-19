package protocol_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const packageName = "Jubo.JuLiao.IM.Wx.Proto"

type fixture struct {
	Case         string `json:"case"`
	MessageType  string `json:"message_type"`
	MsgType      int32  `json:"msg_type"`
	FrameHex     string `json:"frame_hex"`
	UnknownScope string `json:"unknown_scope"`
}

func TestDecodeReplaysAllSyntheticFixtures(t *testing.T) {
	codec := newCodec(t)
	fixtures := readFixtures(t)
	if got, want := len(fixtures), 15; got != want {
		t.Fatalf("fixture count = %d, want %d", got, want)
	}

	for _, fixture := range fixtures {
		t.Run(fixture.Case, func(t *testing.T) {
			body := fixtureBody(t, fixture)
			decoded, err := codec.Decode(body)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if got, want := decoded.MsgType, fixture.MsgType; got != want {
				t.Fatalf("MsgType = %d, want %d", got, want)
			}
			if fixture.MessageType == "TransportMessage" {
				if decoded.Payload != nil {
					t.Fatalf("transport-only fixture returned payload %s", decoded.Payload.Descriptor().FullName())
				}
				return
			}
			if decoded.Payload == nil {
				t.Fatal("decoded payload is nil")
			}
			if got, want := string(decoded.Payload.Descriptor().Name()), fixture.MessageType; got != want {
				t.Fatalf("payload type = %q, want %q", got, want)
			}
			if got, want := decoded.TypeURL, "type.googleapis.com/"+packageName+"."+fixture.MessageType; got != want {
				t.Fatalf("type URL = %q, want %q", got, want)
			}
			if fixture.UnknownScope == "inner" && len(decoded.Payload.GetUnknown()) == 0 {
				t.Fatal("inner unknown field was not preserved")
			}
			if fixture.UnknownScope == "outer" && len(decoded.Transport.GetUnknown()) == 0 {
				t.Fatal("outer unknown field was not preserved")
			}
		})
	}
}

func TestDecodeRejectsMissingOrMismatchedAny(t *testing.T) {
	codec := newCodec(t)
	files, err := schema.Load()
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	descriptor, err := files.FindDescriptorByName(packageName + ".TransportMessage")
	if err != nil {
		t.Fatalf("find transport: %v", err)
	}
	transport := dynamicpb.NewMessage(descriptor.(protoreflect.MessageDescriptor))
	msgTypeField := transport.Descriptor().Fields().ByName("MsgType")
	transport.Set(msgTypeField, protoreflect.ValueOfEnum(1001))
	body, err := proto.Marshal(transport)
	if err != nil {
		t.Fatalf("marshal missing Any: %v", err)
	}
	if _, err := codec.Decode(body); !errors.Is(err, protocol.ErrMissingContent) {
		t.Fatalf("missing Any error = %v, want ErrMissingContent", err)
	}

	replyBody, err := codec.EncodeTalkToFriend(protocol.Reply{
		ID: 1, RefMessageID: 2, AccessToken: "synthetic-token",
		WeChatID: "synthetic-wechat", FriendID: "synthetic-friend",
		ContentType: 1, Content: []byte("synthetic-content"), MsgID: 3,
	})
	if err != nil {
		t.Fatalf("encode reply: %v", err)
	}
	transport.Reset()
	if err := proto.Unmarshal(replyBody, transport); err != nil {
		t.Fatalf("decode reply transport: %v", err)
	}
	transport.Set(msgTypeField, protoreflect.ValueOfEnum(1001))
	mismatched, err := proto.Marshal(transport)
	if err != nil {
		t.Fatalf("marshal mismatch: %v", err)
	}
	if _, err := codec.Decode(mismatched); !errors.Is(err, protocol.ErrTypeMismatch) {
		t.Fatalf("mismatch error = %v, want ErrTypeMismatch", err)
	}
}

func TestEncodeTalkToFriendRoundTripsSemanticFields(t *testing.T) {
	codec := newCodec(t)
	want := protocol.Reply{
		ID: 41, RefMessageID: 40, AccessToken: "synthetic-token",
		WeChatID: "synthetic-wechat", FriendID: "synthetic-friend",
		ContentType: 1, Content: []byte("synthetic-reply"), Remark: "synthetic-remark",
		MsgID: 42, Immediate: true,
	}
	body, err := codec.EncodeTalkToFriend(want)
	if err != nil {
		t.Fatalf("encode talk-to-friend: %v", err)
	}
	decoded, err := codec.Decode(body)
	if err != nil {
		t.Fatalf("decode talk-to-friend: %v", err)
	}
	if decoded.MsgType != 1070 || decoded.ID != want.ID || decoded.RefMessageID != want.RefMessageID {
		t.Fatalf("transport semantics = type:%d id:%d ref:%d", decoded.MsgType, decoded.ID, decoded.RefMessageID)
	}
	fields := decoded.Payload.Descriptor().Fields()
	assertStringField(t, decoded.Payload, fields.ByName("WeChatId"), want.WeChatID)
	assertStringField(t, decoded.Payload, fields.ByName("FriendId"), want.FriendID)
	assertBytesField(t, decoded.Payload, fields.ByName("Content"), want.Content)
	if got := int32(decoded.Payload.Get(fields.ByName("ContentType")).Enum()); got != want.ContentType {
		t.Fatalf("ContentType = %d, want %d", got, want.ContentType)
	}
	if got := decoded.Payload.Get(fields.ByName("MsgId")).Int(); got != want.MsgID {
		t.Fatalf("MsgId = %d, want %d", got, want.MsgID)
	}
	if got := decoded.Payload.Get(fields.ByName("Immediate")).Bool(); got != want.Immediate {
		t.Fatalf("Immediate = %v, want %v", got, want.Immediate)
	}
}

func newCodec(t *testing.T) *protocol.Codec {
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

func readFixtures(t *testing.T) []fixture {
	t.Helper()
	body, err := os.ReadFile("../../proto/testdata/synthetic_frames.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures []fixture
	if err := json.Unmarshal(body, &fixtures); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	return fixtures
}

func fixtureBody(t *testing.T, fixture fixture) []byte {
	t.Helper()
	frame, err := hex.DecodeString(fixture.FrameHex)
	if err != nil || len(frame) < 4 {
		t.Fatalf("decode fixture frame: %v", err)
	}
	return frame[4:]
}

func assertStringField(t *testing.T, message protoreflect.Message, field protoreflect.FieldDescriptor, want string) {
	t.Helper()
	if got := message.Get(field).String(); got != want {
		t.Fatalf("%s = %q, want %q", field.Name(), got, want)
	}
}

func assertBytesField(t *testing.T, message protoreflect.Message, field protoreflect.FieldDescriptor, want []byte) {
	t.Helper()
	if got := message.Get(field).Bytes(); string(got) != string(want) {
		t.Fatalf("%s does not match expected synthetic bytes", field.Name())
	}
}
