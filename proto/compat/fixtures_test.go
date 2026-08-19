package compat_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

var updateFixtures = flag.Bool("update", false, "update synthetic compatibility fixtures")

const fixturePath = "../testdata/synthetic_frames.json"

type syntheticFixture struct {
	Case         string `json:"case"`
	MessageType  string `json:"message_type"`
	MsgType      int32  `json:"msg_type"`
	FrameHex     string `json:"frame_hex"`
	UnknownScope string `json:"unknown_scope"`
}

type fixtureSpec struct {
	caseName     string
	messageType  string
	msgType      int32
	unknownScope string
	setFields    func(protoreflect.Message)
}

func TestSyntheticFramesMatchGolden(t *testing.T) {
	gotFixtures := buildSyntheticFixtures(t, compileRecovered(t))
	gotJSON, err := json.MarshalIndent(gotFixtures, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixtures: %v", err)
	}
	gotJSON = append(gotJSON, '\n')

	if *updateFixtures {
		if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(fixturePath, gotJSON, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	wantJSON, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture (run with -update after reviewing synthetic inputs): %v", err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("synthetic fixture differs from the checked-in golden file; review and run with -update")
	}
}

func TestFrameLengthPrefix(t *testing.T) {
	files := compileRecovered(t)
	transport := requireMessage(t, files, "TransportMessage")
	fixtures := readFixtures(t)
	if got, want := len(fixtures), 15; got != want {
		t.Fatalf("fixture count = %d, want %d", got, want)
	}

	for _, fixture := range fixtures {
		t.Run(fixture.Case, func(t *testing.T) {
			frame := decodeFrameHex(t, fixture.FrameHex)
			if len(frame) < 4 {
				t.Fatalf("frame length = %d, want at least 4", len(frame))
			}
			if got, want := binary.BigEndian.Uint32(frame[:4]), uint32(len(frame)-4); got != want {
				t.Fatalf("body length prefix = %d, want %d", got, want)
			}
			message := dynamicpb.NewMessage(transport)
			if err := proto.Unmarshal(frame[4:], message); err != nil {
				t.Fatalf("decode transport body: %v", err)
			}
			msgType := message.Get(transport.Fields().ByName("MsgType")).Enum()
			if got, want := int32(msgType), fixture.MsgType; got != want {
				t.Fatalf("MsgType = %d, want %d", got, want)
			}
		})
	}
}

func TestUnknownFieldRoundTrip(t *testing.T) {
	files := compileRecovered(t)
	transport := requireMessage(t, files, "TransportMessage")
	fixtures := readFixtures(t)

	for _, fixture := range fixtures {
		if fixture.UnknownScope == "none" {
			continue
		}
		t.Run(fixture.Case, func(t *testing.T) {
			frame := decodeFrameHex(t, fixture.FrameHex)
			outer := dynamicpb.NewMessage(transport)
			if err := proto.Unmarshal(frame[4:], outer); err != nil {
				t.Fatalf("decode transport body: %v", err)
			}

			switch fixture.UnknownScope {
			case "outer":
				requireUnknown127(t, outer.GetUnknown())
				roundTrip := marshalDeterministic(t, outer)
				reparsed := dynamicpb.NewMessage(transport)
				if err := proto.Unmarshal(roundTrip, reparsed); err != nil {
					t.Fatalf("reparse transport body: %v", err)
				}
				requireUnknown127(t, reparsed.GetUnknown())
			case "inner":
				contentField := transport.Fields().ByName("Content")
				content := outer.Get(contentField).Message().Interface()
				packed := new(anypb.Any)
				body, err := proto.Marshal(content)
				if err != nil {
					t.Fatalf("marshal Any: %v", err)
				}
				if err := proto.Unmarshal(body, packed); err != nil {
					t.Fatalf("decode Any: %v", err)
				}
				inner := dynamicpb.NewMessage(requireMessage(t, files, fixture.MessageType))
				if err := proto.Unmarshal(packed.Value, inner); err != nil {
					t.Fatalf("decode inner message: %v", err)
				}
				requireUnknown127(t, inner.GetUnknown())
				roundTrip := marshalDeterministic(t, inner)
				reparsed := dynamicpb.NewMessage(inner.Descriptor())
				if err := proto.Unmarshal(roundTrip, reparsed); err != nil {
					t.Fatalf("reparse inner message: %v", err)
				}
				requireUnknown127(t, reparsed.GetUnknown())
			default:
				t.Fatalf("unsupported unknown scope %q", fixture.UnknownScope)
			}
		})
	}
}

func buildSyntheticFixtures(t *testing.T, files *protoregistry.Files) []syntheticFixture {
	t.Helper()

	specs := []fixtureSpec{
		{caseName: "transport-normal", messageType: "TransportMessage", setFields: setTransportFields},
		{caseName: "transport-boundary", messageType: "TransportMessage"},
		{caseName: "transport-unknown", messageType: "TransportMessage", unknownScope: "outer", setFields: setTransportFields},
		{caseName: "device-auth-normal", messageType: "DeviceAuthReqMessage", msgType: 1010, setFields: func(message protoreflect.Message) {
			setEnum(message, "AuthType", 1)
			setString(message, "Credential", "synthetic-credential")
		}},
		{caseName: "device-auth-boundary", messageType: "DeviceAuthReqMessage", msgType: 1010},
		{caseName: "device-auth-unknown", messageType: "DeviceAuthReqMessage", msgType: 1010, unknownScope: "inner", setFields: func(message protoreflect.Message) {
			setEnum(message, "AuthType", 1)
			setString(message, "Credential", "synthetic-credential")
		}},
		{caseName: "heart-beat-normal", messageType: "HeartBeatMessage", msgType: 1001, setFields: func(message protoreflect.Message) {
			setString(message, "Imei", "synthetic-device")
			setString(message, "WeChatId", "synthetic-wechat")
		}},
		{caseName: "heart-beat-boundary", messageType: "HeartBeatMessage", msgType: 1001},
		{caseName: "heart-beat-unknown", messageType: "HeartBeatMessage", msgType: 1001, unknownScope: "inner", setFields: func(message protoreflect.Message) {
			setString(message, "Imei", "synthetic-device")
			setString(message, "WeChatId", "synthetic-wechat")
		}},
		{caseName: "friend-talk-normal", messageType: "FriendTalkNoticeMessage", msgType: 1024, setFields: setFriendTalkFields},
		{caseName: "friend-talk-boundary", messageType: "FriendTalkNoticeMessage", msgType: 1024},
		{caseName: "friend-talk-unknown", messageType: "FriendTalkNoticeMessage", msgType: 1024, unknownScope: "inner", setFields: setFriendTalkFields},
		{caseName: "talk-to-friend-normal", messageType: "TalkToFriendTaskMessage", msgType: 1070, setFields: setTalkToFriendFields},
		{caseName: "talk-to-friend-boundary", messageType: "TalkToFriendTaskMessage", msgType: 1070},
		{caseName: "talk-to-friend-unknown", messageType: "TalkToFriendTaskMessage", msgType: 1070, unknownScope: "inner", setFields: setTalkToFriendFields},
	}

	fixtures := make([]syntheticFixture, 0, len(specs))
	for index, spec := range specs {
		fixtures = append(fixtures, buildFixture(t, files, spec, int64(index+1)))
	}
	return fixtures
}

func buildFixture(t *testing.T, files *protoregistry.Files, spec fixtureSpec, sequence int64) syntheticFixture {
	t.Helper()

	transportDescriptor := requireMessage(t, files, "TransportMessage")
	outer := dynamicpb.NewMessage(transportDescriptor)
	unknownScope := spec.unknownScope
	if unknownScope == "" {
		unknownScope = "none"
	}

	if spec.messageType == "TransportMessage" {
		if spec.setFields != nil {
			spec.setFields(outer)
		}
		if unknownScope == "outer" {
			outer.SetUnknown(appendUnknown127(outer.GetUnknown()))
		}
	} else {
		inner := dynamicpb.NewMessage(requireMessage(t, files, spec.messageType))
		if spec.setFields != nil {
			spec.setFields(inner)
		}
		if unknownScope == "inner" {
			inner.SetUnknown(appendUnknown127(inner.GetUnknown()))
		}
		innerBody := marshalDeterministic(t, inner)
		packed := &anypb.Any{
			TypeUrl: "type.googleapis.com/" + string(inner.Descriptor().FullName()),
			Value:   innerBody,
		}
		setInt64(outer.ProtoReflect(), "Id", sequence)
		setString(outer.ProtoReflect(), "AccessToken", "synthetic-token")
		setEnum(outer.ProtoReflect(), "MsgType", protoreflect.EnumNumber(spec.msgType))
		outer.ProtoReflect().Set(transportDescriptor.Fields().ByName("Content"), protoreflect.ValueOfMessage(packed.ProtoReflect()))
		setInt64(outer.ProtoReflect(), "RefMessageId", sequence+100)
	}

	body := marshalDeterministic(t, outer)
	frame := make([]byte, 4, len(body)+4)
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	frame = append(frame, body...)

	return syntheticFixture{
		Case:         spec.caseName,
		MessageType:  spec.messageType,
		MsgType:      spec.msgType,
		FrameHex:     hex.EncodeToString(frame),
		UnknownScope: unknownScope,
	}
}

func setTransportFields(message protoreflect.Message) {
	setInt64(message, "Id", 1)
	setString(message, "AccessToken", "synthetic-token")
	setInt64(message, "RefMessageId", 101)
}

func setFriendTalkFields(message protoreflect.Message) {
	setString(message, "WeChatId", "synthetic-wechat")
	setString(message, "FriendId", "synthetic-friend")
	setEnum(message, "ContentType", 1)
	setBytes(message, "Content", []byte("synthetic-content"))
	setInt64(message, "MsgId", 201)
	setInt64(message, "msgSvrId", 202)
	setString(message, "Ext", "synthetic-ext")
	setInt64(message, "CreateTime", 1)
	setString(message, "NickName", "synthetic-name")
}

func setTalkToFriendFields(message protoreflect.Message) {
	setString(message, "WeChatId", "synthetic-wechat")
	setString(message, "FriendId", "synthetic-friend")
	setEnum(message, "ContentType", 1)
	setBytes(message, "Content", []byte("synthetic-content"))
	setString(message, "Remark", "synthetic-remark")
	setInt64(message, "MsgId", 301)
	setBool(message, "Immediate", true)
}

func setString(message protoreflect.Message, name protoreflect.Name, value string) {
	message.Set(message.Descriptor().Fields().ByName(name), protoreflect.ValueOfString(value))
}

func setBytes(message protoreflect.Message, name protoreflect.Name, value []byte) {
	message.Set(message.Descriptor().Fields().ByName(name), protoreflect.ValueOfBytes(value))
}

func setInt64(message protoreflect.Message, name protoreflect.Name, value int64) {
	message.Set(message.Descriptor().Fields().ByName(name), protoreflect.ValueOfInt64(value))
}

func setEnum(message protoreflect.Message, name protoreflect.Name, value protoreflect.EnumNumber) {
	message.Set(message.Descriptor().Fields().ByName(name), protoreflect.ValueOfEnum(value))
}

func setBool(message protoreflect.Message, name protoreflect.Name, value bool) {
	message.Set(message.Descriptor().Fields().ByName(name), protoreflect.ValueOfBool(value))
}

func marshalDeterministic(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		t.Fatalf("marshal %s: %v", message.ProtoReflect().Descriptor().FullName(), err)
	}
	return body
}

func appendUnknown127(body []byte) []byte {
	body = protowire.AppendTag(body, 127, protowire.VarintType)
	return protowire.AppendVarint(body, 1)
}

func requireUnknown127(t *testing.T, body []byte) {
	t.Helper()
	for len(body) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(body)
		if tagLength < 0 {
			t.Fatalf("decode unknown tag: %v", protowire.ParseError(tagLength))
		}
		body = body[tagLength:]
		valueLength := protowire.ConsumeFieldValue(number, wireType, body)
		if valueLength < 0 {
			t.Fatalf("decode unknown value: %v", protowire.ParseError(valueLength))
		}
		if number == 127 && wireType == protowire.VarintType {
			value, consumed := protowire.ConsumeVarint(body[:valueLength])
			if consumed > 0 && value == 1 {
				return
			}
		}
		body = body[valueLength:]
	}
	t.Fatal("unknown field 127 varint 1 was not preserved")
}

func readFixtures(t *testing.T) []syntheticFixture {
	t.Helper()
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures []syntheticFixture
	if err := json.Unmarshal(body, &fixtures); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	return fixtures
}

func decodeFrameHex(t *testing.T, value string) []byte {
	t.Helper()
	frame, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode frame hex: %v", err)
	}
	return frame
}

func TestSyntheticInputsUsePublicSafeNames(t *testing.T) {
	files := compileRecovered(t)
	transport := requireMessage(t, files, "TransportMessage")
	fixtures := readFixtures(t)
	cases := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		cases = append(cases, fixture.Case)
		frame := decodeFrameHex(t, fixture.FrameHex)
		outer := dynamicpb.NewMessage(transport)
		if err := proto.Unmarshal(frame[4:], outer); err != nil {
			t.Fatalf("%s: decode transport: %v", fixture.Case, err)
		}
		requirePublicSafeFields(t, outer.ProtoReflect())

		if fixture.MessageType != "TransportMessage" {
			packed := new(anypb.Any)
			content := outer.Get(transport.Fields().ByName("Content")).Message().Interface()
			body, err := proto.Marshal(content)
			if err != nil {
				t.Fatalf("%s: marshal Any: %v", fixture.Case, err)
			}
			if err := proto.Unmarshal(body, packed); err != nil {
				t.Fatalf("%s: decode Any: %v", fixture.Case, err)
			}
			wantTypeURL := "type.googleapis.com/" + protoPackage + "." + fixture.MessageType
			if packed.TypeUrl != wantTypeURL {
				t.Errorf("%s: Any type URL = %q, want %q", fixture.Case, packed.TypeUrl, wantTypeURL)
			}
			inner := dynamicpb.NewMessage(requireMessage(t, files, fixture.MessageType))
			if err := proto.Unmarshal(packed.Value, inner); err != nil {
				t.Fatalf("%s: decode inner: %v", fixture.Case, err)
			}
			requirePublicSafeFields(t, inner.ProtoReflect())
		}
	}
	sort.Strings(cases)
	for index := 1; index < len(cases); index++ {
		if cases[index] == cases[index-1] {
			t.Fatalf("duplicate fixture case %q", cases[index])
		}
	}
}

func requirePublicSafeFields(t *testing.T, message protoreflect.Message) {
	t.Helper()

	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch field.Kind() {
		case protoreflect.StringKind:
			text := value.String()
			if text != "" && !strings.HasPrefix(text, "synthetic-") {
				t.Errorf("%s contains non-synthetic string", field.FullName())
			}
		case protoreflect.BytesKind:
			body := value.Bytes()
			if len(body) > 0 && !bytes.HasPrefix(body, []byte("synthetic-")) {
				t.Errorf("%s contains non-synthetic bytes", field.FullName())
			}
		case protoreflect.MessageKind:
			if field.Message().FullName() != "google.protobuf.Any" {
				requirePublicSafeFields(t, value.Message())
			}
		}
		return true
	})
}
