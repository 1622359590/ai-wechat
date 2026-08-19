package compat_test

import (
	"testing"

	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const protoPackage = "Jubo.JuLiao.IM.Wx.Proto"

func compileRecovered(t *testing.T) *protoregistry.Files {
	t.Helper()
	registry, err := schema.Load()
	if err != nil {
		t.Fatalf("load recovered schema: %v", err)
	}
	return registry
}

func requireMessage(t *testing.T, files *protoregistry.Files, name string) protoreflect.MessageDescriptor {
	t.Helper()

	descriptor, err := files.FindDescriptorByName(protoreflect.FullName(protoPackage + "." + name))
	if err != nil {
		t.Fatalf("find message %s: %v", name, err)
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("descriptor %s is %T, not a message", name, descriptor)
	}
	return message
}

func TestRecoveredSchema(t *testing.T) {
	files := compileRecovered(t)

	type fieldContract struct {
		name     protoreflect.Name
		number   protoreflect.FieldNumber
		kind     protoreflect.Kind
		typeName protoreflect.FullName
	}
	field := func(name protoreflect.Name, number protoreflect.FieldNumber, kind protoreflect.Kind, typeName ...protoreflect.FullName) fieldContract {
		contract := fieldContract{name: name, number: number, kind: kind}
		if len(typeName) == 1 {
			contract.typeName = typeName[0]
		}
		return contract
	}
	contracts := map[string][]fieldContract{
		"TransportMessage": {
			field("Id", 1, protoreflect.Int64Kind),
			field("AccessToken", 2, protoreflect.StringKind),
			field("MsgType", 3, protoreflect.EnumKind, protoPackage+".EnumMsgType"),
			field("Content", 4, protoreflect.MessageKind, "google.protobuf.Any"),
			field("RefMessageId", 5, protoreflect.Int64Kind),
		},
		"DeviceAuthReqMessage": {
			field("AuthType", 1, protoreflect.EnumKind, protoPackage+".DeviceAuthReqMessage.EnumAuthType"),
			field("Credential", 2, protoreflect.StringKind),
		},
		"HeartBeatMessage": {
			field("Imei", 1, protoreflect.StringKind),
			field("WeChatId", 2, protoreflect.StringKind),
		},
		"FriendTalkNoticeMessage": {
			field("WeChatId", 1, protoreflect.StringKind),
			field("FriendId", 3, protoreflect.StringKind),
			field("ContentType", 5, protoreflect.EnumKind, protoPackage+".EnumContentType"),
			field("Content", 6, protoreflect.BytesKind),
			field("MsgId", 7, protoreflect.Int64Kind),
			field("msgSvrId", 8, protoreflect.Int64Kind),
			field("Ext", 9, protoreflect.StringKind),
			field("CreateTime", 10, protoreflect.Int64Kind),
			field("NickName", 11, protoreflect.StringKind),
		},
		"TalkToFriendTaskMessage": {
			field("WeChatId", 1, protoreflect.StringKind),
			field("FriendId", 2, protoreflect.StringKind),
			field("ContentType", 3, protoreflect.EnumKind, protoPackage+".EnumContentType"),
			field("Content", 4, protoreflect.BytesKind),
			field("Remark", 8, protoreflect.StringKind),
			field("MsgId", 9, protoreflect.Int64Kind),
			field("Immediate", 10, protoreflect.BoolKind),
		},
	}

	for messageName, expectedFields := range contracts {
		message := requireMessage(t, files, messageName)
		if got, want := message.ParentFile().Package(), protoreflect.FullName(protoPackage); got != want {
			t.Errorf("%s package = %q, want %q", messageName, got, want)
		}
		if got, want := message.ParentFile().Syntax(), protoreflect.Proto3; got != want {
			t.Errorf("%s syntax = %s, want %s", messageName, got, want)
		}
		if got, want := message.Fields().Len(), len(expectedFields); got != want {
			t.Errorf("%s field count = %d, want %d", messageName, got, want)
		}
		for _, expected := range expectedFields {
			field := message.Fields().ByName(expected.name)
			if field == nil {
				t.Errorf("%s missing field %s", messageName, expected.name)
				continue
			}
			if field.Number() != expected.number || field.Kind() != expected.kind {
				t.Errorf("%s.%s = field %d/%s, want %d/%s", messageName, expected.name, field.Number(), field.Kind(), expected.number, expected.kind)
			}
			if expected.typeName != "" {
				var got protoreflect.FullName
				switch field.Kind() {
				case protoreflect.EnumKind:
					got = field.Enum().FullName()
				case protoreflect.MessageKind:
					got = field.Message().FullName()
				}
				if got != expected.typeName {
					t.Errorf("%s.%s type = %q, want %q", messageName, expected.name, got, expected.typeName)
				}
			}
		}
	}

	requireEnumValues(t, files, "EnumMsgType", map[string]int32{
		"UnknownMsg":       0,
		"HeartBeatReq":     1001,
		"DeviceAuthReq":    1010,
		"FriendTalkNotice": 1024,
		"TalkToFriendTask": 1070,
	})
	requireEnumValues(t, files, "EnumContentType", map[string]int32{
		"UnknownContent": 0,
		"Text":           1,
	})

	auth := requireMessage(t, files, "DeviceAuthReqMessage").Enums().ByName("EnumAuthType")
	if auth == nil {
		t.Fatal("DeviceAuthReqMessage.EnumAuthType is missing")
	}
	requireValues(t, auth, map[string]int32{
		"Default":      0,
		"DeviceCode":   1,
		"Username":     2,
		"InternalCode": 3,
	})
}

func requireEnumValues(t *testing.T, files *protoregistry.Files, name string, expected map[string]int32) {
	t.Helper()

	descriptor, err := files.FindDescriptorByName(protoreflect.FullName(protoPackage + "." + name))
	if err != nil {
		t.Fatalf("find enum %s: %v", name, err)
	}
	enum, ok := descriptor.(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatalf("descriptor %s is %T, not an enum", name, descriptor)
	}
	requireValues(t, enum, expected)
}

func requireValues(t *testing.T, enum protoreflect.EnumDescriptor, expected map[string]int32) {
	t.Helper()

	for name, number := range expected {
		value := enum.Values().ByName(protoreflect.Name(name))
		if value == nil {
			t.Errorf("%s missing value %s", enum.FullName(), name)
			continue
		}
		if got := int32(value.Number()); got != number {
			t.Errorf("%s.%s = %d, want %d", enum.FullName(), name, got, number)
		}
	}
}
