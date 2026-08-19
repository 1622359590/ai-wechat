package compat_test

import (
	"context"
	"testing"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const protoPackage = "Jubo.JuLiao.IM.Wx.Proto"

var recoveredProtoFiles = []string{
	"TransportMessage.proto",
	"DeviceAuthReq.proto",
	"HeartBeat.proto",
	"FriendTalkNotice.proto",
	"TalkToFriendTask.proto",
}

func compileRecovered(t *testing.T) *protoregistry.Files {
	t.Helper()

	resolver := protocompile.WithStandardImports(&protocompile.SourceResolver{
		ImportPaths: []string{"../minimal"},
	})
	compiler := protocompile.Compiler{Resolver: resolver}
	compiled, err := compiler.Compile(context.Background(), recoveredProtoFiles...)
	if err != nil {
		t.Fatalf("compile recovered schema: %v", err)
	}

	registry := new(protoregistry.Files)
	for _, file := range compiled {
		if err := registry.RegisterFile(file); err != nil {
			t.Fatalf("register %s: %v", file.Path(), err)
		}
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
		name   protoreflect.Name
		number protoreflect.FieldNumber
		kind   protoreflect.Kind
	}
	contracts := map[string][]fieldContract{
		"TransportMessage": {
			{"Id", 1, protoreflect.Int64Kind},
			{"AccessToken", 2, protoreflect.StringKind},
			{"MsgType", 3, protoreflect.EnumKind},
			{"Content", 4, protoreflect.MessageKind},
			{"RefMessageId", 5, protoreflect.Int64Kind},
		},
		"DeviceAuthReqMessage": {
			{"AuthType", 1, protoreflect.EnumKind},
			{"Credential", 2, protoreflect.StringKind},
		},
		"HeartBeatMessage": {
			{"Imei", 1, protoreflect.StringKind},
			{"WeChatId", 2, protoreflect.StringKind},
		},
		"FriendTalkNoticeMessage": {
			{"WeChatId", 1, protoreflect.StringKind},
			{"FriendId", 3, protoreflect.StringKind},
			{"ContentType", 5, protoreflect.EnumKind},
			{"Content", 6, protoreflect.BytesKind},
			{"MsgId", 7, protoreflect.Int64Kind},
			{"msgSvrId", 8, protoreflect.Int64Kind},
			{"Ext", 9, protoreflect.StringKind},
			{"CreateTime", 10, protoreflect.Int64Kind},
			{"NickName", 11, protoreflect.StringKind},
		},
		"TalkToFriendTaskMessage": {
			{"WeChatId", 1, protoreflect.StringKind},
			{"FriendId", 2, protoreflect.StringKind},
			{"ContentType", 3, protoreflect.EnumKind},
			{"Content", 4, protoreflect.BytesKind},
			{"Remark", 8, protoreflect.StringKind},
			{"MsgId", 9, protoreflect.Int64Kind},
			{"Immediate", 10, protoreflect.BoolKind},
		},
	}

	for messageName, expectedFields := range contracts {
		message := requireMessage(t, files, messageName)
		if got, want := message.ParentFile().Package(), protoreflect.FullName(protoPackage); got != want {
			t.Errorf("%s package = %q, want %q", messageName, got, want)
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
		}
	}

	requireEnumValues(t, files, "EnumMsgType", map[string]int32{
		"UnknownMsg":       0,
		"HeartBeatReq":     1001,
		"DeviceAuthReq":    1010,
		"FriendTalkNotice": 1024,
		"TalkToFriendTask": 1070,
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
