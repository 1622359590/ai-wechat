// Package protocol maps recovered TransportMessage envelopes to their payloads.
package protocol

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

const packageName = "Jubo.JuLiao.IM.Wx.Proto"

var (
	ErrMissingContent         = errors.New("transport content is missing")
	ErrTypeMismatch           = errors.New("message type and Any type URL do not match")
	ErrUnsupportedMessageType = errors.New("message type is unsupported")
	ErrInvalidReply           = errors.New("talk-to-friend reply is invalid")
	ErrInvalidAuthResult      = errors.New("device authentication result is invalid")
)

type messageBinding struct {
	typeURL    string
	descriptor protoreflect.MessageDescriptor
}

type Codec struct {
	transport protoreflect.MessageDescriptor
	any       protoreflect.MessageDescriptor
	bindings  map[int32]messageBinding
}

type Decoded struct {
	ID           int64
	AccessToken  string
	RefMessageID int64
	MsgType      int32
	TypeURL      string
	Transport    *dynamicpb.Message
	Payload      *dynamicpb.Message
}

type Reply struct {
	ID           int64
	RefMessageID int64
	AccessToken  string
	WeChatID     string
	FriendID     string
	ContentType  int32
	Content      []byte
	Remark       string
	MsgID        int64
	Immediate    bool
}

func NewCodec(files *protoregistry.Files) (*Codec, error) {
	transport, err := findMessage(files, packageName+".TransportMessage")
	if err != nil {
		return nil, err
	}
	anyDescriptor, err := findMessage(files, "google.protobuf.Any")
	if err != nil {
		return nil, err
	}

	bindings := make(map[int32]messageBinding, 5)
	for msgType, name := range map[int32]string{
		1001: "HeartBeatMessage",
		1010: "DeviceAuthReqMessage",
		1011: "DeviceAuthRspMessage",
		1024: "FriendTalkNoticeMessage",
		1070: "TalkToFriendTaskMessage",
	} {
		descriptor, err := findMessage(files, protoreflect.FullName(packageName+"."+name))
		if err != nil {
			return nil, err
		}
		bindings[msgType] = messageBinding{
			typeURL:    "type.googleapis.com/" + string(descriptor.FullName()),
			descriptor: descriptor,
		}
	}
	return &Codec{transport: transport, any: anyDescriptor, bindings: bindings}, nil
}

func (codec *Codec) Decode(body []byte) (*Decoded, error) {
	transport := dynamicpb.NewMessage(codec.transport)
	if err := proto.Unmarshal(body, transport); err != nil {
		return nil, fmt.Errorf("decode TransportMessage: %w", err)
	}
	fields := codec.transport.Fields()
	msgType := int32(transport.Get(fields.ByName("MsgType")).Enum())
	decoded := &Decoded{
		ID:           transport.Get(fields.ByName("Id")).Int(),
		AccessToken:  transport.Get(fields.ByName("AccessToken")).String(),
		RefMessageID: transport.Get(fields.ByName("RefMessageId")).Int(),
		MsgType:      msgType,
		Transport:    transport,
	}

	if msgType == 0 && !transport.Has(fields.ByName("Content")) {
		return decoded, nil
	}
	binding, ok := codec.bindings[msgType]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedMessageType, msgType)
	}
	contentField := fields.ByName("Content")
	if !transport.Has(contentField) {
		return nil, ErrMissingContent
	}
	packed := transport.Get(contentField).Message()
	anyFields := codec.any.Fields()
	typeURL := packed.Get(anyFields.ByName("type_url")).String()
	if typeURL != binding.typeURL {
		return nil, fmt.Errorf("%w: message type %d", ErrTypeMismatch, msgType)
	}
	payload := dynamicpb.NewMessage(binding.descriptor)
	if err := proto.Unmarshal(packed.Get(anyFields.ByName("value")).Bytes(), payload); err != nil {
		return nil, fmt.Errorf("decode %s: %w", binding.descriptor.FullName(), err)
	}
	decoded.TypeURL = typeURL
	decoded.Payload = payload
	return decoded, nil
}

func (codec *Codec) EncodeDeviceAuth(accessToken string) ([]byte, error) {
	if accessToken == "" {
		return nil, ErrInvalidAuthResult
	}
	binding := codec.bindings[1011]
	payload := dynamicpb.NewMessage(binding.descriptor)
	setString(payload, binding.descriptor.Fields().ByName("AccessToken"), accessToken)
	payloadBody, err := marshal(payload)
	if err != nil {
		return nil, err
	}

	packed := dynamicpb.NewMessage(codec.any)
	anyFields := codec.any.Fields()
	packed.Set(anyFields.ByName("type_url"), protoreflect.ValueOfString(binding.typeURL))
	packed.Set(anyFields.ByName("value"), protoreflect.ValueOfBytes(payloadBody))

	transport := dynamicpb.NewMessage(codec.transport)
	transportFields := codec.transport.Fields()
	transport.Set(transportFields.ByName("MsgType"), protoreflect.ValueOfEnum(1011))
	transport.Set(transportFields.ByName("Content"), protoreflect.ValueOfMessage(packed))
	return marshal(transport)
}

func (codec *Codec) EncodeTalkToFriend(reply Reply) ([]byte, error) {
	if reply.WeChatID == "" || reply.FriendID == "" || len(reply.Content) == 0 {
		return nil, ErrInvalidReply
	}
	binding := codec.bindings[1070]
	payload := dynamicpb.NewMessage(binding.descriptor)
	fields := binding.descriptor.Fields()
	setString(payload, fields.ByName("WeChatId"), reply.WeChatID)
	setString(payload, fields.ByName("FriendId"), reply.FriendID)
	payload.Set(fields.ByName("ContentType"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(reply.ContentType)))
	payload.Set(fields.ByName("Content"), protoreflect.ValueOfBytes(reply.Content))
	setString(payload, fields.ByName("Remark"), reply.Remark)
	payload.Set(fields.ByName("MsgId"), protoreflect.ValueOfInt64(reply.MsgID))
	payload.Set(fields.ByName("Immediate"), protoreflect.ValueOfBool(reply.Immediate))
	payloadBody, err := marshal(payload)
	if err != nil {
		return nil, err
	}

	packed := dynamicpb.NewMessage(codec.any)
	anyFields := codec.any.Fields()
	packed.Set(anyFields.ByName("type_url"), protoreflect.ValueOfString(binding.typeURL))
	packed.Set(anyFields.ByName("value"), protoreflect.ValueOfBytes(payloadBody))

	transport := dynamicpb.NewMessage(codec.transport)
	transportFields := codec.transport.Fields()
	transport.Set(transportFields.ByName("Id"), protoreflect.ValueOfInt64(reply.ID))
	setString(transport, transportFields.ByName("AccessToken"), reply.AccessToken)
	transport.Set(transportFields.ByName("MsgType"), protoreflect.ValueOfEnum(1070))
	transport.Set(transportFields.ByName("Content"), protoreflect.ValueOfMessage(packed))
	transport.Set(transportFields.ByName("RefMessageId"), protoreflect.ValueOfInt64(reply.RefMessageID))
	return marshal(transport)
}

func findMessage(files *protoregistry.Files, name protoreflect.FullName) (protoreflect.MessageDescriptor, error) {
	descriptor, err := files.FindDescriptorByName(name)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", name, err)
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is %T, not a message", name, descriptor)
	}
	return message, nil
}

func setString(message *dynamicpb.Message, field protoreflect.FieldDescriptor, value string) {
	if value != "" {
		message.Set(field, protoreflect.ValueOfString(value))
	}
}

func marshal(message proto.Message) ([]byte, error) {
	return (proto.MarshalOptions{Deterministic: true}).Marshal(message)
}
