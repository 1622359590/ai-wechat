package deploy_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/frame"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

const smokeMaxBodyBytes = 1024 * 1024

func TestRegistryAuthenticationLifecycle(t *testing.T) {
	address := requiredEnvironment(t, "SMOKE_GATEWAY_ADDRESS")
	credentials := []string{
		requiredEnvironment(t, "SMOKE_ACTIVE_ONE"),
		requiredEnvironment(t, "SMOKE_ACTIVE_TWO"),
	}
	disabled := requiredEnvironment(t, "SMOKE_DISABLED")
	expired := requiredEnvironment(t, "SMOKE_EXPIRED")
	unknown := requiredEnvironment(t, "SMOKE_UNKNOWN")

	files, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocol.NewCodec(files)
	if err != nil {
		t.Fatal(err)
	}

	first := authenticate(t, address, files, codec, credentials[0])
	defer first.Close()
	second := authenticate(t, address, files, codec, credentials[1])
	defer second.Close()

	replacement := authenticate(t, address, files, codec, credentials[0])
	defer replacement.Close()
	assertClosed(t, first, "replaced connection")

	for _, credential := range []string{disabled, expired, unknown} {
		if outcome := rejectedOutcome(t, address, files, credential); outcome != "rejected" {
			t.Fatalf("rejection outcome = %q", outcome)
		}
	}

	malformed, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := malformed.Write([]byte{0, 0, 0, 0}); err != nil {
		malformed.Close()
		t.Fatal(err)
	}
	assertClosed(t, malformed, "malformed frame")
	_ = malformed.Close()

	connections := make([]net.Conn, 0, 6)
	for range 6 {
		connection, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	assertAtLeastOneClosed(t, connections, "per-IP admission limit")
}

func authenticate(t *testing.T, address string, files *protoregistry.Files, codec *protocol.Codec, credential string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	body := encodeAuthRequest(t, files, credential)
	if err := frame.Write(connection, body, smokeMaxBodyBytes); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	response, err := frame.NewDecoder(connection, smokeMaxBodyBytes).Read()
	if err != nil {
		connection.Close()
		t.Fatalf("authentication rejected: %v", err)
	}
	decoded, err := codec.Decode(response)
	if err != nil || decoded.MsgType != 1011 {
		connection.Close()
		t.Fatalf("invalid authentication response")
	}
	fields := decoded.Payload.Descriptor().Fields()
	if decoded.Payload.Get(fields.ByName("AccessToken")).String() == "" {
		connection.Close()
		t.Fatalf("authentication response has no token")
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}

func rejectedOutcome(t *testing.T, address string, files *protoregistry.Files, credential string) string {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := frame.Write(connection, encodeAuthRequest(t, files, credential), smokeMaxBodyBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := frame.NewDecoder(connection, smokeMaxBodyBytes).Read(); err == nil {
		return "accepted"
	}
	return "rejected"
}

func assertClosed(t *testing.T, connection net.Conn, label string) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	_, err := connection.Read(value[:])
	var networkError net.Error
	if err == nil || (errors.As(err, &networkError) && networkError.Timeout()) {
		t.Fatalf("%s remained open", label)
	}
}

func assertAtLeastOneClosed(t *testing.T, connections []net.Conn, label string) {
	t.Helper()
	results := make(chan bool, len(connections))
	deadline := time.Now().Add(2 * time.Second)
	for _, connection := range connections {
		go func(connection net.Conn) {
			if err := connection.SetReadDeadline(deadline); err != nil {
				results <- false
				return
			}
			var value [1]byte
			_, err := connection.Read(value[:])
			var networkError net.Error
			results <- err != nil && !(errors.As(err, &networkError) && networkError.Timeout())
		}(connection)
	}
	for range connections {
		if <-results {
			return
		}
	}
	t.Fatalf("%s rejected no connection", label)
}

func encodeAuthRequest(t *testing.T, files *protoregistry.Files, credential string) []byte {
	t.Helper()
	authDescriptor := messageDescriptor(t, files, "Jubo.JuLiao.IM.Wx.Proto.DeviceAuthReqMessage")
	auth := dynamicpb.NewMessage(authDescriptor)
	authFields := authDescriptor.Fields()
	auth.Set(authFields.ByName("AuthType"), protoreflect.ValueOfEnum(1))
	auth.Set(authFields.ByName("Credential"), protoreflect.ValueOfString(credential))
	authBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}

	anyDescriptor := messageDescriptor(t, files, "google.protobuf.Any")
	packed := dynamicpb.NewMessage(anyDescriptor)
	anyFields := anyDescriptor.Fields()
	packed.Set(anyFields.ByName("type_url"), protoreflect.ValueOfString("type.googleapis.com/"+string(authDescriptor.FullName())))
	packed.Set(anyFields.ByName("value"), protoreflect.ValueOfBytes(authBody))

	transportDescriptor := messageDescriptor(t, files, "Jubo.JuLiao.IM.Wx.Proto.TransportMessage")
	transport := dynamicpb.NewMessage(transportDescriptor)
	transportFields := transportDescriptor.Fields()
	transport.Set(transportFields.ByName("Id"), protoreflect.ValueOfInt64(time.Now().UnixNano()))
	transport.Set(transportFields.ByName("MsgType"), protoreflect.ValueOfEnum(1010))
	transport.Set(transportFields.ByName("Content"), protoreflect.ValueOfMessage(packed))
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func messageDescriptor(t *testing.T, files *protoregistry.Files, name protoreflect.FullName) protoreflect.MessageDescriptor {
	t.Helper()
	descriptor, err := files.FindDescriptorByName(name)
	if err != nil {
		t.Fatal(err)
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatal(fmt.Errorf("%s is not a message", name))
	}
	return message
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s is not configured", name)
	}
	return value
}
