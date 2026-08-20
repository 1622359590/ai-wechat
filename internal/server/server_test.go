package server_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/1622359590/ai-wechat/internal/frame"
	"github.com/1622359590/ai-wechat/internal/gateway"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/internal/server"
	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestServerRunsSyntheticFlowAndIsolatesBadConnection(t *testing.T) {
	codec := serverCodec(t)
	authenticator := &acceptAuth{}
	handler := gateway.NewHandler(codec, authenticator, syntheticResponder{})
	service := server.New(server.Config{
		MaxBodyBytes:               1024 * 1024,
		UnauthenticatedReadTimeout: time.Second,
		AuthenticatedReadTimeout:   time.Second,
		WriteTimeout:               time.Second,
	}, handler)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- service.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})

	bad, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial malformed connection: %v", err)
	}
	if _, err := bad.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("write malformed frame: %v", err)
	}
	_ = bad.Close()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial valid connection: %v", err)
	}
	defer connection.Close()
	if err := frame.Write(connection, serverFixtureBody(t, "device-auth-normal"), 1024*1024); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	decoder := frame.NewDecoder(connection, 1024*1024)
	authBody, err := decoder.Read()
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	authResponse, err := codec.Decode(authBody)
	if err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	if authResponse.MsgType != 1011 {
		t.Fatalf("auth response MsgType = %d, want 1011", authResponse.MsgType)
	}
	if authenticator.peerIP == nil || !authenticator.peerIP.IsLoopback() {
		t.Fatalf("authenticator peer IP = %v, want loopback", authenticator.peerIP)
	}

	if err := frame.Write(connection, serverFixtureBody(t, "friend-talk-normal"), 1024*1024); err != nil {
		t.Fatalf("write friend talk: %v", err)
	}
	replyBody, err := decoder.Read()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	reply, err := codec.Decode(replyBody)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if reply.MsgType != 1070 {
		t.Fatalf("reply MsgType = %d, want 1070", reply.MsgType)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("serve returned error: %v", err)
	}
	if service.Ready() {
		t.Fatal("server stayed ready after shutdown")
	}
}

func TestServerReplacesSameDeviceOnlyAfterAuthenticationResponse(t *testing.T) {
	deviceID := devices.ID("00000000-0000-0000-0000-000000000041")
	service, listener := startDeviceServer(t, &acceptAuth{deviceIDs: []devices.ID{deviceID, deviceID}}, 2)
	first := authenticateConnection(t, listener.Addr().String())
	defer first.Close()
	second := authenticateConnection(t, listener.Addr().String())
	defer second.Close()

	assertConnectionClosed(t, first)
	assertConnectionOpen(t, second)
	service.DisconnectDevice(deviceID)
	assertConnectionClosed(t, second)
}

func TestServerKeepsDifferentDevicesOnline(t *testing.T) {
	firstID := devices.ID("00000000-0000-0000-0000-000000000042")
	secondID := devices.ID("00000000-0000-0000-0000-000000000043")
	service, listener := startDeviceServer(t, &acceptAuth{deviceIDs: []devices.ID{firstID, secondID}}, 2)
	first := authenticateConnection(t, listener.Addr().String())
	defer first.Close()
	second := authenticateConnection(t, listener.Addr().String())
	defer second.Close()

	service.DisconnectDevice(firstID)
	assertConnectionClosed(t, first)
	assertConnectionOpen(t, second)
	service.DisconnectDevice(secondID)
	assertConnectionClosed(t, second)
}

func TestServerClosesCapacityOverflowWithoutEvictingExistingDevice(t *testing.T) {
	firstID := devices.ID("00000000-0000-0000-0000-000000000044")
	secondID := devices.ID("00000000-0000-0000-0000-000000000045")
	service, listener := startDeviceServer(t, &acceptAuth{deviceIDs: []devices.ID{firstID, secondID}}, 1)
	first := authenticateConnection(t, listener.Addr().String())
	defer first.Close()
	second := authenticateConnection(t, listener.Addr().String())
	defer second.Close()

	assertConnectionClosed(t, second)
	assertConnectionOpen(t, first)
	service.DisconnectDevice(firstID)
	assertConnectionClosed(t, first)
}

func TestServerRejectsExcessUnauthenticatedConnections(t *testing.T) {
	service := server.New(server.Config{
		MaxBodyBytes:                  1024,
		UnauthenticatedReadTimeout:    time.Hour,
		AuthenticatedReadTimeout:      time.Hour,
		WriteTimeout:                  time.Second,
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerIP:       1,
		MaxAuthenticatedConnections:   1,
	}, rejectingHandler{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = service.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})

	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	assertConnectionClosed(t, second)

	_ = first.Close()
	third, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	defer third.Close()
	assertConnectionOpen(t, third)
}

func TestServerReleasesUnauthenticatedCapacityAfterLegacyAuthResponse(t *testing.T) {
	service := server.New(server.Config{
		MaxBodyBytes:                  1024 * 1024,
		UnauthenticatedReadTimeout:    time.Hour,
		AuthenticatedReadTimeout:      time.Hour,
		WriteTimeout:                  time.Second,
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerIP:       1,
		MaxAuthenticatedConnections:   1,
	}, gateway.NewHandler(serverCodec(t), &acceptAuth{}, gateway.NoopResponder{}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = service.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})

	first := authenticateConnection(t, listener.Addr().String())
	defer first.Close()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial after legacy auth: %v", err)
	}
	defer second.Close()
	assertConnectionOpen(t, second)
}

func startDeviceServer(t *testing.T, authenticator gateway.Authenticator, max int) (*server.Server, net.Listener) {
	t.Helper()
	service := server.New(server.Config{
		MaxBodyBytes:                1024 * 1024,
		UnauthenticatedReadTimeout:  time.Second,
		AuthenticatedReadTimeout:    time.Second,
		WriteTimeout:                time.Second,
		MaxAuthenticatedConnections: max,
	}, gateway.NewHandler(serverCodec(t), authenticator, gateway.NoopResponder{}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = service.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})
	return service, listener
}

func authenticateConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := frame.Write(connection, serverFixtureBody(t, "device-auth-normal"), 1024*1024); err != nil {
		connection.Close()
		t.Fatalf("write auth: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		connection.Close()
		t.Fatalf("set auth deadline: %v", err)
	}
	if _, err := frame.NewDecoder(connection, 1024*1024).Read(); err != nil {
		connection.Close()
		t.Fatalf("read auth response: %v", err)
	}
	return connection
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set closed deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("connection did not close before deadline: %v", err)
	}
}

func assertConnectionOpen(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set open deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("unexpected data on idle connection")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("connection closed unexpectedly: %v", err)
	}
}

func TestServerClosesConnectionAcceptedDuringShutdown(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()

	service := server.New(server.Config{
		MaxBodyBytes:               1024,
		UnauthenticatedReadTimeout: time.Hour,
		AuthenticatedReadTimeout:   time.Hour,
		WriteTimeout:               time.Second,
	}, rejectingHandler{})
	listener := &shutdownOnAcceptListener{
		connection: serverConnection,
		shutdown: func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := service.Shutdown(ctx); err != nil {
				t.Errorf("shutdown: %v", err)
			}
		},
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- service.Serve(listener) }()

	if err := <-serveErr; err != nil {
		t.Fatalf("serve returned error: %v", err)
	}
	if err := clientConnection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := clientConnection.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("read after shutdown error = %v, want EOF", err)
	}
}

type shutdownOnAcceptListener struct {
	connection net.Conn
	shutdown   func()
	closed     bool
}

func (listener *shutdownOnAcceptListener) Accept() (net.Conn, error) {
	if listener.closed {
		return nil, net.ErrClosed
	}
	listener.shutdown()
	return listener.connection, nil
}

func (listener *shutdownOnAcceptListener) Close() error {
	listener.closed = true
	return nil
}

func (listener *shutdownOnAcceptListener) Addr() net.Addr {
	return testAddress("shutdown-listener")
}

type testAddress string

func (address testAddress) Network() string { return "test" }
func (address testAddress) String() string  { return string(address) }

type rejectingHandler struct{}

func (rejectingHandler) Handle(context.Context, *gateway.Session, []byte) ([]byte, error) {
	return nil, errors.New("unexpected message")
}

type acceptAuth struct {
	mu        sync.Mutex
	peerIP    net.IP
	deviceIDs []devices.ID
	calls     int
}

func (authenticator *acceptAuth) Authenticate(_ context.Context, request gateway.AuthRequest) (gateway.AuthResult, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.peerIP = append(net.IP(nil), request.PeerIP...)
	var deviceID devices.ID
	if authenticator.calls < len(authenticator.deviceIDs) {
		deviceID = authenticator.deviceIDs[authenticator.calls]
	}
	authenticator.calls++
	return gateway.AuthResult{AccessToken: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour), DeviceID: deviceID}, nil
}

type syntheticResponder struct{}

func (syntheticResponder) OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error) {
	return &protocol.Reply{
		ID: 700, RefMessageID: 600, AccessToken: "synthetic-token",
		WeChatID: "synthetic-wechat", FriendID: "synthetic-friend",
		ContentType: 1, Content: []byte("synthetic-reply"), MsgID: 701,
	}, nil
}

func serverCodec(t *testing.T) *protocol.Codec {
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

func serverFixtureBody(t *testing.T, caseName string) []byte {
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
		if fixture.Case == caseName {
			frameBytes, err := hex.DecodeString(fixture.FrameHex)
			if err != nil || len(frameBytes) < 4 {
				t.Fatalf("decode fixture: %v", err)
			}
			return frameBytes[4:]
		}
	}
	t.Fatal(errors.New("fixture not found"))
	return nil
}
