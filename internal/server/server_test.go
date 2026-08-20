package server_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

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
	peerIP net.IP
}

func (authenticator *acceptAuth) Authenticate(_ context.Context, request gateway.AuthRequest) (gateway.AuthResult, error) {
	authenticator.peerIP = append(net.IP(nil), request.PeerIP...)
	return gateway.AuthResult{AccessToken: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
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
