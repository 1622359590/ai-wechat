package server

import (
	"bytes"
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
	"github.com/1622359590/ai-wechat/proto/schema"
)

func TestDeviceConnectionsKeepsDifferentDevices(t *testing.T) {
	directory := newDeviceConnections(2)
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()

	if _, replaced, err := directory.Register(testDeviceID(1), first); err != nil || replaced != nil {
		t.Fatalf("register first = replaced %v, error %v", replaced, err)
	}
	if _, replaced, err := directory.Register(testDeviceID(2), second); err != nil || replaced != nil {
		t.Fatalf("register second = replaced %v, error %v", replaced, err)
	}
	if got := directory.count(); got != 2 {
		t.Fatalf("connection count = %d, want 2", got)
	}
}

func TestDeviceConnectionsReplacesSameDevice(t *testing.T) {
	directory := newDeviceConnections(1)
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()

	firstGeneration, _, err := directory.Register(testDeviceID(1), first)
	if err != nil {
		t.Fatalf("register first: %v", err)
	}
	secondGeneration, replaced, err := directory.Register(testDeviceID(1), second)
	if err != nil {
		t.Fatalf("register replacement: %v", err)
	}
	if replaced != first {
		t.Fatalf("replaced connection = %v, want first connection", replaced)
	}
	if secondGeneration == firstGeneration {
		t.Fatal("replacement reused the old generation")
	}
	directory.Unregister(testDeviceID(1), firstGeneration)
	if got := directory.count(); got != 1 {
		t.Fatalf("old-generation unregister removed replacement; count = %d", got)
	}
	directory.Unregister(testDeviceID(1), secondGeneration)
	if got := directory.count(); got != 0 {
		t.Fatalf("replacement unregister count = %d, want 0", got)
	}
}

func TestDeviceConnectionsEnforcesMaximumCapacity(t *testing.T) {
	directory := newDeviceConnections(1)
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer first.Close()
	defer firstPeer.Close()
	defer second.Close()
	defer secondPeer.Close()

	if _, _, err := directory.Register(testDeviceID(1), first); err != nil {
		t.Fatalf("register first: %v", err)
	}
	if _, replaced, err := directory.Register(testDeviceID(2), second); !errors.Is(err, errDeviceConnectionCapacity) || replaced != nil {
		t.Fatalf("register over capacity = replaced %v, error %v", replaced, err)
	}
	if got := directory.count(); got != 1 {
		t.Fatalf("capacity failure changed count to %d", got)
	}
}

func TestDeviceConnectionsCloseDevice(t *testing.T) {
	directory := newDeviceConnections(1)
	connection, peer := net.Pipe()
	defer peer.Close()
	if _, _, err := directory.Register(testDeviceID(1), connection); err != nil {
		t.Fatalf("register: %v", err)
	}

	directory.CloseDevice(testDeviceID(1))
	if got := directory.count(); got != 0 {
		t.Fatalf("count after close = %d, want 0", got)
	}
	buffer := make([]byte, 1)
	if _, err := peer.Read(buffer); err == nil {
		t.Fatal("peer remained open after CloseDevice")
	}
}

func TestDeviceConnectionsConcurrentRegisterUnregister(t *testing.T) {
	directory := newDeviceConnections(8)
	var wait sync.WaitGroup
	for worker := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			connection, peer := net.Pipe()
			defer connection.Close()
			defer peer.Close()
			deviceID := testDeviceID(byte(worker%8 + 1))
			generation, replaced, err := directory.Register(deviceID, connection)
			if err != nil {
				t.Errorf("register: %v", err)
				return
			}
			if replaced != nil {
				_ = replaced.Close()
			}
			directory.Unregister(deviceID, generation)
		}()
	}
	wait.Wait()
	if got := directory.count(); got < 0 || got > 8 {
		t.Fatalf("final connection count = %d", got)
	}
}

func TestServerDoesNotActivateDeviceBeforeAuthResponseWriteSucceeds(t *testing.T) {
	files, err := schema.Load()
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	codec, err := protocol.NewCodec(files)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	deviceID := testDeviceID(9)
	service := New(Config{
		MaxBodyBytes:                1024 * 1024,
		UnauthenticatedReadTimeout:  time.Second,
		AuthenticatedReadTimeout:    time.Second,
		WriteTimeout:                time.Second,
		MaxAuthenticatedConnections: 1,
	}, gateway.NewHandler(codec, fixedDeviceAuthenticator{deviceID: deviceID}, gateway.NoopResponder{}))

	var input bytes.Buffer
	if err := frame.Write(&input, deviceAuthFixture(t), 1024*1024); err != nil {
		t.Fatalf("encode auth frame: %v", err)
	}
	connection := &blockedWriteConnection{
		reader:       input.Bytes(),
		writeStarted: make(chan struct{}),
		releaseWrite: make(chan struct{}),
	}
	done := make(chan struct{})
	service.wait.Add(1)
	go func() {
		service.serveConnection(connection, func() {})
		close(done)
	}()

	select {
	case <-connection.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("server did not attempt the auth response write")
	}
	if got := service.deviceConnections.count(); got != 0 {
		t.Fatalf("device activated before response write; count = %d", got)
	}
	close(connection.releaseWrite)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after failed response write")
	}
}

type fixedDeviceAuthenticator struct {
	deviceID devices.ID
}

func (authenticator fixedDeviceAuthenticator) Authenticate(context.Context, gateway.AuthRequest) (gateway.AuthResult, error) {
	return gateway.AuthResult{
		AccessToken: "synthetic-token",
		ExpiresAt:   time.Now().Add(time.Hour),
		DeviceID:    authenticator.deviceID,
	}, nil
}

type blockedWriteConnection struct {
	reader       []byte
	writeStarted chan struct{}
	releaseWrite chan struct{}
	once         sync.Once
}

func (connection *blockedWriteConnection) Read(buffer []byte) (int, error) {
	if len(connection.reader) == 0 {
		return 0, io.EOF
	}
	read := copy(buffer, connection.reader)
	connection.reader = connection.reader[read:]
	return read, nil
}
func (connection *blockedWriteConnection) Write([]byte) (int, error) {
	connection.once.Do(func() { close(connection.writeStarted) })
	<-connection.releaseWrite
	return 0, io.ErrClosedPipe
}
func (*blockedWriteConnection) Close() error { return nil }
func (*blockedWriteConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (*blockedWriteConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}
}
func (*blockedWriteConnection) SetDeadline(time.Time) error      { return nil }
func (*blockedWriteConnection) SetReadDeadline(time.Time) error  { return nil }
func (*blockedWriteConnection) SetWriteDeadline(time.Time) error { return nil }

func deviceAuthFixture(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile("../../proto/testdata/synthetic_frames.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures []struct {
		Case     string `json:"case"`
		FrameHex string `json:"frame_hex"`
	}
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	for _, fixture := range fixtures {
		if fixture.Case != "device-auth-normal" {
			continue
		}
		encoded, err := hex.DecodeString(fixture.FrameHex)
		if err != nil || len(encoded) < 4 {
			t.Fatalf("decode auth fixture: %v", err)
		}
		return encoded[4:]
	}
	t.Fatal("device auth fixture not found")
	return nil
}

func testDeviceID(last byte) devices.ID {
	const hex = "0123456789abcdef"
	return devices.ID("00000000-0000-0000-0000-00000000000" + string(hex[last&0x0f]))
}
