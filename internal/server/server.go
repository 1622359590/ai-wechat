// Package server owns TCP connection lifecycle around the gateway handler.
package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1622359590/ai-wechat/internal/frame"
	"github.com/1622359590/ai-wechat/internal/gateway"
)

type MessageHandler interface {
	Handle(context.Context, *gateway.Session, []byte) ([]byte, error)
}

type Config struct {
	MaxBodyBytes               uint32
	UnauthenticatedReadTimeout time.Duration
	AuthenticatedReadTimeout   time.Duration
	WriteTimeout               time.Duration
}

type Server struct {
	config  Config
	handler MessageHandler

	ready       atomic.Bool
	closing     atomic.Bool
	mu          sync.Mutex
	listener    net.Listener
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
}

func New(config Config, handler MessageHandler) *Server {
	return &Server{
		config:      config,
		handler:     handler,
		connections: make(map[net.Conn]struct{}),
	}
}

func (server *Server) Ready() bool {
	return server.ready.Load()
}

func (server *Server) Serve(listener net.Listener) error {
	server.mu.Lock()
	if server.listener != nil {
		server.mu.Unlock()
		return errors.New("server is already serving")
	}
	server.listener = listener
	server.ready.Store(true)
	server.mu.Unlock()

	for {
		connection, err := listener.Accept()
		if err != nil {
			server.ready.Store(false)
			if server.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		server.mu.Lock()
		server.connections[connection] = struct{}{}
		server.wait.Add(1)
		server.mu.Unlock()
		go server.serveConnection(connection)
	}
}

func (server *Server) serveConnection(connection net.Conn) {
	defer func() {
		_ = connection.Close()
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		server.wait.Done()
	}()

	session := gateway.NewSession()
	decoder := frame.NewDecoder(connection, server.config.MaxBodyBytes)
	ctx := context.Background()
	for {
		readTimeout := server.config.UnauthenticatedReadTimeout
		if session.Authenticated() {
			readTimeout = server.config.AuthenticatedReadTimeout
		}
		if err := connection.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return
		}
		body, err := decoder.Read()
		if err != nil {
			return
		}
		response, err := server.handler.Handle(ctx, session, body)
		if err != nil {
			return
		}
		if len(response) == 0 {
			continue
		}
		if err := connection.SetWriteDeadline(time.Now().Add(server.config.WriteTimeout)); err != nil {
			return
		}
		if err := frame.Write(connection, response, server.config.MaxBodyBytes); err != nil {
			return
		}
	}
}

func (server *Server) Shutdown(ctx context.Context) error {
	server.closing.Store(true)
	server.ready.Store(false)

	server.mu.Lock()
	listener := server.listener
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}

	done := make(chan struct{})
	go func() {
		server.wait.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
