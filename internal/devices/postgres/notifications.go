package postgres

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices"
	"github.com/jackc/pgx/v5"
)

const adminEventChannel = "device_admin_events"

type AdminEventListener struct {
	dsn      string
	onDevice func(devices.ID)

	connectionMu sync.Mutex
	connection   *pgx.Conn

	eventMu   sync.Mutex
	cursor    int64
	seen      map[int64]struct{}
	malformed atomic.Uint64
}

func NewAdminEventListener(ctx context.Context, dsn string, onDevice func(devices.ID)) (*AdminEventListener, error) {
	if dsn == "" || onDevice == nil {
		return nil, errors.New("admin event listener configuration is invalid")
	}
	connection, err := connectAdminEvents(ctx, dsn)
	if err != nil {
		return nil, listenerUnavailable(ctx)
	}
	var cursor int64
	if err := connection.QueryRow(ctx, "SELECT COALESCE(max(id), 0) FROM device_admin_events").Scan(&cursor); err != nil {
		_ = connection.Close(ctx)
		return nil, listenerUnavailable(ctx)
	}
	return &AdminEventListener{
		dsn:        dsn,
		onDevice:   onDevice,
		connection: connection,
		cursor:     cursor,
		seen:       make(map[int64]struct{}),
	}, nil
}

func (listener *AdminEventListener) Run(ctx context.Context) error {
	defer listener.closeConnection()
	for {
		if ctx.Err() != nil {
			return nil
		}
		connection := listener.currentConnection()
		if connection == nil {
			if err := listener.reconnect(ctx); err != nil {
				return err
			}
			continue
		}

		notification, err := connection.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			listener.dropConnection(connection)
			continue
		}
		listener.handlePayload(notification.Payload)
	}
}

func (listener *AdminEventListener) MalformedCount() uint64 {
	return listener.malformed.Load()
}

func (listener *AdminEventListener) Close() {
	listener.closeConnection()
}

func (listener *AdminEventListener) backendPID() uint32 {
	listener.connectionMu.Lock()
	defer listener.connectionMu.Unlock()
	if listener.connection == nil {
		return 0
	}
	return listener.connection.PgConn().PID()
}

func connectAdminEvents(ctx context.Context, dsn string) (*pgx.Conn, error) {
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := connection.Exec(ctx, "LISTEN "+adminEventChannel); err != nil {
		_ = connection.Close(ctx)
		return nil, err
	}
	return connection, nil
}

func (listener *AdminEventListener) reconnect(ctx context.Context) error {
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}

		connection, err := connectAdminEvents(ctx, listener.dsn)
		if err == nil {
			if err = listener.catchUp(ctx, connection); err == nil {
				listener.connectionMu.Lock()
				listener.connection = connection
				listener.connectionMu.Unlock()
				return nil
			}
			_ = connection.Close(context.Background())
		}
		if ctx.Err() != nil {
			return nil
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (listener *AdminEventListener) catchUp(ctx context.Context, connection *pgx.Conn) error {
	listener.eventMu.Lock()
	cursor := listener.cursor
	listener.eventMu.Unlock()

	rows, err := connection.Query(ctx, `SELECT id, device_id::text
		FROM device_admin_events WHERE id > $1 ORDER BY id`, cursor)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var eventID int64
		var deviceID devices.ID
		if err := rows.Scan(&eventID, &deviceID); err != nil {
			return err
		}
		listener.deliver(eventID, deviceID)
	}
	return rows.Err()
}

func (listener *AdminEventListener) handlePayload(payload string) {
	idText, deviceText, found := strings.Cut(payload, ":")
	if !found || strings.Contains(deviceText, ":") || !validUUID(deviceText) {
		listener.malformed.Add(1)
		return
	}
	eventID, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || eventID <= 0 {
		listener.malformed.Add(1)
		return
	}
	listener.deliver(eventID, devices.ID(deviceText))
}

func (listener *AdminEventListener) deliver(eventID int64, deviceID devices.ID) {
	listener.eventMu.Lock()
	if _, exists := listener.seen[eventID]; exists {
		listener.eventMu.Unlock()
		return
	}
	listener.seen[eventID] = struct{}{}
	if eventID > listener.cursor {
		listener.cursor = eventID
	}
	listener.eventMu.Unlock()
	listener.onDevice(deviceID)
}

func (listener *AdminEventListener) currentConnection() *pgx.Conn {
	listener.connectionMu.Lock()
	defer listener.connectionMu.Unlock()
	return listener.connection
}

func (listener *AdminEventListener) dropConnection(connection *pgx.Conn) {
	listener.connectionMu.Lock()
	if listener.connection == connection {
		listener.connection = nil
	}
	listener.connectionMu.Unlock()
	_ = connection.Close(context.Background())
}

func (listener *AdminEventListener) closeConnection() {
	listener.connectionMu.Lock()
	connection := listener.connection
	listener.connection = nil
	listener.connectionMu.Unlock()
	if connection != nil {
		_ = connection.Close(context.Background())
	}
}

func listenerUnavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("device admin event listener is unavailable")
}
