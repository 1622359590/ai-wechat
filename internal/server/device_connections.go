package server

import (
	"errors"
	"net"
	"sync"

	"github.com/1622359590/ai-wechat/internal/devices"
)

var (
	errDeviceConnectionCapacity = errors.New("authenticated device connection capacity reached")
	errInvalidDeviceConnection  = errors.New("invalid authenticated device connection")
)

type deviceConnection struct {
	generation uint64
	connection net.Conn
}

type deviceConnections struct {
	mu          sync.Mutex
	max         int
	next        uint64
	connections map[devices.ID]deviceConnection
}

func newDeviceConnections(max int) *deviceConnections {
	return &deviceConnections{
		max:         max,
		connections: make(map[devices.ID]deviceConnection),
	}
}

func (directory *deviceConnections) Register(deviceID devices.ID, connection net.Conn) (uint64, net.Conn, error) {
	if deviceID == "" || connection == nil {
		return 0, nil, errInvalidDeviceConnection
	}
	directory.mu.Lock()
	defer directory.mu.Unlock()

	current, exists := directory.connections[deviceID]
	if !exists && (directory.max <= 0 || len(directory.connections) >= directory.max) {
		return 0, nil, errDeviceConnectionCapacity
	}
	directory.next++
	if directory.next == 0 {
		directory.next++
	}
	directory.connections[deviceID] = deviceConnection{
		generation: directory.next,
		connection: connection,
	}
	return directory.next, current.connection, nil
}

func (directory *deviceConnections) Unregister(deviceID devices.ID, generation uint64) {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	current, exists := directory.connections[deviceID]
	if exists && current.generation == generation {
		delete(directory.connections, deviceID)
	}
}

func (directory *deviceConnections) CloseDevice(deviceID devices.ID) {
	directory.mu.Lock()
	current, exists := directory.connections[deviceID]
	if exists {
		delete(directory.connections, deviceID)
	}
	directory.mu.Unlock()

	if exists {
		_ = current.connection.Close()
	}
}

func (directory *deviceConnections) count() int {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	return len(directory.connections)
}
