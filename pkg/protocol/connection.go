package protocol

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// ConnectionState tracks the lifecycle of a proxy connection
type ConnectionState int

const (
	// StateNew indicates a pending connection awaiting establishment
	StateNew ConnectionState = iota

	// StateConnected indicates an active connection with data flow
	StateConnected

	// StateClosed indicates a terminated connection
	StateClosed
)

// Connection manages a proxy connection between client and target.
// It is safe for concurrent use by multiple goroutines.
type Connection struct {
	// ID uniquely identifies the connection
	ID uuid.UUID

	// State indicates current connection lifecycle phase
	State ConnectionState

	// Conn holds the network connection (optional)
	Conn net.Conn

	// ReadBuffer receives data from the remote endpoint
	ReadBuffer chan []byte

	// Closed signals connection termination
	Closed chan struct{}

	// CreatedAt records connection creation time
	CreatedAt time.Time

	// LastActivity tracks most recent data transfer
	LastActivity time.Time

	// SecretKey holds encryption key for secure communication
	SecretKey []byte
}

// NewConnection creates a connection with specified ID.
// Initializes channels and sets initial timestamps.
func NewConnection(id uuid.UUID) *Connection {
	return &Connection{
		ID:           id,
		State:        StateNew,
		ReadBuffer:   make(chan []byte),
		Closed:       make(chan struct{}),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
}

// Close terminates the connection and its resources.
// Safe to call multiple times. Returns ErrNone on success.
func (c *Connection) Close() byte {
	if c.State == StateClosed {
		return ErrNone
	}

	c.State = StateClosed

	select {
	case <-c.Closed:
		// Already closed
	default:
		close(c.Closed)
	}

	if c.Conn != nil {
		err := c.Conn.Close()
		if err != nil {
			return ErrConnectionClosed
		}
	}

	return ErrNone
}
