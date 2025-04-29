// Package transport provides interfaces and implementations for communication
// between proxy components. It abstracts the underlying transport mechanism
// and ensures reliable data transfer with proper error handling.
package transport

import (
	"context"
)

// Error codes for transport operations.
const (
	ErrNone            byte = 0 // Operation completed successfully
	ErrContextCanceled byte = 2 // Context was canceled during operation

	// Transport errors (20-29)
	ErrTransportClosed  byte = 20 // Transport is permanently closed
	ErrTransportTimeout byte = 21 // Operation exceeded time limit
	ErrTransportError   byte = 22 // Generic transport error
)

// Transport defines an interface for bidirectional packet communication.
// Implementations must ensure reliable delivery and proper error handling.
// All methods are safe for concurrent use.
type Transport interface {
	// Send transmits data to the recipient. It blocks until the data is sent
	// or the context is canceled. Returns an error code indicating success
	// or specific failure reason.
	Send(ctx context.Context, data []byte) byte

	// Receive waits for and returns available data. It blocks until data
	// is available or the context is canceled. Returns the received data
	// and an error code indicating success or failure reason.
	Receive(ctx context.Context) ([]byte, byte)

	// IsClosed reports whether the transport is permanently closed.
	// The error code parameter helps determine the closure reason.
	IsClosed(byte) bool
}
