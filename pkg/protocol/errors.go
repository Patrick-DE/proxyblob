// Package protocol defines the communication protocol between proxy and agent.
package protocol

import (
	"proxyblob/pkg/transport"
)

// Protocol error codes for agent-server communication.
// Uses byte values to minimize binary size and network traffic.
const (
	// General errors (0-9)
	ErrNone            byte = 0 // Operation completed successfully
	ErrInvalidCommand  byte = 1 // Command type is not recognized
	ErrContextCanceled byte = 2 // Context canceled

	// Connection errors (10-19)
	ErrConnectionClosed   byte = 10 // Connection was terminated
	ErrConnectionNotFound byte = 11 // Connection ID does not exist
	ErrConnectionExists   byte = 12 // Connection ID already in use
	ErrInvalidState       byte = 13 // Connection in wrong state for operation
	ErrPacketSendFailed   byte = 14 // Packet transmission failed
	ErrHandlerStopped     byte = 15 // Protocol handler is not running
	ErrUnexpectedPacket   byte = 16 // Received unexpected packet type

	// Transport errors (20-29)
	ErrTransportClosed  byte = transport.ErrTransportClosed  // Transport layer terminated
	ErrTransportTimeout byte = transport.ErrTransportTimeout // Transport operation timed out
	ErrTransportError   byte = transport.ErrTransportError   // Transport operation failed

	// SOCKS errors (30-39)
	ErrInvalidSocksVersion byte = 30 // Unsupported SOCKS protocol version
	ErrUnsupportedCommand  byte = 31 // SOCKS command not implemented
	ErrHostUnreachable     byte = 32 // Target host not accessible
	ErrConnectionRefused   byte = 33 // Target refused connection
	ErrNetworkUnreachable  byte = 34 // Network path not accessible
	ErrAddressNotSupported byte = 35 // Address format not supported
	ErrTTLExpired          byte = 36 // Time-to-live exceeded
	ErrGeneralSocksFailure byte = 37 // Unspecified SOCKS failure
	ErrAuthFailed          byte = 38 // Authentication rejected

	// Packet errors (40-49)
	ErrInvalidPacket byte = 40 // Malformed packet structure
	ErrInvalidCrypto byte = 41 // Cryptographic operation failed
)
