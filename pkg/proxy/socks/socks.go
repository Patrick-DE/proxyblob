// Package proxy implements SOCKS5 proxy functionality.
// It provides a complete SOCKS5 implementation following RFC 1928, supporting
// CONNECT and UDP ASSOCIATE (BIND not implemented) commands with NoAuth authentication.
package proxy

import (
	"context"
	"slices"

	"proxyblob/pkg/protocol"
	"proxyblob/pkg/transport"

	"github.com/google/uuid"
)

// SocksHandler implements a SOCKS5 protocol handler.
// It processes authentication, commands, and data transfer between clients
// and remote targets. The handler is safe for concurrent use.
type SocksHandler struct {
	*protocol.BaseHandler
}

// NewSocksHandler creates a SOCKS5 handler with the given transport.
// The transport is used for sending and receiving protocol messages.
func NewSocksHandler(ctx context.Context, transport transport.Transport) *SocksHandler {
	handler := &SocksHandler{}
	handler.BaseHandler = protocol.NewBaseHandler(ctx, transport)
	handler.PacketHandler = handler
	return handler
}

// Start begins processing SOCKS5 requests. The address parameter is ignored
// as there are no listeners on the agent side.
func (h *SocksHandler) Start(address string) {
	go h.ReceiveLoop()
}

// Stop gracefully terminates the handler, closing all active connections
// and canceling the context.
func (h *SocksHandler) Stop() {
	h.CloseAllConnections()
	h.Cancel()
}

// OnNew handles new connection requests by initializing it and
// starting the SOCKS5 protocol flow.
func (h *SocksHandler) OnNew(connectionID uuid.UUID, data []byte) byte {
	// Check if the connection already exists
	if _, ok := h.Connections.Load(connectionID); ok {
		return protocol.ErrConnectionExists
	}

	// Create new connection
	conn := protocol.NewConnection(connectionID)
	h.Connections.Store(conn.ID, conn)

	// Process the server's nonce and public key from data
	if len(data) >= 24+32 {
		// Extract nonce and server public key
		nonce := data[:24]
		serverPublicKey := data[24 : 24+32]

		// Store temporary data for key derivation during ACK
		tmp := make([]byte, len(nonce)+len(serverPublicKey))
		copy(tmp[:len(nonce)], nonce)
		copy(tmp[len(nonce):], serverPublicKey)
		conn.SecretKey = tmp
	}

	// Send connection acknowledgment
	errCode := h.SendConnAck(connectionID)
	if errCode != protocol.ErrNone {
		return errCode
	}

	// Process the connection
	go h.processConnection(conn)
	return protocol.ErrNone
}

// OnAck reports ErrUnexpectedPacket as the agent only accepts incoming
// connections and does not initiate them.
func (h *SocksHandler) OnAck(connectionID uuid.UUID, data []byte) byte {
	return protocol.ErrUnexpectedPacket
}

// OnData processes incoming data for a connection.
// It decrypts the data and forwards it to the connection's read buffer.
func (h *SocksHandler) OnData(connectionID uuid.UUID, data []byte) byte {
	value, ok := h.Connections.Load(connectionID)
	if !ok {
		return protocol.ErrConnectionNotFound
	}
	conn := value.(*protocol.Connection)

	decrypted, errCode := protocol.Decrypt(conn.SecretKey, data)
	if errCode != protocol.ErrNone {
		h.SendClose(connectionID, protocol.ErrInvalidCrypto)
		return errCode
	}
	data = decrypted

	select {
	case <-h.Ctx.Done():
		return protocol.ErrConnectionClosed
	case conn.ReadBuffer <- data:
		return protocol.ErrNone

	}
}

// OnClose cleans up resources associated with a connection.
// It is safe to call multiple times.
func (h *SocksHandler) OnClose(connectionID uuid.UUID, errorCode byte) byte {
	value, ok := h.Connections.Load(connectionID)
	if !ok {
		return protocol.ErrNone // Connection already removed, nothing to do
	}
	conn := value.(*protocol.Connection)
	conn.Close()

	h.Connections.Delete(connectionID)
	return protocol.ErrNone
}

// processConnection handles the SOCKS5 protocol flow for a single connection.
// The flow consists of three phases:
//
//  1. Authentication method negotiation
//  2. Command processing (CONNECT, UDP ASSOCIATE)
//  3. Data transfer between client and target
func (h *SocksHandler) processConnection(conn *protocol.Connection) {
	// SOCKS protocol has 3 sequential phases
	errCode := h.handleAuthNegotiation(conn)
	if errCode != protocol.ErrNone {
		h.SendClose(conn.ID, errCode)
		return
	}

	errCode = h.handleCommand(conn)
	if errCode != protocol.ErrNone {
		h.SendClose(conn.ID, errCode)
		return
	}

	errCode = h.handleDataTransfer(conn)
	if errCode != protocol.ErrNone {
		h.SendClose(conn.ID, errCode)
		return
	}
}

// SendError sends a SOCKS5 error reply to the client.
// It maps internal error codes to SOCKS5 reply codes as defined in RFC 1928.
func (h *SocksHandler) SendError(conn *protocol.Connection, errCode byte) {
	// Default to general failure
	socksReplyCode := GeneralFailure

	// Map internal error codes to SOCKS reply codes
	switch errCode {
	case protocol.ErrNone:
		socksReplyCode = Succeeded
	case protocol.ErrNetworkUnreachable:
		socksReplyCode = NetworkUnreachable
	case protocol.ErrHostUnreachable:
		socksReplyCode = HostUnreachable
	case protocol.ErrConnectionRefused:
		socksReplyCode = ConnectionRefused
	case protocol.ErrTTLExpired:
		socksReplyCode = TTLExpired
	case protocol.ErrUnsupportedCommand:
		socksReplyCode = CommandNotSupported
	case protocol.ErrAddressNotSupported:
		socksReplyCode = AddressTypeNotSupported
	case protocol.ErrAuthFailed:
		socksReplyCode = NoAcceptableMethods
	}

	// Build and send error response
	response := []byte{Version5, socksReplyCode, 0x00, IPv4, 0, 0, 0, 0, 0, 0}
	h.SendData(conn.ID, response)
}

// handleAuthNegotiation processes the client's authentication method selection.
// Currently only the NO AUTHENTICATION REQUIRED (0x00) method is supported.
func (h *SocksHandler) handleAuthNegotiation(conn *protocol.Connection) byte {
	select {
	case methods := <-conn.ReadBuffer:
		// Currently we only support NoAuth (0x00)
		if !slices.Contains(methods, NoAuth) {
			h.SendError(conn, protocol.ErrAuthFailed)
			return protocol.ErrAuthFailed
		}

		// Send response
		errCode := h.SendData(conn.ID, []byte{Version5, NoAuth})
		if errCode != protocol.ErrNone {
			return errCode
		}

		return protocol.ErrNone

	case <-conn.Closed:
		return protocol.ErrConnectionClosed

	case <-h.Ctx.Done():
		return protocol.ErrHandlerStopped
	}
}

// handleCommand processes SOCKS5 commands from the client.
// Supported commands are:
//
//   - CONNECT (0x01): Establish TCP/IP stream connection
//   - UDP ASSOCIATE (0x03): UDP relay
//
// Unsupported commands are:
//
//   - BIND (0x02): TCP/IP port binding
func (h *SocksHandler) handleCommand(conn *protocol.Connection) byte {
	select {
	case cmdData := <-conn.ReadBuffer:
		// Validate command format
		if len(cmdData) < 4 {
			h.SendError(conn, protocol.ErrInvalidPacket)
			return protocol.ErrInvalidPacket
		}

		// Check SOCKS version
		if cmdData[0] != Version5 {
			h.SendError(conn, protocol.ErrInvalidSocksVersion)
			return protocol.ErrInvalidSocksVersion
		}

		var errCode byte
		switch cmdData[1] {
		case Connect:
			errCode = h.handleConnect(conn, cmdData)
		case Bind:
			errCode = h.handleBind(conn, cmdData)
		case UDPAssociate:
			errCode = h.handleUDPAssociate(conn)
		default:
			h.SendError(conn, protocol.ErrUnsupportedCommand)
			return protocol.ErrUnsupportedCommand
		}

		return errCode

	case <-conn.Closed:
		return protocol.ErrConnectionClosed
	case <-h.Ctx.Done():
		return protocol.ErrHandlerStopped
	}
}

// handleDataTransfer manages the flow of data between client and target.
// Each command handler implements its own data transfer mechanism.
func (h *SocksHandler) handleDataTransfer(conn *protocol.Connection) byte {
	// Each command handler takes care of data transfer
	// Just wait for connection to be closed
	<-conn.Closed
	return protocol.ErrNone
}
