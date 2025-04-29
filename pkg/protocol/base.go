package protocol

import (
	"context"
	"sync"
	"time"

	"proxyblob/pkg/transport"

	"github.com/google/uuid"
)

// PacketHandler processes protocol packets and manages connection lifecycle.
// Implementations must be safe for concurrent use by multiple goroutines.
type PacketHandler interface {
	// Start begins packet processing and listens on the specified address (listen only on proxy side)
	Start(string)

	// Stop gracefully terminates all connections and processing
	Stop()

	// ReceiveLoop processes incoming packets until stopped
	ReceiveLoop()

	// OnNew handles connection establishment request
	OnNew(uuid.UUID, []byte) byte

	// OnAck handles connection establishment acknowledgment
	OnAck(uuid.UUID, []byte) byte

	// OnData handles payload transfer for established connection
	OnData(uuid.UUID, []byte) byte

	// OnClose handles connection termination request
	OnClose(uuid.UUID, byte) byte
}

// BaseHandler implements common protocol functionality for proxy and agent.
// It provides connection management, packet routing, and error handling.
type BaseHandler struct {
	// transport handles underlying packet transmission
	transport transport.Transport

	// Connections maps UUIDs to active Connection objects
	Connections sync.Map

	// Ctx controls handler lifecycle
	Ctx context.Context

	// Cancel terminates handler context
	Cancel context.CancelFunc

	// PacketHandler routes packets to specific handlers
	PacketHandler
}

// NewBaseHandler creates a handler with specified context and transport.
// Uses background context if parent context is nil.
func NewBaseHandler(parentCtx context.Context, transport transport.Transport) *BaseHandler {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	return &BaseHandler{
		transport: transport,
		Ctx:       ctx,
		Cancel:    cancel,
	}
}

// ReceiveLoop processes incoming packets until context cancellation.
// Implements exponential backoff for consecutive errors.
func (h *BaseHandler) ReceiveLoop() {
	consecutiveErrors := 0
	maxConsecutiveErrors := 5

	for {
		select {
		case <-h.Ctx.Done():
			return
		default:
			data, errCode := h.transport.Receive(h.Ctx)
			if errCode != ErrNone {
				if h.transport.IsClosed(errCode) {
					h.Stop()
					return
				}

				if h.Ctx.Err() == nil && errCode != ErrTransportError {
					consecutiveErrors++
					if consecutiveErrors == maxConsecutiveErrors {
						return // Too many errors, just exit
					}
					time.Sleep(time.Duration(consecutiveErrors*50) * time.Millisecond)
				}
				continue
			}

			consecutiveErrors = 0

			if len(data) == 0 {
				continue
			}

			packet := Decode(data)
			if packet == nil {
				continue
			}

			errCode = h.handlePacket(packet)
			if errCode != ErrNone {
				if h.Ctx.Err() != nil && errCode == ErrConnectionClosed {
					continue
				}
				h.SendClose(packet.ConnectionID, errCode)
			}
		}
	}
}

// handlePacket routes packet to appropriate handler based on command.
// Returns error code indicating success or specific failure.
func (h *BaseHandler) handlePacket(packet *Packet) byte {
	switch packet.Command {
	case CmdNew:
		return h.PacketHandler.OnNew(packet.ConnectionID, packet.Data)
	case CmdAck:
		return h.PacketHandler.OnAck(packet.ConnectionID, packet.Data)
	case CmdData:
		return h.PacketHandler.OnData(packet.ConnectionID, packet.Data)
	case CmdClose:
		return h.PacketHandler.OnClose(packet.ConnectionID, packet.Data[0])
	default:
		return ErrInvalidCommand
	}
}

// SendNewConnection initiates key exchange for new connection.
// Returns error code indicating success or specific failure.
func (h *BaseHandler) SendNewConnection(connectionID uuid.UUID) byte {
	privateKey, publicKey := GenerateKeyPair()
	nonce := GenerateNonce()

	connObj, exists := h.Connections.Load(connectionID)
	if !exists {
		return ErrConnectionNotFound
	}
	conn := connObj.(*Connection)

	// Store nonce and private key for key derivation during ACK
	tempData := make([]byte, len(nonce)+len(privateKey))
	copy(tempData[:len(nonce)], nonce)
	copy(tempData[len(nonce):], privateKey)
	conn.SecretKey = tempData

	// Send nonce and public key to peer
	data := make([]byte, len(nonce)+len(publicKey))
	copy(data[:len(nonce)], nonce)
	copy(data[len(nonce):], publicKey)

	return h.sendPacket(CmdNew, connectionID, data)
}

// SendConnAck completes key exchange by deriving shared key.
// Returns error code indicating success or specific failure.
func (h *BaseHandler) SendConnAck(connectionID uuid.UUID) byte {
	connObj, exists := h.Connections.Load(connectionID)
	if !exists {
		return ErrConnectionNotFound
	}
	conn := connObj.(*Connection)

	privateKey, publicKey := GenerateKeyPair()

	// The first 24 bytes of SecretKey should be the nonce,
	// and the server's public key should be in the data field from OnNew
	serverData := conn.SecretKey
	nonce := serverData[:24]
	serverPublicKey := serverData[24:]

	symmetricKey, errCode := DeriveKey(privateKey, serverPublicKey, nonce)
	if errCode != ErrNone {
		return errCode
	}

	conn.SecretKey = symmetricKey

	// Send public key in CmdAck
	return h.sendPacket(CmdAck, connectionID, publicKey)
}

func (h *BaseHandler) SendData(connectionID uuid.UUID, data []byte) byte {
	// Get connection
	connObj, exists := h.Connections.Load(connectionID)
	if !exists {
		return ErrConnectionNotFound
	}
	conn := connObj.(*Connection)

	encrypted, errCode := Encrypt(conn.SecretKey, data)
	if errCode != ErrNone {
		return errCode
	}
	data = encrypted

	return h.sendPacket(CmdData, connectionID, data)
}

// SendClose sends a connection termination packet with an error code.
func (h *BaseHandler) SendClose(connectionID uuid.UUID, errCode byte) byte {
	connObj, exists := h.Connections.Load(connectionID)
	if !exists {
		return ErrConnectionNotFound
	}
	conn := connObj.(*Connection)

	conn.Close()
	return h.sendPacket(CmdClose, connectionID, []byte{errCode})
}

// sendPacket is the internal method that encodes and sends all packet types.
// It handles error checking and context checking.
func (h *BaseHandler) sendPacket(cmd byte, connectionID uuid.UUID, data []byte) byte {
	if h.Ctx.Err() != nil {
		return ErrHandlerStopped
	}

	packet := NewPacket(cmd, connectionID, data)
	if packet == nil {
		return ErrInvalidPacket
	}

	encoded := packet.Encode()
	if encoded == nil {
		return ErrInvalidPacket
	}

	errCode := h.transport.Send(h.Ctx, encoded)
	if errCode != ErrNone {
		// Check if this is a transport closure
		if h.transport.IsClosed(errCode) {
			return ErrTransportClosed
		}
		return ErrPacketSendFailed
	}

	return ErrNone
}

func (h *BaseHandler) CloseAllConnections() {
	h.Connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)

		// Only notify if not already closed
		select {
		case <-conn.Closed:
			// Already closed
		default:
			conn.Close()
		}

		return true
	})
}
