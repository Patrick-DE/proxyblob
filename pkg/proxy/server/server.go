// Package proxy implements a SOCKS proxy server.
// It accepts client connections and forwards traffic through transport channels
// to remote agents. The server manages connection lifecycle, encryption, and
// bidirectional data transfer.
package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"proxyblob/pkg/protocol"
	"proxyblob/pkg/transport"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ProxyServer implements a SOCKS proxy server that forwards traffic transparently.
// It accepts client connections and manages the protocol flow between clients and
// remote agents.
type ProxyServer struct {
	// BaseHandler provides common protocol functionality
	*protocol.BaseHandler

	// Listener accepts incoming TCP connections
	Listener net.Listener
}

// NewProxyServer creates a proxy server instance with the given transport.
// The transport is used for communication with remote agents.
func NewProxyServer(ctx context.Context, transport transport.Transport) *ProxyServer {
	server := &ProxyServer{}
	server.BaseHandler = protocol.NewBaseHandler(ctx, transport)
	server.PacketHandler = server
	return server
}

// Start begins listening for client connections on the specified address.
// It launches background goroutines for accepting connections and processing
// protocol messages. If listening fails, the server is stopped.
func (s *ProxyServer) Start(address string) {
	var err error
	s.Listener, err = net.Listen("tcp", address)
	if err != nil {
		log.Error().Err(err).Str("addr", address).Msg("Failed to listen on address")
		s.Stop()
		return
	}

	go s.ReceiveLoop()
	go s.acceptLoop()
}

// Stop gracefully terminates the proxy server by closing all active
// connections, canceling the handler's context, and stopping the listener.
func (s *ProxyServer) Stop() {
	s.CloseAllConnections()
	s.Cancel()
	if s.Listener != nil {
		s.Listener.Close()
	}
}

// OnNew handles new connection requests. The server is the only one initiating
// connections, so this always returns ErrUnexpectedPacket.
func (s *ProxyServer) OnNew(connectionID uuid.UUID, data []byte) byte {
	return protocol.ErrUnexpectedPacket
}

// OnAck processes connection acknowledgments from agents. It derives a shared
// encryption key using the agent's public key and updates the connection state.
// Returns an error code indicating success or failure.
func (s *ProxyServer) OnAck(connectionID uuid.UUID, data []byte) byte {
	value, ok := s.Connections.Load(connectionID)
	if !ok {
		return protocol.ErrConnectionNotFound
	}
	conn := value.(*protocol.Connection)

	if conn.State != protocol.StateNew {
		return protocol.ErrInvalidState
	}

	clientPublicKey := data[:32]

	// At this point,conn.SecretKey contains [24B nonce][32B server private key]
	nonce := conn.SecretKey[:24]
	serverPrivateKey := conn.SecretKey[24:]

	// Derive the shared key
	symmetricKey, errCode := protocol.DeriveKey(serverPrivateKey, clientPublicKey, nonce)
	if errCode != protocol.ErrNone {
		return errCode
	}

	// Store the symmetric key
	conn.SecretKey = symmetricKey

	// Signal connection acknowledgment (non-blocking)
	conn.ReadBuffer <- []byte{}
	conn.State = protocol.StateConnected
	conn.LastActivity = time.Now()
	return protocol.ErrNone
}

// OnData processes data received from agents. It decrypts the data and forwards
// it to the client. Returns an error code indicating success or failure.
func (s *ProxyServer) OnData(connectionID uuid.UUID, data []byte) byte {
	value, ok := s.Connections.Load(connectionID)
	if !ok {
		return protocol.ErrConnectionNotFound
	}
	conn := value.(*protocol.Connection)
	conn.LastActivity = time.Now()

	decrypted, errCode := protocol.Decrypt(conn.SecretKey, data)
	if errCode != protocol.ErrNone {
		return errCode
	}
	data = decrypted

	// Writing to client is handled by forwardToClient goroutine
	select {
	case <-s.Ctx.Done():
		return protocol.ErrConnectionClosed
	case conn.ReadBuffer <- data:
		return protocol.ErrNone

	}
}

// OnClose handles connection termination from agents. It cleans up the
// connection state.
func (s *ProxyServer) OnClose(connectionID uuid.UUID, errorCode byte) byte {
	value, ok := s.Connections.Load(connectionID)
	if !ok {
		return protocol.ErrNone // Connection already removed, nothing to do
	}
	conn := value.(*protocol.Connection)
	conn.Close()
	s.Connections.Delete(connectionID)
	return errorCode
}

// acceptLoop accepts incoming TCP connections and spawns goroutines to handle
// each one. It continues until the context is canceled or a non-temporary
// error occurs.
func (s *ProxyServer) acceptLoop() {
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				if s.Ctx.Err() != nil {
					return // Exit quietly on shutdown
				}

				if _, ok := err.(net.Error); ok {
					continue // Retry on temporary network errors
				}
				return
			}

			go s.handleConnection(conn)
		}
	}
}

// handleConnection processes a new client connection by:
//   - Generating a unique connection ID
//   - Initiating connection with remote agent
//   - Setting up bidirectional data forwarding
//   - Managing connection lifecycle and cleanup
func (s *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	connID := uuid.New()
	proxyConn := protocol.NewConnection(connID)
	s.Connections.Store(proxyConn.ID, proxyConn)

	// 1. Initiate connection with the agent
	errCode := s.SendNewConnection(connID)
	if errCode != protocol.ErrNone {
		s.Connections.Delete(connID)
		return
	}

	// 2. Wait for agent acknowledgment with timeout
	select {
	case <-s.Ctx.Done():
		s.SendClose(connID, protocol.ErrHandlerStopped)
		s.Connections.Delete(connID)
		return
	case <-time.After(5 * time.Second):
		s.SendClose(connID, protocol.ErrTransportTimeout)
		s.Connections.Delete(connID)
		return
	case <-proxyConn.ReadBuffer:
		// Agent acknowledged connection
	}

	// 3. Connection established, start bidirectional forwarding
	proxyConn.State = protocol.StateConnected
	proxyConn.LastActivity = time.Now()

	errCh := make(chan byte, 2)
	go s.forwardToAgent(clientConn, proxyConn, errCh)
	go s.forwardToClient(clientConn, proxyConn, errCh)

	// Wait for error, closed connection, or context cancellation
	select {
	case <-s.Ctx.Done():
		// Context cancelled, closing connection
	case <-proxyConn.Closed:
		// Connection closed by agent
	case errCode := <-errCh:
		if errCode != protocol.ErrNone && errCode != protocol.ErrConnectionClosed {
			log.Error().Str("msg", ErrToString[errCode]).Msg("Connection error")
		}
	}

	// Clean up the connection
	s.SendClose(connID, protocol.ErrConnectionClosed)
	proxyConn.Close()
	s.Connections.Delete(connID)
}

// forwardToAgent reads data from the client connection and forwards it to
// the remote agent. It continues until an error occurs or the connection
// is closed.
func (s *ProxyServer) forwardToAgent(clientConn net.Conn, proxyConn *protocol.Connection, errCh chan<- byte) {
	buffer := make([]byte, 64*1024)

	for {
		// Check early termination conditions
		if proxyConn.State == protocol.StateClosed {
			return
		}

		select {
		case <-s.Ctx.Done():
			return
		case <-proxyConn.Closed:
			return
		default:
			// Continue processing
		}

		n, err := clientConn.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				errCh <- protocol.ErrConnectionClosed
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				errCh <- protocol.ErrTransportTimeout
			} else {
				// General network error
				errCh <- protocol.ErrNetworkUnreachable
			}
			return
		}

		errCode := s.SendData(proxyConn.ID, buffer[:n])
		if errCode != protocol.ErrNone {
			errCh <- protocol.ErrPacketSendFailed
			return
		}

		proxyConn.LastActivity = time.Now()
	}
}

// forwardToClient reads data from the connection's read buffer and forwards
// it to the client. It continues until an error occurs or the connection
// is closed.
func (s *ProxyServer) forwardToClient(clientConn net.Conn, proxyConn *protocol.Connection, errCh chan<- byte) {
	for {
		select {
		case <-s.Ctx.Done():
			return
		case <-proxyConn.Closed:
			return
		case data := <-proxyConn.ReadBuffer:
			proxyConn.LastActivity = time.Now()
			_, err := clientConn.Write(data)
			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- protocol.ErrConnectionClosed
				} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					errCh <- protocol.ErrTransportTimeout
				} else {
					// General network error
					errCh <- protocol.ErrNetworkUnreachable
				}
				return
			}
		}
	}
}
