package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"proxyblob/pkg/protocol"
)

// handleConnect processes the SOCKS5 CONNECT command.
// It establishes a TCP connection to the requested target and
// sets up bidirectional data transfer between client and target.
//
// The CONNECT command format is:
//
//	+-----+-----+-----+------+----------+----------+
//	| VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
//	+-----+-----+-----+------+----------+----------+
//	|  1  |  1  |  1  |  1   | Variable |    2     |
//
// Returns an error code indicating success or specific failure reason.
func (h *SocksHandler) handleConnect(conn *protocol.Connection, cmdData []byte) byte {
	if len(cmdData) < 4 {
		// Send malformed request response
		response := []byte{Version5, GeneralFailure, 0x00, IPv4, 0, 0, 0, 0, 0, 0}
		h.SendData(conn.ID, response)
		return protocol.ErrAddressNotSupported
	}

	// Parse target address
	target, errCode := ParseAddress(cmdData[3:])
	if errCode != protocol.ErrNone {
		h.SendError(conn, errCode)
		return errCode
	}

	// Establish TCP connection to target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// Map network error to appropriate SOCKS5 error code
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			errCode = protocol.ErrTTLExpired
		} else if opErr, ok := err.(*net.OpError); ok {
			if opErr.Op == "dial" {
				errCode = protocol.ErrNetworkUnreachable
			} else if opErr.Op == "read" {
				errCode = protocol.ErrHostUnreachable
			}
		} else if _, ok := err.(*net.DNSError); ok {
			errCode = protocol.ErrHostUnreachable
		} else {
			errCode = protocol.ErrConnectionRefused
		}

		// Send failure response with appropriate code
		h.SendError(conn, errCode)
		return errCode
	}

	// Send success response
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	response := make([]byte, 10)
	response[0] = Version5
	response[1] = Succeeded
	response[2] = 0x00
	response[3] = IPv4
	copy(response[4:8], localAddr.IP.To4())
	binary.BigEndian.PutUint16(response[8:], uint16(localAddr.Port))

	errCode = h.SendData(conn.ID, response)
	if errCode != protocol.ErrNone {
		targetConn.Close()
		return protocol.ErrPacketSendFailed
	}

	// Store connection and set state
	conn.Conn = targetConn
	conn.State = protocol.StateConnected

	// Start data transfer
	return h.handleTCPDataTransfer(conn, targetConn)
}

// handleTCPDataTransfer manages bidirectional data transfer for TCP connections.
// It spawns two goroutines:
//   - One reads from client and writes to target
//   - One reads from target and writes to client
//
// The transfer continues until either:
//   - The connection is closed by either end
//   - The context is canceled
//   - An error occurs
func (h *SocksHandler) handleTCPDataTransfer(conn *protocol.Connection, tcpConn net.Conn) byte {
	// Create channels for communication
	clientToTarget := make(chan []byte)
	targetToClient := make(chan []byte)
	errorCh := make(chan byte, 2)

	// Read from SOCKS client and forward to target
	go func() {
		for {
			select {
			case <-conn.Closed:
				return
			case <-h.Ctx.Done():
				return
			case data, ok := <-conn.ReadBuffer:
				if !ok {
					return
				}
				clientToTarget <- data
			}
		}
	}()

	// Read from target and forward to SOCKS client
	go func() {
		buffer := make([]byte, 128*1024)
		for {
			n, err := tcpConn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					errorCh <- protocol.ErrConnectionClosed
				} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					errorCh <- protocol.ErrTTLExpired
				} else {
					errorCh <- protocol.ErrHostUnreachable
				}
				return
			}
			// Copy data since buffer will be reused
			data := make([]byte, n)
			copy(data, buffer[:n])
			targetToClient <- data
		}
	}()

	// Main data transfer loop
	for {
		select {
		case <-conn.Closed:
			tcpConn.Close()
			return protocol.ErrNone

		case <-h.Ctx.Done():
			tcpConn.Close()
			return protocol.ErrHandlerStopped

		case errCode := <-errorCh:
			tcpConn.Close()
			return errCode

		case data := <-clientToTarget:
			_, err := tcpConn.Write(data)
			if err != nil {
				tcpConn.Close()
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return protocol.ErrTTLExpired
				}
				return protocol.ErrHostUnreachable
			}
		case data := <-targetToClient:
			errCode := h.SendData(conn.ID, data)
			if errCode != protocol.ErrNone {
				tcpConn.Close()
				return protocol.ErrPacketSendFailed
			}
		}
	}
}
