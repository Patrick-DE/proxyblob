package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"proxyblob/pkg/protocol"
)

// handleUDPAssociate processes the SOCKS5 UDP ASSOCIATE command.
// It creates a UDP relay that allows clients to send and receive
// UDP datagrams through the SOCKS server.
//
// The process involves:
//  1. Creating a UDP socket for client communication
//  2. Sending the socket address back to the client
//  3. Maintaining the TCP control connection
//  4. Relaying UDP datagrams between client and targets
//
// The command format follows RFC 1928 Section 4.
func (h *SocksHandler) handleUDPAssociate(conn *protocol.Connection) byte {
	// Create UDP socket
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		// Send network unreachable error
		h.SendError(conn, protocol.ErrNetworkUnreachable)
		return protocol.ErrNetworkUnreachable
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		// Determine specific error type
		errCode := protocol.ErrGeneralSocksFailure
		if opErr, ok := err.(*net.OpError); ok {
			if errors.Is(opErr, net.ErrClosed) {
				errCode = protocol.ErrTransportClosed
			} else if opErr.Op == "listen" {
				errCode = protocol.ErrNetworkUnreachable
			}
		}

		// Send appropriate error response
		h.SendError(conn, errCode)
		return errCode
	}

	// Get the allocated port
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	// Create response
	// Format: |VER|REP|RSV|ATYP|BND.ADDR|BND.PORT|
	response := []byte{
		Version5,   // VER
		Succeeded,  // REP - success
		0,          // RSV - reserved, must be 0
		IPv4,       // ATYP - IPv4
		0, 0, 0, 0, // BND.ADDR - 0.0.0.0 (any address)
		byte(port >> 8),   // BND.PORT - high byte
		byte(port & 0xff), // BND.PORT - low byte
	}

	errCode := h.SendData(conn.ID, response)
	if errCode != protocol.ErrNone {
		udpConn.Close()
		return protocol.ErrPacketSendFailed
	}

	// Store UDP connection and start handling packets
	conn.Conn = udpConn
	conn.State = protocol.StateConnected

	go h.handleUDPPackets(conn)

	// Keep the control connection open until it's closed elsewhere
	select {
	case <-conn.Closed:
		// Control connection closed, UDP associate terminated
	case <-h.Ctx.Done():
		udpConn.Close()
	}

	return protocol.ErrNone
}

// handleUDPPackets manages the UDP relay for a client.
// It:
//   - Receives UDP packets from the client
//   - Extracts target addresses from SOCKS headers
//   - Forwards packets to targets
//   - Receives responses from targets
//   - Wraps responses in SOCKS headers
//   - Returns them to the client
//
// The relay operates until the control connection closes or
// the context is canceled.
func (h *SocksHandler) handleUDPPackets(conn *protocol.Connection) {
	udpConn := conn.Conn.(*net.UDPConn)
	buffer := make([]byte, 64*1024)
	var clientAddr *net.UDPAddr

	// Create a UDP connection for sending to targets
	targetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		h.SendClose(conn.ID, protocol.ErrNetworkUnreachable)
		return
	}

	// Ensure connections are properly closed when this handler exits
	defer targetConn.Close()

	// Map to track target addresses and their corresponding responses
	type targetInfo struct {
		addr       *net.UDPAddr
		lastActive time.Time
	}
	targets := make(map[string]*targetInfo)

	// Channel for receiving UDP responses
	responses := make(chan struct {
		data []byte
		addr *net.UDPAddr
	}, 100)

	// Start a goroutine to handle responses
	go func() {
		respBuf := make([]byte, 128*1024)
		for {
			// Check for cancellation
			select {
			case <-h.Ctx.Done():
				return
			case <-conn.Closed:
				return
			default:
				// Continue processing
			}

			// Set read deadline
			if err := targetConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue // Non-fatal, just retry
			}

			n, addr, err := targetConn.ReadFromUDP(respBuf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}

			if n > 0 {
				// Make a copy of the data since respBuf will be reused
				data := make([]byte, n)
				copy(data, respBuf[:n])

				// Send response through channel
				select {
				case responses <- struct {
					data []byte
					addr *net.UDPAddr
				}{data, addr}:
					// Successfully sent
				default:
					// Channel full, log and continue
				}
			}
		}
	}()

	// Timeout to clean up inactive targets
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.Ctx.Done():
			return
		case <-conn.Closed:
			return
		case resp := <-responses:
			// Find the target that matches this response
			var found bool

			for _, target := range targets {
				if target.addr.IP.Equal(resp.addr.IP) && target.addr.Port == resp.addr.Port {
					// Update last active time
					target.lastActive = time.Now()
					found = true
					break
				}
			}

			if !found {
				// Skip unknown targets
				continue
			}

			if clientAddr == nil {
				// Skip client address not set
				continue
			}

			// Create response packet with appropriate header
			// For simplicity, we'll just use a minimal header with the correct address type
			var respHeader []byte

			// Determine address type
			var addrType byte
			if resp.addr.IP.To4() != nil {
				addrType = IPv4
			} else {
				addrType = IPv6
			}

			// header: RSV(2) + FRAG(0) + ATYP(1) + ADDR + PORT(2)
			respHeader = append(respHeader, 0, 0, 0, addrType)

			if addrType == IPv4 {
				respHeader = append(respHeader, resp.addr.IP.To4()...)
			} else {
				respHeader = append(respHeader, resp.addr.IP.To16()...)
			}

			// Add port
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(resp.addr.Port))
			respHeader = append(respHeader, portBytes...)

			// Combine header and payload
			respPacket := append(respHeader, resp.data...)

			_, err = udpConn.WriteToUDP(respPacket, clientAddr)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
			}

		case <-ticker.C:
			// Clean up inactive targets
			now := time.Now()
			for targetKey, targetInfo := range targets {
				if now.Sub(targetInfo.lastActive) > 1*time.Minute {
					delete(targets, targetKey)
				}
			}

		default:
			// Set read deadline to prevent blocking forever
			if err := udpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue // Non-fatal
			}

			n, remoteAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				// Handle various error conditions
				if errors.Is(err, net.ErrClosed) {
					return
				}

				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						// This is expected due to deadline, don't log
						continue
					}
				}

				h.SendClose(conn.ID, protocol.ErrNetworkUnreachable)
				return
			}

			// Store client address from first packet
			if clientAddr == nil {
				clientAddr = remoteAddr
			}

			// Only accept packets from original client
			if !remoteAddr.IP.Equal(clientAddr.IP) {
				continue
			}

			// Handle UDP packet
			if n > 3 {
				// Extract target address from UDP header
				targetAddr, headerLen, errCode := ExtractUDPHeader(buffer[:n])
				if errCode != protocol.ErrNone {
					continue
				}

				// Resolve target address
				targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					continue
				}

				// Store target information
				targetKey := targetAddr
				targets[targetKey] = &targetInfo{
					addr:       targetUDPAddr,
					lastActive: time.Now(),
				}

				// Send payload to target
				_, err = targetConn.WriteToUDP(buffer[headerLen:n], targetUDPAddr)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
			}
		}
	}
}
