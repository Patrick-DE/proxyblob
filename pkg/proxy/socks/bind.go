package proxy

import (
	"proxyblob/pkg/protocol"
)

// handleBind processes the SOCKS5 BIND command.
// The BIND command is used to accept incoming TCP connections
// on behalf of the client. This implementation returns
// ErrUnsupportedCommand as BIND is not currently supported.
//
// The command format follows RFC 1928 Section 4.
func (h *SocksHandler) handleBind(conn *protocol.Connection, data []byte) byte {
	return protocol.ErrUnsupportedCommand
}
