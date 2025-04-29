// Package proxy implements SOCKS5 proxy functionality.
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"

	"proxyblob/pkg/protocol"
)

// ParseAddress extracts a target address from SOCKS5 address data.
// It returns the address in host:port format and any error encountered.
// The address format follows RFC 1928 Section 4.
func ParseAddress(data []byte) (string, byte) {
	addr, _, err := ParseNetworkAddress(data[0], data[1:])
	if err != protocol.ErrNone {
		return "", err
	}
	return addr, protocol.ErrNone
}

// ParseNetworkAddress parses a network address from SOCKS5 formatted data.
// The format is:
//
//	+------+----------+----------+
//	| ATYP | DST.ADDR | DST.PORT |
//	+------+----------+----------+
//	|  1   | Variable |    2     |
//
// Returns the address string in host:port format, bytes consumed, and any error.
func ParseNetworkAddress(addrType byte, data []byte) (string, int, byte) {
	cursor := 0
	var addr string

	switch addrType {
	case IPv4:
		if len(data) < cursor+4+2 { // 4 bytes IPv4 + 2 bytes port
			return "", 0, protocol.ErrAddressNotSupported
		}
		ip := net.IPv4(data[cursor], data[cursor+1], data[cursor+2], data[cursor+3])
		addr = ip.String()
		cursor += 4

	case IPv6:
		if len(data) < cursor+16+2 { // 16 bytes IPv6 + 2 bytes port
			return "", 0, protocol.ErrAddressNotSupported
		}
		ip := net.IP(data[cursor : cursor+16])
		addr = fmt.Sprintf("[%s]", ip.String())
		cursor += 16

	case Domain:
		if len(data) < cursor+1 { // Need length byte
			return "", 0, protocol.ErrAddressNotSupported
		}
		domainLen := int(data[cursor])
		cursor++
		if len(data) < cursor+domainLen+2 { // +2 for port
			return "", 0, protocol.ErrAddressNotSupported
		}
		addr = string(data[cursor : cursor+domainLen])
		cursor += domainLen

	default:
		return "", 0, protocol.ErrAddressNotSupported
	}

	if len(data) < cursor+2 {
		return "", 0, protocol.ErrAddressNotSupported
	}

	port := binary.BigEndian.Uint16(data[cursor : cursor+2])
	cursor += 2

	return fmt.Sprintf("%s:%d", addr, port), cursor, protocol.ErrNone
}

// ExtractUDPHeader parses a SOCKS5 UDP datagram header and returns the target address.
// The format is:
//
//	+-----+------+------+----------+----------+----------+
//	| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+------+------+----------+----------+----------+
//	|  2  |  1   |  1   | Variable |    2     | Variable |
//
// Returns the target address, header length, and any error encountered.
func ExtractUDPHeader(data []byte) (string, int, byte) {
	headerLen := 4 // RSV(2) + FRAG(1) + ATYP(1)

	// Parse the address part of the header
	addr, addrLen, err := ParseNetworkAddress(data[3], data[4:]) // Use ATYP and pass remaining data
	if err != protocol.ErrNone {
		return "", 0, err
	}
	return addr, headerLen + addrLen, protocol.ErrNone
}
