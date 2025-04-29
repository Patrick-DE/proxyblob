// Package protocol implements the communication protocol between proxy server and agent.
// It provides packet encoding/decoding, connection management, and secure data transfer
// using ChaCha20-Poly1305.
//
// The protocol uses a binary packet format with fixed-size headers and variable-length
// payloads. Each packet contains a command type, connection ID, and optional data.
package protocol

import (
	"bytes"
	"encoding/binary"

	"github.com/google/uuid"
)

// Command types for protocol operations.
const (
	CmdNew   byte = iota + 1 // Request new connection
	CmdAck                   // Acknowledge connection
	CmdData                  // Transfer data
	CmdClose                 // Terminate connection
)

// Protocol packet field sizes in bytes.
const (
	CommandSize    = 1  // Command field
	UUIDSize       = 16 // Connection ID field
	DataLengthSize = 4  // Payload length field
	HeaderSize     = CommandSize + UUIDSize + DataLengthSize
)

// Packet represents a protocol message with the following binary format:
//
//	+---------+----------------+--------------+---------+
//	| Command | Connection ID  | Data Length  | Payload |
//	+---------+----------------+--------------+---------+
//	|    1B   |      16B       |     4B       |   var   |
type Packet struct {
	Command      byte      // Operation type (CmdNew, CmdAck, etc.)
	ConnectionID uuid.UUID // Unique connection identifier
	Data         []byte    // Optional payload data
}

// NewPacket creates a protocol packet with the given parameters.
// The data parameter is optional and may be nil.
func NewPacket(command byte, connectionID uuid.UUID, data []byte) *Packet {
	return &Packet{
		Command:      command,
		ConnectionID: connectionID,
		Data:         data,
	}
}

// Encode serializes the packet into a byte slice following the protocol format.
// Returns nil if any encoding operation fails.
func (p *Packet) Encode() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, HeaderSize+len(p.Data)))

	if err := buf.WriteByte(p.Command); err != nil {
		return nil
	}

	if _, err := buf.Write(p.ConnectionID[:]); err != nil {
		return nil
	}

	if err := binary.Write(buf, binary.BigEndian, uint32(len(p.Data))); err != nil {
		return nil
	}

	if len(p.Data) > 0 {
		if _, err := buf.Write(p.Data); err != nil {
			return nil
		}
	}

	return buf.Bytes()
}

// Decode deserializes a byte slice into a protocol packet.
// Returns nil if the data is malformed, incomplete, or contains an invalid command.
// The input must contain at least HeaderSize bytes and match the encoded length.
func Decode(data []byte) *Packet {
	if len(data) < HeaderSize {
		return nil
	}

	command := data[0]
	if command < CmdNew || command > CmdClose {
		return nil
	}

	var id uuid.UUID
	copy(id[:], data[CommandSize:CommandSize+UUIDSize])

	dataLength := binary.BigEndian.Uint32(data[CommandSize+UUIDSize : HeaderSize])
	if uint32(len(data)) != uint32(HeaderSize)+dataLength {
		return nil
	}

	var packetData []byte
	if dataLength > 0 {
		packetData = make([]byte, dataLength)
		copy(packetData, data[HeaderSize:])
	}

	return NewPacket(command, id, packetData)
}
