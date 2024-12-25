package mule

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// ErrPayloadTooShort is returned when the payload is too short.
	ErrPayloadTooShort = errors.New("payload too short")
	// ErrPayloadNotMatch is returned when the timestamp or sequence or payloadType number mismatch.
	ErrPayloadNotMatch = errors.New("timestamp or sequence or payloadType number mismatch")
)

// SimpleEncodeIPPacket encodes a UDP packet simply with the given parameters.
func SimpleEncodeIPPacket(localIP, dstIP string, localPort, remotePort uint16, payload []byte) ([]byte, error) {
	return EncodeIPPacket(localIP, dstIP, localPort, remotePort, payload, 64, 0, 0)
}

// EncodeIPPacket encodes a UDP packet with the given parameters.
func EncodeIPPacket(localIP, dstIP string, localPort, remotePort uint16, payload []byte,
	ttl, tos uint8, ipv4Flags layers.IPv4Flag) ([]byte, error) {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(localIP),
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		TOS:      tos,
		Flags:    ipv4Flags,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(localPort),
		DstPort: layers.UDPPort(remotePort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(payload))

	return buf.Bytes(), err
}

// EncodePayload encodes the timestamp and sequence number into head of the payload.
func EncodePayload(ts, seq uint64, payload []byte, payloadType PayloadType) error {
	if len(payload) < 17 {
		return ErrPayloadTooShort
	}

	binary.BigEndian.PutUint64(payload[:8], ts)
	binary.BigEndian.PutUint64(payload[8:16], seq)
	payload[16] = byte(payloadType)

	return nil
}

// EncodePayloadWithPort encodes the timestamp, sequence number, src port and dst port into head of the payload.
func EncodePayloadWithPort(ts, seq uint64, srcPort, dstPort uint16, payload []byte, payloadType PayloadType) error {
	if len(payload) < 21 {
		return ErrPayloadTooShort
	}

	binary.BigEndian.PutUint64(payload[:8], ts)
	binary.BigEndian.PutUint64(payload[8:16], seq)
	binary.BigEndian.PutUint16(payload[16:18], srcPort)
	binary.BigEndian.PutUint16(payload[18:20], dstPort)
	payload[20] = byte(payloadType)

	return nil
}

// DecodePayload decodes the timestamp and sequence number from the head of the payload.
func DecodePayload(payload []byte) (ts, seq uint64, payloadType PayloadType, err error) {
	if len(payload) < 17 {
		return 0, 0, 0, ErrPayloadTooShort
	}

	ts = binary.BigEndian.Uint64(payload[:8])
	seq = binary.BigEndian.Uint64(payload[8:16])
	payloadType = PayloadType(payload[16])

	return
}

// DecodePayloadWithPort decodes the timestamp, sequence number, src port and dst port from the head of the payload.
func DecodePayloadWithPort(payload []byte) (ts, seq uint64, srcPort, dstPort uint16, payloadType PayloadType, err error) {
	if len(payload) < 17 {
		return 0, 0, 0, 0, 0, ErrPayloadTooShort
	}

	ts = binary.BigEndian.Uint64(payload[:8])
	seq = binary.BigEndian.Uint64(payload[8:16])
	srcPort = binary.BigEndian.Uint16(payload[16:18])
	dstPort = binary.BigEndian.Uint16(payload[18:20])
	payloadType = PayloadType(payload[20])

	return
}

// ComparePayload compares two payloads and returns whether they are different and the changes.
func ComparePayload(payload1, payload2 []byte, start, end int) (bool, []string) {
	bitflip := false
	changes := make([]string, 0)

	for i := start; i < end; i++ {
		if payload1[i] != payload2[i] {
			changes = append(changes, fmt.Sprintf("index %d: %08b -> %08b", i, payload1[i], payload2[i]))
			bitflip = true
		}
	}

	return bitflip, changes
}

// PayloadType represents the type of payload.
type PayloadType byte

const (
	PayloadTypeZero PayloadType = iota
	PayloadTypeOne
	PayloadType5A
	PayloadTypeRandom
)

// MakeFullZeroPaylod makes a full zero payload with the given size.
func MakeFullZeroPaylod(size int) []byte {
	payload := bytes.Repeat([]byte{0}, size)
	return payload
}

// MakeFullOnePaylod makes a full one payload with the given size.
func MakeFullOnePaylod(size int) []byte {
	payload := bytes.Repeat([]byte{0xFF}, size)
	return payload
}

// Make5APaylod makes a full 0x5A payload with the given size.
func Make5APaylod(size int) []byte {
	payload := bytes.Repeat([]byte{0x5A}, size)
	return payload
}

// MakeFullRandomPaylod makes a full random payload with the given size.
func MakeFullRandomPaylod(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

// MakePayload makes a payload with the given type and size.
func MakePayload(payloadType PayloadType, size int) []byte {
	var payload []byte

	switch payloadType {
	case PayloadTypeZero:
		payload = MakeFullZeroPaylod(size)
	case PayloadTypeOne:
		payload = MakeFullOnePaylod(size)
	case PayloadType5A:
		payload = Make5APaylod(size)
	case PayloadTypeRandom:
		payload = MakeFullRandomPaylod(size)
	default:
		payload = MakeFullRandomPaylod(size)
	}

	return payload
}
