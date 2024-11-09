package mule

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	qbpf "github.com/smallnest/qianmo/bpf"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// IPUDPConn represents a connection that combines an IPv4 raw connection and a UDP connection.
// It is used to send UDP packets with raw IP headers.
// And receive UDP packets with net.recvConn.
type IPUDPConn struct {
	sendConn *ipv4.RawConn
	recvConn *net.UDPConn

	localIP string

	timeout time.Duration

	tos      uint8
	ttl      uint8
	ipv4Flag IPv4Flag
}

// NewIPUDPConn creates a new IPUDPConn.
// It creates an IPv4 raw connection for sending UDP packets with raw IP headers.
// And a UDP connection for receiving UDP packets.
func NewIPUDPConn(localAddr string, port int) (*IPUDPConn, error) {
	pconn, err := net.ListenPacket("ip:udp", localAddr)

	// Create an IPv4 raw connection
	sendConn, err := ipv4.NewRawConn(pconn)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	// only send packets with the drop all filter
	dropAllFilter := createDropAllBPF()
	filter, err := bpf.Assemble(dropAllFilter)
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}
	err = sendConn.SetBPF(filter)
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}

	uconn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(localAddr),
		Port: port,
	})
	if err != nil {
		_ = sendConn.Close()
		return nil, err
	}

	return &IPUDPConn{
		sendConn: sendConn,
		recvConn: uconn,

		ttl: 64,
	}, nil
}

func createDropAllBPF() []bpf.Instruction {
	return []bpf.Instruction{
		bpf.RetConstant{Val: 0},
	}
}

// SetTimeout sets the timeout for the connection.
func (c *IPUDPConn) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetTOS sets the Type of Service (TOS) for the connection.
func (c *IPUDPConn) SetTOS(tos uint8) {
	c.tos = tos
}

// SetTTL sets the Time To Live (TTL) for the connection.
func (c *IPUDPConn) SetTTL(ttl uint8) {
	c.ttl = ttl
}

// SetIPv4Flag sets the IPv4 flag for the connection.
func (c *IPUDPConn) SetIPv4Flag(flag IPv4Flag) {
	c.ipv4Flag = flag
}

// WriteToIP writes UDP data to the specified destination IP and port.
func (c *IPUDPConn) WriteToIP(payload []byte, localIP, remoteIP string, localPort, remotePort uint16) (int, error) {
	if localIP == "" {
		localIP = c.localIP
	}

	data, err := c.encodeIPPacket(localIP, remoteIP, localPort, remotePort, payload)
	if err != nil {
		return 0, fmt.Errorf("failed to encode IP packet: %w", err)
	}

	if c.timeout > 0 {
		c.sendConn.SetDeadline(time.Now().Add(c.timeout))
	}
	n, err := c.sendConn.WriteToIP(data, &net.IPAddr{IP: net.ParseIP(remoteIP)})
	if err != nil {
		return 0, fmt.Errorf("failed to write to IP: %w", err)
	}
	return n, nil
}

func (c *IPUDPConn) encodeIPPacket(localIP, dstIP string, localPort, remotePort uint16, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(localIP),
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      c.ttl,
		Protocol: layers.IPProtocolUDP,
		TOS:      c.tos,
		Flags:    layers.IPv4Flag(c.ipv4Flag),
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

// ReadFrom reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *IPUDPConn) Read(b []byte) (int, error) {
	return c.recvConn.Read(b)
}

// ReadFrom reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *IPUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.recvConn.ReadFrom(b)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *IPUDPConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	return c.recvConn.ReadFromUDPAddrPort(b)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the oob data, the flags, the source address and the error.
func (c *IPUDPConn) ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	return c.recvConn.ReadMsgUDPAddrPort(b, oob)
}

// ReadFromUDP reads a UDP packet from the connection.
// It returns the number of bytes read, the source address and the error.
func (c *IPUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	return c.recvConn.ReadFromUDP(b)
}

// SetBBF sets the BPF filter for the connection.
func (c *IPUDPConn) SetBBF(filter []bpf.RawInstruction) error {
	return c.sendConn.SetBPF(filter)
}

// SetBBFExpr sets the BPF filter for the connection.
// It parses the filter expression like tcpdump and sets the BPF filter.
func (c *IPUDPConn) SetBBFExpr(expr string) error {
	filter := qbpf.ParseTcpdumpFitlerData(expr)
	return c.sendConn.SetBPF(filter)
}

// Close closes the connection.
func (c *IPUDPConn) Close() error {
	_ = c.sendConn.Close()
	return c.recvConn.Close()
}
