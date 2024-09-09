package mule

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Constants for the package
const (
	protocolICMP   = 1
	defaultLocalIP = "127.0.0.1"
	maxPacketSize  = 65535
)

// IPv4Flag represents the flags in an IPv4 header.
type IPv4Flag uint8

// OptionFn is a function type for configuring Conn options
type OptionFn func(*Conn)

// WithLocalIP sets the local IP address for the connection
func WithLocalIP(localIP string) OptionFn {
	return func(c *Conn) {
		c.localIP = localIP
	}
}

// WithTimeout sets the timeout duration for the connection
func WithTimeout(timeout time.Duration) OptionFn {
	return func(c *Conn) {
		c.timeout = timeout
	}
}

// WithTOS sets the Type of Service (TOS) for the connection
func WithTOS(tos uint8) OptionFn {
	return func(c *Conn) {
		c.tos = tos
	}
}

// WithTTL sets the Time To Live (TTL) for the connection
func WithTTL(ttl uint8) OptionFn {
	return func(c *Conn) {
		c.ttl = ttl
	}
}

// WithIPv4Flag sets the IPv4 flag for the connection
func WithIPv4Flag(flag IPv4Flag) OptionFn {
	return func(c *Conn) {
		c.ipv4Flag = flag
	}
}

// Conn represents a Mule connection.
// You can use it to send UDP packets to multiple remote servers with unreachable ports.
// Then you receive ICMP Destination/Port Unreachable packets from the remote servers.
type Conn struct {
	sendConn *ipv4.RawConn
	recvConn *icmp.PacketConn

	localIP string

	timeout time.Duration

	tos      uint8
	ttl      uint8
	ipv4Flag IPv4Flag
}

// New creates a new Mule connection with the given options.
func New(opts ...OptionFn) (*Conn, error) {
	conn := &Conn{}

	for _, opt := range opts {
		opt(conn)
	}

	if conn.localIP == "" {
		conn.localIP = defaultLocalIP
	}

	// begin to listen
	err := conn.listen()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Close closes the Mule connection and releases associated resources.
func (c *Conn) Close() error {
	if c.sendConn != nil {
		_ = c.sendConn.Close()
	}

	if c.recvConn != nil {
		return c.recvConn.Close()
	}

	return nil
}

// listen initializes the send and receive connections for the Mule connection.
func (c *Conn) listen() error {
	pconn, err := net.ListenPacket("ip4:udp", c.localIP)
	if err != nil {
		return fmt.Errorf("failed to listen packet: %w", err)
	}
	rawConn, err := ipv4.NewRawConn(pconn)
	if err != nil {
		_ = pconn.Close()
		return fmt.Errorf("failed to create raw connection: %w", err)
	}
	c.sendConn = rawConn

	recvConn, err := icmp.ListenPacket("ip4:1", c.localIP)
	if err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("failed to listen ICMP: %w", err)
	}
	c.recvConn = recvConn

	return nil
}

// ReadFrom reads ICMP data from the remote server and returns the destination IP, source port, and destination port.
func (c *Conn) ReadFrom() (string, uint16, uint16, error) {
	buf := make([]byte, maxPacketSize)

	var deadline time.Time
	if c.timeout > 0 {
		deadline = time.Now().Add(c.timeout)
		c.recvConn.SetReadDeadline(deadline)
	}

	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return "", 0, 0, fmt.Errorf("timeout")
		}

		n, _, err := c.recvConn.ReadFrom(buf)
		if err != nil {
			return "", 0, 0, fmt.Errorf("failed to read: %w", err)
		}

		// 解析 ICMP 报文
		msg, err := icmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil {
			return "", 0, 0, err
		}

		// 打印结果
		switch msg.Type {
		case ipv4.ICMPTypeDestinationUnreachable:
			dstUnreach, ok := msg.Body.(*icmp.DstUnreach)
			if !ok {
				continue
			}

			packet := gopacket.NewPacket(dstUnreach.Data, layers.LayerTypeIPv4, gopacket.Default)
			if packet == nil {
				continue
			}

			// 获取IP层
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}

			ip, _ := ipLayer.(*layers.IPv4)

			// 获取UDP层
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)

			return ip.DstIP.String(), uint16(udp.SrcPort), uint16(udp.DstPort), nil

		default:

		}
	}
}

// WriteToIP writes UDP data to the specified destination IP and port.
func (c *Conn) WriteToIP(payload []byte, remoteIP string, localPort, remotePort uint16) (int, error) {
	data, err := c.encodeIPPacket(remoteIP, localPort, remotePort, payload)
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

func (c *Conn) encodeIPPacket(dstIP string, localPort, remotePort uint16, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(c.localIP),
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
