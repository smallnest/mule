package mule

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	protocolICMP = 1
)

// IPv4Flag represents the flags in an IPv4 header.
type IPv4Flag uint8

type OptionFn func(*Conn)

func WithLocalIP(localIP string) OptionFn {
	return func(c *Conn) {
		c.localIP = localIP
	}
}

func WithTimeout(timeout time.Duration) OptionFn {
	return func(c *Conn) {
		c.timeout = timeout
	}
}

func WithTOS(tos uint8) OptionFn {
	return func(c *Conn) {
		c.tos = tos
	}
}

func WithTTL(ttl uint8) OptionFn {
	return func(c *Conn) {
		c.ttl = ttl
	}
}

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

// New creates a new Mule connection.
func New(opts ...OptionFn) (*Conn, error) {
	conn := &Conn{}

	for _, opt := range opts {
		opt(conn)
	}

	if conn.localIP == "" {
		conn.localIP = "127.0.0.1"
	}

	// begin to listen
	err := conn.listen()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *Conn) Close() error {
	if c.sendConn != nil {
		_ = c.sendConn.Close()
	}

	if c.recvConn != nil {
		return c.recvConn.Close()
	}

	return nil
}

func (c *Conn) listen() error {
	pconn, err := net.ListenPacket("ip4:udp", c.localIP)
	if err != nil {
		return err
	}
	rawConn, err := ipv4.NewRawConn(pconn)
	if err != nil {
		_ = pconn.Close()
		return err
	}
	c.sendConn = rawConn

	recvConn, err := icmp.ListenPacket("ip4:1", c.localIP)
	if err != nil {
		return err
	}
	c.recvConn = recvConn

	return nil
}

// ReadFromIP reads ICMP data from the remote server.
func (c *Conn) ReadFrom() (string, uint16, uint16, error) {
	buf := make([]byte, 65535)

	start := time.Now()

loop:
	for {
		if c.timeout > 0 {
			c.recvConn.SetReadDeadline(time.Now().Add(c.timeout))
		}

		n, _, err := c.recvConn.ReadFrom(buf)
		if err != nil {
			return "", 0, 0, err
		}

		if time.Since(start) > c.timeout {
			return "", 0, 0, err
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
				continue loop
			}

			packet := gopacket.NewPacket(dstUnreach.Data, layers.LayerTypeIPv4, gopacket.Default)
			if packet == nil {
				continue loop
			}

			// 获取IP层
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue loop
			}

			ip, _ := ipLayer.(*layers.IPv4)

			// 获取UDP层
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue loop
			}
			udp, _ := udpLayer.(*layers.UDP)

			return ip.DstIP.String(), uint16(udp.SrcPort), uint16(udp.DstPort), nil

		default:

		}
	}
}

// WriteToIP writes UDP data to the destination.
func (c *Conn) WriteToIP(payload []byte, remoteIP string, localPort, remotePort uint16) (int, error) {
	data, _ := c.encodeIPPacket(remoteIP, localPort, remotePort, payload)

	if c.timeout > 0 {
		c.sendConn.SetDeadline(time.Now().Add(c.timeout))
	}
	return c.sendConn.WriteToIP(data, &net.IPAddr{IP: net.ParseIP(remoteIP)})
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
