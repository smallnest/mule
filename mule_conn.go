package mule

import (
	"fmt"
	"log"
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

func WithLocalPort(localPort uint16) OptionFn {
	return func(c *Conn) {
		c.localPort = localPort
	}
}

func WithRemotePort(remotePort uint16) OptionFn {
	return func(c *Conn) {
		c.remotePort = remotePort
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
	packetConn net.PacketConn
	rawConn    *ipv4.RawConn

	localIP    string
	localPort  uint16
	remotePort uint16

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

	if conn.remotePort == 0 {
		conn.remotePort = 65535
	}

	// begin to listen
	err := conn.listen()
	if err != nil {
		return nil, err
	}

	rawConn, err := ipv4.NewRawConn(conn.packetConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn.rawConn = rawConn

	return conn, nil
}

func (c *Conn) Close() error {
	return c.packetConn.Close()
}

func (c *Conn) listen() error {
	conn, err := net.ListenPacket("ip4:udp", c.localIP)
	if err != nil {
		return err
	}
	c.packetConn = conn

	return nil
}

// ReadFromIP reads ICMP data from the remote server.
func (c *Conn) ReadFromIP() ([]byte, string, uint16, error) {
	buf := make([]byte, 65535)

	start := time.Now()
	for {
		if c.timeout > 0 {
			c.rawConn.SetReadDeadline(time.Now().Add(c.timeout))
		}
		header, payload, _, err := c.rawConn.ReadFrom(buf)
		if err != nil {
			return nil, "", 0, err
		}

		if time.Since(start) > c.timeout {
			return nil, "", 0, fmt.Errorf("timeout")
		}

		// 解析 ICMP 报文
		msg, err := icmp.ParseMessage(protocolICMP, payload)
		if err != nil {
			log.Fatal(err)
		}

		// 打印结果
		switch msg.Type {
		case ipv4.ICMPTypeDestinationUnreachable:
			dstUnreach, ok := msg.Body.(*icmp.DstUnreach)
			if !ok {
				continue
			}

			// 解析dstUnreach， 它是一个UDP的包头, 打印源目端口
			udpPacket := gopacket.NewPacket(dstUnreach.Data, layers.LayerTypeUDP, gopacket.Default)
			udpLayer := udpPacket.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}

			udpHeader := udpLayer.(*layers.UDP)
			return dstUnreach.Data, header.Dst.String(), uint16(udpHeader.DstPort), nil

		default:
			fmt.Printf("Unexpected ICMP message type: %v\n", msg.Type)
		}
	}
}

// WriteToIP writes UDP data to the destination.
func (c *Conn) WriteToIP(payload []byte, remoteIP string) (int, error) {
	data, _ := c.encodeIPPacket(remoteIP, payload)

	if c.timeout > 0 {
		c.rawConn.SetDeadline(time.Now().Add(c.timeout))
	}
	return c.rawConn.WriteToIP(data, &net.IPAddr{IP: net.ParseIP(remoteIP)})
}

func (c *Conn) encodeIPPacket(dstIP string, payload []byte) ([]byte, error) {
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
		SrcPort: layers.UDPPort(c.localPort),
		DstPort: layers.UDPPort(c.remotePort),
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
