package mule

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConn tests the functionality of the Mule connection
func TestConn(t *testing.T) {
	// Establish a temporary connection to get the local IP
	conn, err := net.Dial("tcp4", "bing.com:80")
	require.NoError(t, err)
	localIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
	_ = conn.Close()

	// Get the last IP in the subnet
	remoteIP, err := getLastIP(localIP)
	assert.NoError(t, err)

	// Create a new Mule connection
	muleConn, err := New(WithLocalIP(localIP), WithTimeout(10*time.Second))
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, muleConn.Close())
	})

	// Use context to control timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pid := os.Getpid()
	seq := uint16(pid & 0xffff)

	// Send a UDP packet in a goroutine
	go func() {

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
			n, err := muleConn.WriteToIP(seq, []byte("test"), remoteIP, 8972, 65535)
			require.NoError(t, err)
			assert.Greater(t, n, 0)
		}
	}()

	// Read the ICMP response
	dstIP, srcPort, dstPort, err := muleConn.ReadFrom()
	assert.NoError(t, err)
	assert.Equal(t, uint16(8972), srcPort)
	assert.Equal(t, uint16(65535), dstPort)
	assert.Equal(t, remoteIP, dstIP)
}

// getLastIP returns the last IP address in the subnet of the given IP address
func getLastIP(ipAddr string) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}

		ip := ipNet.IP.To4()
		if ip.String() != ipAddr {
			continue
		}

		lastIP := calculateLastIP(ip, ipNet.Mask)
		return lastIP.String(), nil
	}

	return "", errors.New("no matching non-loopback IPv4 address found")
}

// calculateLastIP calculates the last usable IP address in a subnet
func calculateLastIP(ip net.IP, mask net.IPMask) net.IP {
	ipUint32 := binary.BigEndian.Uint32(ip)
	maskUint32 := binary.BigEndian.Uint32(mask)

	networkPrefixUint32 := ipUint32 & maskUint32
	lastIPUint32 := (networkPrefixUint32 | ^maskUint32) - 1 // remove broadcast address

	lastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(lastIP, lastIPUint32)

	return lastIP
}
