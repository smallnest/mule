package mule

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	conn, err := net.Dial("tcp4", "bing.com:80")
	require.NoError(t, err)
	localIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
	_ = conn.Close()

	remoteIP, err := getLastIP(localIP)
	assert.NoError(t, err)

	muleConn, err := New(WithLocalIP(localIP), WithTimeout(10*time.Second))
	require.NoError(t, err)

	go func() {
		time.Sleep(time.Second)
		n, err := muleConn.WriteToIP([]byte("test"), remoteIP, 8972, 65535)
		require.NoError(t, err)
		assert.Greater(t, n, 0)
	}()

	dstIP, srcPort, dstPort, err := muleConn.ReadFrom()
	assert.NoError(t, err)
	assert.Equal(t, srcPort, uint16(8972))
	assert.Equal(t, dstPort, uint16(65535))
	assert.Equal(t, dstIP, remoteIP)
}

func getLastIP(ipAddr string) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			// 找到一个非本地环回的IPv4地址
			ip := ipNet.IP.To4()
			if ip.String() != ipAddr {
				continue
			}

			mask := ipNet.Mask
			lastIP := calculateLastIP(ip, mask)
			return lastIP.String(), nil
		}
	}

	return "", errors.New("not found")
}

func calculateLastIP(ip net.IP, mask net.IPMask) net.IP {
	ipUint32 := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	maskUint32 := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])

	networkPrefixUint32 := ipUint32 & maskUint32
	// firstIPUint32 := networkPrefixUint32 + 1
	lastIPUint32 := networkPrefixUint32 | ^maskUint32
	lastIPUint32 = lastIPUint32 - 1 // remove broadcast address

	lastIP := make(net.IP, 4)
	lastIP[0] = byte(lastIPUint32 >> 24)
	lastIP[1] = byte(lastIPUint32 >> 16)
	lastIP[2] = byte(lastIPUint32 >> 8)
	lastIP[3] = byte(lastIPUint32)

	return lastIP
}
