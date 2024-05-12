package mule

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	conn, err := net.Dial("tcp", "bing.com:80")
	require.NoError(t, err)
	localIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
	_ = conn.Close()

	muleConn, err := New(WithLocalIP(localIP), WithTimeout(30*time.Second), WithRemotePort(65535))
	require.NoError(t, err)

	n, err := muleConn.WriteToIP([]byte("GET / HTTP/1.1\r\nHost: bing.com\r\n\r\n"), "114.114.114.114")
	require.NoError(t, err)
	assert.Greater(t, n, 0)

	payload, dstIP, dstPort, err := muleConn.ReadFromIP()
	assert.NoError(t, err)
	assert.NotEmpty(t, payload)
	assert.Equal(t, dstIP, "114.114.114.114")
	assert.Equal(t, dstPort, uint16(65535))
}
