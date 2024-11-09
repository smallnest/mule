package main

import (
	"fmt"
	"net"

	"github.com/smallnest/mule"
)

func main() {
	go startServer()

	conn, err := mule.NewIPUDPConn("127.0.0.1", 40000)
	if err != nil {
		panic(err)
	}

	var buf = make([]byte, 1024)
	localPort := uint16(20000)
	for {
		_, err = conn.WriteToIP([]byte(fmt.Sprintf("test-%d", localPort)), "127.0.0.1", "127.0.0.1", localPort, 30000)
		if err != nil {
			panic(err)
		}
		localPort++
		if localPort == 21000 {
			localPort = 20000
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("received from %s: %s\n", addr.String(), buf[:n])
	}
}

func startServer() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 30000})
	if err != nil {
		panic(err)
	}

	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("server received from %s: %s\n", addr.String(), buf[:n])

		addr.Port = 40000
		_, _ = conn.WriteToUDP(buf[:n], addr)
	}
}
