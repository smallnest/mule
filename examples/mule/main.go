package main

import (
	"fmt"
	"log"
	"time"

	"github.com/smallnest/mule"
)

func main() {
	muleConn, err := mule.New(
		mule.WithLocalIP("192.168.1.1"),
		mule.WithTimeout(5*time.Second),
		mule.WithTTL(64),
		mule.WithTOS(0),
		mule.WithIPv4Flag(0),
	)

	if err != nil {
		log.Fatalf("failed to create mule connection: %v", err)
	}

	defer muleConn.Close()

	// send a UDP packet
	_, err = muleConn.WriteToIP([]byte("Hello, Mule!"), "192.168.1.2", 1234, 80)
	if err != nil {
		log.Fatalf("failed to send UDP packet: %v", err)
	}

	// read the ICMP response
	dstIP, srcPort, dstPort, err := muleConn.ReadFrom()
	if err != nil {
		log.Fatalf("failed to read ICMP response: %v", err)
	}

	fmt.Printf("received ICMP response: dstIP=%s, srcPort=%d, dstPort=%d\n", dstIP, srcPort, dstPort)

}
