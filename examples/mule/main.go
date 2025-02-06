package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juju/ratelimit"
	"github.com/smallnest/mule"
	"github.com/spf13/pflag"
)

var (
	localAddr  = pflag.StringP("local-addr", "l", "", "local address")
	localPort  = pflag.IntP("local-port", "p", 33434, "local port")
	remotePort = pflag.IntP("remote-port", "r", 0, "remote port")
	timeout    = pflag.DurationP("timeout", "t", 5*time.Second, "timeout")
	ttl        = pflag.IntP("ttl", "", 64, "ttl")
	tos        = pflag.IntP("tos", "", 0, "tos")
	pps        = pflag.IntP("pps", "", 1, "pps")
	msgLen     = pflag.IntP("msg-len", "", 6, "message length")
)

func main() {
	pflag.ErrHelp = errors.New("")
	pflag.Parse()

	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		return
	}

	targets, err := mule.ConvertAddrs(args[0])
	if err != nil {
		log.Fatalf("failed to convert target addresses: %v", err)
	}
	if len(targets) == 0 {
		log.Fatalf("no target addresses found")
	}

	if *localAddr == "" {
		*localAddr = mule.LocalAddr(targets[0])
	}

	muleConn, err := mule.New(
		mule.WithLocalIP(*localAddr),
		mule.WithTimeout(*timeout),
		mule.WithTTL(uint8(*ttl)),
		mule.WithTOS(uint8(*tos)),
	)
	if err != nil {
		log.Fatalf("failed to create mule connection: %v", err)
	}
	defer muleConn.Close()

	ratelimiter := ratelimit.NewBucketWithRate(float64(*pps), int64(*pps))
	// send a UDP packet
	go func() {
		payload := bytes.Repeat([]byte{255}, *msgLen)
		ratelimiter.Wait(1)
		pid := os.Getpid()
		seq := uint16(pid & 0xffff)
		for {
			ratelimiter.Wait(1)
			for _, target := range targets {
				_, err = muleConn.WriteToIP(seq, payload, target, uint16(*localPort), uint16(*remotePort))
				if err != nil {
					log.Fatalf("failed to send UDP packet: %v", err)
				}
			}
		}
	}()

	go func() {
		for {
			// read the ICMP response
			dstIP, srcPort, dstPort, err := muleConn.ReadFrom()
			if err != nil {
				log.Fatalf("failed to read ICMP response: %v", err)
			}

			if dstPort != uint16(*remotePort) && srcPort != uint16(*localPort) {
				continue
			}

			fmt.Printf("src=%s:%d, dst=%s:%d\n", *localAddr, srcPort, dstIP, dstPort)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
