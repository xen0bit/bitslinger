package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/AkihiroSuda/go-netfilter-queue"

	"github.com/xen0bit/bitslinger/internal/api"
	"github.com/xen0bit/bitslinger/internal/opts"
	"github.com/xen0bit/bitslinger/internal/plumbing"
)

// var tcpClient net.Conn

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	opts.ParseFlags()
}

func main() {
	fmt.Println("BitSlinger: The TCP/UDP Packet Payload Editing Tool")

	// Configure Send/Recievers
	switch opts.Mode {
	case opts.Websockets:
		go api.ListenAndServeWebsockets()
	case opts.HTTP:
		go api.ListenAndServeHTTP()
	}

	log.Trace().
		Uint16("num", opts.QueueNum).
		Uint32("max", opts.QueueMax).
		Msg("Constructing nfqueue...")

	nfq, err := netfilter.NewNFQueue(uint16(opts.QueueNum), uint32(opts.QueueMax), opts.PacketSize)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize NFQueue, cannot continue")
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	for p := range packets {
		plumbing.SendToProxy(&p)
	}
}
