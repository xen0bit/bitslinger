package plumbing

import (
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/api"
	"github.com/xen0bit/bitslinger/internal/opts"
)

// SendToProxy handles an incoming packet and then send its to the appropriate proxy listener as defined by opts.
func SendToProxy(p *netfilter.NFPacket) int {
	// gpq.Lock()
	// defer gpq.Unlock()
	// Decode a packet
	// packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	pckt := gpq.AddPacket(p)
	if !pckt.Valid() {
		return 0
	}

	log.Trace().Caller().Str("caller", pckt.UUID()).Msg("New Packet")

	switch opts.Mode {
	case opts.Websockets:
		log.Trace().Caller().Str("caller", pckt.UUID()).Msg("-> WebSocket")
		api.SendPacketToWS(pckt)
	case opts.HTTP:
		log.Trace().Caller().Str("caller", pckt.UUID()).Msg("-> HTTP")
		api.SendPacketToHTTP(pckt)
	default:
		log.Panic().Uint8("mode", uint8(opts.Mode)).Msg("unknown handler mode")
	}

	// Needed for C API
	return 0
}
