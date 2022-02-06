package packets

import (
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var Queue *PacketQueue

func init() {
	Queue = NewPacketQueue()
}

func ReleaseModifiedPacket(packetUUID string, packetPayload []byte) {
	slog := log.With().Str("caller", packetUUID).Logger()

	// Look up nfqueue pointer
	p, ok := Queue.FromUUID(packetUUID)

	if !ok {
		slog.Debug().Msg("Packet UUID Not found")
		return
	}
	slog.Trace().Str("rtt", p.Latency().String()).Msg("latency")

	// Decode packet from nfqueue
	packet := gopacket.NewPacket(p.Data(), layers.LayerTypeIPv4, gopacket.Default)

	// Check that packet has a app payload and has been modifed
	app := packet.ApplicationLayer()
	if app == nil {
		// Packet did not have application layer, default accept
		slog.Trace().Msg("no application layer, releasing...")
		Queue.AcceptAndRelease(packetUUID)
		return
	}
	if testEq(packetPayload, app.Payload()) {
		slog.Trace().Msg("packet not modified, releasing...")
		Queue.AcceptAndRelease(packetUUID)
		return
	}

	buffer, ok := reconstructPacket(packetUUID, packet, packetPayload)
	if ok {
		packetBytes := buffer.Bytes()
		p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packetBytes)
	}

	Queue.Release(packetUUID)
}