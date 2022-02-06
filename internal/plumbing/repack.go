package plumbing

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

type packetProto uint8

const (
	unknown packetProto = iota
	tcp
	udp
)

func reconstructPacket(packetUUID string, packet gopacket.Packet, packetPayload []byte) (buffer gopacket.SerializeBuffer, ok bool) {
	slog := log.With().Str("caller", packetUUID).Logger()

	defer slog.Trace().Msg("done reconstructing, released!")

	var pp packetProto = unknown

	slog.Trace().Msg("reconstructing packet....")

	// Set flags for TCP vs UDP
	isTCP := packet.Layer(layers.LayerTypeTCP) != nil
	isUDP := packet.Layer(layers.LayerTypeUDP) != nil

	// Configure Checksums
	switch {
	case isTCP:
		err := packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err == nil {
			slog.Trace().Msg("packet is TCP...")
			pp = tcp
			break
		}
		slog.Warn().Err(err).Caller().Msg("Failed to set TCP network layer for checksum")
		break
	case isUDP:
		err := packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err == nil {
			slog.Trace().Msg("packet is UDP...")
			pp = udp
			break
		}
		slog.Warn().Err(err).Caller().Msg("Failed to set UDP network layer for checksum")
		break
	default:
		slog.Trace().Caller().Msg("unhandled packet")
		return
	}

	slog.Trace().Msg("Setting packet options...")

	// Rebuild with new payload
	buffer = gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	slog.Trace().Msg("Reserializing packet...")

	switch pp {
	case tcp:

		err := gopacket.SerializeLayers(buffer, options,
			packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			packet.Layer(layers.LayerTypeTCP).(*layers.TCP),
			gopacket.Payload(packetPayload),
		)

		if err != nil {
			slog.Warn().Err(err).Msg("TCP serialization failure")
			return
		}
	case udp:
		if err := gopacket.SerializeLayers(buffer, options,
			packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			packet.Layer(layers.LayerTypeUDP).(*layers.UDP),
			gopacket.Payload(packetPayload),
		); err != nil {
			slog.Warn().Err(err).Msg("UDP serialization failure")
			return
		}
	default:
		slog.Debug().Msg("unhandled packet")
		return
	}

	ok = true
	return
}
