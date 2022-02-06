package packets

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var (
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	arp layers.ARP
)

/*// Stream the byte slice of the underlying byte slices, hold a readlock on it while we do this to avoid mutation.
// Reference: https://pkg.go.dev/github.com/google/gopacket@v1.1.19#hdr-Lazy_Decoding
func (kp *KnownPacket) Stream() {
	kp.mu.RLock()
	kp.mu.RUnlock()
}
*/

// Reconstruct reconstructs our packet with the new given payload.
func (kp *KnownPacket) Reconstruct(newPayload []byte) (buffer gopacket.SerializeBuffer, ok bool) {
	slog := log.With().Str("caller", kp.UUID()).Logger()

	slog.Trace().Msg("reconstructing packet...")
	defer slog.Trace().Msg("done reconstructing, releasing!")

	// Set flags for TCP vs UDP
	isTCP := kp.gop.Layer(layers.LayerTypeTCP) != nil
	isUDP := kp.gop.Layer(layers.LayerTypeUDP) != nil
	/*	isARP := kp.gop.Layer(layers.LayerTypeARP) != nil
		isDHCP4 := kp.gop.Layer(layers.LayerTypeDHCPv4) != nil
	*/
	// Configure Checksums
	switch {
	case isTCP:
		err := kp.gop.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(kp.gop.NetworkLayer())
		if err == nil {
			slog.Trace().Msg("packet is TCP...")
			break
		}
		slog.Warn().Err(err).Caller().Msg("Failed to set TCP network layer for checksum")
		break
	case isUDP:
		err := kp.gop.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(kp.gop.NetworkLayer())
		if err == nil {
			slog.Trace().Msg("packet is UDP...")
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
			kp.gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			kp.gop.Layer(layers.LayerTypeTCP).(*layers.TCP),
			gopacket.Payload(newPayload),
		)
		if err != nil {
			slog.Warn().Err(err).Msg("TCP serialization failure")
			return
		}
	case udp:
		if err := gopacket.SerializeLayers(buffer, options,
			kp.gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			kp.gop.Layer(layers.LayerTypeUDP).(*layers.UDP),
			gopacket.Payload(newPayload),
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
