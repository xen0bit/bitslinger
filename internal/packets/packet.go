package packets

import (
	"sync"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/common"
)

// KnownPacket implements the Packet interface and helps us keep track of netfilter packets.
type KnownPacket struct {
	uuid    string
	nfp     *netfilter.NFPacket
	gop     gopacket.Packet
	payload []byte

	v4, v6, tcp, udp bool
	trace            *zerolog.Logger

	ok      bool
	mu      *sync.RWMutex
	manager *PacketQueue

	// gopacket.Packet contains this metadata:
	// ts      time.Time
	//
	// "CaptureInfo provides standardized information about a packet captured off the wire or read from a file."
}

// Payload is a concurrent safe way to return the byte slice of of the underlying netfilter.Packet data.
func (kp KnownPacket) Payload() []byte {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	// The idea here is that if the data bytes in our struct are somehow empty, we refer to the original data.
	if len(kp.payload) < 1 {
		log.Warn().Str("caller", kp.UUID()).Caller().Msg("kp.data was empty, it shouldn't have been")
		return kp.nfp.Packet.Data()
	}

	return kp.payload
}

// SetVerdict is a concurrent safe wrapper around netfilter.Packet.SetVerdict.
func (kp KnownPacket) SetVerdict(verdict interface{}) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.nfp.SetVerdict(verdict.(netfilter.Verdict))
}

// Release releases the packet from nfqueue to continue on it's miserable, mangled journey.
func (kp KnownPacket) Release() {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.manager.Release(kp.uuid)
}

// SetPayload changes the packet's payload that we have stored with presumably a modified version of it's former self.
func (kp KnownPacket) SetPayload(data []byte) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.payload = data
}

// SetRequeueVerdict is a concurrent safe wrapper around netfilter.Packet.SetRequeueVerdict.
func (kp KnownPacket) SetRequeueVerdict(u uint16) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.nfp.SetRequeueVerdict(u)
}

// SetVerdictWithPacket is a concurrent safe wrapper around netfilter.Packet.SetVerdictWithPacket.
func (kp KnownPacket) SetVerdictWithPacket(verdict interface{}, data []byte) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.payload = data
	kp.nfp.SetVerdictWithPacket(verdict.(netfilter.Verdict), kp.payload)
}

// UUID returns the unique identifier that bitslinger uses to reference KnownPacket instances.
func (kp KnownPacket) UUID() string {
	return kp.uuid
}

// AppLayer returns the application layer of the underlying Packet implementation.
func (kp KnownPacket) AppLayer() gopacket.ApplicationLayer {
	return kp.gop.ApplicationLayer()
}

// Valid returns if we consider this packet valid for us to track or not.
func (kp KnownPacket) Valid() bool {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.ok
}

// Timestamp returns the time that this packet was first captured.
func (kp KnownPacket) Timestamp() time.Time {
	return kp.gop.Metadata().Timestamp
}

// Latency returns the RTT time since the packet became known to us
func (kp KnownPacket) Latency() time.Duration {
	return time.Since(kp.Timestamp())
}

func (kp KnownPacket) TraceLog() *zerolog.Logger {
	return kp.trace
}

func (kp KnownPacket) SetVersion(known uint8) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	switch common.PacketStack(known) {
	case common.IPv4, common.TCP4, common.UDP4:
		kp.v4 = true
		kp.v6 = false
	case common.IPv6, common.TCP6, common.UDP6:
		kp.v4 = false
		kp.v6 = true
	default:
		kp.v4 = false
		kp.v6 = false
		kp.tcp = false
		kp.udp = false
		return
	}

	switch common.PacketStack(known) {
	case common.TCP4, common.TCP6:
		kp.tcp = true
		kp.udp = false
	case common.UDP4, common.UDP6:
		kp.tcp = false
		kp.udp = true
	default:
		kp.tcp = false
		kp.udp = false
		return
	}
}

func (kp KnownPacket) GetVersion() uint8 {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	switch {
	case kp.v4:
		if kp.tcp {
			return uint8(common.TCP4)
		}
		if kp.udp {
			return uint8(common.UDP4)
		}
		return uint8(common.IPv4)
	case kp.v6:
		if kp.tcp {
			return uint8(common.TCP6)
		}
		if kp.udp {
			return uint8(common.UDP6)
		}
		return uint8(common.IPv6)
	default:
		return uint8(common.Unknown)
	}
}
