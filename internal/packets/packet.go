package packets

import (
	"sync"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/rs/zerolog/log"
)

// KnownPacket implements the Packet interface and helps us keep track of netfilter packets.
type KnownPacket struct {
	uuid    string
	nfp     *netfilter.NFPacket
	gop     gopacket.Packet
	payload []byte

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
	return kp.nfp.Packet.ApplicationLayer()
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
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return time.Since(kp.Timestamp())
}
