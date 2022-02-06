package packets

import (
	"sync"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
)

// KnownPacket implements the Packet interface and helps us keep track of netfilter packets.
type KnownPacket struct {
	uuid    string
	p       *netfilter.NFPacket
	ok      bool
	mu      *sync.RWMutex
	ts      time.Time
	manager *PacketQueue
}

// Data is a concurrent safe way to return the byte slice of of the underlying netfilter.Packet data.
func (kp KnownPacket) Data() []byte {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.p.Packet.Data()
}

// SetVerdict is a concurrent safe wrapper around netfilter.Packet.SetVerdict.
func (kp KnownPacket) SetVerdict(verdict interface{}) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.p.SetVerdict(verdict.(netfilter.Verdict))
}

// Release releases the packet from nfqueue to continue on it's miserable, mangled journey.
func (kp KnownPacket) Release() {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.manager.Release(kp.UUID())
}

// SetRequeueVerdict is a concurrent safe wrapper around netfilter.Packet.SetRequeueVerdict.
func (kp KnownPacket) SetRequeueVerdict(u uint16) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.p.SetRequeueVerdict(u)
}

// SetVerdictWithPacket is a concurrent safe wrapper around netfilter.Packet.SetVerdictWithPacket.
func (kp KnownPacket) SetVerdictWithPacket(v interface{}, packet []byte) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.p.SetVerdictWithPacket(v.(netfilter.Verdict), packet)
}

// UUID returns the unique identifier that bitslinger uses to reference KnownPacket instances.
func (kp KnownPacket) UUID() string {
	return kp.uuid
}

// AppLayer returns the application layer of the underlying Packet implementation.
func (kp KnownPacket) AppLayer() gopacket.ApplicationLayer {
	return kp.p.Packet.ApplicationLayer()
}

// Valid returns if we consider this packet valid for us to track or not.
func (kp KnownPacket) Valid() bool {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return kp.ok
}

// Latency returns the RTT time since the packet became known to us
func (kp KnownPacket) Latency() time.Duration {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return time.Since(kp.ts)
}
