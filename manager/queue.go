package manager

import "C"
import (
	"sync"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// PacketQueue keeps track of relevant packets via libnetfilter_queue.
type PacketQueue struct {
	packets map[string]Packet
	mu      *sync.RWMutex
}

// NewPacketQueue instantiates our package tracker/manager.
func NewPacketQueue() *PacketQueue {
	return &PacketQueue{
		mu:      &sync.RWMutex{},
		packets: make(map[string]Packet),
	}
}

// FromUUID safely attempts to retrieve a packet by referencing a UUID that we previously generated.
func (pq *PacketQueue) FromUUID(UUID string) (pckt Packet, ok bool) {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	pckt, ok = pq.packets[UUID]
	return
}

// AddPacket ingests a netfilter packet and prepares it as a KnownPacket.
func (pq *PacketQueue) AddPacket(p *netfilter.NFPacket) (pckt Packet) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if applayer := p.Packet.ApplicationLayer(); applayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return &KnownPacket{ok: false, mu: &sync.RWMutex{}}
	}

	// instantiate our type that implements the Packet interface
	// generate UUID to Identify packet during this
	pckt = &KnownPacket{
		p:    p,
		ok:   true,
		mu:   &sync.RWMutex{},
		uuid: uuid.New().String(),
		ts:   time.Now(),
	}

	// Insert marker into PacketQueue
	pq.packets[pckt.UUID()] = pckt

	return
}

// AcceptAndRelease sets the netfilter verdict to NF_ACCEPT before Releasing the packet referenced by given packetUUID.
func (pq *PacketQueue) AcceptAndRelease(packetUUID string) {
	pckt, _ := pq.FromUUID(packetUUID)
	pckt.SetVerdict(netfilter.NF_ACCEPT)
	pq.Release(packetUUID)
}

// Release stops tracking a packet referenced by the given packetUUID.
func (pq *PacketQueue) Release(packetUUID string) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	// Remove UUID from map
	delete(pq.packets, packetUUID)
}

type nfVerdict netfilter.Verdict

// Packet represents a type that contains the necessary information we need to track a packet from libnetfilter_queue.
type Packet interface {
	UUID() string
	AppLayer() gopacket.ApplicationLayer
	Data() []byte

	SetVerdict(interface{})
	SetRequeueVerdict(uint16)
	SetVerdictWithPacket(v interface{}, packet []byte)

	Valid() bool

	Latency() time.Duration
}

// KnownPacket implements the Packet interface and helps us keep track of netfilter packets.
type KnownPacket struct {
	uuid string
	p    *netfilter.NFPacket
	ok   bool
	mu   *sync.RWMutex
	ts   time.Time
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
