package manager

import "C"
import (
	"sync"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// PacketTracker keeps track of relevant packets via libnetfilter_queue.
type PacketTracker struct {
	packets map[string]Packet
	mu      *sync.RWMutex
}

// NewPacketTracker instantiates our package tracker/manager.
func NewPacketTracker() *PacketTracker {
	return &PacketTracker{
		mu:      &sync.RWMutex{},
		packets: make(map[string]Packet),
	}
}

// FromUUID safely attempts to retrieve a packet by referencing a UUID that we previously generated.
func (tracker *PacketTracker) FromUUID(UUID string) (pckt Packet, ok bool) {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	pckt, ok = tracker.packets[UUID]
	return
}

// StartTracking ingests
func (tracker *PacketTracker) StartTracking(p *netfilter.NFPacket) (pckt *TrackedPacket) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if applayer := p.Packet.ApplicationLayer(); applayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return &TrackedPacket{ok: false}
	}

	// instantiate our type that implements the Packet interface
	// generate UUID to Identify packet during this
	pckt = &TrackedPacket{
		p:    p,
		ok:   true,
		mu:   &sync.RWMutex{},
		uuid: uuid.New().String(),
	}

	// Insert marker into PacketTracker
	tracker.packets[pckt.UUID()] = pckt

	return
}

// AcceptAndRelease sets the netfilter verdict to NF_ACCEPT before Releasing the packet referenced by given packetUUID.
func (tracker *PacketTracker) AcceptAndRelease(packetUUID string) {
	pckt, _ := tracker.FromUUID(packetUUID)
	pckt.SetVerdict(netfilter.NF_ACCEPT)
	tracker.Release(packetUUID)
}

// Release stops tracking a packet referenced by the given packetUUID.
func (tracker *PacketTracker) Release(packetUUID string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	// Remove UUID from map
	delete(tracker.packets, packetUUID)
}

type nfVerdict C.uint

// Packet represents a type that contains the necessary information we need to track a packet from libnetfilter_queue.
type Packet interface {
	UUID() string
	AppLayer() gopacket.ApplicationLayer
	Data() []byte

	SetVerdict(nfVerdict)
	SetRequeueVerdict(uint16)
	SetVerdictWithPacket(v nfVerdict, packet []byte)

	Valid() bool
}

// TrackedPacket implements the Packet interface and helps us keep track of netfilter packets.
type TrackedPacket struct {
	uuid string
	p    *netfilter.NFPacket
	ok   bool
	mu   *sync.RWMutex
}

// Data is a concurrent safe way to return the byte slice of of the underlying netfilter.Packet data.
func (tp TrackedPacket) Data() []byte {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.p.Packet.Data()
}

// SetVerdict is a concurrent safe wrapper around netfilter.Packet.SetVerdict.
func (tp TrackedPacket) SetVerdict(verdict nfVerdict) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetVerdict(verdict)
}

// SetRequeueVerdict is a concurrent safe wrapper around netfilter.Packet.SetRequeueVerdict.
func (tp TrackedPacket) SetRequeueVerdict(u uint16) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetRequeueVerdict(u)
}

// SetVerdictWithPacket is a concurrent safe wrapper around netfilter.Packet.SetVerdictWithPacket.
func (tp TrackedPacket) SetVerdictWithPacket(v nfVerdict, packet []byte) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetVerdictWithPacket(v, packet)
}

// UUID returns the unique identifier that bitslinger uses to reference TrackedPacket instances.
func (tp TrackedPacket) UUID() string {
	return tp.uuid
}

// AppLayer returns the application layer of the underlying Packet implementation.
func (tp TrackedPacket) AppLayer() gopacket.ApplicationLayer {
	return tp.p.Packet.ApplicationLayer()
}

// Valid returns if we consider this packet valid for us to track or not.
func (tp TrackedPacket) Valid() bool {
	return tp.ok
}
