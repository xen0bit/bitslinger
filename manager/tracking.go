package manager

import "C"
import (
	"sync"

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

// AddPacket ingests
func (pq *PacketQueue) AddPacket(p *netfilter.NFPacket) (pckt *KnownPacket) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if applayer := p.Packet.ApplicationLayer(); applayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return &KnownPacket{ok: false}
	}

	// instantiate our type that implements the Packet interface
	// generate UUID to Identify packet during this
	pckt = &KnownPacket{
		p:    p,
		ok:   true,
		mu:   &sync.RWMutex{},
		uuid: uuid.New().String(),
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

// KnownPacket implements the Packet interface and helps us keep track of netfilter packets.
type KnownPacket struct {
	uuid string
	p    *netfilter.NFPacket
	ok   bool
	mu   *sync.RWMutex
}

// Data is a concurrent safe way to return the byte slice of of the underlying netfilter.Packet data.
func (tp KnownPacket) Data() []byte {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.p.Packet.Data()
}

// SetVerdict is a concurrent safe wrapper around netfilter.Packet.SetVerdict.
func (tp KnownPacket) SetVerdict(verdict nfVerdict) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetVerdict(verdict)
}

// SetRequeueVerdict is a concurrent safe wrapper around netfilter.Packet.SetRequeueVerdict.
func (tp KnownPacket) SetRequeueVerdict(u uint16) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetRequeueVerdict(u)
}

// SetVerdictWithPacket is a concurrent safe wrapper around netfilter.Packet.SetVerdictWithPacket.
func (tp KnownPacket) SetVerdictWithPacket(v nfVerdict, packet []byte) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.p.SetVerdictWithPacket(v, packet)
}

// UUID returns the unique identifier that bitslinger uses to reference KnownPacket instances.
func (tp KnownPacket) UUID() string {
	return tp.uuid
}

// AppLayer returns the application layer of the underlying Packet implementation.
func (tp KnownPacket) AppLayer() gopacket.ApplicationLayer {
	return tp.p.Packet.ApplicationLayer()
}

// Valid returns if we consider this packet valid for us to track or not.
func (tp KnownPacket) Valid() bool {
	return tp.ok
}
