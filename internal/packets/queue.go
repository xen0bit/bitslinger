package packets

import "C"
import (
	"sync"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/uuid"

	"github.com/xen0bit/bitslinger/internal/common"
)

// PacketQueue keeps track of relevant packets via libnetfilter_queue.
type PacketQueue struct {
	packets map[string]common.Packet
	mu      *sync.RWMutex
}

// NewPacketQueue instantiates our packet tracker/packets.
func NewPacketQueue() *PacketQueue {
	return &PacketQueue{
		mu:      &sync.RWMutex{},
		packets: make(map[string]common.Packet),
	}
}

// FromUUID safely attempts to retrieve a packet by referencing a UUID that we previously generated.
func (pq *PacketQueue) FromUUID(UUID string) (pckt common.Packet, ok bool) {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	pckt, ok = pq.packets[UUID]
	return
}

// NewPacket ingests a netfilter packet and prepares it as a KnownPacket.
func (pq *PacketQueue) NewPacket(p *netfilter.NFPacket) (pckt common.Packet) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if applayer := p.Packet.ApplicationLayer(); applayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return &KnownPacket{ok: false, mu: &sync.RWMutex{}}
	}

	// instantiate our type that implements the Packet interface
	// generate UUID to Identify packet during this
	pckt = &KnownPacket{
		nfp:     p,
		ok:      true,
		mu:      &sync.RWMutex{},
		uuid:    uuid.New().String(),
		payload: p.Packet.Data(),
		manager: pq,
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
