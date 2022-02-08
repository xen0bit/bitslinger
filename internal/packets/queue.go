package packets

import "C"
import (
	"sync"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/common"
)

var Queue *PacketQueue

var rejected = &KnownPacket{ok: false}

func init() {
	Queue = NewPacketQueue()
}

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
func (pq *PacketQueue) NewPacket(p *netfilter.NFPacket) (kp common.Packet) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// netfilter package has already read the packet for us using lazy and nocopy, we should know the layers now.

	discard := func(p *netfilter.NFPacket, missing string) *KnownPacket {
		log.Trace().Msgf("missing %s layer, discard", missing)
		p.SetVerdict(netfilter.NF_ACCEPT)
		return rejected
	}

	// ethl := p.Packet.LinkLayer()
	netl := p.Packet.NetworkLayer()
	ip4, ok4 := netl.(*layers.IPv4)
	ip6, ok6 := netl.(*layers.IPv6)

	switch {
	// case ethl == nil:
	//	return discard(p, "ethernet")
	case netl == nil:
		return discard(p, "network")
	case !ok4 && !ok6:
		return discard(p, "IP")
	}

	// trace := log.With().
	// 	MACAddr("src", ethl.LinkFlow().Src().Raw()).
	// 	MACAddr("dst", ethl.LinkFlow().Dst().Raw()).Logger()

	// total shim, ignore
	trace := log.With().Str("NewPacket", "trace").Logger()

	// instantiate our type that implements the Packet interface
	// generate UUID to Identify packet during this
	kp = &KnownPacket{
		gop:     p.Packet,
		mu:      &sync.RWMutex{},
		manager: pq,
		trace:   &trace,
		uuid:    uuid.New().String(),
		ok:      true,
	}

	kp.(*KnownPacket).TraceLog().Trace().Msg("link layer found")

	switch {
	case ok4:
		kp.SetVersion(uint8(common.IPv4))
		trace2 := trace.With().Str("flow", ip4.NetworkFlow().String()).Logger()
		kp.(*KnownPacket).trace = &trace2
		trace = zerolog.Logger{}
	case ok6:
		kp.SetVersion(uint8(common.IPv6))
		trace2 := trace.With().Str("flow", ip6.NetworkFlow().String()).Logger()
		kp.(*KnownPacket).trace = &trace2
		trace = zerolog.Logger{}
	default:
		return discard(p, "IP")
	}

	kp.(*KnownPacket).TraceLog().Trace().Msg("link layer found")

	if applayer := p.Packet.ApplicationLayer(); applayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return &KnownPacket{ok: false, mu: &sync.RWMutex{}}
	}

	/*
		nfp:     p,
		ok:      true,
		uuid:    uuid.New().String(),
		payload: p.Packet.Data(),*/

	// Insert marker into PacketQueue
	pq.packets[kp.UUID()] = kp

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

func testEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
