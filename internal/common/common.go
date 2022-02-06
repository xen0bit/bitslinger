package common

import (
	"errors"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
)

// ErrUnknownPacket is what we throw internally when we haven't a clue what the client is babbling about.
var ErrUnknownPacket = errors.New("packet UUID Not found")

type nfVerdict netfilter.Verdict

type PacketStack uint8

const (
	Unknown PacketStack = iota
	IPv4
	IPv6
	TCP4
	TCP6
	UDP4
	UDP6
)

// Packet represents a type that contains the necessary information we need to track a packet from libnetfilter_queue.
type Packet interface {
	UUID() string

	Payload() []byte
	AppLayer() gopacket.ApplicationLayer
	Timestamp() time.Time

	SetVersion(uint8)
	GetVersion() uint8

	SetPayload([]byte)
	SetVerdict(interface{})
	SetRequeueVerdict(uint16)
	SetVerdictWithPacket(v interface{}, packet []byte)

	Release()

	Valid() bool
	Latency() time.Duration
}
