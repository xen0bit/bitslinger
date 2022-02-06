package common

import (
	"errors"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
)

var ErrUnknownPacket = errors.New("packet UUID Not found")

type nfVerdict netfilter.Verdict

// Packet represents a type that contains the necessary information we need to track a packet from libnetfilter_queue.
type Packet interface {
	UUID() string

	Payload() []byte
	AppLayer() gopacket.ApplicationLayer
	Timestamp() time.Time

	SetPayload([]byte)
	SetVerdict(interface{})
	SetRequeueVerdict(uint16)
	SetVerdictWithPacket(v interface{}, packet []byte)

	Release()

	Valid() bool
	Latency() time.Duration
}
