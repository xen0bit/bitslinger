# manager

#### type KnownPacket

```go
type KnownPacket struct {
}
```

KnownPacket implements the Packet interface and helps us keep track of netfilter
packets.

#### func (KnownPacket) AppLayer

```go
func (kp KnownPacket) AppLayer() gopacket.ApplicationLayer
```
AppLayer returns the application layer of the underlying Packet implementation.

#### func (KnownPacket) Data

```go
func (kp KnownPacket) Data() []byte
```
Data is a concurrent safe way to return the byte slice of of the underlying
netfilter.Packet data.

#### func (KnownPacket) SetRequeueVerdict

```go
func (kp KnownPacket) SetRequeueVerdict(u uint16)
```
SetRequeueVerdict is a concurrent safe wrapper around
netfilter.Packet.SetRequeueVerdict.

#### func (KnownPacket) SetVerdict

```go
func (kp KnownPacket) SetVerdict(verdict interface{})
```
SetVerdict is a concurrent safe wrapper around netfilter.Packet.SetVerdict.

#### func (KnownPacket) SetVerdictWithPacket

```go
func (kp KnownPacket) SetVerdictWithPacket(v interface{}, packet []byte)
```
SetVerdictWithPacket is a concurrent safe wrapper around
netfilter.Packet.SetVerdictWithPacket.

#### func (KnownPacket) UUID

```go
func (kp KnownPacket) UUID() string
```
UUID returns the unique identifier that bitslinger uses to reference KnownPacket
instances.

#### func (KnownPacket) Valid

```go
func (kp KnownPacket) Valid() bool
```
Valid returns if we consider this packet valid for us to track or not.

#### type Packet

```go
type Packet interface {
	UUID() string
	AppLayer() gopacket.ApplicationLayer
	Data() []byte

	SetVerdict(interface{})
	SetRequeueVerdict(uint16)
	SetVerdictWithPacket(v interface{}, packet []byte)

	Valid() bool
}
```

Packet represents a type that contains the necessary information we need to
track a packet from libnetfilter_queue.

#### type PacketQueue

```go
type PacketQueue struct {
}
```

PacketQueue keeps track of relevant packets via libnetfilter_queue.

#### func  NewPacketQueue

```go
func NewPacketQueue() *PacketQueue
```
NewPacketQueue instantiates our package tracker/manager.

#### func (*PacketQueue) AcceptAndRelease

```go
func (pq *PacketQueue) AcceptAndRelease(packetUUID string)
```
AcceptAndRelease sets the netfilter verdict to NF_ACCEPT before Releasing the
packet referenced by given packetUUID.

#### func (*PacketQueue) AddPacket

```go
func (pq *PacketQueue) AddPacket(p *netfilter.NFPacket) (pckt Packet)
```
AddPacket ingests a netfilter packet and prepares it as a KnownPacket.

#### func (*PacketQueue) FromUUID

```go
func (pq *PacketQueue) FromUUID(UUID string) (pckt Packet, ok bool)
```
FromUUID safely attempts to retrieve a packet by referencing a UUID that we
previously generated.

#### func (*PacketQueue) Release

```go
func (pq *PacketQueue) Release(packetUUID string)
```
Release stops tracking a packet referenced by the given packetUUID.
