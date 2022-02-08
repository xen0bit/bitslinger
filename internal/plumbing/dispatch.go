package plumbing

import (
	"bytes"
	"encoding/hex"
	"net/http"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/common"
	"github.com/xen0bit/bitslinger/internal/opts"
	"github.com/xen0bit/bitslinger/internal/packets"
)

var (
	wsConn     *websocket.Conn
	httpClient = &http.Client{
		Timeout:   0,
		Transport: &http.Transport{Proxy: http.ProxyURL(opts.ProxyURL)},
	}
)

// SendToProxy handles an incoming packet to be sent to the appropriate proxy listener as defined by opts.
func SendToProxy(p *netfilter.NFPacket) int {
	// gpq.Lock()
	// defer gpq.Unlock()
	// Decode a packet
	// packet := gopacket.NewPacket(payload.Payload, layers.LayerTypeIPv4, gopacket.Default)

	pckt := packets.Queue.NewPacket(p)
	if !pckt.Valid() {
		return 0
	}

	log.Trace().Caller().Str("caller", pckt.UUID()).Msg("New Packet")

	switch opts.Mode {
	case opts.Websockets:
		log.Trace().Caller().Str("caller", pckt.UUID()).Msg("-> WebSocket")
		SendPacketToWS(pckt)
	case opts.HTTP:
		log.Trace().Caller().Str("caller", pckt.UUID()).Msg("-> HTTP")
		SendPacketToHTTP(pckt)
	default:
		log.Panic().Uint8("mode", uint8(opts.Mode)).Msg("unknown handler mode")
	}

	// Needed for C API
	return 0
}

// SendPacketToHTTP handles an incoming packet destined for further handling by clients of the interactive HTTP server.
func SendPacketToHTTP(pckt common.Packet) {
	slog := log.With().Caller().Str("caller", pckt.UUID()).Logger()

	// HTTP Mode
	hexEncodedPayload := []byte(hex.EncodeToString(pckt.AppLayer().Payload()))
	payloadReader := bytes.NewReader(hexEncodedPayload)
	req, err := http.NewRequest("POST", "http://"+opts.BindAddr+"/bitslinger", payloadReader)
	if err != nil {
		slog.Error().Err(err).Msg("failed to craft http request")
		return
	}

	req.Header.Add("Packet-Uuid", pckt.UUID())
	slog.Trace().Str("body", string(hexEncodedPayload)).Msg("Sending HTTP Request")
	resp, err := httpClient.Do(req)
	defer closeResponse(resp)

	if err == nil {
		return
	}

	slog.Warn().Msg("HTTP Proxy communication failed, Default forwarding packet as-is")
	packets.Queue.AcceptAndRelease(pckt.UUID())
}

// SendPacketToWS  handles an incoming packet destined for further handling by clients of the interactive websocket server.
func SendPacketToWS(pckt common.Packet) {
	slog := log.With().Str("caller", pckt.UUID()).Logger()

	defer slog.Trace().Msg("SendPacketToWS done")

	hexEncodedPayload := []byte(pckt.UUID() + "\n" + hex.EncodeToString(pckt.AppLayer().Payload()))
	if wsConn == nil {
		slog.Warn().Caller().Msg("WebSocket proxy communication failed, Default forwarding packet as-is")
		pckt.SetVerdict(netfilter.NF_ACCEPT)
		packets.Queue.Release(pckt.UUID())
		return
	}

	err := wsConn.WriteMessage(websocket.TextMessage, hexEncodedPayload)
	if err != nil {
		slog.Warn().Err(err).Msg("WebSocket proxy communication failed, Default forwarding packet as-is")
		packets.Queue.AcceptAndRelease(pckt.UUID())
	}

}
