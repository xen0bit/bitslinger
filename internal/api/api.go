package api

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/opts"
	"github.com/xen0bit/bitslinger/internal/plumbing"
	"github.com/xen0bit/bitslinger/internal/queue"
)

var (
	wsConn     *websocket.Conn
	httpClient *http.Client
)

var upgrader = websocket.Upgrader{
	EnableCompression: false,
}

func HandleHTTPPayload(w http.ResponseWriter, req *http.Request) {
	// Retrieve Packet UUID from request
	packetUUID := req.Header.Get("Packet-Uuid")
	slog := log.With().Str("caller", packetUUID).Logger()
	// Retrieve hex from request body and cast as bytes
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		slog.Warn().Err(err).Caller().Msg("failed to receive payload over HTTP")
		return
	}
	packetPayload, err := hex.DecodeString(string(body))
	if err != nil {
		slog.Warn().Err(err).Caller().Msg("failed to decode HTTP request body")
	}
	plumbing.ReleasePacket(packetUUID, packetPayload)
	w.WriteHeader(200)
}

func HandleWebsocketPayload(w http.ResponseWriter, r *http.Request) {
	slog := log.With().Str("caller", r.RemoteAddr).Logger()

	slog.Trace().Msg("websocket payload received...")

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn().Err(err).Msg("Failed to upgrade websocket conn")
		return
	}

	slog.Info().Str("caller", r.RemoteAddr).Msg("WS Client Connected")

	// slog.SetOutput(ioutil.Discard)
	c.EnableWriteCompression(false)
	err = c.SetCompressionLevel(0)
	if err != nil {
		log.Debug().Err(err).Str("caller", r.RemoteAddr).Caller().Msg("failed to disable compression")
	}

	wsConn = c

	defer func(c *websocket.Conn) {
		err := c.Close()
		if err != nil {
			slog.Debug().Err(err).Msg("Failed to properly close websocket handler")
		} else {
			slog.Trace().Msg("done with websocket payload")
		}

	}(c)

	for {
		// wsConn.SetReadDeadline(time.Now().Add(time.Second * 1))
		_, message, err := c.ReadMessage()
		if err != nil {
			slog.Warn().Err(err).Msg("read error")
			break
		}

		slog.Trace().Msg(string(message))

		// Segment Message
		segments := strings.Split(string(message), "\n")
		if len(segments) != 2 {
			slog.Warn().Str("message", string(message)).Msg("unexpected message format")
			continue
		}

		slog.Trace().Strs("segments", segments).Msg("websocket message")

		packetUUID := segments[0]
		payloadHex := segments[1]
		packetPayload, err := hex.DecodeString(payloadHex)

		if err != nil {
			slog.Error().Err(err).Interface("payload", payloadHex).Msg("Packet decode failure!")
			continue
		}

		plumbing.ReleasePacket(packetUUID, packetPayload)

	}
}

func closeResponse(resp *http.Response) {
	if resp != nil {
		slog := log.With().Str("caller", resp.Request.Header.Get("Packet-Uuid")).Logger()
		err := resp.Body.Close()
		if err != nil {
			slog.Warn().Err(err).Caller().Msg("failed close response body...")
		}
		slog.Trace().Interface("status", resp.StatusCode).Msg("SendPacketToHTTP done")
	}
}

func SendPacketToHTTP(pckt queue.Packet) {
	slog := log.With().Str("caller", pckt.UUID()).Logger()

	// HTTP Mode
	hexEncodedPayload := []byte(hex.EncodeToString(pckt.AppLayer().Payload()))
	payloadReader := bytes.NewReader(hexEncodedPayload)
	req, err := http.NewRequest("POST", "http://"+opts.ProxyURI+"/bitslinger", payloadReader)
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
	gpq.AcceptAndRelease(pckt.UUID())
}

func SendPacketToWS(pckt queue.Packet) {
	slog := log.With().Str("caller", pckt.UUID()).Logger()

	defer slog.Trace().Msg("SendPacketToWS done")

	hexEncodedPayload := []byte(pckt.UUID() + "\n" + hex.EncodeToString(pckt.AppLayer().Payload()))
	if wsConn != nil {
		err := wsConn.WriteMessage(websocket.TextMessage, hexEncodedPayload)
		if err != nil {
			slog.Warn().Err(err).Msg("WebSocket proxy communication failed, Default forwarding packet as-is")
			gpq.AcceptAndRelease(pckt.UUID())
		}
	} else {
		slog.Warn().Caller().Msg("WebSocket proxy communication failed, Default forwarding packet as-is")
		pckt.SetVerdict(netfilter.NF_ACCEPT)
		gpq.Release(pckt.UUID())
	}
}

func ListenAndServeWebsockets() {
	// WebSocket Listener
	http.HandleFunc("/bitslinger", HandleWebsocketPayload)
	log.Info().Msgf("Starting WS listener on: %s\n", "ws://"+server+"/bitslinger")
	log.Fatal().Err(http.ListenAndServe(server, nil)).Msg("Websocket listen failure")
}

func ListenAndServeHTTP() {
	// HTTP Sender

	httpClient = &http.Client{
		Timeout:   0,
		Transport: &http.Transport{Proxy: http.ProxyURL(opts.ProxyURL)},
	}
	// HTTP Listener
	http.HandleFunc("/bitslinger", HandleHTTPPayload)

	log.Info().Msgf("Starting HTTP listener on: %s\n", "http://"+opts.ProxyURI+"/bitslinger")

	log.Fatal().Err(http.ListenAndServe(opts.ProxyURI, nil)).Msg("HTTP listen failure")
}
