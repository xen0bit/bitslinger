package api

import (
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/opts"
	"github.com/xen0bit/bitslinger/internal/packets"
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
	packets.ReleaseModifiedPacket(packetUUID, packetPayload)
	w.WriteHeader(200)
}

func HandleIncomingWS(w http.ResponseWriter, r *http.Request) {
	slog := log.With().Str("caller", r.RemoteAddr).Logger()

	slog.Trace().Msg("websocket payload received...")

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn().Err(err).Msg("Failed to upgrade websocket conn")
		return
	}

	slog.Info().Str("caller", r.RemoteAddr).Msg("WS Client Connected")

	// slog.SetOutput(ioutil.Discard)
	wsConn.EnableWriteCompression(false)
	err = wsConn.SetCompressionLevel(0)
	if err != nil {
		log.Debug().Err(err).Str("caller", r.RemoteAddr).Caller().Msg("failed to disable compression")
	}

	defer closeWebsocket(wsConn)

	for {
		// wsConn.SetReadDeadline(time.Now().Add(time.Second * 1))
		_, message, err := wsConn.ReadMessage()
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

		packets.ReleaseModifiedPacket(packetUUID, packetPayload)

	}
}

func ListenAndServeWebsockets() {
	// WebSocket Listener
	http.HandleFunc("/bitslinger", HandleIncomingWS)
	log.Info().Msgf("Starting WS listener on: %s\n", "ws://"+opts.BindAddr+"/bitslinger")
	log.Fatal().Err(http.ListenAndServe(opts.ProxyDestination, nil)).Msg("Websocket listen failure")
}

func ListenAndServeHTTP() {
	// HTTP Sender

	// HTTP Listener
	http.HandleFunc("/bitslinger", HandleHTTPPayload)

	// TODO: Fix the wording/semantics here, it's a little confusing that we're listening on the InterActiveAPI
	log.Info().Msgf("Starting HTTP listener on: %s\n", "http://"+opts.BindAddr+"/bitslinger")

	log.Fatal().Err(http.ListenAndServe(opts.BindAddr, nil)).Msg("HTTP listen failure")
}
