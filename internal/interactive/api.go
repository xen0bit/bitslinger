package interactive

import (
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/xen0bit/bitslinger/internal/common"
	"github.com/xen0bit/bitslinger/internal/opts"
	"github.com/xen0bit/bitslinger/internal/packets"
)

var upgrader = websocket.Upgrader{
	EnableCompression: false,
}

// HandleInteractiveHTTP handles HTTP requests that are meant to target a specific packet UUID and provide a modified payload.
func HandleInteractiveHTTP(w http.ResponseWriter, req *http.Request) {
	// Retrieve Packet UUID from request
	packetUUID := req.Header.Get("Packet-Uuid")
	slog := log.With().Str("caller", packetUUID).Logger()

	// If we don't know of the UUID, quickly discard the request.
	// We also instantiate our KnownPacket type, which is useful.
	known, ok := packets.Queue.FromUUID(packetUUID)
	if !ok {
		slog.Warn().Err(common.ErrUnknownPacket).Msg("invalid request")
		w.WriteHeader(400)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		slog.Warn().Err(err).Caller().Msg("failed to receive payload over HTTP")
		w.WriteHeader(400)
		return
	}

	// Retrieve modified packet data in hex form from our HTTP client
	newPayload, err := hex.DecodeString(string(body))
	if err != nil {
		slog.Warn().Err(err).Caller().Msg("failed to decode HTTP request body")
		w.WriteHeader(400)
	}

	// Presuming we were able to decode it, we release the modified packet with its new payload from our queue.
	known.SetPayload(newPayload)
	known.Release()
	w.WriteHeader(200)
}

// HandleInteractiveWS handles websocket connections that will receive packets from our queue and determine any modifications.
func HandleInteractiveWS(w http.ResponseWriter, r *http.Request) {
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

		// Again we see if this is a valid UUID and substantiate our KnownPacket type.
		known, ok := packets.Queue.FromUUID(segments[0])

		if !ok {
			slog.Error().Err(common.ErrUnknownPacket).Interface("received", segments[0]).Msg("invalid request")
			continue
		}

		payloadHex := segments[1]
		newPayload, err := hex.DecodeString(payloadHex)

		if err != nil {
			slog.Error().Err(err).Interface("received", payloadHex).Msg("Packet decode failure!")
			continue
		}

		known.SetPayload(newPayload)
		known.Release()

	}
}

// ListenAndServeWebsockets starts our websocket listener for packet modification requests.
func ListenAndServeWebsockets() {
	// WebSocket Listener
	http.HandleFunc("/bitslinger", HandleInteractiveWS)
	log.Info().Msgf("Starting WS listener on: %s\n", "ws://"+opts.BindAddr+"/bitslinger")
	log.Fatal().Err(http.ListenAndServe(opts.ProxyDestination, nil)).Msg("Websocket listen failure")
}

// ListenAndServeHTTP starts our HTTP listener for packet modification requests.
func ListenAndServeHTTP() {
	// HTTP Sender

	// HTTP Listener
	http.HandleFunc("/bitslinger", HandleInteractiveHTTP)

	// TODO: Fix the wording/semantics here, it's a little confusing that we're listening on the InterActiveAPI
	log.Info().Msgf("Starting HTTP listener on: %s\n", "http://"+opts.BindAddr+"/bitslinger")

	log.Fatal().Err(http.ListenAndServe(opts.BindAddr, nil)).Msg("HTTP listen failure")
}
