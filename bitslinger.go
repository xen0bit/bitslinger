package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/xen0bit/bitslinger/manager"
)

var (
	server   string
	proxyURI string

	wsMode bool

	qnum int

	proxyURL   *url.URL
	wsConn     *websocket.Conn
	httpClient *http.Client
)

var upgrader = websocket.Upgrader{} // use default options

// var tcpClient net.Conn
var gpq *manager.PacketQueue

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	parseUserOpts()
	gpq = manager.NewPacketQueue()
}

func parseUserOpts() {
	// using standard library "flag" package
	flag.String("server", "127.0.0.1:9393", "host:port pair for bitslinger (http:// or ws://) listener")
	flag.String("proxy", "127.0.0.1:8080", "host:port pair for HTTP Proxy based modifications.")
	flag.Bool("ws", false, `Configures the packet encapsulation to use websockets`)
	flag.Int("qnum", 0, "NFQueue queue number to attach to.")
	flag.Bool("verbose", false, "Verbose logging. May slow down operation, but useful for debugging.")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	server = viper.GetString("server")
	proxyURI = viper.GetString("proxy")
	wsMode = viper.GetBool("ws")

	// TODO: More options for levels of verbosity
	if viper.GetBool("verbose") {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	qnum = viper.GetInt("qnum")
}

type packetProto uint8

const (
	unknown packetProto = iota
	tcp
	udp
)

func reconstructPacket(packetUUID string, packet gopacket.Packet, packetPayload []byte) (buffer gopacket.SerializeBuffer, ok bool) {
	slog := log.With().Str("caller", packetUUID).Logger()

	var pp packetProto = unknown

	// Set flags for TCP vs UDP
	isTCP := packet.Layer(layers.LayerTypeTCP)
	isUDP := packet.Layer(layers.LayerTypeUDP)

	// Configure Checksums
	switch {
	case isTCP != nil:
		err := packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err != nil {
			slog.Warn().Err(err).Caller().Msg("Failed to set TCP network layer for checksum")
		} else {
			pp = tcp
		}
	case isUDP != nil:
		err := packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		if err != nil {
			slog.Warn().Err(err).Caller().Msg("Failed to set UDP network layer for checksum")
		} else {
			pp = udp
		}
	default:
		slog.Debug().Msg("unhandled packet")
		return
	}

	if pp == unknown {
		slog.Debug().Msg("unhandled packet")
		return
	}

	// Rebuild with new payload
	buffer = gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	switch pp {
	case tcp:
		if err := gopacket.SerializeLayers(buffer, options,
			packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			packet.Layer(layers.LayerTypeTCP).(*layers.TCP),
			gopacket.Payload(packetPayload),
		); err != nil {
			slog.Warn().Err(err).Msg("TCP serialization failure")
			return
		}
	case udp:
		if err := gopacket.SerializeLayers(buffer, options,
			packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
			packet.Layer(layers.LayerTypeUDP).(*layers.UDP),
			gopacket.Payload(packetPayload),
		); err != nil {
			slog.Warn().Err(err).Msg("TCP serialization failure")
			return
		}
	}
	ok = true
	return
}

func releaseFromNfqueue(packetUUID string, packetPayload []byte) {
	// Look up nfqueue pointer
	p, ok := gpq.FromUUID(packetUUID)
	slog := log.With().Str("caller", packetUUID).Logger()
	if !ok {
		slog.Debug().Msg("Packet UUID Not found")
		return
	}

	// Decode packet from nfqueue
	packet := gopacket.NewPacket(p.Data(), layers.LayerTypeIPv4, gopacket.Default)
	// Check that packet has a app payload and has been modifed
	app := packet.ApplicationLayer()
	if app == nil {
		// Packet did not have application layer, default accept
		// slog.Trace().Msg("no application layer")
		gpq.AcceptAndRelease(packetUUID)
		return
	}
	if testEq(packetPayload, app.Payload()) {
		// slog.Trace().Msg("packet not modified")
		gpq.AcceptAndRelease(packetUUID)
		return
	}

	buffer, ok := reconstructPacket(packetUUID, packet, packetPayload)
	if ok {
		packetBytes := buffer.Bytes()
		p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packetBytes)
	}

	gpq.Release(packetUUID)
}

func receivePayloadHTTP(w http.ResponseWriter, req *http.Request) {
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
	releaseFromNfqueue(packetUUID, packetPayload)
	w.WriteHeader(200)
}

func receivePayloadWS(w http.ResponseWriter, r *http.Request) {
	slog := log.With().Str("caller", r.RemoteAddr).Logger()
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn().Err(err).Msg("Failed to upgrade websocket conn")
		return
	}
	slog.Info().Str("caller", r.RemoteAddr).Msg("WS Client Connected")
	// slog.SetOutput(ioutil.Discard)
	wsConn = c

	defer func(c *websocket.Conn) {
		err := c.Close()
		if err != nil {
			slog.Trace().Err(err).Msg("Failed to properly close websocket handler")
		}
	}(c)

	for {
		// wsConn.SetReadDeadline(time.Now().Add(time.Second * 1))
		_, message, err := c.ReadMessage()
		if err != nil {
			slog.Warn().Err(err).Msg("read error")
			break
		}
		// log.Println(messageString)
		// Segment Message
		segments := strings.Split(string(message), "\n")
		if len(segments) < 2 {
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
		releaseFromNfqueue(packetUUID, packetPayload)

	}
}

func closeResponse(resp *http.Response) {
	err := resp.Body.Close()
	if err != nil {
		log.Debug().Err(err).Msg("failed close response body...")
	}
}

func httpModeHandler(pckt manager.Packet) {
	// HTTP Mode
	hexEncodedPayload := []byte(hex.EncodeToString(pckt.AppLayer().Payload()))
	payloadReader := bytes.NewReader(hexEncodedPayload)
	req, err := http.NewRequest("POST", "http://"+server+"/bitslinger", payloadReader)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to submit packet to proxy")
	}
	req.Header.Add("Packet-Uuid", pckt.UUID())
	resp, err := httpClient.Do(req)

	defer closeResponse(resp)

	if err == nil {
		return
	}

	log.Warn().Msg("HTTP Proxy communication failed, Default forwarding packet as-is")
	gpq.AcceptAndRelease(pckt.UUID())
}

func wsModeHandler(pckt manager.Packet) {
	slog := log.With().Str("caller", pckt.UUID()).Logger()
	hexEncodedPayload := []byte(pckt.UUID() + "\n" + hex.EncodeToString(pckt.AppLayer().Payload()) + "\n")
	if wsConn != nil {
		err := wsConn.WriteMessage(websocket.TextMessage, hexEncodedPayload)
		if err != nil {
			slog.Warn().Err(err).Msg("WebSocket proxy communication failed, Default forwarding packet as-is")

			gpq.AcceptAndRelease(pckt.UUID())
		}
	} else {
		slog.Warn().Msg("WebSocket proxy communication failed, Default forwarding packet as-is")
		pckt.SetVerdict(netfilter.NF_ACCEPT)
		gpq.Release(pckt.UUID())
	}
}

func sendToProxy(p *netfilter.NFPacket) int {
	// gpq.Lock()
	// defer gpq.Unlock()
	// Decode a packet
	// packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	pckt := gpq.AddPacket(p)
	if !pckt.Valid() {
		return 0
	}

	log.Trace().Caller().Str("caller", pckt.UUID()).Msg("-> proxy")

	switch {
	case wsMode:
		wsModeHandler(pckt)
	default:
		httpModeHandler(pckt)
	}
	// Needed for C API
	return 0
}

func main() {
	fmt.Println("BitSlinger: The TCP/UDP Packet Payload Editing Tool")

	// Configure Send/Recievers
	if wsMode {
		http.HandleFunc("/bitslinger", receivePayloadWS)

		log.Printf("Starting WS listener on: %s\n", "ws://"+server+"/bitslinger")
		go func() {
			log.Fatal().Err(http.ListenAndServe(server, nil)).Msg("Websocket listn failure")
		}()

	} else {
		// HTTP Listener
		http.HandleFunc("/bitslinger", receivePayloadHTTP)

		log.Printf("Starting HTTP listener on: %s\n", "http://"+server+"/bitslinger")
		go func() {
			log.Fatal().Err(http.ListenAndServe(server, nil)).Msg("HTTP listen failure")
		}()

		// HTTP Sender
		proxy, err := url.Parse("http://" + proxyURI)
		if err != nil {
			panic(err)
		}
		proxyURL = proxy
		httpClient = &http.Client{
			Timeout:   0,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
	}

	nfq, err := netfilter.NewNFQueue(uint16(qnum), 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize NFQueue, cannot continue")
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	for p := range packets {
		sendToProxy(&p)
	}
}
