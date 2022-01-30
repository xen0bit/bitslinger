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
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/xen0bit/bitslinger/manager"
)

var server string
var wsMode bool
var proxyURI string
var proxyURL *url.URL
var wsConn *websocket.Conn
var httpClient *http.Client

var upgrader = websocket.Upgrader{} // use default options

// var tcpClient net.Conn
var gpq *manager.PacketTracker

func init() {
	gpq = manager.NewPacketTracker()
}

func releaseFromNfqueue(packetUUID string, packetPayload []byte) {
	// Look up nfqueue pointer
	p, ok := gpq.FromUUID(packetUUID)
	if !ok {
		log.Debug().Str("caller", packetUUID).Msg("Packet UUID Not found")
		return
	}

	// Decode packet from nfqueue
	packet := gopacket.NewPacket(p.Data(), layers.LayerTypeIPv4, gopacket.Default)
	// Check that packet has a app payload and has been modifed
	if app := packet.ApplicationLayer(); app != nil && !testEq(packetPayload, app.Payload()) {
		// Set flags for TCP vs UDP
		isTCP := packet.Layer(layers.LayerTypeTCP)
		isUDP := packet.Layer(layers.LayerTypeUDP)

		// Configure Checksums
		if isTCP != nil {
			packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		}
		if isUDP != nil {
			packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		}

		// Rebuild with new payload
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		if isTCP != nil {
			gopacket.SerializeLayers(buffer, options,
				packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
				packet.Layer(layers.LayerTypeTCP).(*layers.TCP),
				gopacket.Payload(packetPayload),
			)
		}
		if isUDP != nil {
			gopacket.SerializeLayers(buffer, options,
				packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
				packet.Layer(layers.LayerTypeUDP).(*layers.UDP),
				gopacket.Payload(packetPayload),
			)
		}

		packetBytes := buffer.Bytes()
		// Lock Mutex
		// gpq.Lock()
		p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packetBytes)

	} else {
		// Packet did not have application layer, default accept
		// Lock Mutex
		// gpq.Lock()
		p.Self().SetVerdict(netfilter.NF_ACCEPT)
		// Remove UUID from map
		delete(gpq.packets, packetUUID)
		// gpq.Unlock()
	}

	// gpq.Unlock()
}

func receivePayloadHTTP(w http.ResponseWriter, req *http.Request) {
	// Retrieve Packet UUID from request
	packetUuid := req.Header.Get("Packet-Uuid")
	// Retrieve hex from request body and cast as bytes
	body, _ := ioutil.ReadAll(req.Body)
	packetPayload, _ := hex.DecodeString(string(body))
	releaseFromNfqueue(packetUuid, packetPayload)
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
	// log.SetOutput(ioutil.Discard)
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
			log.Warn().Str("message", string(message)).Msg("unexpected message format")
			continue
		}

		slog.Trace().Strs("segments", segments).Msg("websocket message")
		packetUUID := segments[0]
		payloadHex := segments[1]
		packetPayload, err := hex.DecodeString(payloadHex)
		if err != nil {
			log.Error().Err(err).Interface("payload", payloadHex).Msg("Packet decode failure!")
			continue
		}
		releaseFromNfqueue(packetUUID, packetPayload)

	}
}

func wsModeHandler(packet Packet) {
	hexEncodedPayload := []byte(packet.UUID() + "\n" + hex.EncodeToString(packet.AppLayer().Payload()) + "\n")
	if wsConn != nil {
		err := wsConn.WriteMessage(websocket.TextMessage, hexEncodedPayload)
		if err != nil {
			log.Println(err)
			log.Println("WARNING: WebSocket proxy communication failed, Default forwarding packet as-is")
			p.SetVerdict(netfilter.NF_ACCEPT)
			// Lock Mutex
			gpq.Lock()
			// Remove UUID from map
			delete(gpq.packets, packetUUID)
			gpq.Unlock()
		}
	} else {
		log.Println("WARNING: WebSocket proxy communication failed, Default forwarding packet as-is")
		p.SetVerdict(netfilter.NF_ACCEPT)
		// Lock Mutex
		gpq.Lock()
		// Remove UUID from map
		delete(gpq.packets, packetUUID)
		gpq.Unlock()
	}

}

func sendToProxy(p *netfilter.NFPacket) int {
	// gpq.Lock()
	// defer gpq.Unlock()
	// Decode a packet
	// packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	packetUUID, ok := newTrackedPacket(p)
	if !ok {
		return 0
	}

	log.Trace().Interface("tracked", gpq.packets).Msg("[+]")

	log.Trace().Str("caller", packetUUID).Msg("-> proxy")

	switch {
	case wsMode:
		wsModeHandler(packetUUID)
	default:
		// HTTP Mode
		hexEncodedPayload := []byte(hex.EncodeToString(applayer.Payload()))
		payloadReader := bytes.NewReader(hexEncodedPayload)
		req, err := http.NewRequest("POST", "http://"+server+"/bitslinger", payloadReader)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Add("Packet-Uuid", packetUUID)
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Println(err)
			log.Println("WARNING: HTTP Proxy communication failed, Default forwarding packet as-is")
			p.SetVerdict(netfilter.NF_ACCEPT)
			// Lock Mutex
			gpq.Lock()
			// Remove UUID from map
			delete(gpq.packets, packetUUID)
			gpq.Unlock()
		} else {
			resp.Body.Close()
		}
	}
	// Needed for C API
	return 0
}

func main() {
	fmt.Println("BitSlinger: The TCP/UDP Packet Payload Editing Tool")
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
	proxyUri = viper.GetString("proxy")
	wsMode = viper.GetBool("ws")
	verbose := viper.GetBool("verbose")
	qnum := viper.GetInt("qnum")

	// Configure Send/Recievers
	if wsMode {
		http.HandleFunc("/bitslinger", receivePayloadWS)

		log.Printf("Starting WS listener on: %s\n", "ws://"+server+"/bitslinger")
		go func() {
			http.ListenAndServe(server, nil)
		}()

	} else {
		// HTTP Listener
		http.HandleFunc("/bitslinger", receivePayloadHTTP)

		log.Printf("Starting HTTP listener on: %s\n", "http://"+server+"/bitslinger")
		go func() {
			http.ListenAndServe(server, nil)
		}()

		// HTTP Sender
		proxy, err := url.Parse("http://" + proxyUri)
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
		log.Fatal(err)
	}
	defer nfq.Close()
	if !verbose {
		log.SetOutput(ioutil.Discard)
		os.Stderr = nil
	}
	packets := nfq.GetPackets()

	for p := range packets {
		sendToProxy(&p)
	}
}
