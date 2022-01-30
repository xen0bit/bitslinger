package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type GoPacketQueue struct {
	sync.Mutex
	packets map[string]*netfilter.NFPacket
}

var server string
var wsMode bool
var proxyUri string
var proxyUrl *url.URL
var wsConn *websocket.Conn
var httpClient *http.Client

var upgrader = websocket.Upgrader{} // use default options

//var tcpClient net.Conn
var gpq GoPacketQueue

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

func releaseFromNfqueue(packetUuid string, packetPayload []byte) {
	gpq.Lock()
	defer gpq.Unlock()
	//Look up nfqueue pointer
	if p, ok := gpq.packets[packetUuid]; ok {
		//Decode packet from nfqueue
		packet := gopacket.NewPacket(p.Packet.Data(), layers.LayerTypeIPv4, gopacket.Default)
		//Check that packet has a app payload and has been modifed
		if app := packet.ApplicationLayer(); app != nil && !testEq(packetPayload, app.Payload()) {
			//Set flags for TCP vs UDP
			isTCP := packet.Layer(layers.LayerTypeTCP)
			isUDP := packet.Layer(layers.LayerTypeUDP)

			//Configure Checksums
			if isTCP != nil {
				packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
			}
			if isUDP != nil {
				packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
			}

			//Rebuild with new payload
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
			//Lock Mutex
			//gpq.Lock()
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packetBytes)
			//Remove UUID from map
			delete(gpq.packets, packetUuid)
			//gpq.Unlock()
		} else {
			//Packet did not have application layer, default accept
			//Lock Mutex
			//gpq.Lock()
			p.SetVerdict(netfilter.NF_ACCEPT)
			//Remove UUID from map
			delete(gpq.packets, packetUuid)
			//gpq.Unlock()
		}
	} else {
		//Log, no need to call mutex, nothing to remove
		log.Println("Packet UUID Not found:", packetUuid)
	}
	//gpq.Unlock()
}

func receivePayloadHTTP(w http.ResponseWriter, req *http.Request) {
	//Retrieve Packet UUID from request
	packetUuid := req.Header.Get("Packet-Uuid")
	//Retrieve hex from request body and cast as bytes
	body, _ := ioutil.ReadAll(req.Body)
	packetPayload, _ := hex.DecodeString(string(body))
	releaseFromNfqueue(packetUuid, packetPayload)
	w.WriteHeader(200)
}

func receivePayloadWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	log.SetOutput(os.Stdout)
	log.Println("WS Client Connected")
	log.SetOutput(ioutil.Discard)
	wsConn = c
	defer c.Close()
	for {
		//wsConn.SetReadDeadline(time.Now().Add(time.Second * 1))
		_, message, err := c.ReadMessage()
		if err != nil {
			log.SetOutput(os.Stdout)
			log.Println("read:", err)
			log.SetOutput(ioutil.Discard)
			break
		} else {
			messageString := string(message)
			//log.Println(messageString)
			//Segment Message
			if segments := strings.Split(messageString, "\n"); len(segments) >= 2 {
				//log.Println(segments)
				packetUuid := segments[0]
				payloadHex := segments[1]
				packetPayload, _ := hex.DecodeString(payloadHex)
				releaseFromNfqueue(packetUuid, packetPayload)
			} else {
				log.Println("WARNING: WS Received unexpected message format.")
				log.Println(messageString)
			}
		}
	}
}

func sendToProxy(p *netfilter.NFPacket) int {
	// gpq.Lock()
	// defer gpq.Unlock()
	// Decode a packet
	//packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	if applayer := p.Packet.ApplicationLayer(); applayer != nil {
		//Mutex on Queue
		gpq.Lock()
		//Generate UUID to Identify packet
		packetUuid := uuid.New().String()
		//Insert marker into GoPacketQueue
		gpq.packets[packetUuid] = p
		gpq.Unlock()
		//fmt.Println(gpq.packets)
		log.Printf("Packet UUID %s\n", packetUuid)
		if wsMode {
			hexEncodedPayload := []byte(packetUuid + "\n" + hex.EncodeToString(applayer.Payload()) + "\n")
			if wsConn != nil {
				err := wsConn.WriteMessage(websocket.TextMessage, hexEncodedPayload)
				if err != nil {
					log.Println(err)
					log.Println("WARNING: WebSocket proxy communication failed, Default forwarding packet as-is")
					p.SetVerdict(netfilter.NF_ACCEPT)
					//Lock Mutex
					gpq.Lock()
					//Remove UUID from map
					delete(gpq.packets, packetUuid)
					gpq.Unlock()
				}
			} else {
				log.Println("WARNING: WebSocket proxy communication failed, Default forwarding packet as-is")
				p.SetVerdict(netfilter.NF_ACCEPT)
				//Lock Mutex
				gpq.Lock()
				//Remove UUID from map
				delete(gpq.packets, packetUuid)
				gpq.Unlock()
			}
		} else {
			//HTTP Mode
			hexEncodedPayload := []byte(hex.EncodeToString(applayer.Payload()))
			payloadReader := bytes.NewReader(hexEncodedPayload)
			req, err := http.NewRequest("POST", "http://"+server+"/bitslinger", payloadReader)
			if err != nil {
				log.Fatal(err)
			}
			req.Header.Add("Packet-Uuid", packetUuid)
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Println(err)
				log.Println("WARNING: HTTP Proxy communication failed, Default forwarding packet as-is")
				p.SetVerdict(netfilter.NF_ACCEPT)
				//Lock Mutex
				gpq.Lock()
				//Remove UUID from map
				delete(gpq.packets, packetUuid)
				gpq.Unlock()
			} else {
				resp.Body.Close()
			}
		}
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
	//Needed for C API
	return 0
}

func newGoPacketQueue() *GoPacketQueue {
	t := GoPacketQueue{
		packets: make(map[string]*netfilter.NFPacket),
	}
	return &t
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

	//Configure Send/Recievers
	if wsMode {
		http.HandleFunc("/bitslinger", receivePayloadWS)

		log.Printf("Starting WS listener on: %s\n", "ws://"+server+"/bitslinger")
		go func() {
			http.ListenAndServe(server, nil)
		}()

	} else {
		//HTTP Listener
		http.HandleFunc("/bitslinger", receivePayloadHTTP)

		log.Printf("Starting HTTP listener on: %s\n", "http://"+server+"/bitslinger")
		go func() {
			http.ListenAndServe(server, nil)
		}()

		//HTTP Sender
		proxy, err := url.Parse("http://" + proxyUri)
		if err != nil {
			panic(err)
		}
		proxyUrl = proxy
		httpClient = &http.Client{
			Timeout:   0,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)},
		}
	}

	gpq = *newGoPacketQueue()

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
