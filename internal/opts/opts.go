package opts

import (
	"flag"
	"net/url"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/rs/zerolog/log"
)

type ListenMode uint8

const (
	HTTP ListenMode = iota
	Websockets
)

var (
	// ProxyDestination is where bitslinger will send packets to be modified by an external HTTP proxy (e.g: BurpSuite)
	ProxyDestination string
	ProxyURL         *url.URL

	// BindAddr is the bind address for our interactive API allowing for realtime, arbitrary packet modification.
	BindAddr string

	// Mode is an opcode representing which type of API listener(s) we are using
	Mode ListenMode = HTTP

	// QueueNum represents our specific nfqueue ID used to receive and release packets.
	// Be aware that Suricata and potentially other IPS systems may also use the default of 0.
	QueueNum uint16

	// QueueMax is our upper limit of packets we will hold in our packets before we start giving up and droppping them.
	QueueMax uint32

	// PacketSize is the maximum packet size we accept into our packets.
	PacketSize = netfilter.NF_DEFAULT_PACKET_SIZE
)

// ParseFlags interprets command line flags and stores them as options for bitslinger.
func ParseFlags() {
	// using standard library "flag" package
	flag.String("server", "127.0.0.1:9393", "host:port pair for bitslinger (http:// or ws://) listener")
	flag.String("proxy", "127.0.0.1:8080", "host:port pair for HTTP Proxy based modifications.")
	flag.Bool("ws", false, `Configures the packet encapsulation to use websockets`)
	flag.Int("qnum", 0, "NFQueue packets number to attach to.")
	flag.Int("qmax", 65535, "Configures maximum number of packets allowed in packets")
	flag.Bool("verbose", false, "Verbose logging. May slow down operation, but useful for debugging.")
	flag.Bool("trace", false, "Extremely verbose logging. WILL slow down operation, but useful for fixing a broken bitslinger.")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse command line arguments")
	}

	BindAddr = viper.GetString("server")
	ProxyDestination = viper.GetString("proxy")

	// Default is set to HTTP above, if they choose websockets, we switch.
	if viper.GetBool("ws") {
		Mode = Websockets
	}

	// TODO: More options for levels of verbosity
	if viper.GetBool("verbose") {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	QueueNum = uint16(viper.GetInt("qnum"))
	QueueMax = uint32(viper.GetInt("qmax"))

	var urlerr error
	if ProxyURL, urlerr = url.Parse("http://" + ProxyDestination); urlerr != nil {
		log.Fatal().Err(urlerr).Msg("Invalid proxy bind URI")
	}
}
