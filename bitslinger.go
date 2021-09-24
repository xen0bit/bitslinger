package main

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/chifflier/nfqueue-go/nfqueue"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

type Rules struct {
	XMLName xml.Name `xml:"rules"`
	Rules   []Rule   `xml:"rule"`
}

type Rule struct {
	XMLName     xml.Name `xml:"rule"`
	Type        string   `xml:"type,attr"`
	Name        string   `xml:"name"`
	Pattern     string   `xml:"pattern"`
	Interpreter string   `xml:"interpreter"`
}

var ruleNames []string
var regexpPatterns []*regexp.Regexp
var packetInterpreters []func([]byte) []byte

var origHexDump *widgets.Paragraph
var ruleIndicator *widgets.List
var modHexDump *widgets.Paragraph

var logString string
var originalHexPayload string
var modifiedHexPayload string

func loadGoRules(goRuleDir string) {
	var files []string

	root := goRuleDir
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		panic(err)
	}
	sort.Strings(files)
	for _, file := range files {
		fmt.Println(file)
		b, err := ioutil.ReadFile(file) // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		str := string(b)
		//Compile golang interpreters
		ruleInterpreter := interp.New(interp.Options{})
		ruleInterpreter.Use(stdlib.Symbols)
		//Validate it compiles
		_, err = ruleInterpreter.Eval(str)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		//Validate export compiles
		v, err := ruleInterpreter.Eval("mod.Packet")
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		//Store pointer to interpreter
		modifyPacket := v.Interface().(func([]byte) []byte)
		packetInterpreters = append(packetInterpreters, modifyPacket)
	}
}

func loadRules() {
	var tempRuleNames []string
	var tempRegexpPatterns []*regexp.Regexp
	var tempPacketInterpreters []func([]byte) []byte

	// Open our xmlFile
	xmlFile, err := os.Open("rules.xml")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println("Successfully Opened rules.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()
	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	// we initialize our Users array
	var rules Rules
	// we unmarshal our byteArray which contains our
	// xmlFiles content into 'users' which we defined above
	err = xml.Unmarshal(byteValue, &rules)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	// we iterate through every user within our users array and
	// print out the user Type, their name, and their facebook url
	// as just an example

	for i := 0; i < len(rules.Rules); i++ {
		fmt.Println("Rule: " + strconv.Itoa(i))
		fmt.Println("Type: " + rules.Rules[i].Type)
		fmt.Println("Name: " + rules.Rules[i].Name)
		fmt.Println("Pattern: " + rules.Rules[i].Pattern)
		fmt.Println("Interpreter: " + rules.Rules[i].Interpreter)

		//Keep rule names
		ruleNames = append(ruleNames, "["+strconv.Itoa(i)+"] "+rules.Rules[i].Name)

		//Compile regex patterns
		r, err := regexp.Compile(rules.Rules[i].Pattern)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		tempRegexpPatterns = append(tempRegexpPatterns, r)
		//Compile golang interpreters
		ruleInterpreter := interp.New(interp.Options{})
		ruleInterpreter.Use(stdlib.Symbols)
		//Read contents of go rule
		b, err := ioutil.ReadFile("gorules/" + rules.Rules[i].Interpreter) // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		interpreterString := string(b)
		//Validate it compiles
		_, err = ruleInterpreter.Eval(interpreterString)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		//Validate export compiles
		v, err := ruleInterpreter.Eval("mod.Packet")
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		//Store pointer to interpreter
		modifyPacket := v.Interface().(func([]byte) []byte)
		tempPacketInterpreters = append(tempPacketInterpreters, modifyPacket)

	}
	fmt.Println("Loaded All Rules Successfully!")
	ruleNames = tempRuleNames
	regexpPatterns = tempRegexpPatterns
	packetInterpreters = tempPacketInterpreters
}

func matchHexPacket(hexPacket string) (bool, int) {
	for i, r := range regexpPatterns {
		doesMatch := r.MatchString(hexPacket)
		if doesMatch {
			return true, i
		}
	}
	return false, 0
}

func realCallback(payload *nfqueue.Payload) int {
	// Decode a packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	if app := packet.ApplicationLayer(); app != nil {
		hexString := fmt.Sprintf("%x", app.Payload())
		matched, ruleId := matchHexPacket(hexString)
		originalHexPayload = hex.Dump(app.Payload())
		//Set flags for TCP vs UDP
		isTCP := packet.Layer(layers.LayerTypeTCP)
		isUDP := packet.Layer(layers.LayerTypeUDP)
		if matched {
			ruleIndicator.SelectedRow = ruleId
			out := packetInterpreters[ruleId](app.Payload())
			if isTCP != nil {
				packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
			}
			if isUDP != nil {
				packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			if isTCP != nil {
				gopacket.SerializeLayers(buffer, options,
					packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
					packet.Layer(layers.LayerTypeTCP).(*layers.TCP),
					gopacket.Payload(out),
				)
			}
			if isUDP != nil {
				gopacket.SerializeLayers(buffer, options,
					packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4),
					packet.Layer(layers.LayerTypeUDP).(*layers.UDP),
					gopacket.Payload(out),
				)
			}
			packetBytes := buffer.Bytes()
			//fmt.Printf("Modified  id: %d\n", payload.Id)

			modifiedHexPayload = hex.Dump(out)
			payload.SetVerdictModified(nfqueue.NF_ACCEPT, packetBytes)
			return 0
		} else {
			modifiedHexPayload = ""
			payload.SetVerdict(nfqueue.NF_ACCEPT)
			return 0
		}
	} else {
		//fmt.Println("-- ")
		payload.SetVerdict(nfqueue.NF_ACCEPT)
		return 0
	}
}

func route2nf() {
	//Set iptables rule to route packets from sourc eport 9999 to queue number 0
	cmd := exec.Command("iptables", "-t", "raw", "-A", "PREROUTING", "-p", "udp", "--source-port", "9999", "-j", "NFQUEUE", "--queue-num", "0")
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdout))
	}

	cmd = exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func unroute2nf() {
	//Remove iptables rules that route packets into nfqueue
	unroute := exec.Command("iptables", "-F", "-t", "raw")
	stdoutUnroute, err := unroute.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdoutUnroute))
	}
}

func setupUI() {
	//Original Packet Payload
	origHexDump = widgets.NewParagraph()
	origHexDump.Title = "Original Payload"
	origHexDump.Text = ""
	origHexDump.SetRect(0, 0, 80, 32)
	origHexDump.TextStyle.Fg = ui.ColorGreen
	origHexDump.BorderStyle.Fg = ui.ColorCyan

	//Modified Packet Payload
	modHexDump = widgets.NewParagraph()
	modHexDump.Title = "Modified Payload"
	modHexDump.Text = ""
	//Min Width 130
	modHexDump.SetRect(105, 0, 185, 32)
	modHexDump.TextStyle.Fg = ui.ColorRed
	modHexDump.BorderStyle.Fg = ui.ColorCyan

	//Create list widget for rules
	ruleIndicator = widgets.NewList()
	ruleIndicator.Title = "Rules"
	ruleIndicator.Rows = ruleNames
	ruleIndicator.SetRect(80, 0, 105, 32)
	ruleIndicator.WrapText = false
	ruleIndicator.TextStyle.Fg = ui.ColorYellow
	ruleIndicator.SelectedRowStyle.Bg = ui.ColorWhite
	ruleIndicator.SelectedRowStyle.Fg = ui.ColorBlue
}

func updateUI() {
	origHexDump.Text = originalHexPayload
	modHexDump.Text = modifiedHexPayload
	ui.Render(origHexDump, ruleIndicator, modHexDump)
}

func main() {
	//Load our XML Rules
	loadRules()
	//UI init
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	log.SetOutput(ioutil.Discard)
	//Create go nfqueue
	q := new(nfqueue.Queue)
	//Set callback for queue
	q.SetCallback(realCallback)
	//Initialize queue
	q.Init()
	//Generic reset for bind
	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)
	//Create nfqueue "0"
	q.CreateQueue(0)

	route2nf()

	setupUI()

	ui.Render(origHexDump, ruleIndicator, modHexDump)
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Millisecond * 500).C

	go func() {
		for {
			select {
			case e := <-uiEvents:
				switch e.ID {
				//Quit
				case "q", "<C-c>":
					q.StopLoop()
					unroute2nf()
					return
				//Reload
				case "r":
					//q.StopLoop()
					unroute2nf()
					loadRules()
					route2nf()
					ui.Render(origHexDump, ruleIndicator, modHexDump)
				}
			case <-ticker:
				updateUI()
			}
		}
	}()
	// XXX Drop privileges here

	q.Loop()
	q.DestroyQueue()
	q.Close()
}
