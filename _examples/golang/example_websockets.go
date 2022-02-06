//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var done chan interface{}
var interrupt chan os.Signal

func unpackBitSlinger(message []byte) (packetUuid string, packetPayload []byte, err error) {
	segments := strings.Split(string(message), "\n")
	if len(segments) == 2 {
		packetUuid := segments[0]
		packetPayload, err := hex.DecodeString(segments[1])
		if err != nil {
			return "", nil, err
		} else {
			return packetUuid, packetPayload, nil
		}
	} else {
		return "", nil, errors.New("unknown message format")
	}
}

func packBitSlinger(packetUuid string, packetPayload []byte) (message []byte) {
	return []byte(packetUuid + "\n" + hex.EncodeToString(packetPayload))
}

func modifyPayload(payload []byte) []byte {
	return bytes.ReplaceAll(payload, []byte{'w', 'o', 'r', 'l', 'd'}, []byte{'r', 'e', 'm', 'y', '!'})
}

func main() {
	done = make(chan interface{})    // Channel to indicate that the receiverHandler is done
	interrupt = make(chan os.Signal) // Channel to listen for interrupt signal to terminate gracefully

	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM) // Notify the interrupt channel for SIGINT

	socketUrl := "ws://localhost:9393" + "/bitslinger"
	conn, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
	if err != nil {
		log.Fatal("Error connecting to Websocket Server:", err)
	}
	log.Println("Connected!")
	defer conn.Close()
	// go receiveHandler(conn)

	// Our main loop for the client
	// We send our relevant packets here
	for {
		select {
		default:
			// Read Message
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("Error in receive:", err)
				return
			}
			// Unpack Segments
			packetUuid, packetPayload, err := unpackBitSlinger(message)
			if err != nil {
				break
			}
			// Modify Payload
			newPacketPayload := modifyPayload(packetPayload)

			// Repack Segments
			newMessage := packBitSlinger(packetUuid, newPacketPayload)

			// Send Message
			conn.WriteMessage(websocket.TextMessage, newMessage)

		case <-interrupt:
			// We received a SIGINT (Ctrl + C). Terminate gracefully...
			log.Println("Received SIGINT interrupt signal. Closing all pending connections")

			// Close our websocket connection
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("Error during closing websocket:", err)
				return
			}

			select {
			case <-done:
				log.Println("Receiver Channel Closed! Exiting....")
			case <-time.After(time.Duration(1) * time.Second):
				log.Println("Timeout in closing receiving channel. Exiting....")
			}
			return
		}
	}
}
