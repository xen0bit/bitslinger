package api

import (
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

func closeWebsocket(c *websocket.Conn) {
	err := c.Close()
	if err != nil {
		log.Warn().Str("caller", c.LocalAddr().String()).
			Str("remote", c.RemoteAddr().String()).
			Err(err).Msg("Failed to properly close websocket handler")
	} else {
		log.Trace().Str("caller", c.LocalAddr().String()).
			Str("remote", c.RemoteAddr().String()).
			Err(err).Msg("Websocket connection closed")
	}
}
