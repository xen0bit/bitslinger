package plumbing

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

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
