package detect

import "context"

// tlsPhase tries a TLS handshake and, if it succeeds, detects the service
// inside the tunnel. It reports false if the port does not speak TLS.
func (d *detector) tlsPhase(ctx context.Context, rep *Report) ([]Result, bool) {
	return nil, false
}
