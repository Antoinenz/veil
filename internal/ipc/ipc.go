// Package ipc provides the local control channel between the veil GUI/CLI and
// the privileged daemon: a unix domain socket on Linux and a named pipe on
// Windows. The daemon serves an HTTP/JSON API over it; clients use HTTPClient.
package ipc

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Host is a placeholder host used in request URLs (e.g. "http://veil/v1/status").
// The dialer ignores the address and connects to the socket/pipe instead.
const Host = "http://veil"

// HTTPClient returns an *http.Client that talks to the daemon over the local IPC
// transport. Use URLs like Host + "/v1/status".
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return DialContext(ctx)
			},
		},
	}
}

// eventClient is like HTTPClient but without a timeout, for the long-lived
// /v1/events stream.
func eventClientTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return DialContext(ctx)
		},
	}
}

// EventClient returns an *http.Client suitable for the streaming events endpoint
// (no overall timeout).
func EventClient() *http.Client {
	return &http.Client{Transport: eventClientTransport()}
}
