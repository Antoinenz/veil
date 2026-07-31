// Package daemon runs the privileged tunnel engine and exposes a small HTTP/JSON
// control API over the local IPC channel (unix socket / named pipe), so an
// unprivileged GUI or the `veil ctl` CLI can drive it.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/veilvpn/veil/internal/client"
	"github.com/veilvpn/veil/internal/ipc"
)

// ConnectRequest is the body of POST /v1/connect.
type ConnectRequest struct {
	Full bool `json:"full"`
}

// Daemon wraps a client.Engine with a control server.
type Daemon struct {
	engine *client.Engine
	base   client.Options // connection options loaded from config; Full is per-request
}

// New builds a daemon that connects with base (Full is overridden per request).
func New(base client.Options) *Daemon {
	return &Daemon{engine: client.NewEngine(), base: base}
}

// Serve listens on the IPC channel and serves the control API until ctx ends.
func (d *Daemon) Serve(ctx context.Context) error {
	lis, err := ipc.Listen()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", d.handleStatus)
	mux.HandleFunc("/v1/connect", d.handleConnect)
	mux.HandleFunc("/v1/disconnect", d.handleDisconnect)
	mux.HandleFunc("/v1/events", d.handleEvents)
	srv := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		_ = d.engine.Disconnect()
		_ = srv.Close()
	}()

	log.Printf("veil daemon: control API listening on the local IPC channel")
	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.engine.Status())
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req ConnectRequest
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	}
	opt := d.base
	opt.FullTunnel = req.Full
	if err := d.engine.Connect(opt); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, d.engine.Status())
}

func (d *Daemon) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	_ = d.engine.Disconnect()
	writeJSON(w, http.StatusOK, d.engine.Status())
}

// handleEvents streams status changes as Server-Sent Events.
func (d *Daemon) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	sub, unsub := d.engine.Subscribe()
	defer unsub()
	for {
		select {
		case <-r.Context().Done():
			return
		case st, ok := <-sub:
			if !ok {
				return
			}
			b, _ := json.Marshal(st)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
