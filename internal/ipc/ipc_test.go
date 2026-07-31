//go:build !windows

package ipc

import (
	"io"
	"net/http"
	"path/filepath"
	"testing"
)

// TestRoundTrip verifies the daemon can serve HTTP over the local socket and a
// client can reach it via HTTPClient.
func TestRoundTrip(t *testing.T) {
	t.Setenv("VEIL_IPC", filepath.Join(t.TempDir(), "veil.sock"))

	lis, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"disconnected"}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(lis)
	defer srv.Close()

	resp, err := HTTPClient().Get(Host + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"state":"disconnected"}` {
		t.Fatalf("unexpected response %d: %s", resp.StatusCode, body)
	}
}
