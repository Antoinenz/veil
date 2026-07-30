package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/veilvpn/veil/internal/control"
)

// Enroll registers this device with the server over the HTTPS control plane and
// returns the server's static public key (base64) and fingerprint.
//
// TLS verification is skipped (the server uses a self-signed cert by default and
// the tunnel's trust is the pinned Noise key); the returned fingerprint should
// be compared out-of-band with the one printed by `veil-server init` to detect a
// man-in-the-middle during enrollment.
func Enroll(ctx context.Context, host, tlsPort, invite, devicePubB64, name string) (control.EnrollResponse, error) {
	reqBody, _ := json.Marshal(control.EnrollRequest{
		Invite:          invite,
		DevicePublicKey: devicePubB64,
		Name:            name,
	})
	url := "https://" + net.JoinHostPort(host, tlsPort) + control.EnrollPath

	httpc := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return control.EnrollResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return control.EnrollResponse{}, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return control.EnrollResponse{}, fmt.Errorf("enroll rejected (%s): %s", resp.Status, bytes.TrimSpace(body))
	}
	var er control.EnrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		return control.EnrollResponse{}, fmt.Errorf("enroll: bad response: %w", err)
	}
	if er.ServerPublicKey == "" {
		return control.EnrollResponse{}, fmt.Errorf("enroll: server returned no public key")
	}
	return er, nil
}
