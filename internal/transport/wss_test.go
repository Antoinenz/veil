package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/veilvpn/veil/internal/certutil"
)

func newWSSTestListener(t *testing.T, token string) *WSSListener {
	t.Helper()
	cfg, err := certutil.SelfSignedConfig("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	lis, err := ListenWSS("127.0.0.1:0", cfg, nil, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	return lis
}

// A probe to the tunnel path without the token must look like the decoy site.
func TestWSSTokenGatesProbeToDecoy(t *testing.T) {
	lis := newWSSTestListener(t, "s3cr3t-token")
	httpc := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := httpc.Get("https://" + lis.Addr().String() + TunnelPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200 (decoy)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "It works") {
		t.Fatalf("probe did not return decoy page: %q", body)
	}
}

// A WSS dial with the wrong token must be refused the upgrade.
func TestWSSWrongTokenRefusesUpgrade(t *testing.T) {
	lis := newWSSTestListener(t, "correct-token")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := WSSDialer{ServerName: "127.0.0.1", AuthToken: "WRONG"}.Dial(ctx, "wss://"+lis.Addr().String()+TunnelPath)
	if err == nil {
		conn.Close()
		t.Fatal("expected upgrade to be refused with wrong token")
	}
}

// The correct token upgrades successfully.
func TestWSSCorrectTokenUpgrades(t *testing.T) {
	const token = "correct-token"
	lis := newWSSTestListener(t, token)
	go func() {
		if c, err := lis.Accept(); err == nil {
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := WSSDialer{ServerName: "127.0.0.1", AuthToken: token}.Dial(ctx, "wss://"+lis.Addr().String()+TunnelPath)
	if err != nil {
		t.Fatalf("dial with correct token: %v", err)
	}
	conn.Close()
}
