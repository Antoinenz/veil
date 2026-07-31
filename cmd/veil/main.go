// Command veil is the client: a privileged daemon that manages the TUN device,
// races transports to connect, runs the tunnel, and enforces the kill-switch —
// plus the CLI used to enroll and control it.
//
// M0 provides the CLI surface and local device-key generation. Enrollment
// networking, the tunnel, and the daemon land in M1+.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/veilvpn/veil/internal/client"
	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/daemon"
	"github.com/veilvpn/veil/internal/ipc"
	"github.com/veilvpn/veil/internal/noise"
)

const usage = `veil — one-button self-hostable VPN client

usage:
  veil login <server> <invite>   enroll this device with a gateway
  veil up [--full]               connect in the foreground (auto-selects transport)
  veil daemon                    run the background control service (for the GUI/ctl)
  veil ctl connect [--full]      tell the daemon to connect
  veil ctl disconnect            tell the daemon to disconnect
  veil ctl status                show the daemon's connection state
  veil status | down             shortcuts for ctl status | disconnect
  veil version

`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "login":
		err = cmdLogin(os.Args[2:])
	case "up":
		err = cmdUp(os.Args[2:])
	case "daemon":
		err = cmdDaemon(os.Args[2:])
	case "ctl":
		err = cmdCtl(os.Args[2:])
	case "down":
		err = ctlPost("/v1/disconnect", nil)
	case "status":
		err = ctlStatus()
	case "version", "--version", "-v":
		fmt.Println(version())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("veil login", flag.ContinueOnError)
	dataDir := fs.String("data-dir", config.DefaultClient().DataDir, "client data directory")
	// serverKey is a temporary manual pin until the M3 control plane fetches the
	// server's static key automatically during invite enrollment.
	serverKey := fs.String("server-key", "", "server static public key (base64) [temporary]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: veil login [--data-dir dir] [--server-key b64] <server> <invite>")
	}
	server, invite := fs.Arg(0), fs.Arg(1)

	cfg := config.DefaultClient()
	cfg.Server = server
	cfg.DataDir = *dataDir
	cfg.ServerPublicKey = *serverKey
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	kp, err := noise.GenerateKeyPair()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(cfg.DataDir, "device.key")
	if err := os.WriteFile(keyPath, kp.Private.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write device key: %w", err)
	}
	fmt.Printf("device key generated: %s\n", noise.Fingerprint(kp.Public))

	if *serverKey == "" {
		// Enroll over the HTTPS control plane to fetch and pin the server key.
		devicePub := base64.StdEncoding.EncodeToString(kp.Public.Bytes())
		name, _ := os.Hostname()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		er, err := client.Enroll(ctx, server, cfg.TLSPort, invite, devicePub, name)
		if err != nil {
			return err
		}
		cfg.ServerPublicKey = er.ServerPublicKey
		cfg.ServerKeyFingerprint = er.Fingerprint
		cfg.TunnelToken = er.TunnelToken
		fmt.Printf("enrolled with %s\n", server)
		fmt.Printf("server fingerprint: %s  (compare with `veil-server init` output)\n", er.Fingerprint)
	}

	if err := config.Save(filepath.Join(cfg.DataDir, "client.json"), cfg); err != nil {
		return err
	}
	fmt.Printf("saved config for %s\n", server)
	return nil
}

// loadOptions loads the client config + device key from dataDir and builds the
// connection options, applying the full-tunnel / kill-switch flags.
func loadOptions(dataDir string, full, killSwitch bool) (client.Options, error) {
	cfg, err := config.LoadClient(filepath.Join(dataDir, "client.json"))
	if err != nil {
		return client.Options{}, err
	}
	cfg.FullTunnel = cfg.FullTunnel || full
	cfg.KillSwitch = killSwitch
	if cfg.ServerPublicKey == "" {
		return client.Options{}, fmt.Errorf("no server public key in config; run `veil login` first")
	}
	serverStatic, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
	if err != nil {
		return client.Options{}, fmt.Errorf("decode server public key: %w", err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(dataDir, "device.key"))
	if err != nil {
		return client.Options{}, fmt.Errorf("read device key: %w", err)
	}
	device, err := noise.LoadKeyPair(keyBytes)
	if err != nil {
		return client.Options{}, err
	}
	return client.FromConfig(cfg, device, serverStatic), nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("veil up", flag.ContinueOnError)
	dataDir := fs.String("data-dir", config.DefaultClient().DataDir, "client data directory")
	full := fs.Bool("full", false, "route ALL traffic through the tunnel (full VPN: default route + DNS)")
	killSwitch := fs.Bool("kill-switch", true, "with --full, block non-tunnel traffic if the tunnel drops")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opt, err := loadOptions(*dataDir, *full, *killSwitch)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return client.Run(ctx, opt)
}

func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("veil daemon", flag.ContinueOnError)
	dataDir := fs.String("data-dir", config.DefaultClient().DataDir, "client data directory")
	killSwitch := fs.Bool("kill-switch", true, "with full-tunnel, block non-tunnel traffic if the tunnel drops")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opt, err := loadOptions(*dataDir, false, *killSwitch)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return daemon.New(opt).Serve(ctx)
}

func cmdCtl(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veil ctl connect [--full] | disconnect | status")
	}
	switch args[0] {
	case "status":
		return ctlStatus()
	case "disconnect":
		return ctlPost("/v1/disconnect", nil)
	case "connect":
		fs := flag.NewFlagSet("veil ctl connect", flag.ContinueOnError)
		full := fs.Bool("full", false, "route all traffic through the tunnel")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return ctlConnect(*full)
	default:
		return fmt.Errorf("unknown ctl command %q", args[0])
	}
}

func daemonErr(err error) error {
	return fmt.Errorf("cannot reach the veil daemon (is `sudo veil daemon` running?): %w", err)
}

func fetchStatus() (client.Status, error) {
	resp, err := ipc.HTTPClient().Get(ipc.Host + "/v1/status")
	if err != nil {
		return client.Status{}, daemonErr(err)
	}
	defer resp.Body.Close()
	var st client.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return client.Status{}, err
	}
	return st, nil
}

func ctlStatus() error {
	st, err := fetchStatus()
	if err != nil {
		return err
	}
	printStatus(st)
	return nil
}

func ctlPost(path string, body any) error {
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	resp, err := ipc.HTTPClient().Post(ipc.Host+path, "application/json", buf)
	if err != nil {
		return daemonErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("daemon returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var st client.Status
	if json.NewDecoder(resp.Body).Decode(&st) == nil {
		printStatus(st)
	}
	return nil
}

func ctlConnect(full bool) error {
	if err := ctlPost("/v1/connect", daemon.ConnectRequest{Full: full}); err != nil {
		return err
	}
	// Poll until the state leaves "connecting".
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		st, err := fetchStatus()
		if err != nil {
			return err
		}
		if st.State != client.StateConnecting {
			printStatus(st)
			if st.State == client.StateDisconnected && st.Err != "" {
				return fmt.Errorf("%s", st.Err)
			}
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting to connect")
}

func printStatus(st client.Status) {
	line := "state: " + string(st.State)
	if st.Transport != "" {
		line += "  transport: " + st.Transport
	}
	if st.AssignedIP != "" {
		line += "  ip: " + st.AssignedIP
	}
	if st.Server != "" {
		line += "  server: " + st.Server
	}
	if st.FullTunnel {
		line += "  [full-tunnel]"
	}
	fmt.Println(line)
	if st.Err != "" {
		fmt.Println("error:", st.Err)
	}
}
