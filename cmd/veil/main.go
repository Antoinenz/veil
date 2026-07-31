// Command veil is the client: a privileged daemon that manages the TUN device,
// races transports to connect, runs the tunnel, and enforces the kill-switch —
// plus the CLI used to enroll and control it.
//
// M0 provides the CLI surface and local device-key generation. Enrollment
// networking, the tunnel, and the daemon land in M1+.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/veilvpn/veil/internal/client"
	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/noise"
)

const usage = `veil — one-button self-hostable VPN client

usage:
  veil login <server> <invite>   enroll this device with a gateway
  veil up                        connect (auto-selects the best transport)
  veil down                      disconnect
  veil status                    show connection state
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
	case "down":
		err = cmdDown(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
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

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("veil up", flag.ContinueOnError)
	dataDir := fs.String("data-dir", config.DefaultClient().DataDir, "client data directory")
	full := fs.Bool("full", false, "route ALL traffic through the tunnel (full VPN: default route + DNS)")
	killSwitch := fs.Bool("kill-switch", true, "with --full, block non-tunnel traffic if the tunnel drops")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadClient(filepath.Join(*dataDir, "client.json"))
	if err != nil {
		return err
	}
	if *full {
		cfg.FullTunnel = true
	}
	cfg.KillSwitch = *killSwitch
	if cfg.ServerPublicKey == "" {
		return fmt.Errorf("no server public key in config; run `veil login --server-key ...` first")
	}
	serverStatic, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("decode server public key: %w", err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(*dataDir, "device.key"))
	if err != nil {
		return fmt.Errorf("read device key: %w", err)
	}
	device, err := noise.LoadKeyPair(keyBytes)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return client.Run(ctx, client.FromConfig(cfg, device, serverStatic))
}

func cmdDown(args []string) error {
	// The M1 client is foreground (Ctrl-C to disconnect). A background daemon
	// with IPC control lands with the service work in M4.
	fmt.Println("down: the M1 client runs in the foreground — stop it with Ctrl-C")
	return nil
}

func cmdStatus(args []string) error {
	fmt.Println("status: the M1 client runs in the foreground; see the `veil up` process")
	return nil
}
