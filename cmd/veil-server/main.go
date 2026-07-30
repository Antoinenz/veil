// Command veil-server is the self-hostable gateway: it terminates client tunnels,
// assigns virtual IPs, masquerades traffic to the internet, and serves the
// control plane (enrollment + admin) alongside a decoy site on :443.
//
// M0 provides the CLI surface and the `init` wizard (real keypair generation).
// The data plane and control plane land in M1–M3.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/server"
	"github.com/veilvpn/veil/internal/store"
)

const usage = `veil-server — self-hostable VPN gateway

usage:
  veil-server init    --domain <host> [--data-dir <dir>]   generate keys + config, print fingerprint & invite
  veil-server run     [--config <file>]                     run the gateway
  veil-server invite  [--data-dir <dir>]                    mint a new single-use enrollment invite
  veil-server devices [--data-dir <dir>] [--revoke <key>]   list or revoke enrolled devices
  veil-server version

`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "invite":
		err = cmdInvite(os.Args[2:])
	case "devices":
		err = cmdDevices(os.Args[2:])
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

func cmdInit(args []string) error {
	fs := newFlagSet("init")
	domain := fs.String("domain", "", "public hostname clients connect to (required)")
	dataDir := fs.String("data-dir", "/var/lib/veil", "directory for keys, config, and device store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	kp, err := noise.GenerateKeyPair()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(*dataDir, "server.key")
	if err := os.WriteFile(keyPath, kp.Private.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}
	// server.pub holds the base64 static public key clients need to enroll.
	pubB64 := base64.StdEncoding.EncodeToString(kp.Public.Bytes())
	pubPath := filepath.Join(*dataDir, "server.pub")
	if err := os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644); err != nil {
		return fmt.Errorf("write server pubkey: %w", err)
	}

	cfg := config.DefaultServer()
	cfg.Domain = *domain
	cfg.DataDir = *dataDir
	cfgPath := filepath.Join(*dataDir, "server.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}

	st, err := store.Open(filepath.Join(*dataDir, "veil.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	invite := newInvite()
	if err := st.CreateInvite(invite); err != nil {
		return fmt.Errorf("store invite: %w", err)
	}

	fmt.Printf(`veil-server initialized.

  config       %s
  private key  %s   (keep secret)
  public key   %s
  server fingerprint:

      %s

  first invite code:

      %s

Enroll a client with:

  veil login %s %s

Next: open TCP+UDP :443 to this host, point %s at it, then run:

  veil-server run --config %s
`,
		cfgPath, keyPath, pubB64, noise.Fingerprint(kp.Public), invite,
		*domain, invite, *domain, cfgPath)
	return nil
}

func cmdRun(args []string) error {
	fs := newFlagSet("run")
	cfgPath := fs.String("config", "/var/lib/veil/server.json", "path to server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(filepath.Join(cfg.DataDir, "server.key"))
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}
	kp, err := noise.LoadKeyPair(keyBytes)
	if err != nil {
		return err
	}

	st, err := store.Open(filepath.Join(cfg.DataDir, "veil.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	srv, err := server.New(cfg, kp, st)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func cmdInvite(args []string) error {
	fs := newFlagSet("invite")
	dataDir := fs.String("data-dir", "/var/lib/veil", "server data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "veil.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	invite := newInvite()
	if err := st.CreateInvite(invite); err != nil {
		return err
	}
	fmt.Printf("new invite: %s\n", invite)
	return nil
}

func cmdDevices(args []string) error {
	fs := newFlagSet("devices")
	dataDir := fs.String("data-dir", "/var/lib/veil", "server data directory")
	revoke := fs.String("revoke", "", "revoke the device with this base64 public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "veil.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	if *revoke != "" {
		ok, err := st.RevokeDevice(*revoke)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no such device: %s", *revoke)
		}
		fmt.Printf("revoked %s\n", *revoke)
		return nil
	}

	devices, err := st.ListDevices()
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		fmt.Println("no enrolled devices")
		return nil
	}
	for _, d := range devices {
		name := d.Name
		if name == "" {
			name = "-"
		}
		fmt.Printf("%s  %-16s  enrolled %s\n", d.PublicKey, name, d.EnrolledAt.Format("2006-01-02 15:04"))
	}
	return nil
}

// newInvite returns a random, human-typeable one-time enrollment code.
func newInvite() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	return enc[:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16]
}
