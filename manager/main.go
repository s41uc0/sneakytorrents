// sneaky is the supervisor for the sneakytorrents image: it locks qBittorrent's
// traffic to a VPN tunnel, manages that tunnel (Mullvad, WireGuard, OpenVPN),
// and serves the setup UI in front of qBittorrent's own web UI.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	configDir  = "/config"
	dataDir    = "/data"
	runDir     = "/run/sneaky"
	hookSocket = runDir + "/hook.sock"
	vpnIface   = "vpn0"
	qbtWebPort = 8081
)

type Env struct {
	UID, GID int
	WebPort  int
}

type App struct {
	env     Env
	caps    Caps
	logins  loginLimiter
	log     *Logger
	store   *Store
	host    *HostNet
	qbt     *QBit
	vpn     *VPN
	mullvad *Mullvad
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		os.Exit(runHook())
	}
	log := NewLogger(600)
	if err := run(log); err != nil {
		log.Printf("sneaky", "fatal: %v", err)
		os.Exit(1)
	}
}

func run(log *Logger) error {
	env, err := loadEnv()
	if err != nil {
		return err
	}
	for _, d := range []string{configDir, runDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, d := range []string{filepath.Join(dataDir, "downloads"), filepath.Join(dataDir, "incomplete")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		if err := os.Chown(d, env.UID, env.GID); err != nil {
			return err
		}
	}

	store, err := OpenStore(filepath.Join(configDir, "sneaky.json"))
	if err != nil {
		return err
	}
	host, err := SetupHostNet()
	if err != nil {
		return fmt.Errorf("network setup: %w", err)
	}
	// The kill switch goes up before qBittorrent starts and is never taken down.
	if err := ApplyFirewall(env.WebPort); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	if err := SetForwardedPort(store.Get().ForwardedPort); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	log.Printf("sneaky", "kill switch active: qBittorrent (uid %d) can only use %s", env.UID, vpnIface)

	a := &App{env: env, log: log, store: store, host: host, caps: DetectCaps()}
	switch {
	case a.caps.WireGuard == "kernel":
		log.Printf("sneaky", "WireGuard: kernel module")
	case a.caps.WireGuard == "userspace":
		log.Printf("sneaky", "WireGuard: no kernel module, using wireguard-go")
	case !a.caps.OpenVPN:
		log.Printf("sneaky", "no /dev/net/tun and no kernel WireGuard: no VPN can run; pass --device /dev/net/tun")
	default:
		log.Printf("sneaky", "WireGuard unavailable; only OpenVPN can be used")
	}
	a.mullvad = NewMullvad(filepath.Join(configDir, "mullvad-relays.json"))
	a.qbt = NewQBit(a)
	a.vpn = NewVPN(a)
	net.DefaultResolver = a.resolver()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// qBittorrent stops before the tunnel does, so it can announce/save cleanly.
	qbtCtx, stopQbt := context.WithCancel(context.Background())
	qbtDone := make(chan struct{})
	go func() { a.qbt.Supervise(qbtCtx); close(qbtDone) }()

	vpnCtx, stopVPN := context.WithCancel(context.Background())
	vpnDone := make(chan struct{})
	go func() { a.vpn.Run(vpnCtx); close(vpnDone) }()
	a.vpn.Kick()

	go a.serveHook(sigCtx)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", env.WebPort),
		Handler:           a.routes(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		<-sigCtx.Done()
		log.Printf("sneaky", "shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Printf("sneaky", "web UI on :%d (setup at /vpn/)", env.WebPort)
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	stopQbt()
	<-qbtDone
	stopVPN()
	<-vpnDone
	return err
}

func loadEnv() (Env, error) {
	env := Env{UID: 1000, GID: 1000, WebPort: 8080}
	for _, v := range []struct {
		name string
		dst  *int
	}{{"PUID", &env.UID}, {"PGID", &env.GID}, {"WEBUI_PORT", &env.WebPort}} {
		s := strings.TrimSpace(os.Getenv(v.name))
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return env, fmt.Errorf("%s must be a non-negative number, got %q", v.name, s)
		}
		*v.dst = n
	}
	// The kill switch tells qBittorrent apart from the tunnel by uid, so it must not run as root.
	if env.UID == 0 {
		return env, errors.New("PUID=0 is not supported: qBittorrent must run as a non-root user for the kill switch to work")
	}
	if env.WebPort == 0 || env.WebPort > 65535 || env.WebPort == qbtWebPort {
		return env, fmt.Errorf("WEBUI_PORT must be 1-65535 and not %d", qbtWebPort)
	}
	return env, nil
}

// resolver sends the manager's own DNS lookups through the tunnel's DNS while
// it is up, and to the container's original resolvers otherwise.
func (a *App) resolver() *net.Resolver {
	var n atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			servers := a.vpn.DNS()
			if len(servers) == 0 {
				servers = a.host.Nameservers
			}
			if len(servers) == 0 {
				return nil, errors.New("no DNS servers configured")
			}
			srv := servers[int(n.Add(1))%len(servers)]
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(srv, "53"))
		},
	}
}

func run1(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runInput(input, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func output(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}
