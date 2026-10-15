// sneaky is the supervisor for the sneakytorrents image: it locks qBittorrent's
// traffic to a VPN tunnel, manages that tunnel (Mullvad, WireGuard, OpenVPN),
// and serves the setup UI in front of qBittorrent's own web UI.
package main

import (
	"context"
	"encoding/json"
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
	runDir     = "/run/sneaky"
	hookSocket = runDir + "/hook.sock"
	vpnIface   = "vpn0"
	qbtWebPort = 8081
)

// Settings and qBittorrent's profile live in configDir; downloads in dataDir.
// Both can be moved with CONFIG_DIR / DATA_DIR, and as a Home Assistant app
// dataDir comes from the app's download_dir option.
var (
	configDir = "/config"
	dataDir   = "/data"
)

type Env struct {
	UID, GID int
	WebPort  int
	// HA is set when running as a Home Assistant app; IngressIP is the
	// Supervisor's ingress proxy, whose requests Home Assistant has already authenticated.
	HA        bool
	IngressIP string
	// ExtraPaths are additional folders qBittorrent may save to (Home Assistant
	// app option), each optionally exposed as a qBittorrent category.
	ExtraPaths []ExtraPath
}

type ExtraPath struct {
	Path     string `json:"path"`
	Category string `json:"category"`
}

func inMediaOrShare(dir string) bool {
	return strings.HasPrefix(dir, "/media/") || strings.HasPrefix(dir, "/share/")
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
	if env.HA {
		log.Printf("sneaky", "running as a Home Assistant app; downloads in %s", dataDir)
	}
	for _, p := range env.ExtraPaths {
		if err := prepareWritable(p.Path, env); err != nil {
			log.Printf("sneaky", "extra path %s: %v", p.Path, err)
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
	log.Printf("sneaky", "kill switch active: qBittorrent (uid %d, gid %d) can only use %s", env.UID, env.GID, vpnIface)
	if env.UID == 0 {
		log.Printf("sneaky", "qBittorrent runs as root with only file-access capabilities, so it can write to root-owned network shares")
	}

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
	// The kill switch recognises qBittorrent by a non-root uid or gid.
	if env.UID == 0 && env.GID == 0 {
		return env, errors.New("PUID=0 needs a non-zero PGID: the kill switch recognises qBittorrent by its group")
	}
	if env.WebPort == 0 || env.WebPort > 65535 || env.WebPort == qbtWebPort {
		return env, fmt.Errorf("WEBUI_PORT must be 1-65535 and not %d", qbtWebPort)
	}
	if d := os.Getenv("CONFIG_DIR"); d != "" {
		configDir = d
	}
	if d := os.Getenv("DATA_DIR"); d != "" {
		dataDir = d
	}

	if os.Getenv("SUPERVISOR_TOKEN") != "" {
		env.HA = true
		env.IngressIP = "172.30.32.2"
		if ip := os.Getenv("SNEAKY_INGRESS_IP"); ip != "" {
			env.IngressIP = ip // for testing outside Home Assistant
		}
		var opts struct {
			DownloadDir string      `json:"download_dir"`
			ExtraPaths  []ExtraPath `json:"extra_paths"`
		}
		if data, err := os.ReadFile("/data/options.json"); err == nil {
			if err := json.Unmarshal(data, &opts); err != nil {
				return env, fmt.Errorf("reading app options: %w", err)
			}
		}
		if opts.DownloadDir != "" {
			dir := filepath.Clean(opts.DownloadDir)
			if !inMediaOrShare(dir) {
				return env, fmt.Errorf("download_dir must be inside /media or /share, got %q", opts.DownloadDir)
			}
			dataDir = dir
		}
		for _, p := range opts.ExtraPaths {
			dir := filepath.Clean(p.Path)
			if !inMediaOrShare(dir) {
				return env, fmt.Errorf("extra_paths: %q must be inside /media or /share", p.Path)
			}
			env.ExtraPaths = append(env.ExtraPaths, ExtraPath{Path: dir, Category: strings.TrimSpace(p.Category)})
		}
	}
	return env, nil
}

// prepareWritable creates dir if needed and makes sure qBittorrent's user can
// write to it, taking ownership of the folder itself (not its contents) only
// when it can't already.
func prepareWritable(dir string, env Env) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writable := func() bool { return env.qbtCmd("test", "-w", dir).Run() == nil }
	if writable() {
		return nil
	}
	if err := os.Chown(dir, env.UID, env.GID); err == nil && writable() {
		return nil
	}
	if env.UID != 0 {
		return fmt.Errorf("qBittorrent (uid %d) can't write here; for a network share, set PUID=0", env.UID)
	}
	return errors.New("qBittorrent can't write here; check that the share isn't mounted read-only")
}

// qbtCmd prepares a command to run with qBittorrent's identity: the PUID/PGID
// user, or with PUID=0 root keeping only file-access capabilities. Root is
// needed to write to network shares that are mounted root-owned (as Home
// Assistant does), and dac_override/fowner to keep writing files other users
// created; without the network capabilities it can't touch the firewall or routing.
func (e Env) qbtCmd(name string, args ...string) *exec.Cmd {
	if e.UID == 0 {
		return exec.Command("setpriv", append([]string{
			"--reuid=0", "--regid=" + strconv.Itoa(e.GID), "--clear-groups",
			"--inh-caps=-all", "--bounding-set=-all,+dac_override,+fowner", "--no-new-privs",
			"--", name}, args...)...)
	}
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(e.UID), Gid: uint32(e.GID)}}
	return cmd
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
