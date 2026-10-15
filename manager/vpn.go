package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Status struct {
	State       string    `json:"state"` // off | connecting | connected | error
	Error       string    `json:"error,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	Server      string    `json:"server,omitempty"`
	Location    string    `json:"location,omitempty"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Since       time.Time `json:"since,omitzero"`
	Handshake   time.Time `json:"handshake,omitzero"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	PublicIP    string    `json:"public_ip,omitempty"`
	ExitCountry string    `json:"exit_country,omitempty"`
	ExitCity    string    `json:"exit_city,omitempty"`
	MullvadExit bool      `json:"mullvad_exit"`
}

// VPN owns the tunnel. A single worker goroutine (Run) starts and stops
// sessions; Kick asks it to re-read the settings. Status updates carry the
// generation of the session that made them, so a session being torn down can't
// overwrite the status of its replacement.
type VPN struct {
	a    *App
	kick chan struct{}

	mu            sync.Mutex
	gen           uint64
	st            Status
	dns           []string
	epRoute       string
	userspace     *exec.Cmd
	userspaceDone chan struct{}
}

func NewVPN(a *App) *VPN {
	return &VPN{a: a, kick: make(chan struct{}, 1), st: Status{State: "off"}}
}

func (v *VPN) Kick() {
	s := v.a.store.Get()
	v.mu.Lock()
	v.gen++
	if s.Onboarded && s.Enabled {
		v.st = Status{State: "connecting", Provider: s.Provider}
	} else {
		v.st = Status{State: "off"}
	}
	v.mu.Unlock()
	select {
	case v.kick <- struct{}{}:
	default:
	}
}

func (v *VPN) Status() Status {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.st
}

func (v *VPN) DNS() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.dns...)
}

func (v *VPN) update(gen uint64, fn func(*Status)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if gen == v.gen {
		fn(&v.st)
	}
}

func (v *VPN) currentGen() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.gen
}

func (v *VPN) Run(ctx context.Context) {
	type session struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	var cur *session
	stop := func() {
		if cur != nil {
			cur.cancel()
			<-cur.done
			cur = nil
		}
	}
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-v.kick:
			stop()
			s := v.a.store.Get()
			if !s.Onboarded || !s.Enabled {
				continue
			}
			sctx, cancel := context.WithCancel(ctx)
			cur = &session{cancel: cancel, done: make(chan struct{})}
			go func(done chan struct{}, gen uint64) {
				defer close(done)
				v.loop(sctx, gen, s)
			}(cur.done, v.currentGen())
		}
	}
}

// loop keeps one provider's tunnel up, reconnecting with backoff.
func (v *VPN) loop(ctx context.Context, gen uint64, s Settings) {
	backoff := 5 * time.Second
	for {
		started := time.Now()
		v.update(gen, func(st *Status) {
			*st = Status{State: "connecting", Provider: s.Provider, Error: st.Error}
		})
		var err error
		switch s.Provider {
		case "mullvad", "wireguard":
			err = v.runWireGuard(ctx, gen, s)
		case "openvpn":
			err = v.runOpenVPN(ctx, gen, s)
		default:
			err = fmt.Errorf("unknown provider %q", s.Provider)
		}
		v.teardown()
		if ctx.Err() != nil {
			return
		}
		v.a.log.Printf("vpn", "%v (retrying in %s)", err, backoff)
		v.update(gen, func(st *Status) {
			*st = Status{State: "error", Provider: s.Provider, Error: err.Error(), Server: st.Server, Location: st.Location}
		})
		if time.Since(started) > 2*time.Minute {
			backoff = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 2*time.Minute)
	}
}

func (v *VPN) setDNS(servers []string) error {
	v.mu.Lock()
	v.dns = append([]string(nil), servers...)
	v.mu.Unlock()
	return v.a.host.SetDNS(servers)
}

func (v *VPN) clearDNS() {
	v.mu.Lock()
	v.dns = nil
	v.mu.Unlock()
	if err := v.a.host.RestoreDNS(); err != nil {
		v.a.log.Printf("vpn", "restoring resolv.conf: %v", err)
	}
}

func (v *VPN) teardown() {
	_ = run1("ip", "link", "del", vpnIface)
	v.mu.Lock()
	cmd, done, ep := v.userspace, v.userspaceDone, v.epRoute
	v.userspace, v.userspaceDone, v.epRoute = nil, nil, ""
	v.mu.Unlock()
	if cmd != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}
	if ep != "" {
		_ = run1("ip", "route", "del", ep+"/32")
	}
	v.clearDNS()
}

// --- WireGuard (Mullvad and custom) ---

type wgPeer struct {
	Name, Location        string
	PrivateKey, PublicKey string
	PresharedKey          string
	EndpointIP            string
	Port                  int
	Address               string
	DNS                   []string
	MTU                   int
}

func (p wgPeer) endpoint() string { return net.JoinHostPort(p.EndpointIP, strconv.Itoa(p.Port)) }

func (v *VPN) wgPeer(ctx context.Context, s Settings) (wgPeer, error) {
	switch s.Provider {
	case "mullvad":
		m := s.Mullvad
		if m.PrivateKey == "" {
			return wgPeer{}, errors.New("not signed in to Mullvad")
		}
		rl, err := v.a.mullvad.Relays(ctx)
		if err != nil {
			return wgPeer{}, err
		}
		r, err := PickRelay(rl, m.Country, m.City, m.Hostname)
		if err != nil {
			return wgPeer{}, err
		}
		loc := rl.Locations[r.Location]
		dns := firstNonEmpty(rl.WireGuard.IPv4Gateway, "10.64.0.1")
		return wgPeer{
			Name:       r.Hostname,
			Location:   strings.Trim(loc.City+", "+loc.Country, ", "),
			PrivateKey: m.PrivateKey,
			PublicKey:  r.PublicKey,
			EndpointIP: r.IPv4,
			Port:       51820,
			Address:    m.Address,
			DNS:        []string{dns},
			MTU:        1380,
		}, nil
	case "wireguard":
		w := s.WireGuard
		host, portStr, err := net.SplitHostPort(w.Endpoint)
		if err != nil {
			return wgPeer{}, fmt.Errorf("bad endpoint %q", w.Endpoint)
		}
		port, _ := strconv.Atoi(portStr)
		ip := host
		if a, err := netip.ParseAddr(host); err != nil || !a.Is4() {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return wgPeer{}, fmt.Errorf("could not resolve %s: %v", host, err)
			}
			ip = ips[0].String()
		}
		addr, err := firstIPv4Prefix(w.Address)
		if err != nil {
			return wgPeer{}, err
		}
		dns := ipv4List(w.DNS)
		if len(dns) == 0 {
			dns = []string{"1.1.1.1"}
		}
		mtu := w.MTU
		if mtu == 0 {
			mtu = 1380
		}
		return wgPeer{
			Name: host, PrivateKey: w.PrivateKey, PublicKey: w.PublicKey, PresharedKey: w.PresharedKey,
			EndpointIP: ip, Port: port, Address: addr, DNS: dns, MTU: mtu,
		}, nil
	}
	return wgPeer{}, fmt.Errorf("provider %q is not WireGuard", s.Provider)
}

func (v *VPN) runWireGuard(ctx context.Context, gen uint64, s Settings) error {
	p, err := v.wgPeer(ctx, s)
	if err != nil {
		return err
	}
	v.update(gen, func(st *Status) { st.Server, st.Location, st.Endpoint = p.Name, p.Location, p.endpoint() })
	v.a.log.Printf("vpn", "connecting to %s (%s) over WireGuard", p.Name, p.endpoint())
	if err := v.wgUp(p); err != nil {
		return err
	}
	if err := v.setDNS(p.DNS); err != nil {
		return err
	}

	start := time.Now()
	connected := false
	var lastCheck time.Time
	for {
		hs, rx, tx, err := wgStats()
		if err != nil {
			return err
		}
		v.update(gen, func(st *Status) { st.Handshake, st.RxBytes, st.TxBytes = hs, rx, tx })
		if !hs.IsZero() && !connected {
			connected = true
			v.a.log.Printf("vpn", "connected to %s", p.Name)
			v.update(gen, func(st *Status) { st.State, st.Error, st.Since = "connected", "", time.Now() })
		}
		if hs.IsZero() && time.Since(start) > 30*time.Second {
			return fmt.Errorf("no handshake from %s after 30s: check the keys and that the server is reachable", p.Name)
		}
		if !hs.IsZero() && time.Since(hs) > 4*time.Minute {
			return fmt.Errorf("lost contact with %s (no handshake for 4 minutes)", p.Name)
		}
		if connected && time.Since(lastCheck) > 10*time.Minute {
			lastCheck = time.Now()
			go v.checkIP(ctx, gen)
		}
		wait := 15 * time.Second
		if !connected {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (v *VPN) wgUp(p wgPeer) error {
	_ = run1("ip", "link", "del", vpnIface)
	if v.a.caps.WireGuard != "kernel" || run1("ip", "link", "add", vpnIface, "type", "wireguard") != nil {
		if err := v.startUserspace(); err != nil {
			return err
		}
	}
	var conf strings.Builder
	fmt.Fprintf(&conf, "[Interface]\nPrivateKey = %s\nFwMark = %d\n\n[Peer]\nPublicKey = %s\n", p.PrivateKey, wgFwMark, p.PublicKey)
	if p.PresharedKey != "" {
		fmt.Fprintf(&conf, "PresharedKey = %s\n", p.PresharedKey)
	}
	fmt.Fprintf(&conf, "Endpoint = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n", p.endpoint())
	if err := runInput(conf.String(), "wg", "setconf", vpnIface, "/dev/stdin"); err != nil {
		return err
	}

	// Pin the route to the VPN server to the Docker network before taking over the default route.
	epRoute, err := routeTo(p.EndpointIP)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.epRoute = p.EndpointIP
	v.mu.Unlock()
	for _, args := range [][]string{
		{"ip", "-4", "address", "add", p.Address, "dev", vpnIface},
		{"ip", "link", "set", "dev", vpnIface, "mtu", strconv.Itoa(p.MTU), "up"},
		append([]string{"ip", "route", "replace", p.EndpointIP + "/32"}, epRoute...),
		{"ip", "route", "replace", "0.0.0.0/1", "dev", vpnIface},
		{"ip", "route", "replace", "128.0.0.0/1", "dev", vpnIface},
	} {
		if err := run1(args[0], args[1:]...); err != nil {
			return err
		}
	}
	// Re-setting the keepalive makes WireGuard send a packet now rather than waiting for traffic.
	_ = run1("wg", "set", vpnIface, "peer", p.PublicKey, "persistent-keepalive", "25")
	return nil
}

// routeTo returns the "via X dev Y" arguments the kernel currently uses to reach ip.
func routeTo(ip string) ([]string, error) {
	out, err := output("ip", "-4", "-j", "route", "get", ip)
	if err != nil {
		return nil, err
	}
	var r []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal(out, &r); err != nil || len(r) == 0 || r[0].Dev == "" {
		return nil, fmt.Errorf("no route to VPN server %s", ip)
	}
	if r[0].Dev == vpnIface {
		return nil, fmt.Errorf("VPN server %s would be routed through the tunnel itself", ip)
	}
	if r[0].Gateway != "" {
		return []string{"via", r[0].Gateway, "dev", r[0].Dev}, nil
	}
	return []string{"dev", r[0].Dev}, nil
}

func (v *VPN) startUserspace() error {
	cmd := exec.Command("wireguard-go", "-f", vpnIface)
	cmd.Env = append(os.Environ(), "WG_PROCESS_FOREGROUND=1", "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1")
	w := v.a.log.Writer("wireguard-go")
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting wireguard-go: %w", err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	v.mu.Lock()
	v.userspace, v.userspaceDone = cmd, done
	v.mu.Unlock()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat("/sys/class/net/" + vpnIface); err == nil {
			return nil
		}
		select {
		case <-done:
			return errors.New("wireguard-go exited; is /dev/net/tun passed to the container?")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("wireguard-go did not create the interface")
}

func wgStats() (handshake time.Time, rx, tx uint64, err error) {
	out, err := output("wg", "show", vpnIface, "dump")
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		err = errors.New("WireGuard interface has no peer")
		return
	}
	f := strings.Split(lines[1], "\t")
	if len(f) < 8 {
		err = errors.New("unexpected output from wg")
		return
	}
	if sec, _ := strconv.ParseInt(f[4], 10, 64); sec > 0 {
		handshake = time.Unix(sec, 0)
	}
	rx, _ = strconv.ParseUint(f[5], 10, 64)
	tx, _ = strconv.ParseUint(f[6], 10, 64)
	return
}

// --- OpenVPN ---

func (v *VPN) runOpenVPN(ctx context.Context, gen uint64, s Settings) error {
	o := s.OpenVPN
	cfg := filepath.Join(runDir, "client.ovpn")
	if err := os.WriteFile(cfg, []byte(o.Config), 0o600); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// Our options come after --config so they override the file's.
	args := []string{
		"--config", cfg,
		"--dev", vpnIface, "--dev-type", "tun",
		"--redirect-gateway", "def1",
		"--pull-filter", "ignore", "route-ipv6",
		"--pull-filter", "ignore", "ifconfig-ipv6",
		"--pull-filter", "ignore", "block-outside-dns",
		"--script-security", "2",
		"--up", self + " hook", "--down", self + " hook",
		"--resolv-retry", "infinite",
		"--verb", "3",
	}
	if o.Username != "" {
		auth := filepath.Join(runDir, "auth.txt")
		if err := os.WriteFile(auth, []byte(o.Username+"\n"+o.Password+"\n"), 0o600); err != nil {
			return err
		}
		args = append(args, "--auth-user-pass", auth, "--auth-nocache")
	}

	v.a.log.Printf("vpn", "starting OpenVPN")
	cmd := exec.Command("openvpn", args...)
	cmd.Dir = runDir
	w := v.a.log.Writer("openvpn")
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting openvpn: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("openvpn stopped (%v); see the log for details", err)
		case <-ctx.Done():
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				cmd.Process.Kill()
				<-exited
			}
			return ctx.Err()
		case <-tick.C:
			if v.Status().State == "connected" {
				go v.checkIP(ctx, gen)
			}
		}
	}
}

// onHook handles OpenVPN's --up/--down callbacks (relayed by `sneaky hook`).
func (v *VPN) onHook(env map[string]string) error {
	gen := v.currentGen()
	switch env["script_type"] {
	case "up":
		dns := ipv4List(v.a.store.Get().OpenVPN.DNS)
		if len(dns) == 0 {
			for k, val := range env {
				f := strings.Fields(val)
				if strings.HasPrefix(k, "foreign_option_") && len(f) == 3 && f[0] == "dhcp-option" && f[1] == "DNS" {
					dns = append(dns, ipv4List(f[2])...)
				}
			}
		}
		if len(dns) == 0 {
			dns = []string{"1.1.1.1"}
		}
		if err := v.setDNS(dns); err != nil {
			return err
		}
		server := firstNonEmpty(env["remote_1"], env["trusted_ip"])
		v.update(gen, func(st *Status) {
			st.State, st.Error, st.Since = "connected", "", time.Now()
			st.Server = server
			if env["trusted_ip"] != "" {
				st.Endpoint = net.JoinHostPort(env["trusted_ip"], env["trusted_port"])
			}
		})
		v.a.log.Printf("vpn", "OpenVPN connected to %s, DNS %s", server, strings.Join(dns, ", "))
		go func() {
			// OpenVPN adds its routes after --up returns.
			time.Sleep(3 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			v.checkIP(ctx, gen)
		}()
	case "down":
		v.clearDNS()
		v.update(gen, func(st *Status) { st.State, st.PublicIP, st.ExitCity, st.ExitCountry = "connecting", "", "", "" })
	}
	return nil
}

// serveHook listens on a root-only unix socket for `sneaky hook` calls.
func (a *App) serveHook(ctx context.Context) {
	os.Remove(hookSocket)
	l, err := net.Listen("unix", hookSocket)
	if err != nil {
		a.log.Printf("sneaky", "hook socket: %v", err)
		return
	}
	os.Chmod(hookSocket, 0o600)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env map[string]string
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.vpn.onHook(env); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})}
	go func() { <-ctx.Done(); srv.Close() }()
	srv.Serve(l)
}

// runHook is `sneaky hook`, run by OpenVPN as its up/down script.
func runHook() int {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		k, val, _ := strings.Cut(kv, "=")
		switch {
		case k == "script_type", k == "dev", k == "trusted_ip", k == "trusted_port", k == "remote_1",
			strings.HasPrefix(k, "foreign_option_"):
			env[k] = val
		}
	}
	body, _ := json.Marshal(env)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", hookSocket)
		}},
	}
	resp, err := client.Post("http://sneaky/hook", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sneaky hook:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "sneaky hook:", resp.Status)
		return 1
	}
	return 0
}

// --- exit IP check ---

func (v *VPN) checkIP(ctx context.Context, gen uint64) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
	resp, err := tunnelClient(v.DNS()).Do(req)
	if err != nil {
		v.a.log.Printf("vpn", "exit IP check failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var r struct {
		IP            string `json:"ip"`
		Country       string `json:"country"`
		City          string `json:"city"`
		MullvadExitIP bool   `json:"mullvad_exit_ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		v.a.log.Printf("vpn", "exit IP check: %v", err)
		return
	}
	v.update(gen, func(st *Status) {
		st.PublicIP, st.ExitCountry, st.ExitCity, st.MullvadExit = r.IP, r.Country, r.City, r.MullvadExitIP
	})
	v.a.log.Printf("vpn", "torrent traffic exits at %s (%s)", r.IP, strings.Trim(r.City+", "+r.Country, ", "))
}

// tunnelClient makes HTTP requests (and their DNS lookups) strictly through the tunnel interface.
func tunnelClient(dns []string) *http.Client {
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}
	bind := func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vpnIface)
		}); err != nil {
			return err
		}
		return serr
	}
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Control: bind}
		return d.DialContext(ctx, network, net.JoinHostPort(dns[0], "53"))
	}}
	d := &net.Dialer{Control: bind, Resolver: res, Timeout: 10 * time.Second}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second},
	}
}

// --- parsing helpers ---

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return err == nil && len(b) == 32
}

// firstIPv4Prefix picks the IPv4 entry from a WireGuard Address list ("10.0.0.2/32, fd00::2/128").
func firstIPv4Prefix(list string) (string, error) {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			part += "/32"
		}
		if p, err := netip.ParsePrefix(part); err == nil && p.Addr().Is4() {
			return p.String(), nil
		}
	}
	return "", fmt.Errorf("address %q has no IPv4 address", list)
}

func ipv4List(list string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a, err := netip.ParseAddr(part); err == nil && a.Is4() {
			out = append(out, a.String())
		}
	}
	return out
}
