package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// HostNet is the container's own (non-VPN) network: the Docker interface,
// its gateway, and the resolvers Docker gave us.
type HostNet struct {
	Dev, Gateway, Addr string
	Nameservers        []string
	resolvConf         []byte
}

// SetupHostNet records the Docker-side network and adds a policy route so that
// replies to web UI clients keep leaving via Docker even while the VPN owns the
// default route.
func SetupHostNet() (*HostNet, error) {
	_ = run1("ip", "link", "del", vpnIface) // leftover from a previous run

	out, err := output("ip", "-4", "-j", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return nil, err
	}
	if len(routes) == 0 || routes[0].Gateway == "" {
		return nil, errors.New("no default route; the container needs a normal (bridge) network")
	}
	h := &HostNet{Dev: routes[0].Dev, Gateway: routes[0].Gateway}

	out, err = output("ip", "-4", "-j", "addr", "show", "dev", h.Dev)
	if err != nil {
		return nil, err
	}
	var addrs []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &addrs); err != nil {
		return nil, err
	}
	if len(addrs) == 0 || len(addrs[0].AddrInfo) == 0 {
		return nil, fmt.Errorf("no IPv4 address on %s", h.Dev)
	}
	h.Addr = addrs[0].AddrInfo[0].Local

	if err := run1("ip", "route", "replace", "default", "via", h.Gateway, "dev", h.Dev, "table", "100"); err != nil {
		return nil, err
	}
	_ = run1("ip", "rule", "del", "from", h.Addr, "table", "100")
	if err := run1("ip", "rule", "add", "from", h.Addr, "table", "100", "pref", "100"); err != nil {
		return nil, err
	}

	h.resolvConf, err = os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(h.resolvConf), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(f[1]); err == nil && ip.Is4() {
				h.Nameservers = append(h.Nameservers, f[1])
			}
		}
	}
	return h, nil
}

// SetDNS points the container's resolv.conf (which qBittorrent uses) at the tunnel's DNS.
func (h *HostNet) SetDNS(servers []string) error {
	var b strings.Builder
	b.WriteString("# managed by sneakytorrents: DNS through the VPN\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	return os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644)
}

func (h *HostNet) RestoreDNS() error {
	return os.WriteFile("/etc/resolv.conf", h.resolvConf, 0o644)
}

// Caps is what this host can run: WireGuard in the kernel, WireGuard in
// userspace (wireguard-go, needs only /dev/net/tun), and OpenVPN (needs /dev/net/tun).
type Caps struct {
	WireGuard string `json:"wireguard"` // kernel | userspace | none
	OpenVPN   bool   `json:"openvpn"`
}

func DetectCaps() Caps {
	tun := false
	if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err == nil {
		f.Close()
		tun = true
	}
	c := Caps{WireGuard: "none", OpenVPN: tun}
	if run1("ip", "link", "add", "wgprobe0", "type", "wireguard") == nil {
		_ = run1("ip", "link", "del", "wgprobe0")
		c.WireGuard = "kernel"
	} else if _, err := exec.LookPath("wireguard-go"); err == nil && tun {
		c.WireGuard = "userspace"
	}
	return c
}

// wgFwMark marks kernel WireGuard's encrypted packets. They keep the uid of the
// socket whose traffic they carry, so the kill switch lets them out by this mark
// (setting a mark needs CAP_NET_ADMIN, which qBittorrent doesn't have).
const wgFwMark = 51820

// The kill switch. Every socket not owned by root (i.e. qBittorrent) may only
// send through loopback or the tunnel, and not to Docker's embedded DNS (which
// would resolve outside the tunnel). Root (this manager, wireguard-go, openvpn)
// needs the Docker network to reach the VPN server itself.
const nftRuleset = `table inet sneaky
delete table inet sneaky
table inet sneaky {
	counter leak_blocked {
	}
	set fwd_ports {
		type inet_service
	}
	chain output {
		type filter hook output priority filter; policy accept;
		meta skuid != 0 jump torrent_out
	}
	chain torrent_out {
		oifname "lo" ip daddr 127.0.0.11 counter name "leak_blocked" reject
		oifname "lo" accept
		oifname "%[1]s" accept
		meta mark %[3]d accept
		counter name "leak_blocked" reject
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established,related accept
		ct state invalid drop
		iifname != "%[1]s" tcp dport %[2]d accept
		iifname "%[1]s" meta l4proto { tcp, udp } th dport @fwd_ports accept
		meta l4proto { icmp, ipv6-icmp } accept
	}
}
`

func ApplyFirewall(webPort int) error {
	return runInput(fmt.Sprintf(nftRuleset, vpnIface, webPort, wgFwMark), "nft", "-f", "-")
}

// SetForwardedPort opens a provider-forwarded port for inbound peers on the tunnel (0 closes it).
func SetForwardedPort(port int) error {
	script := "flush set inet sneaky fwd_ports\n"
	if port > 0 {
		script += fmt.Sprintf("add element inet sneaky fwd_ports { %d }\n", port)
	}
	return runInput(script, "nft", "-f", "-")
}

// BlockedPackets is how many packets the kill switch has stopped from leaving outside the tunnel.
func BlockedPackets() (uint64, error) {
	out, err := output("nft", "-j", "list", "counter", "inet", "sneaky", "leak_blocked")
	if err != nil {
		return 0, err
	}
	var res struct {
		Nftables []struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return 0, err
	}
	for _, e := range res.Nftables {
		if e.Counter != nil {
			return e.Counter.Packets, nil
		}
	}
	return 0, nil
}
