# sneakytorrents

qBittorrent in one container, with all of its traffic forced through a VPN.
Mount `/config` and `/data`, open the web UI, and set the VPN up there:

- **Mullvad**: enter your account number, then pick a country, city or server.
- **WireGuard**: any provider or your own server. Paste or upload a `.conf` file.
- **OpenVPN**: any provider. Paste or upload a `.ovpn` file, plus a username and password if it needs them.

## Run

```sh
docker compose up -d --build
```

Then open `http://<host>:8080`. The first visit walks you through:

1. creating your login, which protects both the VPN page and qBittorrent (qBittorrent's own login page never shows),
2. choosing a VPN,
3. connecting, and showing the IP your torrents now come from.

After that, `http://<host>:8080/` is qBittorrent and `http://<host>:8080/vpn/` is the VPN dashboard.
qBittorrent also shows a small VPN status badge in its bottom-right corner, which links to the dashboard.

Plain `docker run`:

```sh
docker run -d --name sneakytorrents \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -p 8080:8080 \
  -e PUID=1000 -e PGID=1000 -e TZ=Europe/Amsterdam \
  -v ./config:/config -v ./data:/data \
  sneakytorrents:latest
```

Pushes to `main` and `v*` tags publish a multi-arch image (amd64 and arm64) to `ghcr.io/<owner>/<repo>`, via `.github/workflows/container.yml`.
To use it, replace `build: .` in the compose file with that image.

`NET_ADMIN` and `/dev/net/tun` are required: the container builds its own tunnel and firewall.
No other privileges are needed.

| Variable | Default | |
| --- | --- | --- |
| `PUID` / `PGID` | `1000` | Owner of downloads and config. Must not be 0. |
| `WEBUI_PORT` | `8080` | Port the web UI listens on inside the container. |
| `TZ` | `UTC` | |

| Volume | |
| --- | --- |
| `/config` | VPN settings (`sneaky.json`, includes keys and passwords) and qBittorrent's profile. |
| `/data` | `downloads/` and `incomplete/`. |

## How it works

- **Kill switch.** An nftables rule lets any non-root process, which means qBittorrent, send traffic only over loopback or the tunnel interface `vpn0`.
  It is applied before qBittorrent starts and is never removed.
  If the VPN drops or is switched off, qBittorrent's traffic is blocked rather than sent over your own connection.
  qBittorrent is also bound to `vpn0` as a second layer.
  The dashboard shows how many packets the kill switch has blocked.
- **DNS** goes through the tunnel: Mullvad's resolver, the DNS from your WireGuard config, or the DNS pushed by the OpenVPN server.
  Docker's resolver is blocked for qBittorrent.
- **Web UI.** The web UI port stays on the Docker network. Replies to your browser are routed back out the normal way, so the UI keeps working whether the VPN is up or not.
- **Mullvad.** Signing in registers a new WireGuard key as a device on your account. Signing out removes it.
  With "Any" server selected, a server is picked by Mullvad's own weighting, and a different one is used if it stops responding.
- **Login.** sneakytorrents has its own login, with a rate-limited, 30-day session cookie.
  qBittorrent's web UI listens on localhost only and trusts it, and the proxy forwards only logged-in requests.
  qBittorrent's options dialog can't change the settings this depends on, such as web UI address, port, auth or network interface.
  Its *Log out* menu item logs you out of sneakytorrents.
- **WireGuard** uses the kernel module when the host has it, and falls back to `wireguard-go` otherwise.
  If neither works, the WireGuard and Mullvad options are hidden and only OpenVPN is offered.
- **IPv6** is not tunnelled, so qBittorrent gets no IPv6 at all.

## Notes

- **Mullvad has no port forwarding**, so peers can't connect to you. Downloading works, but poorly seeded torrents can be slow.
  If your provider forwards a port, enter it under *Port forwarding*. qBittorrent then listens on it and the firewall lets it in through the tunnel.
- **OpenVPN** configs must have certificates and keys inline (`<ca>…</ca>` and so on), not as separate files. Only `tun` configs are supported.
- **Mullvad is WireGuard-only.** Mullvad has shut down its OpenVPN servers, so there is no Mullvad-over-OpenVPN option.
- **Password.** Change it on the dashboard; doing so logs out every other device.
- **Onboarding is open to anyone** who can reach the port until the login is created, so set it up right after first start.
  Set the port mapping to `127.0.0.1:8080:8080` if the UI shouldn't be reachable from your LAN.
- `docker logs sneakytorrents` shows everything: the manager, qBittorrent and the VPN client. The same log is on the dashboard.

## Development

`nix develop` gives you Go. The manager lives in `manager/` and uses only the standard library.

```sh
cd manager && CGO_ENABLED=0 go vet ./... && go build .
docker build -t sneakytorrents:dev .
```
