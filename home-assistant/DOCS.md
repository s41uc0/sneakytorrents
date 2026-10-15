# sneakytorrents

qBittorrent with all of its traffic locked to a VPN.

## Setup

1. Start the app and open **Torrents** in the sidebar.
2. Choose your VPN:
   - **Mullvad**: enter your account number, then pick a country, city or server.
   - **WireGuard**: any provider or your own server. Upload or paste its `.conf` file.
   - **OpenVPN**: any provider. Upload or paste its `.ovpn` file, plus a username and password if it needs them.
3. Once it shows the IP your torrents exit from, open qBittorrent.

Your Home Assistant login is used, so there is no separate password.

## Options

**Download folder** (`download_dir`, default `/media/torrents`): where torrents are saved.
It must be inside `/media` or `/share`, so downloads show up in Home Assistant's media browser and Samba shares.
Finished files go in `downloads/` and unfinished ones in `incomplete/`.
Downloads are not part of the app's backups.

## How the VPN is enforced

A firewall rule inside the app lets qBittorrent send traffic only through the VPN tunnel.
If the tunnel drops or you disconnect, qBittorrent's traffic is blocked, never sent over your own connection.
DNS lookups go through the tunnel too.
The dashboard shows the IP your traffic exits from, and how many packets the kill switch has blocked.

## Access without Home Assistant (optional)

The app's network port is closed by default.
To reach the web UI directly, for example from a phone app:

1. In the app, create a login under **Direct access login**.
2. On the app's **Configuration** tab, set a host port for `8080/tcp`.

Until a login exists, the direct port shows nothing but a note to create one.

## Other apps

Apps that talk to qBittorrent connect with the direct access login, as they would to qBittorrent itself.
This includes Sonarr, Radarr, mobile apps, and Home Assistant's own qBittorrent integration.

- **Home Assistant's qBittorrent integration** and other apps running in Home Assistant can use the app's internal address, `http://<hostname>:8080`, with no host port needed.
  The hostname is shown on the app's **Info** tab.
- **Apps elsewhere on your network** need the host port set (see above), and use `http://<home-assistant-ip>:<port>`.

## Notes

- **Mullvad has no port forwarding**, so peers can't connect to you. Downloading works, but poorly seeded torrents can be slow.
  If your provider forwards a port, enter it under *Port forwarding*.
- **Mullvad is WireGuard-only.** It no longer runs OpenVPN servers.
- **OpenVPN configs** need certificates and keys inline in the file.
