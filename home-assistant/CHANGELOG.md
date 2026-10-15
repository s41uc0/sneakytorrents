# Changelog

## 0.1.3

- Fix "permission denied" when saving to network storage (SMB/NFS shares added in Home Assistant). Home Assistant mounts these so that only root can write, so qBittorrent now runs as root with only file-access capabilities; the kill switch still applies to it.
- After updating, select torrents that errored and choose **Force recheck** (or resume them).

## 0.1.2

- New option `extra_paths`: more folders qBittorrent can save to, each optionally with a qBittorrent category (for Sonarr, Radarr and similar).

## 0.1.1

- Apps that log in to qBittorrent with a username and password (Sonarr, Radarr, mobile apps, Home Assistant's qBittorrent integration) work again, using the direct access login.

## 0.1.0

- First release as a Home Assistant app.
