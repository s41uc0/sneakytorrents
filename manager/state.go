package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
)

// Settings is everything the user configured, persisted to /config/sneaky.json.
type Settings struct {
	Username      string            `json:"username"`
	PasswordHash  string            `json:"password_hash"`
	SessionSecret string            `json:"session_secret"`
	Onboarded     bool              `json:"onboarded"` // a VPN has been configured
	Enabled       bool              `json:"enabled"`   // tunnel should be up
	Provider      string            `json:"provider"`  // mullvad | wireguard | openvpn
	Mullvad       MullvadSettings   `json:"mullvad"`
	WireGuard     WireGuardSettings `json:"wireguard"`
	OpenVPN       OpenVPNSettings   `json:"openvpn"`
	ForwardedPort int               `json:"forwarded_port"`
}

func (s Settings) HasAccount() bool { return s.PasswordHash != "" }

type MullvadSettings struct {
	Account    string `json:"account"`
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Expiry     string `json:"expiry"`
	// Server selection; the most specific non-empty field wins, all empty = anywhere.
	Country  string `json:"country"`
	City     string `json:"city"`
	Hostname string `json:"hostname"`
}

type WireGuardSettings struct {
	PrivateKey   string `json:"private_key"`
	Address      string `json:"address"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Endpoint     string `json:"endpoint"`
	DNS          string `json:"dns"`
	MTU          int    `json:"mtu"`
}

type OpenVPNSettings struct {
	Config   string `json:"config"`
	Username string `json:"username"`
	Password string `json:"password"`
	DNS      string `json:"dns"`
}

type Store struct {
	mu   sync.Mutex
	path string
	s    Settings
}

func OpenStore(path string) (*Store, error) {
	st := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &st.s); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *Store) Get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s
}

// Update applies fn to a copy of the settings and persists the result; if fn
// fails nothing changes.
func (st *Store) Update(fn func(*Settings) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	next := st.s
	if err := fn(&next); err != nil {
		return err
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		return err
	}
	st.s = next
	return nil
}
