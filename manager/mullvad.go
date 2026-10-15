package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const mullvadAPI = "https://api.mullvad.net"

type Mullvad struct {
	cachePath string
	client    *http.Client

	mu      sync.Mutex
	relays  *RelayList
	fetched time.Time
}

type RelayList struct {
	Locations map[string]struct {
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"locations"`
	WireGuard struct {
		IPv4Gateway string  `json:"ipv4_gateway"`
		Relays      []Relay `json:"relays"`
	} `json:"wireguard"`
}

type Relay struct {
	Hostname         string `json:"hostname"`
	Location         string `json:"location"` // "nl-ams"
	Active           bool   `json:"active"`
	Owned            bool   `json:"owned"`
	Provider         string `json:"provider"`
	IPv4             string `json:"ipv4_addr_in"`
	PublicKey        string `json:"public_key"`
	Weight           int    `json:"weight"`
	IncludeInCountry bool   `json:"include_in_country"`
}

func NewMullvad(cachePath string) *Mullvad {
	return &Mullvad{cachePath: cachePath, client: &http.Client{Timeout: 20 * time.Second}}
}

// Relays returns Mullvad's WireGuard server list, refreshed every few hours
// and falling back to the copy on disk when the API is unreachable.
func (m *Mullvad) Relays(ctx context.Context) (*RelayList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relays != nil && time.Since(m.fetched) < 6*time.Hour {
		return m.relays, nil
	}
	data, err := m.get(ctx, "/public/relays/wireguard/v2", "")
	if err == nil {
		var rl RelayList
		if err = json.Unmarshal(data, &rl); err == nil && len(rl.WireGuard.Relays) > 0 {
			m.relays, m.fetched = &rl, time.Now()
			os.WriteFile(m.cachePath, data, 0o644)
			return m.relays, nil
		}
	}
	if m.relays != nil {
		return m.relays, nil
	}
	if cached, cerr := os.ReadFile(m.cachePath); cerr == nil {
		var rl RelayList
		if json.Unmarshal(cached, &rl) == nil && len(rl.WireGuard.Relays) > 0 {
			m.relays = &rl // m.fetched stays zero so the next call retries the API
			return m.relays, nil
		}
	}
	return nil, fmt.Errorf("could not load Mullvad server list: %w", err)
}

// Register adds a new WireGuard device to the account, replacing nothing; the
// caller removes any previous device.
func (m *Mullvad) Register(ctx context.Context, account string) (MullvadSettings, error) {
	token, err := m.token(ctx, account)
	if err != nil {
		return MullvadSettings{}, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return MullvadSettings{}, err
	}
	pub := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	body, _ := json.Marshal(map[string]any{"pubkey": pub, "hijack_dns": false})
	data, err := m.do(ctx, http.MethodPost, "/accounts/v1/devices", token, body)
	if err != nil {
		return MullvadSettings{}, err
	}
	var dev struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		IPv4Address string `json:"ipv4_address"`
	}
	if err := json.Unmarshal(data, &dev); err != nil {
		return MullvadSettings{}, err
	}
	s := MullvadSettings{
		Account:    account,
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
		Address:    dev.IPv4Address,
		DeviceID:   dev.ID,
		DeviceName: dev.Name,
	}
	if data, err := m.do(ctx, http.MethodGet, "/accounts/v1/accounts/me", token, nil); err == nil {
		var acct struct {
			Expiry string `json:"expiry"`
		}
		if json.Unmarshal(data, &acct) == nil {
			s.Expiry = acct.Expiry
		}
	}
	return s, nil
}

func (m *Mullvad) Unregister(ctx context.Context, account, deviceID string) error {
	token, err := m.token(ctx, account)
	if err != nil {
		return err
	}
	_, err = m.do(ctx, http.MethodDelete, "/accounts/v1/devices/"+deviceID, token, nil)
	return err
}

func (m *Mullvad) token(ctx context.Context, account string) (string, error) {
	body, _ := json.Marshal(map[string]string{"account_number": account})
	data, err := m.do(ctx, http.MethodPost, "/auth/v1/token", "", body)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("unexpected response from Mullvad")
	}
	return tok.AccessToken, nil
}

func (m *Mullvad) get(ctx context.Context, path, token string) ([]byte, error) {
	return m.do(ctx, http.MethodGet, path, token, nil)
}

func (m *Mullvad) do(ctx context.Context, method, path, token string, body []byte) ([]byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, mullvadAPI+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach Mullvad: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		switch e.Code {
		case "INVALID_ACCOUNT":
			return nil, errors.New("Mullvad doesn't recognise that account number")
		case "MAX_DEVICES_REACHED":
			return nil, errors.New("this Mullvad account already has the maximum number of devices; remove one at mullvad.net/account and try again")
		case "DEVICE_NOT_FOUND":
			return nil, errors.New("device no longer exists on the Mullvad account")
		}
		if e.Error != "" {
			return nil, fmt.Errorf("Mullvad: %s", e.Error)
		}
		return nil, fmt.Errorf("Mullvad API returned %s", resp.Status)
	}
	return data, nil
}

// PickRelay chooses an active server matching the most specific filter given,
// weighted the way Mullvad's own apps weight them.
func PickRelay(rl *RelayList, country, city, hostname string) (Relay, error) {
	var cands []Relay
	total := 0
	for _, r := range rl.WireGuard.Relays {
		if !r.Active {
			continue
		}
		switch {
		case hostname != "":
			if r.Hostname != hostname {
				continue
			}
		case city != "":
			if r.Location != city {
				continue
			}
		case country != "":
			if !strings.HasPrefix(r.Location, country+"-") || !r.IncludeInCountry {
				continue
			}
		default:
			if !r.IncludeInCountry {
				continue
			}
		}
		cands = append(cands, r)
		total += max(r.Weight, 1)
	}
	if len(cands) == 0 {
		want := firstNonEmpty(hostname, city, country, "anywhere")
		return Relay{}, fmt.Errorf("no active Mullvad server matches %q", want)
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(total)))
	pick := int(n.Int64())
	for _, r := range cands {
		pick -= max(r.Weight, 1)
		if pick < 0 {
			return r, nil
		}
	}
	return cands[len(cands)-1], nil
}

type RelayCountry struct {
	Code   string      `json:"code"`
	Name   string      `json:"name"`
	Cities []RelayCity `json:"cities"`
}

type RelayCity struct {
	Code    string      `json:"code"`
	Name    string      `json:"name"`
	Servers []RelayInfo `json:"servers"`
}

type RelayInfo struct {
	Hostname string `json:"hostname"`
	Owned    bool   `json:"owned"`
	Provider string `json:"provider"`
}

// GroupRelays turns the flat relay list into country → city → server for the picker.
func GroupRelays(rl *RelayList) []RelayCountry {
	byCountry := map[string]*RelayCountry{}
	cityIdx := map[string]int{}
	for _, r := range rl.WireGuard.Relays {
		if !r.Active {
			continue
		}
		cc, _, _ := strings.Cut(r.Location, "-")
		loc := rl.Locations[r.Location]
		c := byCountry[cc]
		if c == nil {
			c = &RelayCountry{Code: cc, Name: firstNonEmpty(loc.Country, cc)}
			byCountry[cc] = c
		}
		i, ok := cityIdx[r.Location]
		if !ok {
			c.Cities = append(c.Cities, RelayCity{Code: r.Location, Name: firstNonEmpty(loc.City, r.Location)})
			i = len(c.Cities) - 1
			cityIdx[r.Location] = i
		}
		c.Cities[i].Servers = append(c.Cities[i].Servers, RelayInfo{Hostname: r.Hostname, Owned: r.Owned, Provider: r.Provider})
	}
	out := make([]RelayCountry, 0, len(byCountry))
	for _, c := range byCountry {
		sort.Slice(c.Cities, func(i, j int) bool { return c.Cities[i].Name < c.Cities[j].Name })
		for _, city := range c.Cities {
			sort.Slice(city.Servers, func(i, j int) bool { return city.Servers[i].Hostname < city.Servers[j].Hostname })
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
