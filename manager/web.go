package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed ui
var uiFS embed.FS

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(format string, a ...any) error {
	return &httpError{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(uiFS, "ui")
	files := http.FileServerFS(static)

	mux.Handle("GET /vpn/static/", http.StripPrefix("/vpn/static/", files))
	mux.HandleFunc("GET /vpn/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, static, "index.html")
	})
	mux.HandleFunc("GET /vpn/badge.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, static, "badge.js")
	})
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.basePath(r)+"/vpn/", http.StatusFound)
	})
	mux.HandleFunc("GET /vpn/healthz", a.handleHealth)

	mux.HandleFunc("GET /vpn/api/session", a.api(false, a.handleSession))
	mux.HandleFunc("POST /vpn/api/setup/account", a.apiW(false, a.handleSetupAccount))
	mux.HandleFunc("POST /vpn/api/login", a.apiW(false, a.handleLogin))
	mux.HandleFunc("POST /vpn/api/logout", a.apiW(false, a.handleLogout))
	mux.HandleFunc("POST /vpn/api/password", a.apiW(true, a.handlePassword))
	mux.HandleFunc("GET /vpn/api/status", a.api(true, a.handleStatus))
	mux.HandleFunc("GET /vpn/api/settings", a.api(true, a.handleSettings))
	mux.HandleFunc("POST /vpn/api/vpn", a.api(true, a.handleSaveVPN))
	mux.HandleFunc("POST /vpn/api/connect", a.api(true, a.handleConnect(true)))
	mux.HandleFunc("POST /vpn/api/disconnect", a.api(true, a.handleConnect(false)))
	mux.HandleFunc("POST /vpn/api/port", a.api(true, a.handlePort))
	mux.HandleFunc("GET /vpn/api/mullvad/relays", a.api(true, a.handleRelays))
	mux.HandleFunc("POST /vpn/api/mullvad/login", a.api(true, a.handleMullvadLogin))
	mux.HandleFunc("POST /vpn/api/mullvad/logout", a.api(true, a.handleMullvadLogout))
	mux.HandleFunc("GET /vpn/api/logs", a.api(true, a.handleLogs))
	mux.HandleFunc("/vpn/", http.NotFound)

	mux.Handle("/", a.qbtProxy())
	return mux
}

// authed: Home Assistant ingress requests are already authenticated by Home
// Assistant. Otherwise, before an account exists there is nothing to protect
// (and no way to log in), except as a Home Assistant app, where the direct port
// stays closed until a login is created from inside Home Assistant.
func (a *App) authed(r *http.Request) bool {
	if a.isIngress(r) {
		return true
	}
	if !a.store.Get().HasAccount() {
		return !a.env.HA
	}
	return a.sessionValid(r)
}

// isIngress reports whether r came through Home Assistant's ingress proxy,
// which only forwards requests from logged-in Home Assistant users.
func (a *App) isIngress(r *http.Request) bool {
	return a.env.HA && clientIP(r) == a.env.IngressIP
}

// basePath is the URL prefix the browser sees: ingress serves the app under
// /api/hassio_ingress/<token>.
func (a *App) basePath(r *http.Request) string {
	if p := r.Header.Get("X-Ingress-Path"); a.isIngress(r) && strings.HasPrefix(p, "/api/hassio_ingress/") {
		return strings.TrimRight(p, "/")
	}
	return ""
}

// sameOrigin refuses cross-site state-changing requests. Ingress requests are
// exempt: Home Assistant authenticates them and rewrites Host on the way in.
func (a *App) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || a.isIngress(r) {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (a *App) api(needAuth bool, h func(*http.Request) (any, error)) http.HandlerFunc {
	return a.apiW(needAuth, func(_ http.ResponseWriter, r *http.Request) (any, error) { return h(r) })
}

// apiW is api for handlers that also set cookies.
func (a *App) apiW(needAuth bool, h func(http.ResponseWriter, *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// JSON-only plus same-origin: a cross-site form can't drive these endpoints.
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "expected JSON"})
				return
			}
			if !a.sameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
				return
			}
		}
		if needAuth && !a.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		v, err := h(w, r)
		if err != nil {
			code := http.StatusInternalServerError
			var he *httpError
			if errors.As(err, &he) {
				code = he.code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		return badRequest("invalid request: %v", err)
	}
	return nil
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	s := a.store.Get()
	if s.Onboarded && s.Enabled && a.vpn.Status().State != "connected" {
		http.Error(w, "vpn not connected", http.StatusServiceUnavailable)
		return
	}
	io.WriteString(w, "ok\n")
}

func (a *App) handleSession(r *http.Request) (any, error) {
	s := a.store.Get()
	authed := a.authed(r)
	res := map[string]any{
		"account_set": s.HasAccount(),
		"onboarded":   s.Onboarded,
		"authed":      authed,
		"ha":          a.env.HA,
		"ingress":     a.isIngress(r),
	}
	if authed {
		res["username"] = s.Username
	}
	return res, nil
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleSetupAccount(w http.ResponseWriter, r *http.Request) (any, error) {
	if a.env.HA && !a.isIngress(r) {
		return nil, &httpError{http.StatusForbidden, "create the login from sneakytorrents in the Home Assistant sidebar"}
	}
	var req credentials
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return nil, badRequest("choose a username")
	}
	if len(req.Password) < 8 {
		return nil, badRequest("the password needs at least 8 characters")
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	var secret string
	err = a.store.Update(func(s *Settings) error {
		if s.HasAccount() {
			return &httpError{http.StatusConflict, "an account already exists"}
		}
		s.Username, s.PasswordHash, s.SessionSecret = req.Username, hash, randomToken(32)
		secret = s.SessionSecret
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.setSessionCookie(w, secret)
	a.log.Printf("sneaky", "account %q created", req.Username)
	return map[string]bool{"ok": true}, nil
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) (any, error) {
	var req credentials
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip := clientIP(r)
	if a.logins.blocked(ip) {
		return nil, &httpError{http.StatusTooManyRequests, "too many wrong passwords; try again in a few minutes"}
	}
	s := a.store.Get()
	if !s.HasAccount() {
		return nil, badRequest("no account has been created yet")
	}
	ok := checkPassword(s.PasswordHash, req.Password)
	if !ok || strings.TrimSpace(req.Username) != s.Username {
		a.logins.fail(ip)
		a.log.Printf("sneaky", "failed login from %s", ip)
		return nil, &httpError{http.StatusForbidden, "wrong username or password"}
	}
	a.logins.success(ip)
	a.setSessionCookie(w, s.SessionSecret)
	return map[string]bool{"ok": true}, nil
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) (any, error) {
	clearSessionCookie(w)
	return map[string]bool{"ok": true}, nil
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if len(req.New) < 8 {
		return nil, badRequest("the new password needs at least 8 characters")
	}
	// Through Home Assistant you're already authenticated, so a forgotten password can be reset there.
	if !a.isIngress(r) && !checkPassword(a.store.Get().PasswordHash, req.Current) {
		return nil, badRequest("the current password is wrong")
	}
	hash, err := hashPassword(req.New)
	if err != nil {
		return nil, err
	}
	var secret string
	err = a.store.Update(func(s *Settings) error {
		// A new secret logs out every other session.
		s.PasswordHash, s.SessionSecret = hash, randomToken(32)
		secret = s.SessionSecret
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.setSessionCookie(w, secret)
	a.log.Printf("sneaky", "password changed")
	return map[string]bool{"ok": true}, nil
}

func (a *App) handleStatus(r *http.Request) (any, error) {
	s := a.store.Get()
	blocked, _ := BlockedPackets()
	return map[string]any{
		"vpn":            a.vpn.Status(),
		"provider":       s.Provider,
		"enabled":        s.Enabled,
		"onboarded":      s.Onboarded,
		"forwarded_port": s.ForwardedPort,
		"leaks_blocked":  blocked,
		"qbittorrent":    a.qbt.Running(),
		"capabilities":   a.caps,
	}, nil
}

// handleSettings returns the settings for the forms, without secrets.
func (a *App) handleSettings(r *http.Request) (any, error) {
	s := a.store.Get()
	m, w, o := s.Mullvad, s.WireGuard, s.OpenVPN
	acct := ""
	if len(m.Account) >= 4 {
		acct = "•••• " + m.Account[len(m.Account)-4:]
	}
	return map[string]any{
		"provider":       s.Provider,
		"enabled":        s.Enabled,
		"forwarded_port": s.ForwardedPort,
		"capabilities":   a.caps,
		"mullvad": map[string]any{
			"signed_in":   m.PrivateKey != "",
			"account":     acct,
			"device_name": m.DeviceName,
			"expiry":      m.Expiry,
			"country":     m.Country,
			"city":        m.City,
			"hostname":    m.Hostname,
		},
		"wireguard": map[string]any{
			"has_private_key":   w.PrivateKey != "",
			"has_preshared_key": w.PresharedKey != "",
			"address":           w.Address,
			"public_key":        w.PublicKey,
			"endpoint":          w.Endpoint,
			"dns":               w.DNS,
			"mtu":               w.MTU,
		},
		"openvpn": map[string]any{
			"config":       o.Config,
			"username":     o.Username,
			"has_password": o.Password != "",
			"dns":          o.DNS,
		},
	}, nil
}

func (a *App) handleSaveVPN(r *http.Request) (any, error) {
	var req struct {
		Provider string `json:"provider"`
		Mullvad  struct {
			Country  string `json:"country"`
			City     string `json:"city"`
			Hostname string `json:"hostname"`
		} `json:"mullvad"`
		WireGuard WireGuardSettings `json:"wireguard"`
		OpenVPN   OpenVPNSettings   `json:"openvpn"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	switch {
	case (req.Provider == "mullvad" || req.Provider == "wireguard") && a.caps.WireGuard == "none":
		return nil, badRequest("WireGuard can't run on this host (needs the kernel module or /dev/net/tun)")
	case req.Provider == "openvpn" && !a.caps.OpenVPN:
		return nil, badRequest("OpenVPN can't run without /dev/net/tun passed to the container")
	}
	err := a.store.Update(func(s *Settings) error {
		switch req.Provider {
		case "mullvad":
			if s.Mullvad.PrivateKey == "" {
				return badRequest("sign in to Mullvad first")
			}
			s.Mullvad.Country, s.Mullvad.City, s.Mullvad.Hostname = req.Mullvad.Country, req.Mullvad.City, req.Mullvad.Hostname
		case "wireguard":
			w := req.WireGuard
			for _, f := range []*string{&w.PrivateKey, &w.Address, &w.PublicKey, &w.PresharedKey, &w.Endpoint, &w.DNS} {
				*f = strings.TrimSpace(*f)
			}
			// Secrets are never sent back to the browser; blank means "keep the saved one".
			if w.PrivateKey == "" {
				w.PrivateKey = s.WireGuard.PrivateKey
			}
			if w.PresharedKey == "" {
				w.PresharedKey = s.WireGuard.PresharedKey
			}
			if err := validateWireGuard(w); err != nil {
				return err
			}
			s.WireGuard = w
		case "openvpn":
			o := req.OpenVPN
			o.Username, o.DNS = strings.TrimSpace(o.Username), strings.TrimSpace(o.DNS)
			if strings.TrimSpace(o.Config) == "" {
				return badRequest("paste or upload an OpenVPN config")
			}
			if !strings.Contains(o.Config, "remote ") && !strings.Contains(o.Config, "<connection>") {
				return badRequest("that OpenVPN config has no 'remote' server line")
			}
			if o.Password == "" && o.Username == s.OpenVPN.Username {
				o.Password = s.OpenVPN.Password
			}
			if o.Username == "" {
				o.Password = ""
			}
			if o.DNS != "" && len(ipv4List(o.DNS)) == 0 {
				return badRequest("DNS must be IPv4 addresses")
			}
			s.OpenVPN = o
		default:
			return badRequest("unknown provider %q", req.Provider)
		}
		s.Provider = req.Provider
		s.Onboarded, s.Enabled = true, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.log.Printf("sneaky", "VPN settings saved (%s)", req.Provider)
	a.vpn.Kick()
	return a.handleStatus(r)
}

func validateWireGuard(w WireGuardSettings) error {
	if !validKey(w.PrivateKey) {
		return badRequest("the private key must be a WireGuard key (44 characters of base64)")
	}
	if !validKey(w.PublicKey) {
		return badRequest("the server public key must be a WireGuard key (44 characters of base64)")
	}
	if w.PresharedKey != "" && !validKey(w.PresharedKey) {
		return badRequest("the preshared key must be a WireGuard key (44 characters of base64)")
	}
	if _, err := firstIPv4Prefix(w.Address); err != nil {
		return badRequest("the address needs an IPv4 address, like 10.2.0.2/32")
	}
	host, port, err := net.SplitHostPort(w.Endpoint)
	if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		return badRequest("the endpoint must be host:port, like vpn.example.com:51820")
	}
	if w.DNS != "" && len(ipv4List(w.DNS)) == 0 {
		return badRequest("DNS must be IPv4 addresses")
	}
	if w.MTU != 0 && (w.MTU < 1280 || w.MTU > 1500) {
		return badRequest("MTU must be between 1280 and 1500")
	}
	return nil
}

func (a *App) handleConnect(enable bool) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		err := a.store.Update(func(s *Settings) error {
			if !s.Onboarded {
				return badRequest("set up a VPN first")
			}
			s.Enabled = enable
			return nil
		})
		if err != nil {
			return nil, err
		}
		a.vpn.Kick()
		return a.handleStatus(r)
	}
}

func (a *App) handlePort(r *http.Request) (any, error) {
	var req struct {
		Port int `json:"port"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Port < 0 || req.Port > 65535 {
		return nil, badRequest("port must be 0-65535")
	}
	if err := a.store.Update(func(s *Settings) error { s.ForwardedPort = req.Port; return nil }); err != nil {
		return nil, err
	}
	if err := SetForwardedPort(req.Port); err != nil {
		return nil, err
	}
	if req.Port > 0 {
		if err := a.qbt.SetPreferences(r.Context(), map[string]any{"listen_port": req.Port, "random_port": false}); err != nil {
			return nil, err
		}
	}
	return a.handleStatus(r)
}

func (a *App) handleRelays(r *http.Request) (any, error) {
	rl, err := a.mullvad.Relays(r.Context())
	if err != nil {
		return nil, err
	}
	return GroupRelays(rl), nil
}

func (a *App) handleMullvadLogin(r *http.Request) (any, error) {
	var req struct {
		Account string `json:"account"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	account := strings.Map(func(c rune) rune {
		if c >= '0' && c <= '9' {
			return c
		}
		return -1
	}, req.Account)
	if len(account) != 16 {
		return nil, badRequest("a Mullvad account number has 16 digits")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	old := a.store.Get().Mullvad
	dev, err := a.mullvad.Register(ctx, account)
	if err != nil {
		return nil, &httpError{http.StatusBadGateway, err.Error()}
	}
	if old.DeviceID != "" && old.DeviceID != dev.DeviceID {
		if err := a.mullvad.Unregister(ctx, old.Account, old.DeviceID); err != nil {
			a.log.Printf("mullvad", "could not remove previous device %q: %v", old.DeviceName, err)
		}
	}
	err = a.store.Update(func(s *Settings) error {
		dev.Country, dev.City, dev.Hostname = s.Mullvad.Country, s.Mullvad.City, s.Mullvad.Hostname
		s.Mullvad = dev
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.log.Printf("mullvad", "signed in, registered device %q", dev.DeviceName)
	if s := a.store.Get(); s.Provider == "mullvad" && s.Enabled {
		a.vpn.Kick()
	}
	return a.handleSettings(r)
}

func (a *App) handleMullvadLogout(r *http.Request) (any, error) {
	old := a.store.Get().Mullvad
	if old.DeviceID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := a.mullvad.Unregister(ctx, old.Account, old.DeviceID); err != nil {
			a.log.Printf("mullvad", "could not remove device %q: %v", old.DeviceName, err)
		}
	}
	err := a.store.Update(func(s *Settings) error {
		s.Mullvad = MullvadSettings{Country: old.Country, City: old.City, Hostname: old.Hostname}
		if s.Provider == "mullvad" {
			s.Enabled = false
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.log.Printf("mullvad", "signed out")
	a.vpn.Kick()
	return a.handleSettings(r)
}

func (a *App) handleLogs(r *http.Request) (any, error) {
	return map[string]any{"lines": a.log.Lines()}, nil
}

// lockedPrefs are qBittorrent settings the container depends on; changes to
// them from qBittorrent's options dialog are dropped.
var lockedPrefs = []string{
	"web_ui_address", "web_ui_port", "web_ui_username", "web_ui_password", "web_ui_upnp",
	"bypass_local_auth", "bypass_auth_subnet_whitelist_enabled", "bypass_auth_subnet_whitelist",
	"web_ui_host_header_validation_enabled", "web_ui_reverse_proxy_enabled", "web_ui_reverse_proxies_list",
	"use_https", "current_network_interface", "current_interface_address", "current_interface_name", "upnp",
}

// qbtProxy forwards everything outside /vpn/ to qBittorrent's web UI for
// logged-in sessions, adding a small VPN status badge to its page. qBittorrent
// sees every request as coming from localhost, which it doesn't ask to log in.
func (a *App) qbtProxy() http.Handler {
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", qbtWebPort)}
	// Relative, so it also resolves under Home Assistant's ingress prefix.
	badge := []byte(`<script src="vpn/badge.js" defer></script></body>`)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			if isQbtIndex(pr.In) {
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if !isQbtIndex(resp.Request) || resp.StatusCode != http.StatusOK ||
				!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || resp.Header.Get("Content-Encoding") != "" {
				return nil
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if err != nil {
				return err
			}
			if i := bytes.LastIndex(body, []byte("</body>")); i >= 0 {
				body = append(body[:i:i], append(badge, body[i+len("</body>"):]...)...)
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.Header.Del("ETag")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `<!doctype html><meta http-equiv="refresh" content="3"><title>Starting</title><body style="font-family:system-ui;padding:2rem">qBittorrent is starting… this page will refresh.</body>`)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auth/login" {
			a.qbtLogin(w, r)
			return
		}
		s := a.store.Get()
		allowed := s.Onboarded && (a.isIngress(r) || (s.HasAccount() && a.sessionValid(r)))
		if !allowed {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Forbidden", http.StatusForbidden)
			} else {
				http.Redirect(w, r, a.basePath(r)+"/vpn/", http.StatusFound)
			}
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !a.sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api/v2/auth/logout":
			// qBittorrent's own "Log out" menu item logs out of sneakytorrents.
			clearSessionCookie(w)
			io.WriteString(w, "Ok.")
			return
		case "/api/v2/app/setPreferences":
			if err := filterPreferences(r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

func filterPreferences(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	var prefs map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.PostForm.Get("json")), &prefs); err != nil {
		return fmt.Errorf("invalid preferences: %v", err)
	}
	for _, k := range lockedPrefs {
		delete(prefs, k)
	}
	b, _ := json.Marshal(prefs)
	body := url.Values{"json": {string(b)}}.Encode()
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Del("Content-Length")
	return nil
}

func isQbtIndex(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/index.html")
}
