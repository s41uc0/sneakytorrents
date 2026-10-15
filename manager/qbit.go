package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// QBit runs qbittorrent-nox as PUID, with its web UI on localhost only and no
// login for localhost clients. Only the manager can reach it there, and the
// manager's proxy only forwards requests from logged-in sessions.
type QBit struct {
	a       *App
	profile string
	client  *http.Client
	running atomic.Bool
}

func NewQBit(a *App) *QBit {
	return &QBit{
		a:       a,
		profile: filepath.Join(configDir, "qbittorrent"),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (q *QBit) Running() bool { return q.running.Load() }

func (q *QBit) confPath() string {
	return filepath.Join(q.profile, "qBittorrent", "config", "qBittorrent.conf")
}

// seed writes the settings the container depends on into qBittorrent.conf.
// qBittorrent rewrites this file on exit, so it is only touched while stopped.
func (q *QBit) seed() error {
	path := q.confPath()
	data, err := os.ReadFile(path)
	fresh := errors.Is(err, fs.ErrNotExist)
	if err != nil && !fresh {
		return err
	}
	c := parseINI(string(data))
	if fresh {
		// Throwaway password: nobody logs in to qBittorrent itself.
		hash, err := pbkdf2Hash(randomToken(24))
		if err != nil {
			return err
		}
		c.set("LegalNotice", "Accepted", "true")
		c.set("BitTorrent", `Session\TempPathEnabled`, "true")
		c.set("Preferences", `WebUI\Username`, "admin")
		c.set("Preferences", `WebUI\Password_PBKDF2`, hash)
	}
	// As a Home Assistant app the download folder is an app option, so follow it.
	if fresh || q.a.env.HA {
		c.set("BitTorrent", `Session\DefaultSavePath`, dataDir+"/downloads")
		c.set("BitTorrent", `Session\TempPath`, dataDir+"/incomplete")
	}
	c.set("BitTorrent", `Session\Interface`, vpnIface)
	c.set("BitTorrent", `Session\InterfaceName`, vpnIface)
	c.set("BitTorrent", `Session\InterfaceAddress`, "")
	c.set("Network", `PortForwardingEnabled`, "false")
	c.set("Preferences", `WebUI\Address`, "127.0.0.1")
	c.set("Preferences", `WebUI\Port`, strconv.Itoa(qbtWebPort))
	c.set("Preferences", `WebUI\LocalHostAuth`, "false")
	c.set("Preferences", `WebUI\HostHeaderValidation`, "false")
	// The proxy checks Origin itself; qBittorrent's check can't see through Home Assistant ingress.
	c.set("Preferences", `WebUI\CSRFProtection`, "false")
	// Ignore X-Forwarded-For entirely: every request qBittorrent sees is from the manager.
	c.set("Preferences", `WebUI\ReverseProxySupportEnabled`, "false")
	c.set("Preferences", `WebUI\AuthSubnetWhitelistEnabled`, "false")
	c.set("Preferences", `WebUI\UseUPnP`, "false")
	if port := q.a.store.Get().ForwardedPort; port > 0 {
		c.set("BitTorrent", `Session\Port`, strconv.Itoa(port))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(c.String()), 0o600); err != nil {
		return err
	}
	return filepath.WalkDir(q.profile, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, q.a.env.UID, q.a.env.GID)
	})
}

// Supervise keeps qbittorrent-nox running until ctx ends, then stops it gracefully.
func (q *QBit) Supervise(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := q.seed(); err != nil {
			q.a.log.Printf("qbittorrent", "could not prepare config: %v", err)
		}
		started := time.Now()
		cmd := exec.Command("qbittorrent-nox", "--profile="+q.profile, "--confirm-legal-notice")
		cmd.Env = []string{
			"HOME=" + q.profile,
			"LANG=C.UTF-8",
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"TZ=" + os.Getenv("TZ"),
		}
		cmd.Dir = q.profile
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(q.a.env.UID), Gid: uint32(q.a.env.GID)},
		}
		w := q.a.log.Writer("qbittorrent")
		cmd.Stdout, cmd.Stderr = w, w
		if err := cmd.Start(); err != nil {
			q.a.log.Printf("qbittorrent", "failed to start: %v", err)
		} else {
			q.running.Store(true)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				q.running.Store(false)
				q.a.log.Printf("qbittorrent", "exited: %v", err)
			case <-ctx.Done():
				q.a.log.Printf("qbittorrent", "stopping")
				cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(45 * time.Second):
					cmd.Process.Kill()
					<-done
				}
				q.running.Store(false)
				return
			}
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (q *QBit) apiURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", qbtWebPort, path)
}

func (q *QBit) WaitReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, q.apiURL("/api/v2/app/version"), nil)
		if resp, err := q.client.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("qBittorrent is not responding")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (q *QBit) SetPreferences(ctx context.Context, prefs map[string]any) error {
	if err := q.WaitReady(ctx); err != nil {
		return err
	}
	b, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	form := url.Values{"json": {string(b)}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, q.apiURL("/api/v2/app/setPreferences"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := q.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("qBittorrent refused settings: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// pbkdf2Hash produces qBittorrent's WebUI\Password_PBKDF2 format.
func pbkdf2Hash(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha512.New, password, salt, 100000, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`"@ByteArray(%s:%s)"`, base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)), nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ini is a minimal order-preserving editor for qBittorrent's INI file.
type ini struct{ sections []*iniSection }

type iniSection struct {
	name  string
	lines []string
}

func parseINI(s string) *ini {
	c := &ini{}
	cur := &iniSection{}
	c.sections = append(c.sections, cur)
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = &iniSection{name: t[1 : len(t)-1]}
			c.sections = append(c.sections, cur)
			continue
		}
		if t != "" {
			cur.lines = append(cur.lines, line)
		}
	}
	return c
}

func (c *ini) set(section, key, value string) {
	var sec *iniSection
	for _, s := range c.sections {
		if s.name == section {
			sec = s
			break
		}
	}
	if sec == nil {
		sec = &iniSection{name: section}
		c.sections = append(c.sections, sec)
	}
	entry := key + "=" + value
	for i, line := range sec.lines {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			sec.lines[i] = entry
			return
		}
	}
	sec.lines = append(sec.lines, entry)
}

func (c *ini) String() string {
	var b strings.Builder
	for _, s := range c.sections {
		if s.name == "" && len(s.lines) == 0 {
			continue
		}
		if s.name != "" {
			fmt.Fprintf(&b, "[%s]\n", s.name)
		}
		for _, l := range s.lines {
			b.WriteString(l + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
