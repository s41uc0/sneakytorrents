package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sneakytorrents has its own login; qBittorrent's web UI only trusts localhost
// (this manager), and the proxy only forwards requests from logged-in sessions.

const (
	sessionCookie = "sneaky_session"
	sessionTTL    = 30 * 24 * time.Hour
	pbkdf2Iter    = 210000
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func checkPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err1 := strconv.Atoi(parts[1])
	salt, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err3 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// Sessions are stateless: "<expiry>.<hmac>". The secret is replaced whenever
// the password changes, which logs out every existing session.
func sessionToken(secret string, exp time.Time) string {
	payload := strconv.FormatInt(exp.Unix(), 10)
	return payload + "." + sessionMAC(secret, payload)
}

func sessionMAC(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *App) sessionValid(r *http.Request) bool {
	s := a.store.Get()
	c, err := r.Cookie(sessionCookie)
	if err != nil || s.SessionSecret == "" {
		return false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(mac), []byte(sessionMAC(s.SessionSecret, payload))) {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	return err == nil && time.Now().Unix() < exp
}

func (a *App) setSessionCookie(w http.ResponseWriter, secret string) {
	exp := time.Now().Add(sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sessionToken(secret, exp), Path: "/",
		Expires: exp, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// loginLimiter locks an IP out for a while after repeated wrong passwords.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*loginFails
}

type loginFails struct {
	n     int
	until time.Time
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string]*loginFails{}
	}
	f := l.fails[ip]
	if f == nil {
		f = &loginFails{}
		l.fails[ip] = f
	}
	f.n++
	if f.n >= 5 {
		f.n = 0
		f.until = time.Now().Add(5 * time.Minute)
	}
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
