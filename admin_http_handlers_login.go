package main

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"sftpguy/internal/adminhttp"
)

const adminOneTimeTokenTTL = 24 * time.Hour

func (s *Server) handleAdminOneTimeLoginURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.TrimSpace(s.cfg.AdminHTTPToken) == "" {
		http.Error(w, "admin token auth is disabled", http.StatusBadRequest)
		return
	}

	oneTimeToken, err := s.issueAdminOneTimeLoginToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	loginURL := s.adminOneTimeLoginURL(r, oneTimeToken)
	if strings.TrimSpace(loginURL) == "" {
		http.Error(w, "failed to construct one-time login URL", http.StatusInternalServerError)
		return
	}

	qrPNG, err := qrcode.Encode(loginURL, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}
	qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG)

	s.store.LogEvent(EventAdminConfig, systemOwner, "admin-http", nil,
		"action", "one-time-login-url-generate",
		"ip", requestIPFromAdminHTTP(r),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"url":             loginURL,
		"single_use":      true,
		"created_at":      time.Now().UTC().Format(time.RFC3339),
		"qr_png_data_url": qrDataURL,
	})
}

func (s *Server) adminOneTimeLoginURL(r *http.Request, oneTimeToken string) string {
	return adminhttp.BuildOneTimeLoginURL(
		requestSchemeFromAdminHTTP(r),
		requestHostFromAdminHTTP(r, s.cfg.AdminHTTP),
		strings.TrimSpace(oneTimeToken),
	)
}

func (s *Server) issueAdminOneTimeLoginToken() (string, error) {
	if strings.TrimSpace(s.cfg.AdminHTTPToken) == "" {
		return "", errors.New("admin token auth is disabled")
	}

	token, err := randomHexSecret(24)
	if err != nil {
		return "", err
	}
	now := time.Now()
	cutoff := now.Add(-adminOneTimeTokenTTL)

	s.adminOneTimeMu.Lock()
	defer s.adminOneTimeMu.Unlock()

	if s.adminOneTime == nil {
		s.adminOneTime = make(map[string]time.Time)
	}
	for k, createdAt := range s.adminOneTime {
		if createdAt.Before(cutoff) {
			delete(s.adminOneTime, k)
		}
	}
	s.adminOneTime[token] = now
	return token, nil
}

func (s *Server) consumeAdminOneTimeLoginToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}

	now := time.Now()
	cutoff := now.Add(-adminOneTimeTokenTTL)

	s.adminOneTimeMu.Lock()
	defer s.adminOneTimeMu.Unlock()

	for k, createdAt := range s.adminOneTime {
		if createdAt.Before(cutoff) {
			delete(s.adminOneTime, k)
		}
	}
	_, ok := s.adminOneTime[token]
	if ok {
		delete(s.adminOneTime, token)
	}
	return ok
}

func requestSchemeFromAdminHTTP(r *http.Request) string {
	if xfp := firstForwardHeaderValue(r.Header.Get("X-Forwarded-Proto")); xfp != "" {
		return strings.ToLower(xfp)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHostFromAdminHTTP(r *http.Request, fallbackAddr string) string {
	if xfh := firstForwardHeaderValue(r.Header.Get("X-Forwarded-Host")); xfh != "" {
		return xfh
	}
	if host := strings.TrimSpace(r.Host); host != "" {
		return host
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(fallbackAddr))
	if err != nil {
		return strings.TrimSpace(fallbackAddr)
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func firstForwardHeaderValue(raw string) string {
	part := strings.TrimSpace(raw)
	if part == "" {
		return ""
	}
	if idx := strings.Index(part, ","); idx >= 0 {
		part = part[:idx]
	}
	return strings.TrimSpace(part)
}

func requestIPFromAdminHTTP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
