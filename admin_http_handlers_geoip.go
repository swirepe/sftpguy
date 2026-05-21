package main

import (
	"net"
	"net/http"
	"strings"
	"time"

	"sftpguy/internal/geoip"
)

func (s *Server) handleAdminGeoIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.geoStatus())
}

func (s *Server) handleAdminGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	if net.ParseIP(strings.Trim(ip, "[]")) == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	loc, ok := s.geoLocation(ip)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"found":  false,
			"ip":     ip,
			"status": s.geoStatus(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"found":    true,
		"location": loc,
		"status":   s.geoStatus(),
	})
}

func (s *Server) geoStatus() geoip.Status {
	if s == nil || s.geo == nil {
		return geoip.Status{Enabled: false}
	}
	return s.geo.Status(time.Now())
}

func (s *Server) geoLocation(ip string) (*geoip.Location, bool) {
	if s == nil || s.geo == nil {
		return nil, false
	}
	return s.geo.Lookup(ip)
}

func geoLocationOrNil(s *Server, ip string) *geoip.Location {
	loc, ok := s.geoLocation(ip)
	if !ok {
		return nil
	}
	return loc
}
