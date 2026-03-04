package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
)

func (s *Server) handleAdminIPLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	whitelist, err := s.readAdminIPListFile(s.store.whitelistPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blacklist, err := s.readAdminIPListFile(s.store.blacklistPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": whitelist,
		"blacklist": blacklist,
	})
}

func (s *Server) handleAdminIPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/api/ip-lists/"))
	if kind == "" || strings.Contains(kind, "/") {
		http.Error(w, "invalid list type", http.StatusBadRequest)
		return
	}

	targetPath, targetList, ok := s.lookupAdminIPList(kind)
	if !ok {
		http.Error(w, "unknown list type", http.StatusBadRequest)
		return
	}

	var payload struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	content := strings.ReplaceAll(payload.Content, "\r\n", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.WriteFile(targetPath, []byte(content), permFile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	reloadEntries := 0
	reloadAddresses := uint64(0)
	if targetList != nil {
		entries, addresses, reloadErr := targetList.Reload(targetPath)
		if reloadErr != nil {
			http.Error(w, reloadErr.Error(), http.StatusInternalServerError)
			return
		}
		reloadEntries = entries
		reloadAddresses = addresses
	}

	fileInfo, err := s.readAdminIPListFile(targetPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fileInfo["kind"] = kind
	fileInfo["reloaded_entries"] = reloadEntries
	fileInfo["reloaded_addresses"] = reloadAddresses

	s.store.LogEvent(EventAdminConfig, systemOwner, "admin-http", nil,
		"action", "ip-list-save",
		"list", kind,
		"path", targetPath,
		"entries", reloadEntries,
		"invalid", fileInfo["invalid_count"],
	)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "list": fileInfo})
}

func (s *Server) handleAdminIPListTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	rawIP := strings.TrimSpace(payload.IP)
	parsed := net.ParseIP(rawIP)
	if parsed == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	ip := parsed.String()

	whitelistMatch := false
	blacklistMatch := false
	if s.store.whitelist != nil {
		whitelistMatch = s.store.whitelist.Matches(ip)
	}
	if s.store.blacklist != nil {
		blacklistMatch = s.store.blacklist.Matches(ip)
	}

	var dbFlag int
	_ = s.store.db.QueryRow(`SELECT 1 FROM ip_banned WHERE ip_address = ?`, ip).Scan(&dbFlag)
	dbBanned := dbFlag == 1
	effective := s.store.IsIPBanned(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"ip": ip,
		"matches": map[string]any{
			"whitelist":        whitelistMatch,
			"blacklist":        blacklistMatch,
			"db_banned":        dbBanned,
			"effective_banned": effective,
		},
		"notes": map[string]any{
			"precedence": "whitelist overrides blacklist and db bans",
		},
	})
}

func (s *Server) readAdminIPListFile(path string) (map[string]any, error) {
	content := ""
	if b, err := os.ReadFile(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		content = string(b)
	}

	entries, invalid := validateAdminIPListContent(content)
	return map[string]any{
		"path":          path,
		"content":       content,
		"entries":       entries,
		"invalid_count": len(invalid),
		"invalid_lines": invalid,
	}, nil
}

func (s *Server) lookupAdminIPList(kind string) (path string, list *IPList, ok bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "whitelist":
		return s.store.whitelistPath, s.store.whitelist, true
	case "blacklist":
		return s.store.blacklistPath, s.store.blacklist, true
	default:
		return "", nil, false
	}
}

func validateAdminIPListContent(content string) (entries int, invalid []string) {
	lines := strings.Split(content, "\n")
	invalid = make([]string, 0, 8)

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cidrStr := normalizeIPPattern(line)
		if _, _, err := net.ParseCIDR(cidrStr); err == nil {
			entries++
			continue
		}
		if net.ParseIP(cidrStr) != nil {
			entries++
			continue
		}

		invalid = append(invalid, line)
	}

	return entries, invalid
}
