package main

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	ipBanTimestampPattern      = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b`)
	ipBanLegacyBannedAtPattern = regexp.MustCompile(`\bbanned_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\b`)
)

func (s *Server) handleAdminInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	window := parseTimeWindow(r, "24h")
	since := window.SinceUnix
	scalar := func(query string, args ...any) int64 {
		var n int64
		_ = s.store.db.QueryRow(query, args...).Scan(&n)
		return n
	}

	type namedCount struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}
	type namedPair struct {
		Name   string `json:"name"`
		Count  int64  `json:"count"`
		Denied int64  `json:"denied"`
	}

	topEvents := make([]namedCount, 0, 12)
	if rows, err := s.store.db.Query(`
		SELECT event, COUNT(*) AS c
		FROM log
		WHERE timestamp >= ?
		GROUP BY event
		ORDER BY c DESC
		LIMIT 12`, since); err == nil {
		defer rows.Close()
		for rows.Next() {
			var item namedCount
			if err := rows.Scan(&item.Name, &item.Count); err == nil {
				topEvents = append(topEvents, item)
			}
		}
	}

	topUsers := make([]namedPair, 0, 10)
	if rows, err := s.store.db.Query(`
		SELECT user_id, COUNT(*) AS c,
		       SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied
		FROM log
		WHERE timestamp >= ? AND user_id != ''
		GROUP BY user_id
		ORDER BY c DESC
		LIMIT 10`, since); err == nil {
		defer rows.Close()
		for rows.Next() {
			var item namedPair
			if err := rows.Scan(&item.Name, &item.Count, &item.Denied); err == nil {
				topUsers = append(topUsers, item)
			}
		}
	}

	topIPs := make([]namedPair, 0, 10)
	suspiciousIPs := make([]namedPair, 0, 10)
	if rows, err := s.store.db.Query(`
		SELECT ip_address, COUNT(*) AS c,
		       SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied
		FROM log
		WHERE timestamp >= ? AND ip_address != ''
		GROUP BY ip_address
		ORDER BY c DESC
		LIMIT 20`, since); err == nil {
		defer rows.Close()
		for rows.Next() {
			var item namedPair
			if err := rows.Scan(&item.Name, &item.Count, &item.Denied); err == nil {
				topIPs = append(topIPs, item)
				if item.Denied >= 3 || item.Count >= 100 {
					suspiciousIPs = append(suspiciousIPs, item)
				}
			}
		}
	}

	lines, _ := tailFile(s.cfg.LogFile, 300, "")
	levelCount := map[string]int{}
	userCount := map[string]int{}
	ipCount := map[string]int{}
	for _, line := range lines {
		fields := parseLogKV(line)
		level := strings.ToUpper(fields["level"])
		if level != "" {
			levelCount[level]++
		}
		if user := pickLogUser(fields); user != "" {
			userCount[user]++
		}
		if ip := pickLogIP(fields); ip != "" {
			ipCount[ip]++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": since,
			"hours":      int(window.Duration.Hours()),
		},
		"kpi": map[string]any{
			"events":         scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ?`, since),
			"users":          scalar(`SELECT COUNT(DISTINCT user_id) FROM log WHERE timestamp >= ? AND user_id != ''`, since),
			"ips":            scalar(`SELECT COUNT(DISTINCT ip_address) FROM log WHERE timestamp >= ? AND ip_address != ''`, since),
			"logins":         scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'login'`, since),
			"uploads":        scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'upload'`, since),
			"downloads":      scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'download'`, since),
			"denied":         scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event LIKE 'denied%'`, since),
			"admin_actions":  scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event LIKE 'admin/%'`, since),
			"session_starts": scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'session/start'`, since),
			"session_ends":   scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'session/end'`, since),
		},
		"top_events":              topEvents,
		"top_users":               topUsers,
		"top_ips":                 topIPs,
		"suspicious_ips":          suspiciousIPs,
		"parsed_levels":           mapCountPairs(levelCount, 6),
		"parsed_users_recent":     mapCountPairs(userCount, 12),
		"parsed_ips_recent":       mapCountPairs(ipCount, 12),
		"parsed_lines_considered": len(lines),
	})
}

func (s *Server) handleAdminSystemLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := parseIntQuery(r, "limit", 100, 10, 500)
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	lines, err := tailFile(s.cfg.LogFile, limit, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

func (s *Server) handleAdminParsedSystemLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := parseIntQuery(r, "limit", 120, 10, 500)
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	lines, err := tailFile(s.cfg.LogFile, limit, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type parsedRow struct {
		Raw    string `json:"raw"`
		Time   string `json:"time"`
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		UserID string `json:"user_id"`
		IP     string `json:"ip"`
	}

	out := make([]parsedRow, 0, len(lines))
	levelCount := map[string]int{}
	for _, line := range lines {
		fields := parseLogKV(line)
		row := parsedRow{
			Raw:    line,
			Time:   fields["time"],
			Level:  strings.ToUpper(fields["level"]),
			Msg:    fields["msg"],
			UserID: pickLogUser(fields),
			IP:     pickLogIP(fields),
		}
		if row.Level != "" {
			levelCount[row.Level]++
		}
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": out,
		"levels":  mapCountPairs(levelCount, 10),
	})
}

func (s *Server) handleAdminBanned(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hashRows, err := s.store.db.Query(`SELECT pubkey_hash, banned_at FROM shadow_banned ORDER BY banned_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer hashRows.Close()
	type bannedHash struct {
		Hash     string `json:"hash"`
		BannedAt string `json:"banned_at"`
	}
	hashes := make([]bannedHash, 0)
	for hashRows.Next() {
		var row bannedHash
		if err := hashRows.Scan(&row.Hash, &row.BannedAt); err == nil {
			hashes = append(hashes, row)
		}
	}

	type bannedIP struct {
		IP       string `json:"ip"`
		BannedAt string `json:"banned_at"`
		Comment  string `json:"comment,omitempty"`
	}
	ips := make([]bannedIP, 0)
	if s.store.blacklist != nil {
		entries, err := s.store.blacklist.ExactEntries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i := len(entries) - 1; i >= 0; i-- {
			entry := entries[i]
			ips = append(ips, bannedIP{
				IP:       entry.ExactIP,
				BannedAt: extractIPBanTimestamp(entry.Comment),
				Comment:  entry.Comment,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"hashes": hashes, "ips": ips})
}

func (s *Server) handleAdminBanIP(w http.ResponseWriter, r *http.Request) {
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
	payload.IP = strings.TrimSpace(payload.IP)
	parsedIP := net.ParseIP(payload.IP)
	if parsedIP == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	payload.IP = parsedIP.String()
	added, err := s.store.blacklist.AddExactIPWithComment(payload.IP, adminIPBanComment(time.Now()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminBan, systemOwner, "admin-http", nil, "target", payload.IP, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": payload.IP, "added": added})
}

func (s *Server) handleAdminUnbanIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/api/banned/ip/"))
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	ip = parsedIP.String()
	removed, err := s.store.blacklist.RemoveExactIP(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminUnban, systemOwner, "admin-http", nil, "target", ip, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip, "removed": removed})
}

func extractIPBanTimestamp(comment string) string {
	if match := ipBanLegacyBannedAtPattern.FindStringSubmatch(comment); len(match) == 2 {
		return match[1]
	}
	return ipBanTimestampPattern.FindString(comment)
}
