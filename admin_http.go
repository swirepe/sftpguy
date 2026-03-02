package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) ListenAdminHTTP() error {
	if s.cfg.AdminHTTP == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("/admin", s.adminAuth(s.handleAdminPage))
	mux.HandleFunc("/admin/api/health", s.adminAuth(s.handleAdminHealth))
	mux.HandleFunc("/admin/api/summary", s.adminAuth(s.handleAdminSummary))
	mux.HandleFunc("/admin/api/users", s.adminAuth(s.handleAdminUsers))
	mux.HandleFunc("/admin/api/users/", s.adminAuth(s.handleAdminUser))
	mux.HandleFunc("/admin/api/files", s.adminAuth(s.handleAdminFiles))
	mux.HandleFunc("/admin/api/audit", s.adminAuth(s.handleAdminAudit))
	mux.HandleFunc("/admin/api/insights", s.adminAuth(s.handleAdminInsights))
	mux.HandleFunc("/admin/api/system-log", s.adminAuth(s.handleAdminSystemLog))
	mux.HandleFunc("/admin/api/system-log/parsed", s.adminAuth(s.handleAdminParsedSystemLog))
	mux.HandleFunc("/admin/api/banned", s.adminAuth(s.handleAdminBanned))
	mux.HandleFunc("/admin/api/banned/ip", s.adminAuth(s.handleAdminBanIP))
	mux.HandleFunc("/admin/api/banned/ip/", s.adminAuth(s.handleAdminUnbanIP))

	httpServer := &http.Server{
		Addr:              s.cfg.AdminHTTP,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.adminShutdownMu.Lock()
	s.adminShutdown = httpServer.Shutdown
	s.adminShutdownMu.Unlock()
	defer func() {
		s.adminShutdownMu.Lock()
		s.adminShutdown = nil
		s.adminShutdownMu.Unlock()
	}()

	s.logger.Info("admin http console online", "addr", s.cfg.AdminHTTP, "token_required", s.cfg.AdminHTTPToken != "")
	if err := httpServer.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminHTTPToken == "" {
			next(w, r)
			return
		}

		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) || strings.TrimSpace(strings.TrimPrefix(header, prefix)) != s.cfg.AdminHTTPToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sftpguy-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(adminHTML))
}

func (s *Server) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"archive": s.cfg.Name,
		"version": AppVersion,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAdminSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u, c, f, b := s.store.GetBannerStats(s.cfg.ContributorThreshold)
	dirCount, _ := s.store.GetDirectoryCount()
	writeJSON(w, http.StatusOK, map[string]any{
		"archive":               s.cfg.Name,
		"version":               AppVersion,
		"ssh_port":              s.cfg.Port,
		"admin_http":            s.cfg.AdminHTTP,
		"users":                 u,
		"contributors":          c,
		"files":                 f,
		"directories":           dirCount,
		"bytes":                 b,
		"formatted_bytes":       formatBytes(int64(b)),
		"contributor_threshold": s.cfg.ContributorThreshold,
	})
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	limit := parseIntQuery(r, "limit", 200, 10, 2000)

	rows, err := s.store.db.Query(`
		SELECT
			u.pubkey_hash,
			IFNULL(u.last_login, ''),
			u.upload_count,
			u.upload_bytes,
			u.download_count,
			u.download_bytes,
			CASE WHEN sb.pubkey_hash IS NULL THEN 0 ELSE 1 END AS is_banned
		FROM users u
		LEFT JOIN shadow_banned sb ON sb.pubkey_hash = u.pubkey_hash
		WHERE u.pubkey_hash != 'system' AND u.pubkey_hash LIKE ?
		ORDER BY u.upload_bytes DESC
		LIMIT ?`, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type userRow struct {
		Hash          string `json:"hash"`
		LastLogin     string `json:"last_login"`
		UploadCount   int64  `json:"upload_count"`
		UploadBytes   int64  `json:"upload_bytes"`
		DownloadCount int64  `json:"download_count"`
		DownloadBytes int64  `json:"download_bytes"`
		IsBanned      bool   `json:"is_banned"`
	}
	out := make([]userRow, 0, limit)
	for rows.Next() {
		var row userRow
		var banned int
		if err := rows.Scan(&row.Hash, &row.LastLogin, &row.UploadCount, &row.UploadBytes, &row.DownloadCount, &row.DownloadBytes, &banned); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.IsBanned = banned == 1
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/users/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	hash := parts[0]

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stats, err := s.store.GetUserStats(hash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		files, err := s.store.FilesByOwner(hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		eventRows, err := s.store.db.Query(`
				SELECT timestamp, event, IFNULL(path,''), IFNULL(meta,''), IFNULL(ip_address,'')
				FROM log
				WHERE user_id = ?
				ORDER BY timestamp DESC
				LIMIT 50`, hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer eventRows.Close()
		type ownerEvent struct {
			Timestamp int64  `json:"timestamp"`
			Time      string `json:"time"`
			Event     string `json:"event"`
			Path      string `json:"path"`
			Meta      string `json:"meta"`
			IP        string `json:"ip"`
		}
		events := make([]ownerEvent, 0, 50)
		for eventRows.Next() {
			var row ownerEvent
			if err := eventRows.Scan(&row.Timestamp, &row.Event, &row.Path, &row.Meta, &row.IP); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
			events = append(events, row)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"hash":      hash,
			"is_banned": s.store.IsBanned(hash),
			"stats":     stats,
			"files":     files,
			"events":    events,
		})
		return
	}

	if len(parts) != 2 || r.Method != http.MethodPost {
		http.Error(w, "bad route", http.StatusBadRequest)
		return
	}
	action := parts[1]

	switch action {
	case "ban":
		s.Ban(hash)
		s.store.LogEvent(EventAdminBan, systemOwner, "admin-http", nil, "target", hash)
	case "unban":
		s.Unban(hash)
		s.store.LogEvent(EventAdminUnban, systemOwner, "admin-http", nil, "target", hash)
	case "purge":
		if err := s.PurgeUser(hash); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": hash, "action": action})
}

func (s *Server) handleAdminFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	relDir, err := cleanRelativePath(r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	abs := filepath.Join(s.absUploadDir, filepath.FromSlash(relDir))
	entries, err := os.ReadDir(abs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	type fileRow struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		Owner     string `json:"owner"`
		IsDir     bool   `json:"is_dir"`
		Size      int64  `json:"size"`
		SizeHuman string `json:"size_human"`
	}

	out := make([]fileRow, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		nextRel := filepath.ToSlash(filepath.Join(relDir, e.Name()))
		owner, _ := s.store.GetFileOwner(nextRel)
		row := fileRow{
			Name:      e.Name(),
			Path:      nextRel,
			Owner:     owner,
			IsDir:     e.IsDir(),
			Size:      info.Size(),
			SizeHuman: formatBytes(info.Size()),
		}
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"path":    relDir,
		"entries": out,
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	limit := parseIntQuery(r, "limit", 100, 10, 500)

	rows, err := s.store.db.Query(`
		SELECT timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, ''), IFNULL(user_session, '')
		FROM log
		WHERE user_id LIKE ? OR event LIKE ? OR path LIKE ? OR meta LIKE ?
		ORDER BY timestamp DESC
		LIMIT ?`, q, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type auditRow struct {
		Timestamp int64  `json:"timestamp"`
		Time      string `json:"time"`
		Event     string `json:"event"`
		UserID    string `json:"user_id"`
		IP        string `json:"ip"`
		Path      string `json:"path"`
		Meta      string `json:"meta"`
		Session   string `json:"session"`
	}
	out := make([]auditRow, 0, limit)
	for rows.Next() {
		var row auditRow
		if err := rows.Scan(&row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (s *Server) handleAdminInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	since := time.Now().Add(-24 * time.Hour).Unix()
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
			"since_unix": since,
			"hours":      24,
		},
		"kpi": map[string]any{
			"events_24h":        scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ?`, since),
			"users_24h":         scalar(`SELECT COUNT(DISTINCT user_id) FROM log WHERE timestamp >= ? AND user_id != ''`, since),
			"ips_24h":           scalar(`SELECT COUNT(DISTINCT ip_address) FROM log WHERE timestamp >= ? AND ip_address != ''`, since),
			"logins_24h":        scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'login'`, since),
			"uploads_24h":       scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'upload'`, since),
			"downloads_24h":     scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'download'`, since),
			"denied_24h":        scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event LIKE 'denied%'`, since),
			"admin_actions_24h": scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event LIKE 'admin/%'`, since),
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

	ipRows, err := s.store.db.Query(`SELECT ip_address, banned_at FROM ip_banned ORDER BY banned_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer ipRows.Close()
	type bannedIP struct {
		IP       string `json:"ip"`
		BannedAt string `json:"banned_at"`
	}
	ips := make([]bannedIP, 0)
	for ipRows.Next() {
		var row bannedIP
		if err := ipRows.Scan(&row.IP, &row.BannedAt); err == nil {
			ips = append(ips, row)
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
	if net.ParseIP(payload.IP) == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	if _, err := s.store.exec("INSERT OR IGNORE INTO ip_banned (ip_address) VALUES (?)", payload.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminBan, systemOwner, "admin-http", nil, "target", payload.IP, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": payload.IP})
}

func (s *Server) handleAdminUnbanIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/api/banned/ip/"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	if _, err := s.store.exec("DELETE FROM ip_banned WHERE ip_address = ?", ip); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminUnban, systemOwner, "admin-http", nil, "target", ip, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

func parseIntQuery(r *http.Request, key string, def, min, max int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

var kvPattern = regexp.MustCompile(`([A-Za-z0-9_.-]+)=("([^"\\]|\\.)*"|[^\s]+)`)

func parseLogKV(line string) map[string]string {
	out := map[string]string{}
	matches := kvPattern.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		key := m[1]
		val := m[2]
		if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
			if unq, err := strconv.Unquote(val); err == nil {
				val = unq
			}
		}
		out[key] = val
	}
	return out
}

func pickLogUser(fields map[string]string) string {
	keys := []string{"user.id", "user_id", "id", "user"}
	for _, k := range keys {
		if v := strings.TrimSpace(fields[k]); v != "" {
			return v
		}
	}
	return ""
}

func pickLogIP(fields map[string]string) string {
	keys := []string{"ip", "ip_address", "remote_address", "remote_addr"}
	for _, k := range keys {
		if v := strings.TrimSpace(fields[k]); v != "" {
			return v
		}
	}
	return ""
}

func mapCountPairs(m map[string]int, limit int) []map[string]any {
	type kv struct {
		K string
		V int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		items = append(items, kv{K: k, V: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].V == items[j].V {
			return items[i].K < items[j].K
		}
		return items[i].V > items[j].V
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{"name": it.K, "count": it.V})
	}
	return out
}

func cleanRelativePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." || p == "/" {
		return ".", nil
	}
	clean := filepath.Clean("/" + p)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" {
		return ".", nil
	}
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("invalid path")
	}
	return clean, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

const adminHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>sftpguy admin</title>
  <style>
    :root {
      --panel: rgba(15, 24, 34, 0.92);
      --line: #2a3e56;
      --text: #dce6f3;
      --dim: #8fa4bc;
      --good: #56d897;
      --warn: #ffbf52;
      --bad: #ff6e79;
      --accent: #5ec7ff;
      --ink: #0f1722;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--text);
      font-family: "IBM Plex Mono", "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
      background:
        radial-gradient(circle at 15% 10%, rgba(94,199,255,.2), transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(86,216,151,.15), transparent 35%),
        linear-gradient(160deg, #060b12 0%, #0a1220 100%);
      min-height: 100vh;
      padding: 16px;
    }
    .shell { max-width: 1280px; margin: 0 auto; display: grid; gap: 12px; }
    .card { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 12px; backdrop-filter: blur(4px); }
    h1 { margin: 0 0 8px; font-size: 18px; letter-spacing: .08em; text-transform: uppercase; }
    h3 { margin: 8px 0; font-size: 14px; }
    .muted { color: var(--dim); font-size: 12px; }
    .tabs { display: flex; flex-wrap: wrap; gap: 8px; }
    .tab { border: 1px solid var(--line); background: transparent; color: var(--dim); border-radius: 8px; padding: 6px 10px; cursor: pointer; }
    .tab.active { color: var(--text); border-color: var(--accent); box-shadow: inset 0 0 0 1px rgba(94,199,255,.25); }
    .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 8px; }
    input, select, button {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--ink);
      color: var(--text);
      padding: 8px 10px;
      font: inherit;
    }
    button { cursor: pointer; }
    button:hover { border-color: var(--accent); }
    .btn-danger { border-color: rgba(255,110,121,.4); color: #ffd0d5; }
    .btn-good { border-color: rgba(86,216,151,.5); color: #cbffe4; }
    .btn-warn { border-color: rgba(255,191,82,.5); color: #ffe6b7; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; }
    .metric { border: 1px solid var(--line); border-radius: 10px; padding: 10px; background: rgba(9,14,21,.7); }
    .metric .k { font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: .08em; }
    .metric .v { font-size: 18px; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid rgba(42,62,86,.5); vertical-align: top; word-break: break-word; }
    th { color: var(--dim); font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: .06em; }
    .tag { padding: 2px 6px; border-radius: 999px; font-size: 11px; border: 1px solid; }
    .ok { color: var(--good); border-color: rgba(86,216,151,.35); }
    .bad { color: var(--bad); border-color: rgba(255,110,121,.35); }
    .owner-link { color: var(--accent); cursor: pointer; text-decoration: underline; border: 0; background: none; padding: 0; font: inherit; }
    .tiny { font-size: 11px; padding: 2px 6px; }
    .inspector-list { margin: 8px 0 0; max-height: 220px; overflow: auto; padding-left: 18px; }
    .events-list { max-height: 220px; overflow: auto; }
    .history { max-height: 120px; overflow: auto; padding-left: 18px; margin: 4px 0 0; }
    .kbd { border: 1px solid var(--line); border-radius: 6px; padding: 2px 6px; font-size: 11px; color: var(--dim); }
    .toast {
      position: fixed; right: 16px; bottom: 16px;
      background: rgba(15,24,34,.95); border: 1px solid var(--line);
      color: var(--text); border-radius: 10px; padding: 10px 12px; min-width: 220px;
      box-shadow: 0 12px 30px rgba(0,0,0,.3);
      opacity: 0; transform: translateY(8px); transition: all .2s ease;
      pointer-events: none;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
    pre { margin: 0; white-space: pre-wrap; font-size: 12px; line-height: 1.4; color: var(--text); }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1>sftpguy web admin console</h1>
      <div class="muted" id="status">loading...</div>
      <div class="muted">Shortcuts: <span class="kbd">Alt+1..6</span> switch tabs, <span class="kbd">Esc</span> close inspector, <span class="kbd">Shift+R</span> refresh all</div>
    </div>

    <div class="card">
      <div class="tabs" id="tabs">
        <button class="tab active" data-tab="summary">Summary</button>
        <button class="tab" data-tab="users">Users</button>
        <button class="tab" data-tab="files">Files</button>
        <button class="tab" data-tab="audit">Audit</button>
        <button class="tab" data-tab="logs">Logs</button>
        <button class="tab" data-tab="banned">Banned</button>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <button class="btn-warn" onclick="refreshAll()">Refresh All</button>
        <label><input id="auto-refresh" type="checkbox" onchange="toggleAutoRefresh()" /> Auto refresh</label>
        <select id="auto-seconds" onchange="toggleAutoRefresh()">
          <option value="10">10s</option>
          <option value="20">20s</option>
          <option value="30" selected>30s</option>
          <option value="60">60s</option>
        </select>
        <button onclick="exportUsersCSV()">Export Users CSV</button>
        <button onclick="exportAuditCSV()">Export Audit CSV</button>
      </div>
      <div class="row">
        <input id="quick-owner" placeholder="owner hash" />
        <button class="btn-danger" onclick="quickBanOwner()">Ban Owner</button>
        <button class="btn-good" onclick="quickUnbanOwner()">Unban Owner</button>
        <button onclick="quickInspectOwner()">Inspect Owner</button>
      </div>
      <div class="row">
        <input id="quick-ip" placeholder="ip address" />
        <button class="btn-danger" onclick="quickBanIP()">Ban IP</button>
      </div>
      <h3>Action History</h3>
      <ol class="history" id="action-history"></ol>
    </div>

    <div class="card hidden" id="owner-inspector">
      <div id="owner-inspector-out"></div>
    </div>

    <div class="card" id="tab-summary"></div>

    <div class="card hidden" id="tab-users">
      <div class="row">
        <input id="user-q" placeholder="search hash..." />
        <button onclick="loadUsers()">Refresh</button>
      </div>
      <div id="users-out"></div>
    </div>

    <div class="card hidden" id="tab-files">
      <div class="row">
        <input id="files-path" placeholder="." value="." />
        <button onclick="loadFiles()">Open</button>
        <button onclick="filesUp()">Up</button>
      </div>
      <div id="files-out"></div>
    </div>

    <div class="card hidden" id="tab-audit">
      <div class="row">
        <input id="audit-q" placeholder="filter event/path/user..." />
        <button onclick="loadAudit()">Refresh</button>
      </div>
      <div id="audit-out"></div>
    </div>

    <div class="card hidden" id="tab-logs">
      <div class="row">
        <input id="log-q" placeholder="filter log lines..." />
        <button onclick="loadLogs()">Refresh</button>
      </div>
      <div id="logs-out"></div>
    </div>

    <div class="card hidden" id="tab-banned">
      <div class="row">
        <input id="ban-ip" placeholder="IP to ban (e.g. 1.2.3.4)" />
        <button class="btn-danger" onclick="banIP()">Ban IP</button>
      </div>
      <div id="banned-out"></div>
    </div>
  </div>
  <div class="toast" id="toast"></div>

  <script>
    const state = {
      token: localStorage.getItem("sftpguy_admin_token") || "",
      inspectedOwner: "",
      users: [],
      audit: [],
      insights: null,
      parsedLogs: [],
      autoTimer: 0,
      activeTab: "summary",
      actions: []
    };

    function setStatus(msg) { document.getElementById("status").textContent = msg; }
    function esc(s) {
      return String(s == null ? "" : s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
    }
    function toast(msg) {
      const t = document.getElementById("toast");
      t.textContent = msg;
      t.classList.add("show");
      clearTimeout(t._timer);
      t._timer = setTimeout(function() { t.classList.remove("show"); }, 1800);
    }
    function addHistory(msg) {
      state.actions.unshift(new Date().toLocaleTimeString() + " - " + msg);
      state.actions = state.actions.slice(0, 20);
      document.getElementById("action-history").innerHTML = state.actions.map(function(x) {
        return "<li><code>" + esc(x) + "</code></li>";
      }).join("");
    }
    function csvEscape(v) {
      const s = String(v == null ? "" : v);
      if (s.includes(",") || s.includes("\"") || s.includes("\n")) {
        return "\"" + s.replaceAll("\"", "\"\"") + "\"";
      }
      return s;
    }
    function download(name, content) {
      const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    }
    function copyText(v) {
      navigator.clipboard.writeText(String(v || "")).then(function() {
        toast("Copied");
      }).catch(function() {
        toast("Copy failed");
      });
    }
    function setTabCount(name, count) {
      const el = document.querySelector(".tab[data-tab='" + name + "']");
      if (!el) return;
      const base = name.charAt(0).toUpperCase() + name.slice(1);
      el.textContent = count == null ? base : (base + " (" + count + ")");
    }

    async function api(path, opts) {
      opts = opts || {};
      const headers = Object.assign({"Accept": "application/json"}, opts.headers || {});
      if (state.token) headers["Authorization"] = "Bearer " + state.token;
      if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const res = await fetch(path, Object.assign({}, opts, { headers: headers }));
      if (res.status === 401) {
        const t = prompt("Admin token required");
        if (t) {
          state.token = t.trim();
          localStorage.setItem("sftpguy_admin_token", state.token);
          return api(path, opts);
        }
      }
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }

    function renderTable(headers, rows) {
      const h = headers.map(function(x) { return "<th>" + esc(x) + "</th>"; }).join("");
      const b = rows.map(function(cols) {
        return "<tr>" + cols.map(function(c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
      }).join("");
      return "<table><thead><tr>" + h + "</tr></thead><tbody>" + b + "</tbody></table>";
    }

    function ownerCell(hash) {
      if (!hash || hash === "-" || hash === "system") {
        return "<code>" + esc(hash || "-") + "</code>";
      }
      return "<button class=\"owner-link\" onclick=\"inspectUser('" + esc(hash) + "')\"><code>" + esc(hash) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(hash) + "')\">Copy</button>";
    }
    function ipCell(ip) {
      return "<code>" + esc(ip || "") + "</code> <button class=\"tiny\" onclick=\"copyText('" + esc(ip || "") + "')\">Copy</button>";
    }

    async function loadSummary() {
      const pair = await Promise.all([api("/admin/api/summary"), api("/admin/api/insights")]);
      const d = pair[0];
      const insight = pair[1] || {};
      state.insights = insight;
      setStatus("archive=" + d.archive + " version=" + d.version + " ssh=:" + d.ssh_port + " admin=" + d.admin_http);
      const entries = [
        ["Users", d.users],
        ["Contributors", d.contributors],
        ["Files", d.files],
        ["Directories", d.directories],
        ["Total Disk", d.formatted_bytes],
        ["Contrib Threshold", d.contributor_threshold + " bytes"]
      ];
      const kpi = insight.kpi || {};
      const activity = [
        ["Events (24h)", kpi.events_24h || 0],
        ["Users Active (24h)", kpi.users_24h || 0],
        ["IPs Active (24h)", kpi.ips_24h || 0],
        ["Logins (24h)", kpi.logins_24h || 0],
        ["Uploads (24h)", kpi.uploads_24h || 0],
        ["Downloads (24h)", kpi.downloads_24h || 0],
        ["Denied (24h)", kpi.denied_24h || 0],
        ["Admin Actions (24h)", kpi.admin_actions_24h || 0]
      ];
      const topEventsRows = (insight.top_events || []).map(function(x) {
        return ["<code>" + esc(x.name) + "</code>", esc(x.count)];
      });
      const topUsersRows = (insight.top_users || []).map(function(x) {
        return [ownerCell(x.name), esc(x.count), esc(x.denied)];
      });
      const topIPRows = (insight.top_ips || []).map(function(x) {
        return [ipCell(x.name), esc(x.count), esc(x.denied), "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(x.name) + "')\">Ban</button>"];
      });
      const suspiciousRows = (insight.suspicious_ips || []).map(function(x) {
        return [ipCell(x.name), esc(x.count), esc(x.denied), "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(x.name) + "')\">Ban</button>"];
      });
      const parsedLevelRows = (insight.parsed_levels || []).map(function(x) {
        return ["<code>" + esc(x.name) + "</code>", esc(x.count)];
      });
      const parsedUserRows = (insight.parsed_users_recent || []).map(function(x) {
        return [ownerCell(x.name), esc(x.count), "<button class=\"tiny\" onclick=\"quickSetOwner('" + esc(x.name) + "')\">Target</button>"];
      });
      const parsedIPRows = (insight.parsed_ips_recent || []).map(function(x) {
        return [ipCell(x.name), esc(x.count), "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(x.name) + "')\">Ban</button>"];
      });

      document.getElementById("tab-summary").innerHTML = "<div class=\"grid\">" +
        entries.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>24h Activity</h3><div class=\"grid\">" +
        activity.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Top Events</h3>" + renderTable(["Event", "Count"], topEventsRows) +
        "<h3>Top Users (24h)</h3>" + renderTable(["User", "Events", "Denied"], topUsersRows) +
        "<h3>Top IPs (24h)</h3>" + renderTable(["IP", "Events", "Denied", "Action"], topIPRows) +
        "<h3>Suspicious IPs</h3>" + renderTable(["IP", "Events", "Denied", "Action"], suspiciousRows) +
        "<h3>Parsed Log Signals (" + esc(insight.parsed_lines_considered || 0) + " lines)</h3>" +
        renderTable(["Level", "Count"], parsedLevelRows) +
        "<h3>Recent Parsed Users</h3>" + renderTable(["User", "Mentions", "Action"], parsedUserRows) +
        "<h3>Recent Parsed IPs</h3>" + renderTable(["IP", "Mentions", "Action"], parsedIPRows);
    }

    async function loadUsers() {
      const q = document.getElementById("user-q").value.trim();
      const d = await api("/admin/api/users?q=" + encodeURIComponent(q) + "&limit=400");
      state.users = d.users || [];
      setTabCount("users", state.users.length);
      const rows = state.users.map(function(u) {
        return [
          ownerCell(u.hash),
          esc(u.last_login || ""),
          esc((u.upload_bytes || 0) + " bytes"),
          esc((u.download_bytes || 0) + " bytes"),
          "<span class=\"tag " + (u.is_banned ? "bad" : "ok") + "\">" + (u.is_banned ? "BANNED" : "ACTIVE") + "</span>",
          "<button onclick=\"userAction('" + u.hash + "','ban')\" class=\"btn-danger\">Ban</button>" +
          " <button onclick=\"userAction('" + u.hash + "','unban')\" class=\"btn-good\">Unban</button>" +
          " <button onclick=\"userAction('" + u.hash + "','purge')\" class=\"btn-danger\">Purge</button>"
        ];
      });
      document.getElementById("users-out").innerHTML = renderTable(
        ["User", "Last Login", "Uploaded", "Downloaded", "Status", "Actions"],
        rows
      );
    }

    async function inspectUser(hash) {
      state.inspectedOwner = hash;
      document.getElementById("quick-owner").value = hash;
      const d = await api("/admin/api/users/" + encodeURIComponent(hash));
      const box = document.getElementById("owner-inspector");
      box.classList.remove("hidden");
      const files = (d.files || []).map(function(x) {
        return "<li><code>" + esc(x) + "</code></li>";
      }).join("");
      const events = (d.events || []).map(function(e) {
        return [
          esc(e.time),
          esc(e.event),
          ipCell(e.ip),
          "<code>" + esc(e.path || "") + "</code>",
          "<code>" + esc(e.meta || "") + "</code>"
        ];
      });
      document.getElementById("owner-inspector-out").innerHTML =
        "<h3>Owner Inspector</h3>" +
        "<div class=\"row\"><b><code>" + esc(hash) + "</code></b>" +
        " <span class=\"tag " + (d.is_banned ? "bad" : "ok") + "\">" + (d.is_banned ? "BANNED" : "ACTIVE") + "</span>" +
        " <button class=\"btn-danger\" onclick=\"userAction('" + esc(hash) + "','ban')\">Ban</button>" +
        " <button class=\"btn-good\" onclick=\"userAction('" + esc(hash) + "','unban')\">Unban</button>" +
        " <button class=\"btn-danger\" onclick=\"userAction('" + esc(hash) + "','purge')\">Purge</button></div>" +
        "<div class=\"muted\">last_login=" + esc(d.stats.last_login || "") +
        " upload_count=" + esc(d.stats.upload_count || 0) +
        " upload_bytes=" + esc(d.stats.upload_bytes || 0) +
        " download_count=" + esc(d.stats.download_count || 0) +
        " download_bytes=" + esc(d.stats.download_bytes || 0) +
        " owned_files=" + esc((d.files || []).length) + "</div>" +
        "<h3>Owned Files</h3><ul class=\"inspector-list\">" + files + "</ul>" +
        "<h3>Recent Activity</h3><div class=\"events-list\">" +
        renderTable(["Time", "Event", "IP", "Path", "Meta"], events) +
        "</div>";
      addHistory("inspected owner " + hash);
    }

    async function userAction(hash, action) {
      if (!hash || hash === "system") return;
      if (action === "purge" && !confirm("Purge " + hash + "? This deletes their files and metadata.")) return;
      await api("/admin/api/users/" + encodeURIComponent(hash) + "/" + action, { method: "POST" });
      toast((action + " " + hash).toUpperCase());
      addHistory(action + " owner " + hash);
      await Promise.all([loadUsers(), loadBanned(), loadAudit(), loadFiles()]);
      if (state.inspectedOwner === hash && action !== "purge") await inspectUser(hash);
      if (state.inspectedOwner === hash && action === "purge") closeInspector();
    }

    async function loadFiles() {
      const p = document.getElementById("files-path").value.trim() || ".";
      const d = await api("/admin/api/files?path=" + encodeURIComponent(p));
      document.getElementById("files-path").value = d.path;
      const rows = (d.entries || []).map(function(e) {
        return [
          e.is_dir ? "<button onclick=\"openPath('" + esc(e.path) + "')\">" + esc(e.name) + "/</button>" : esc(e.name),
          ownerCell(e.owner || "-"),
          esc(e.size_human || "")
        ];
      });
      setTabCount("files", (d.entries || []).length);
      document.getElementById("files-out").innerHTML = "<div class=\"muted\">path=<code>" + esc(d.path) + "</code></div>" +
        renderTable(["Name", "Owner", "Size"], rows);
    }
    function openPath(path) {
      document.getElementById("files-path").value = path;
      loadFiles();
    }
    function filesUp() {
      const p = document.getElementById("files-path").value.trim() || ".";
      if (p === "." || p === "/") return;
      const x = p.split("/").filter(Boolean);
      x.pop();
      document.getElementById("files-path").value = x.length ? x.join("/") : ".";
      loadFiles();
    }

    async function loadAudit() {
      const q = document.getElementById("audit-q").value.trim();
      const d = await api("/admin/api/audit?q=" + encodeURIComponent(q) + "&limit=200");
      state.audit = d.events || [];
      setTabCount("audit", state.audit.length);
      const rows = state.audit.map(function(e) {
        return [
          esc(e.time),
          esc(e.event),
          ownerCell(e.user_id),
          ipCell(e.ip),
          esc(e.path || ""),
          "<code>" + esc(e.meta || "") + "</code>" +
            " <button class=\"btn-danger tiny\" onclick=\"userAction('" + esc(e.user_id) + "','ban')\">Ban</button>" +
            " <button class=\"btn-good tiny\" onclick=\"userAction('" + esc(e.user_id) + "','unban')\">Unban</button>"
        ];
      });
      document.getElementById("audit-out").innerHTML = renderTable(["Time", "Event", "User", "IP", "Path", "Meta + Actions"], rows);
    }

    async function loadLogs() {
      const q = document.getElementById("log-q").value.trim();
      const pair = await Promise.all([
        api("/admin/api/system-log?q=" + encodeURIComponent(q) + "&limit=200"),
        api("/admin/api/system-log/parsed?q=" + encodeURIComponent(q) + "&limit=200")
      ]);
      const d = pair[0];
      const p = pair[1] || {};
      state.parsedLogs = p.entries || [];
      setTabCount("logs", state.parsedLogs.length);
      const parsedRows = state.parsedLogs.map(function(x) {
        return [
          "<code>" + esc(x.time || "") + "</code>",
          "<code>" + esc(x.level || "") + "</code>",
          esc(x.msg || ""),
          ownerCell(x.user_id),
          ipCell(x.ip),
          "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(x.ip) + "')\">Ban IP</button>" +
          " <button class=\"tiny\" onclick=\"quickSetOwner('" + esc(x.user_id) + "')\">Target User</button>"
        ];
      });
      const levelRows = (p.levels || []).map(function(x) {
        return ["<code>" + esc(x.name) + "</code>", esc(x.count)];
      });
      document.getElementById("logs-out").innerHTML =
        "<h3>Parsed Log Entries</h3>" +
        renderTable(["Time", "Level", "Message", "User", "IP", "Actions"], parsedRows) +
        "<h3>Parsed Levels</h3>" +
        renderTable(["Level", "Count"], levelRows) +
        "<h3>Raw Log Tail</h3><pre>" + esc((d.lines || []).join("\n")) + "</pre>";
    }

    async function loadBanned() {
      const d = await api("/admin/api/banned");
      const hashRows = (d.hashes || []).map(function(x) {
        return [
          ownerCell(x.hash),
          esc(x.banned_at || ""),
          "<button class=\"btn-good\" onclick=\"userAction('" + x.hash + "','unban')\">Unban</button>"
        ];
      });
      const ipRows = (d.ips || []).map(function(x) {
        return [
          ipCell(x.ip),
          esc(x.banned_at || ""),
          "<button class=\"btn-good\" onclick=\"unbanIP('" + x.ip + "')\">Unban</button>"
        ];
      });
      setTabCount("banned", (d.hashes || []).length + (d.ips || []).length);
      document.getElementById("banned-out").innerHTML =
        "<h3>Pubkey bans</h3>" + renderTable(["Hash", "Banned At", "Action"], hashRows) +
        "<h3>IP bans</h3>" + renderTable(["IP", "Banned At", "Action"], ipRows);
    }

    async function banIP() {
      const ip = document.getElementById("ban-ip").value.trim();
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: ip }) });
      document.getElementById("ban-ip").value = "";
      toast("BANNED IP " + ip);
      addHistory("banned ip " + ip);
      await Promise.all([loadBanned(), loadAudit()]);
    }
    async function quickBanIP() {
      const ip = document.getElementById("quick-ip").value.trim();
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: ip }) });
      document.getElementById("quick-ip").value = "";
      toast("BANNED IP " + ip);
      addHistory("banned ip " + ip);
      await Promise.all([loadBanned(), loadAudit()]);
    }
    function quickSetOwner(hash) {
      if (!hash || hash === "system") return;
      document.getElementById("quick-owner").value = hash;
      toast("Target owner set");
    }
    async function banIPDirect(ip) {
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: ip }) });
      toast("BANNED IP " + ip);
      addHistory("banned ip " + ip + " (from insights/logs)");
      await Promise.all([loadBanned(), loadAudit(), loadSummary()]);
    }
    async function unbanIP(ip) {
      await api("/admin/api/banned/ip/" + encodeURIComponent(ip), { method: "DELETE" });
      toast("UNBANNED IP " + ip);
      addHistory("unbanned ip " + ip);
      await Promise.all([loadBanned(), loadAudit()]);
    }

    async function quickBanOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      await userAction(hash, "ban");
    }
    async function quickUnbanOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      await userAction(hash, "unban");
    }
    async function quickInspectOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      await inspectUser(hash);
    }

    function closeInspector() {
      document.getElementById("owner-inspector").classList.add("hidden");
      state.inspectedOwner = "";
    }

    function exportUsersCSV() {
      const lines = ["hash,last_login,upload_count,upload_bytes,download_count,download_bytes,is_banned"];
      (state.users || []).forEach(function(u) {
        lines.push([
          csvEscape(u.hash), csvEscape(u.last_login), csvEscape(u.upload_count), csvEscape(u.upload_bytes),
          csvEscape(u.download_count), csvEscape(u.download_bytes), csvEscape(u.is_banned)
        ].join(","));
      });
      download("sftpguy-users.csv", lines.join("\n"));
      addHistory("exported users csv");
      toast("Exported users CSV");
    }
    function exportAuditCSV() {
      const lines = ["time,event,user_id,ip,path,meta"];
      (state.audit || []).forEach(function(e) {
        lines.push([
          csvEscape(e.time), csvEscape(e.event), csvEscape(e.user_id), csvEscape(e.ip), csvEscape(e.path), csvEscape(e.meta)
        ].join(","));
      });
      download("sftpguy-audit.csv", lines.join("\n"));
      addHistory("exported audit csv");
      toast("Exported audit CSV");
    }

    async function refreshAll() {
      try {
        await Promise.all([loadSummary(), loadUsers(), loadFiles(), loadAudit(), loadLogs(), loadBanned()]);
        if (state.inspectedOwner) await inspectUser(state.inspectedOwner);
        toast("Refreshed");
      } catch (err) {
        setStatus("error: " + err.message);
      }
    }
    function toggleAutoRefresh() {
      const enabled = document.getElementById("auto-refresh").checked;
      const seconds = Number(document.getElementById("auto-seconds").value || "30");
      clearInterval(state.autoTimer);
      state.autoTimer = 0;
      if (enabled) {
        state.autoTimer = setInterval(function() {
          const fn = state.activeTab === "summary" ? loadSummary :
            state.activeTab === "users" ? loadUsers :
            state.activeTab === "files" ? loadFiles :
            state.activeTab === "audit" ? loadAudit :
            state.activeTab === "logs" ? loadLogs : loadBanned;
          fn().catch(function(err) { setStatus("error: " + err.message); });
        }, seconds * 1000);
        addHistory("enabled auto-refresh every " + seconds + "s");
      } else {
        addHistory("disabled auto-refresh");
      }
    }

    function switchTab(name) {
      state.activeTab = name;
      document.querySelectorAll(".tab").forEach(function(btn) {
        btn.classList.toggle("active", btn.dataset.tab === name);
      });
      ["summary","users","files","audit","logs","banned"].forEach(function(p) {
        document.getElementById("tab-" + p).classList.toggle("hidden", p !== name);
      });
      const fn = name === "summary" ? loadSummary :
        name === "users" ? loadUsers :
        name === "files" ? loadFiles :
        name === "audit" ? loadAudit :
        name === "logs" ? loadLogs : loadBanned;
      fn().catch(function(err) { setStatus("error: " + err.message); });
    }

    document.getElementById("tabs").addEventListener("click", function(e) {
      const tab = e.target.closest(".tab");
      if (tab) switchTab(tab.dataset.tab);
    });
    window.addEventListener("keydown", function(e) {
      if (e.altKey && ["1","2","3","4","5","6"].includes(e.key)) {
        const map = {"1":"summary","2":"users","3":"files","4":"audit","5":"logs","6":"banned"};
        switchTab(map[e.key]);
      }
      if (e.key === "Escape") closeInspector();
      if (e.key.toLowerCase() === "r" && e.shiftKey) refreshAll();
    });

    (async function boot() {
      try {
        await refreshAll();
      } catch (err) {
        setStatus("error: " + err.message);
      }
    })();
  </script>
</body>
</html>`
