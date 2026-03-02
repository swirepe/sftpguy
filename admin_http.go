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
	mux.HandleFunc("/admin/api/events", s.adminAuth(s.handleAdminEvents))
	mux.HandleFunc("/admin/api/events/stream", s.adminAuth(s.handleAdminEventStream))
	mux.HandleFunc("/admin/api/insights", s.adminAuth(s.handleAdminInsights))
	mux.HandleFunc("/admin/api/sessions", s.adminAuth(s.handleAdminSessions))
	mux.HandleFunc("/admin/api/sessions/", s.adminAuth(s.handleAdminSessionTimeline))
	mux.HandleFunc("/admin/api/uploads/recent", s.adminAuth(s.handleAdminRecentUploads))
	mux.HandleFunc("/admin/api/actor", s.adminAuth(s.handleAdminActor))
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
	window := parseTimeWindow(r, "24h")
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	limit := parseIntQuery(r, "limit", 100, 10, 500)

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, ''), IFNULL(user_session, '')
		FROM log
		WHERE timestamp >= ?
		  AND (user_id LIKE ? OR event LIKE ? OR path LIKE ? OR meta LIKE ? OR ip_address LIKE ? OR user_session LIKE ?)
		ORDER BY timestamp DESC
		LIMIT ?`, window.SinceUnix, q, q, q, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type auditRow struct {
		ID        int64  `json:"id"`
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
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": out,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
			"hours":      int(window.Duration.Hours()),
		},
	})
}

func (s *Server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	limit := parseIntQuery(r, "limit", 300, 10, 2000)
	order := "DESC"
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("order")), "asc") {
		order = "ASC"
	}

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, ''), IFNULL(user_session, '')
		FROM log
		WHERE timestamp >= ?
		  AND (user_id LIKE ? OR event LIKE ? OR path LIKE ? OR meta LIKE ? OR ip_address LIKE ? OR user_session LIKE ?)
		ORDER BY id `+order+`
		LIMIT ?`, window.SinceUnix, q, q, q, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type eventRow struct {
		ID        int64          `json:"id"`
		Timestamp int64          `json:"timestamp"`
		Time      string         `json:"time"`
		Event     string         `json:"event"`
		UserID    string         `json:"user_id"`
		IP        string         `json:"ip"`
		Path      string         `json:"path"`
		Meta      string         `json:"meta"`
		MetaObj   map[string]any `json:"meta_obj,omitempty"`
		Session   string         `json:"session"`
	}

	out := make([]eventRow, 0, limit)
	var lastID int64
	for rows.Next() {
		var row eventRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		row.MetaObj = parseJSONMap(row.Meta)
		if row.ID > lastID {
			lastID = row.ID
		}
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events":  out,
		"last_id": lastID,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
		},
	})
}

func (s *Server) handleAdminEventStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	sinceID := parseInt64Query(r, "since_id", 0)
	limit := parseIntQuery(r, "limit", 120, 10, 500)
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, ''), IFNULL(user_session, '')
		FROM log
		WHERE id > ? AND timestamp >= ?
		  AND (user_id LIKE ? OR event LIKE ? OR path LIKE ? OR meta LIKE ? OR ip_address LIKE ? OR user_session LIKE ?)
		ORDER BY id ASC
		LIMIT ?`, sinceID, window.SinceUnix, q, q, q, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type eventRow struct {
		ID        int64          `json:"id"`
		Timestamp int64          `json:"timestamp"`
		Time      string         `json:"time"`
		Event     string         `json:"event"`
		UserID    string         `json:"user_id"`
		IP        string         `json:"ip"`
		Path      string         `json:"path"`
		Meta      string         `json:"meta"`
		MetaObj   map[string]any `json:"meta_obj,omitempty"`
		Session   string         `json:"session"`
	}

	out := make([]eventRow, 0, limit)
	lastID := sinceID
	for rows.Next() {
		var row eventRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		row.MetaObj = parseJSONMap(row.Meta)
		if row.ID > lastID {
			lastID = row.ID
		}
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events":  out,
		"last_id": lastID,
	})
}

func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	limit := parseIntQuery(r, "limit", 400, 10, 2000)
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"

	rows, err := s.store.db.Query(`
		SELECT
			user_session,
			MIN(timestamp) AS started_at,
			MAX(timestamp) AS ended_at,
			MAX(IFNULL(user_id, '')) AS user_id,
			MAX(IFNULL(ip_address, '')) AS ip_address,
			COUNT(*) AS event_count,
			SUM(CASE WHEN event = 'upload' THEN 1 ELSE 0 END) AS upload_count,
			SUM(CASE WHEN event = 'download' THEN 1 ELSE 0 END) AS download_count,
			SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied_count,
			SUM(CASE WHEN event = 'session/start' THEN 1 ELSE 0 END) AS starts,
			SUM(CASE WHEN event = 'session/end' THEN 1 ELSE 0 END) AS ends
		FROM log
		WHERE timestamp >= ?
		  AND user_session != ''
		  AND (user_session LIKE ? OR user_id LIKE ? OR ip_address LIKE ?)
		GROUP BY user_session
		ORDER BY ended_at DESC
		LIMIT ?`, window.SinceUnix, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type sessionRow struct {
		Session     string `json:"session"`
		UserID      string `json:"user_id"`
		IP          string `json:"ip"`
		StartedAt   int64  `json:"started_at"`
		EndedAt     int64  `json:"ended_at"`
		StartTime   string `json:"start_time"`
		EndTime     string `json:"end_time"`
		DurationSec int64  `json:"duration_sec"`
		EventCount  int64  `json:"event_count"`
		UploadCount int64  `json:"upload_count"`
		DownloadCnt int64  `json:"download_count"`
		DeniedCount int64  `json:"denied_count"`
		HasStart    bool   `json:"has_start"`
		HasEnd      bool   `json:"has_end"`
	}

	out := make([]sessionRow, 0, limit)
	for rows.Next() {
		var row sessionRow
		var starts, ends int64
		if err := rows.Scan(
			&row.Session, &row.StartedAt, &row.EndedAt,
			&row.UserID, &row.IP, &row.EventCount,
			&row.UploadCount, &row.DownloadCnt, &row.DeniedCount, &starts, &ends,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.StartTime = time.Unix(row.StartedAt, 0).Format("2006-01-02 15:04:05")
		row.EndTime = time.Unix(row.EndedAt, 0).Format("2006-01-02 15:04:05")
		if row.EndedAt >= row.StartedAt {
			row.DurationSec = row.EndedAt - row.StartedAt
		}
		row.HasStart = starts > 0
		row.HasEnd = ends > 0
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
		},
	})
}

func (s *Server) handleAdminSessionTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/api/sessions/"))
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	limit := parseIntQuery(r, "limit", 400, 10, 2000)

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, '')
		FROM log
		WHERE user_session = ?
		ORDER BY id DESC
		LIMIT ?`, sessionID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type timelineRow struct {
		ID        int64          `json:"id"`
		Timestamp int64          `json:"timestamp"`
		Time      string         `json:"time"`
		Event     string         `json:"event"`
		UserID    string         `json:"user_id"`
		IP        string         `json:"ip"`
		Path      string         `json:"path"`
		Meta      string         `json:"meta"`
		MetaObj   map[string]any `json:"meta_obj,omitempty"`
	}

	events := make([]timelineRow, 0, limit)
	var startedAt, endedAt int64
	var userID, ip string
	for rows.Next() {
		var row timelineRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		row.MetaObj = parseJSONMap(row.Meta)
		if startedAt == 0 || row.Timestamp < startedAt {
			startedAt = row.Timestamp
		}
		if row.Timestamp > endedAt {
			endedAt = row.Timestamp
		}
		if userID == "" && row.UserID != "" {
			userID = row.UserID
		}
		if ip == "" && row.IP != "" {
			ip = row.IP
		}
		events = append(events, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session":    sessionID,
		"user_id":    userID,
		"ip":         ip,
		"started_at": startedAt,
		"ended_at":   endedAt,
		"start_time": formatUnix(startedAt),
		"end_time":   formatUnix(endedAt),
		"events":     events,
	})
}

func (s *Server) handleAdminRecentUploads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	limit := parseIntQuery(r, "limit", 200, 10, 1000)

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, IFNULL(user_id,''), IFNULL(ip_address,''), IFNULL(path,''), IFNULL(meta,''), IFNULL(user_session,'')
		FROM log
		WHERE event = 'upload'
		  AND timestamp >= ?
		  AND (user_id LIKE ? OR path LIKE ? OR ip_address LIKE ? OR meta LIKE ? OR user_session LIKE ?)
		ORDER BY id DESC
		LIMIT ?`, window.SinceUnix, q, q, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type uploadRow struct {
		ID        int64  `json:"id"`
		Timestamp int64  `json:"timestamp"`
		Time      string `json:"time"`
		UserID    string `json:"user_id"`
		IP        string `json:"ip"`
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		Delta     int64  `json:"delta"`
		Session   string `json:"session"`
	}

	out := make([]uploadRow, 0, limit)
	for rows.Next() {
		var row uploadRow
		var meta string
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.UserID, &row.IP, &row.Path, &meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metaObj := parseJSONMap(meta)
		row.Size = int64FromAny(metaObj["size"])
		row.Delta = int64FromAny(metaObj["delta"])
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		out = append(out, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"uploads": out,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
		},
	})
}

func (s *Server) handleAdminActor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	actorType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	if actorType == "" {
		if net.ParseIP(value) != nil {
			actorType = "ip"
		} else {
			actorType = "user"
		}
	}
	if value == "" {
		http.Error(w, "missing actor value", http.StatusBadRequest)
		return
	}

	type actorEvent struct {
		ID        int64          `json:"id"`
		Timestamp int64          `json:"timestamp"`
		Time      string         `json:"time"`
		Event     string         `json:"event"`
		UserID    string         `json:"user_id"`
		IP        string         `json:"ip"`
		Path      string         `json:"path"`
		Session   string         `json:"session"`
		Meta      string         `json:"meta"`
		MetaObj   map[string]any `json:"meta_obj,omitempty"`
	}
	type actorUpload struct {
		ID        int64  `json:"id"`
		Timestamp int64  `json:"timestamp"`
		Time      string `json:"time"`
		UserID    string `json:"user_id"`
		IP        string `json:"ip"`
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		Delta     int64  `json:"delta"`
		Session   string `json:"session"`
	}
	type actorSession struct {
		Session     string `json:"session"`
		UserID      string `json:"user_id"`
		IP          string `json:"ip"`
		StartedAt   int64  `json:"started_at"`
		EndedAt     int64  `json:"ended_at"`
		StartTime   string `json:"start_time"`
		EndTime     string `json:"end_time"`
		DurationSec int64  `json:"duration_sec"`
		EventCount  int64  `json:"event_count"`
		UploadCount int64  `json:"upload_count"`
		DownloadCnt int64  `json:"download_count"`
		DeniedCount int64  `json:"denied_count"`
		HasEnd      bool   `json:"has_end"`
	}

	whereField := "user_id"
	if actorType == "ip" {
		if net.ParseIP(value) == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}
		whereField = "ip_address"
	}

	eventRows, err := s.store.db.Query(`
		SELECT id, timestamp, event, IFNULL(user_id,''), IFNULL(ip_address,''), IFNULL(path,''), IFNULL(meta,''), IFNULL(user_session,'')
		FROM log
		WHERE `+whereField+` = ? AND timestamp >= ?
		ORDER BY id DESC
		LIMIT 120`, value, window.SinceUnix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer eventRows.Close()

	events := make([]actorEvent, 0, 120)
	for eventRows.Next() {
		var row actorEvent
		if err := eventRows.Scan(&row.ID, &row.Timestamp, &row.Event, &row.UserID, &row.IP, &row.Path, &row.Meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		row.MetaObj = parseJSONMap(row.Meta)
		events = append(events, row)
	}

	uploadRows, err := s.store.db.Query(`
		SELECT id, timestamp, IFNULL(user_id,''), IFNULL(ip_address,''), IFNULL(path,''), IFNULL(meta,''), IFNULL(user_session,'')
		FROM log
		WHERE event = 'upload' AND `+whereField+` = ? AND timestamp >= ?
		ORDER BY id DESC
		LIMIT 50`, value, window.SinceUnix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer uploadRows.Close()

	uploads := make([]actorUpload, 0, 50)
	for uploadRows.Next() {
		var row actorUpload
		var meta string
		if err := uploadRows.Scan(&row.ID, &row.Timestamp, &row.UserID, &row.IP, &row.Path, &meta, &row.Session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metaObj := parseJSONMap(meta)
		row.Size = int64FromAny(metaObj["size"])
		row.Delta = int64FromAny(metaObj["delta"])
		row.Time = time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04:05")
		uploads = append(uploads, row)
	}

	sessionRows, err := s.store.db.Query(`
		SELECT
			user_session,
			MIN(timestamp) AS started_at,
			MAX(timestamp) AS ended_at,
			MAX(IFNULL(user_id,'')) AS user_id,
			MAX(IFNULL(ip_address,'')) AS ip_address,
			COUNT(*) AS event_count,
			SUM(CASE WHEN event = 'upload' THEN 1 ELSE 0 END) AS upload_count,
			SUM(CASE WHEN event = 'download' THEN 1 ELSE 0 END) AS download_count,
			SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied_count,
			SUM(CASE WHEN event = 'session/end' THEN 1 ELSE 0 END) AS ends
		FROM log
		WHERE `+whereField+` = ? AND timestamp >= ? AND user_session != ''
		GROUP BY user_session
		ORDER BY ended_at DESC
		LIMIT 30`, value, window.SinceUnix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sessionRows.Close()

	sessions := make([]actorSession, 0, 30)
	for sessionRows.Next() {
		var row actorSession
		var ends int64
		if err := sessionRows.Scan(
			&row.Session, &row.StartedAt, &row.EndedAt,
			&row.UserID, &row.IP, &row.EventCount, &row.UploadCount, &row.DownloadCnt, &row.DeniedCount, &ends,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.StartTime = formatUnix(row.StartedAt)
		row.EndTime = formatUnix(row.EndedAt)
		row.DurationSec = row.EndedAt - row.StartedAt
		row.HasEnd = ends > 0
		sessions = append(sessions, row)
	}

	summary := map[string]any{
		"events":         len(events),
		"recent_uploads": len(uploads),
		"sessions":       len(sessions),
	}

	if actorType == "user" {
		stats, _ := s.store.GetUserStats(value)
		summary["user_stats"] = stats
		summary["is_banned"] = s.store.IsBanned(value)
	} else {
		summary["is_banned"] = s.store.IsIPBanned(value)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"actor_type":     actorType,
		"actor":          value,
		"summary":        summary,
		"events":         events,
		"recent_uploads": uploads,
		"sessions":       sessions,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
		},
	})
}

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

type adminTimeWindow struct {
	Label     string
	Duration  time.Duration
	SinceUnix int64
}

func parseTimeWindow(r *http.Request, def string) adminTimeWindow {
	label := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if label == "" {
		label = strings.ToLower(strings.TrimSpace(def))
	}
	if label == "" {
		label = "24h"
	}

	var dur time.Duration
	switch label {
	case "15m":
		dur = 15 * time.Minute
	case "1h":
		dur = time.Hour
	case "6h":
		dur = 6 * time.Hour
	case "12h":
		dur = 12 * time.Hour
	case "24h":
		dur = 24 * time.Hour
	case "48h":
		dur = 48 * time.Hour
	case "7d":
		dur = 7 * 24 * time.Hour
	case "14d":
		dur = 14 * 24 * time.Hour
	case "30d":
		dur = 30 * 24 * time.Hour
	default:
		dur = 24 * time.Hour
		label = "24h"
	}

	return adminTimeWindow{
		Label:     label,
		Duration:  dur,
		SinceUnix: time.Now().Add(-dur).Unix(),
	}
}

func parseInt64Query(r *http.Request, key string, def int64) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func parseJSONMap(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func int64FromAny(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		return i
	default:
		return 0
	}
}

func formatUnix(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
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
    .shell { max-width: 1320px; margin: 0 auto; display: grid; gap: 12px; }
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
    .btn-live { border-color: rgba(94,199,255,.6); color: #c9ebff; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; }
    .metric { border: 1px solid var(--line); border-radius: 10px; padding: 10px; background: rgba(9,14,21,.7); }
    .metric .k { font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: .08em; }
    .metric .v { font-size: 18px; margin-top: 4px; }
    .table-wrap { border: 1px solid rgba(42,62,86,.5); border-radius: 10px; overflow: auto; max-height: 460px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid rgba(42,62,86,.5); vertical-align: top; word-break: break-word; }
    th { color: var(--dim); font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: .06em; position: sticky; top: 0; background: rgba(8, 14, 20, .96); z-index: 1; }
    .sort-btn { background: transparent; border: 0; color: inherit; padding: 0; font: inherit; cursor: pointer; text-transform: inherit; letter-spacing: inherit; }
    .sort-btn.active { color: var(--accent); }
    .table-tools { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; }
    .pager { display: flex; align-items: center; gap: 6px; }
    .tag { padding: 2px 6px; border-radius: 999px; font-size: 11px; border: 1px solid; }
    .ok { color: var(--good); border-color: rgba(86,216,151,.35); }
    .bad { color: var(--bad); border-color: rgba(255,110,121,.35); }
    .warn { color: var(--warn); border-color: rgba(255,191,82,.45); }
    .owner-link { color: var(--accent); cursor: pointer; text-decoration: underline; border: 0; background: none; padding: 0; font: inherit; }
    .tiny { font-size: 11px; padding: 2px 6px; }
    .history { max-height: 120px; overflow: auto; padding-left: 18px; margin: 4px 0 0; }
    .kbd { border: 1px solid var(--line); border-radius: 6px; padding: 2px 6px; font-size: 11px; color: var(--dim); }
    .pill { border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; font-size: 11px; color: var(--dim); }
    .drawer { border-color: rgba(94,199,255,.5); }
    .hidden { display: none; }
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
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1>sftpguy web admin console</h1>
      <div class="muted" id="status">loading...</div>
      <div class="muted">Shortcuts: <span class="kbd">Alt+1..8</span> switch tabs, <span class="kbd">Shift+R</span> refresh all, <span class="kbd">Shift+L</span> toggle live logs, <span class="kbd">Esc</span> close drawers</div>
    </div>

    <div class="card">
      <div class="row">
        <button class="btn-warn" onclick="refreshAll()">Refresh All</button>
        <label>Range
          <select id="time-range" onchange="changeRange()">
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="6h">Last 6h</option>
            <option value="12h">Last 12h</option>
            <option value="24h" selected>Last 24h</option>
            <option value="48h">Last 48h</option>
            <option value="7d">Last 7d</option>
            <option value="14d">Last 14d</option>
            <option value="30d">Last 30d</option>
          </select>
        </label>
        <label>Rows / page
          <select id="table-page-size" onchange="changePageSize()">
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </label>
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
        <button onclick="quickOpenOwner()">Open Actor</button>
      </div>
      <div class="row">
        <input id="quick-ip" placeholder="ip address" />
        <button class="btn-danger" onclick="quickBanIP()">Ban IP</button>
        <button onclick="quickOpenIP()">Open Actor</button>
      </div>
      <h3>Action History</h3>
      <ol class="history" id="action-history"></ol>
    </div>

    <div class="card">
      <div class="tabs" id="tabs">
        <button class="tab active" data-tab="summary">Summary</button>
        <button class="tab" data-tab="users">Users</button>
        <button class="tab" data-tab="files">Files</button>
        <button class="tab" data-tab="audit">Audit</button>
        <button class="tab" data-tab="logs">Logs</button>
        <button class="tab" data-tab="sessions">Sessions</button>
        <button class="tab" data-tab="uploads">Uploads</button>
        <button class="tab" data-tab="banned">Banned</button>
      </div>
    </div>

    <div class="card drawer hidden" id="actor-drawer">
      <div id="actor-out"></div>
    </div>

    <div class="card drawer hidden" id="session-timeline">
      <div id="session-out"></div>
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
        <input id="audit-q" placeholder="filter event/path/user/ip/session..." />
        <button onclick="loadAudit()">Refresh</button>
      </div>
      <div id="audit-out"></div>
    </div>

    <div class="card hidden" id="tab-logs">
      <div class="row">
        <input id="log-q" placeholder="filter events..." />
        <button onclick="loadLogs()">Refresh</button>
        <label><input id="logs-live" type="checkbox" onchange="toggleLogLive()" /> Live stream</label>
      </div>
      <div id="logs-out"></div>
    </div>

    <div class="card hidden" id="tab-sessions">
      <div class="row">
        <input id="sessions-q" placeholder="filter session/user/ip..." />
        <button onclick="loadSessions()">Refresh</button>
      </div>
      <div id="sessions-out"></div>
    </div>

    <div class="card hidden" id="tab-uploads">
      <div class="row">
        <input id="uploads-q" placeholder="filter path/user/ip..." />
        <button onclick="loadUploads()">Refresh</button>
      </div>
      <div id="uploads-out"></div>
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
      activeTab: "summary",
      timeRange: localStorage.getItem("sftpguy_admin_range") || "24h",
      pageSize: Number(localStorage.getItem("sftpguy_admin_page_size") || "50"),
      table: {},
      autoTimer: 0,
      liveLogTimer: 0,
      actions: [],
      summary: {},
      insights: {},
      summaryUploads: [],
      users: [],
      files: { path: ".", entries: [] },
      audit: [],
      events: [],
      sessions: [],
      uploads: [],
      banned: { hashes: [], ips: [] },
      actor: null,
      sessionTimeline: null,
      lastEventID: 0
    };

    function setStatus(msg) { document.getElementById("status").textContent = msg; }
    function esc(v) {
      return String(v == null ? "" : v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    }
    function shortSession(v) {
      const s = String(v || "");
      if (s.length <= 16) return s;
      return s.slice(0, 8) + ".." + s.slice(-6);
    }
    function formatBytes(n) {
      let x = Number(n || 0);
      if (!isFinite(x) || x <= 0) return "0 B";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
      return x.toFixed(i === 0 ? 0 : 1) + " " + units[i];
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
      state.actions = state.actions.slice(0, 40);
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

    function withRange(path) {
      const sep = path.includes("?") ? "&" : "?";
      return path + sep + "range=" + encodeURIComponent(state.timeRange);
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

    function setTabCount(name, count) {
      const el = document.querySelector(".tab[data-tab='" + name + "']");
      if (!el) return;
      const base = name.charAt(0).toUpperCase() + name.slice(1);
      el.textContent = count == null ? base : (base + " (" + count + ")");
    }

    function tableState(key, defaultSort, defaultDir) {
      if (!state.table[key]) {
        state.table[key] = { sort: defaultSort || "", dir: defaultDir || "desc", page: 1 };
      }
      if (!state.table[key].sort && defaultSort) {
        state.table[key].sort = defaultSort;
      }
      return state.table[key];
    }
    function normalizeSort(v) {
      if (v == null) return "";
      if (typeof v === "number") return v;
      if (typeof v === "boolean") return v ? 1 : 0;
      const n = Number(v);
      if (!Number.isNaN(n) && String(v).trim() !== "") return n;
      return String(v).toLowerCase();
    }
    function compareSort(a, b) {
      const av = normalizeSort(a);
      const bv = normalizeSort(b);
      if (typeof av === "number" && typeof bv === "number") return av - bv;
      if (av < bv) return -1;
      if (av > bv) return 1;
      return 0;
    }
    function renderSmartTable(key, columns, rows, defaultSort, defaultDir) {
      const st = tableState(key, defaultSort || columns[0].key, defaultDir || "desc");
      if (!columns.find(function(c) { return c.key === st.sort; })) {
        st.sort = columns[0].key;
      }
      const sorted = rows.slice().sort(function(a, b) {
        const cmp = compareSort((a.sort || {})[st.sort], (b.sort || {})[st.sort]);
        return st.dir === "asc" ? cmp : -cmp;
      });

      const pageSize = Math.max(1, Number(state.pageSize || 50));
      const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
      if (st.page > totalPages) st.page = totalPages;
      if (st.page < 1) st.page = 1;
      const start = (st.page - 1) * pageSize;
      const pageRows = sorted.slice(start, start + pageSize);

      const head = columns.map(function(col) {
        const isActive = st.sort === col.key;
        const marker = isActive ? (st.dir === "asc" ? " ▲" : " ▼") : "";
        return "<th><button class=\"sort-btn" + (isActive ? " active" : "") + "\" onclick=\"tableSort('" + esc(key) + "','" + esc(col.key) + "')\">" + esc(col.label) + marker + "</button></th>";
      }).join("");

      const body = pageRows.length ? pageRows.map(function(row) {
        return "<tr>" + row.cells.map(function(c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
      }).join("") : "<tr><td colspan=\"" + columns.length + "\" class=\"muted\">No rows</td></tr>";

      return "<div class=\"table-tools\">" +
        "<div class=\"muted\">Rows " + sorted.length + "</div>" +
        "<div class=\"pager\">" +
          "<button class=\"tiny\" onclick=\"tablePage('" + esc(key) + "',-1)\">Prev</button>" +
          "<span class=\"pill\">Page " + st.page + " / " + totalPages + "</span>" +
          "<button class=\"tiny\" onclick=\"tablePage('" + esc(key) + "',1)\">Next</button>" +
        "</div>" +
      "</div>" +
      "<div class=\"table-wrap\"><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table></div>";
    }

    function tableSort(key, sortKey) {
      const st = tableState(key, sortKey, "desc");
      if (st.sort === sortKey) {
        st.dir = st.dir === "asc" ? "desc" : "asc";
      } else {
        st.sort = sortKey;
        st.dir = "desc";
      }
      st.page = 1;
      rerenderCurrent();
    }
    function tablePage(key, delta) {
      const st = tableState(key, "", "desc");
      st.page += delta;
      rerenderCurrent();
    }

    function ownerCell(hash) {
      if (!hash || hash === "-" || hash === "system") {
        return "<code>" + esc(hash || "-") + "</code>";
      }
      const enc = encodeURIComponent(hash);
      return "<button class=\"owner-link\" onclick=\"openActor('user', decodeURIComponent('" + enc + "'))\"><code>" + esc(hash) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(hash) + "')\">Copy</button>";
    }
    function ipCell(ip) {
      const value = String(ip || "");
      const enc = encodeURIComponent(value);
      return "<button class=\"owner-link\" onclick=\"openActor('ip', decodeURIComponent('" + enc + "'))\"><code>" + esc(value) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(value) + "')\">Copy</button>";
    }
    function sessionCell(session) {
      const value = String(session || "");
      if (!value) return "<code>-</code>";
      const enc = encodeURIComponent(value);
      return "<button class=\"owner-link\" onclick=\"openSessionTimeline(decodeURIComponent('" + enc + "'))\"><code>" + esc(shortSession(value)) + "</code></button>";
    }

    function closeActorDrawer() {
      state.actor = null;
      document.getElementById("actor-drawer").classList.add("hidden");
    }
    function closeSessionTimeline() {
      state.sessionTimeline = null;
      document.getElementById("session-timeline").classList.add("hidden");
    }

    function renderSimpleTable(headers, rows) {
      const h = headers.map(function(x) { return "<th>" + esc(x) + "</th>"; }).join("");
      const b = rows.length ? rows.map(function(cols) {
        return "<tr>" + cols.map(function(c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
      }).join("") : "<tr><td colspan=\"" + headers.length + "\" class=\"muted\">No rows</td></tr>";
      return "<div class=\"table-wrap\"><table><thead><tr>" + h + "</tr></thead><tbody>" + b + "</tbody></table></div>";
    }

    async function loadSummary() {
      const pair = await Promise.all([
        api("/admin/api/summary"),
        api(withRange("/admin/api/insights")),
        api(withRange("/admin/api/uploads/recent?limit=12"))
      ]);
      state.summary = pair[0] || {};
      state.insights = pair[1] || {};
      state.summaryUploads = (pair[2] || {}).uploads || [];
      renderSummary();
    }
    function renderSummary() {
      const d = state.summary || {};
      const insight = state.insights || {};
      const kpi = insight.kpi || {};
      const win = insight.window || {};
      setStatus("archive=" + (d.archive || "") + " version=" + (d.version || "") + " ssh=:" + (d.ssh_port || "") + " admin=" + (d.admin_http || "") + " range=" + (win.label || state.timeRange));

      const entries = [
        ["Users", d.users || 0],
        ["Contributors", d.contributors || 0],
        ["Files", d.files || 0],
        ["Directories", d.directories || 0],
        ["Total Disk", d.formatted_bytes || "0 B"],
        ["Contrib Threshold", formatBytes(d.contributor_threshold || 0)]
      ];
      const activity = [
        ["Events", kpi.events || 0],
        ["Users Active", kpi.users || 0],
        ["IPs Active", kpi.ips || 0],
        ["Logins", kpi.logins || 0],
        ["Uploads", kpi.uploads || 0],
        ["Downloads", kpi.downloads || 0],
        ["Denied", kpi.denied || 0],
        ["Admin Actions", kpi.admin_actions || 0],
        ["Session Starts", kpi.session_starts || 0],
        ["Session Ends", kpi.session_ends || 0]
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
      const quickUploadRows = (state.summaryUploads || []).slice(0, 12).map(function(x) {
        return [
          "<code>" + esc(x.time || "") + "</code>",
          ownerCell(x.user_id),
          "<code>" + esc(x.path || "") + "</code>",
          esc(formatBytes(x.delta || 0)),
          sessionCell(x.session)
        ];
      });

      document.getElementById("tab-summary").innerHTML =
        "<div class=\"row\"><span class=\"pill\">Window " + esc(win.label || state.timeRange) + "</span></div>" +
        "<div class=\"grid\">" + entries.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Activity</h3><div class=\"grid\">" + activity.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Top Events</h3>" + renderSimpleTable(["Event", "Count"], topEventsRows) +
        "<h3>Top Users</h3>" + renderSimpleTable(["User", "Events", "Denied"], topUsersRows) +
        "<h3>Top IPs</h3>" + renderSimpleTable(["IP", "Events", "Denied", "Action"], topIPRows) +
        "<h3>Recent Uploads (Quick View)</h3>" + renderSimpleTable(["Time", "User", "Path", "Delta", "Session"], quickUploadRows);
    }

    async function loadUsers() {
      const q = document.getElementById("user-q").value.trim();
      const d = await api("/admin/api/users?q=" + encodeURIComponent(q) + "&limit=1200");
      state.users = d.users || [];
      setTabCount("users", state.users.length);
      renderUsers();
    }
    function renderUsers() {
      const rows = (state.users || []).map(function(u) {
        return {
          sort: {
            hash: u.hash || "",
            last_login: u.last_login || "",
            upload_bytes: Number(u.upload_bytes || 0),
            download_bytes: Number(u.download_bytes || 0),
            banned: u.is_banned ? 1 : 0
          },
          cells: [
            ownerCell(u.hash),
            esc(u.last_login || ""),
            esc(formatBytes(u.upload_bytes || 0)),
            esc(formatBytes(u.download_bytes || 0)),
            "<span class=\"tag " + (u.is_banned ? "bad" : "ok") + "\">" + (u.is_banned ? "BANNED" : "ACTIVE") + "</span>",
            "<button onclick=\"userAction('" + esc(u.hash) + "','ban')\" class=\"btn-danger tiny\">Ban</button> " +
            "<button onclick=\"userAction('" + esc(u.hash) + "','unban')\" class=\"btn-good tiny\">Unban</button> " +
            "<button onclick=\"userAction('" + esc(u.hash) + "','purge')\" class=\"btn-danger tiny\">Purge</button> " +
            "<button onclick=\"openActor('user','" + esc(u.hash) + "')\" class=\"tiny\">Open</button>"
          ]
        };
      });
      document.getElementById("users-out").innerHTML = renderSmartTable(
        "users",
        [
          {label:"User", key:"hash"},
          {label:"Last Login", key:"last_login"},
          {label:"Uploaded", key:"upload_bytes"},
          {label:"Downloaded", key:"download_bytes"},
          {label:"Status", key:"banned"},
          {label:"Actions", key:"hash"}
        ],
        rows,
        "upload_bytes",
        "desc"
      );
    }

    async function loadFiles() {
      const p = document.getElementById("files-path").value.trim() || ".";
      const d = await api("/admin/api/files?path=" + encodeURIComponent(p));
      state.files = { path: d.path || ".", entries: d.entries || [] };
      setTabCount("files", state.files.entries.length);
      document.getElementById("files-path").value = state.files.path;
      renderFiles();
    }
    function renderFiles() {
      const entries = (state.files.entries || []);
      const rows = entries.map(function(e) {
        return {
          sort: {
            name: e.name || "",
            owner: e.owner || "",
            size: Number(e.size || 0),
            is_dir: e.is_dir ? 1 : 0
          },
          cells: [
            e.is_dir ? "<button onclick=\"openPath('" + esc(e.path) + "')\">" + esc(e.name) + "/</button>" : esc(e.name),
            ownerCell(e.owner || "-"),
            esc(e.size_human || formatBytes(e.size || 0)),
            e.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>"
          ]
        };
      });
      document.getElementById("files-out").innerHTML = "<div class=\"muted\">path=<code>" + esc(state.files.path) + "</code></div>" +
        renderSmartTable(
          "files",
          [
            {label:"Name", key:"name"},
            {label:"Owner", key:"owner"},
            {label:"Size", key:"size"},
            {label:"Type", key:"is_dir"}
          ],
          rows,
          "name",
          "asc"
        );
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
      const d = await api(withRange("/admin/api/audit?q=" + encodeURIComponent(q) + "&limit=1000"));
      state.audit = d.events || [];
      setTabCount("audit", state.audit.length);
      renderAudit();
    }
    function renderAudit() {
      const rows = (state.audit || []).map(function(e) {
        return {
          sort: {
            id: Number(e.id || 0),
            time: Number(e.timestamp || 0),
            event: e.event || "",
            user: e.user_id || "",
            ip: e.ip || ""
          },
          cells: [
            "<code>" + esc(e.time || "") + "</code>",
            "<code>" + esc(e.event || "") + "</code>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            "<code>" + esc(e.path || "") + "</code>",
            "<code>" + esc(e.meta || "") + "</code>"
          ]
        };
      });
      document.getElementById("audit-out").innerHTML = renderSmartTable(
        "audit",
        [
          {label:"Time", key:"time"},
          {label:"Event", key:"event"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Session", key:"id"},
          {label:"Path", key:"event"},
          {label:"Meta", key:"id"}
        ],
        rows,
        "time",
        "desc"
      );
    }

    async function loadLogs() {
      const q = document.getElementById("log-q").value.trim();
      const d = await api(withRange("/admin/api/events?q=" + encodeURIComponent(q) + "&limit=1000"));
      state.events = d.events || [];
      state.lastEventID = d.last_id || (state.events.length ? state.events[0].id : 0);
      setTabCount("logs", state.events.length);
      renderLogs();
    }
    function renderLogs() {
      const rows = (state.events || []).map(function(e) {
        const level = String((e.event || "").startsWith("denied") ? "WARN" : (e.event || "")).toUpperCase();
        return {
          sort: {
            id: Number(e.id || 0),
            time: Number(e.timestamp || 0),
            event: e.event || "",
            user: e.user_id || "",
            ip: e.ip || "",
            session: e.session || ""
          },
          cells: [
            "<code>" + esc(e.time || "") + "</code>",
            "<code>" + esc(level) + "</code>",
            "<code>" + esc(e.event || "") + "</code>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            "<code>" + esc(e.path || "") + "</code>",
            "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(e.ip || "") + "')\">Ban IP</button>"
          ]
        };
      });
      document.getElementById("logs-out").innerHTML =
        "<div class=\"row\"><span class=\"pill\">last_event_id=" + esc(state.lastEventID || 0) + "</span></div>" +
        renderSmartTable(
          "logs",
          [
            {label:"Time", key:"time"},
            {label:"Level", key:"event"},
            {label:"Event", key:"event"},
            {label:"User", key:"user"},
            {label:"IP", key:"ip"},
            {label:"Session", key:"session"},
            {label:"Path", key:"event"},
            {label:"Action", key:"id"}
          ],
          rows,
          "time",
          "desc"
        );
    }

    async function streamLogs() {
      if (state.activeTab !== "logs") return;
      const q = document.getElementById("log-q").value.trim();
      const d = await api(withRange("/admin/api/events/stream?since_id=" + encodeURIComponent(state.lastEventID || 0) + "&q=" + encodeURIComponent(q) + "&limit=200"));
      const incoming = d.events || [];
      if (!incoming.length) return;
      state.lastEventID = d.last_id || state.lastEventID;
      state.events = incoming.concat(state.events || []);
      if (state.events.length > 1500) state.events = state.events.slice(0, 1500);
      setTabCount("logs", state.events.length);
      renderLogs();
      toast("+" + incoming.length + " live events");
    }
    function toggleLogLive() {
      clearInterval(state.liveLogTimer);
      state.liveLogTimer = 0;
      const enabled = document.getElementById("logs-live").checked;
      if (enabled) {
        state.liveLogTimer = setInterval(function() {
          streamLogs().catch(function(err) { setStatus("error: " + err.message); });
        }, 2000);
        addHistory("enabled live logs");
      } else {
        addHistory("paused live logs");
      }
    }

    async function loadSessions() {
      const q = document.getElementById("sessions-q").value.trim();
      const d = await api(withRange("/admin/api/sessions?q=" + encodeURIComponent(q) + "&limit=1200"));
      state.sessions = d.sessions || [];
      setTabCount("sessions", state.sessions.length);
      renderSessions();
    }
    function renderSessions() {
      const rows = (state.sessions || []).map(function(s) {
        return {
          sort: {
            session: s.session || "",
            time: Number(s.ended_at || 0),
            user: s.user_id || "",
            ip: s.ip || "",
            events: Number(s.event_count || 0),
            duration: Number(s.duration_sec || 0),
            denied: Number(s.denied_count || 0)
          },
          cells: [
            sessionCell(s.session),
            ownerCell(s.user_id),
            ipCell(s.ip),
            "<code>" + esc(s.start_time || "") + "</code>",
            "<code>" + esc(s.end_time || "") + "</code>",
            esc((s.duration_sec || 0) + "s"),
            esc(s.event_count || 0),
            esc(s.upload_count || 0),
            esc(s.download_count || 0),
            "<span class=\"tag " + ((s.denied_count || 0) > 0 ? "warn" : "ok") + "\">" + esc(s.denied_count || 0) + "</span>",
            "<span class=\"tag " + (s.has_end ? "ok" : "warn") + "\">" + (s.has_end ? "CLOSED" : "OPEN") + "</span>"
          ]
        };
      });
      document.getElementById("sessions-out").innerHTML = renderSmartTable(
        "sessions",
        [
          {label:"Session", key:"session"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Start", key:"time"},
          {label:"End", key:"time"},
          {label:"Duration", key:"duration"},
          {label:"Events", key:"events"},
          {label:"Uploads", key:"events"},
          {label:"Downloads", key:"events"},
          {label:"Denied", key:"denied"},
          {label:"State", key:"session"}
        ],
        rows,
        "time",
        "desc"
      );
    }

    async function openSessionTimeline(sessionID) {
      if (!sessionID) return;
      const d = await api("/admin/api/sessions/" + encodeURIComponent(sessionID) + "?limit=700");
      state.sessionTimeline = d || null;
      renderSessionTimeline();
      document.getElementById("session-timeline").classList.remove("hidden");
    }
    function renderSessionTimeline() {
      if (!state.sessionTimeline) return;
      const d = state.sessionTimeline;
      const events = d.events || [];
      const rows = events.map(function(e) {
        return [
          "<code>" + esc(e.time || "") + "</code>",
          "<code>" + esc(e.event || "") + "</code>",
          "<code>" + esc(e.path || "") + "</code>",
          "<code>" + esc(e.meta || "") + "</code>"
        ];
      });
      document.getElementById("session-out").innerHTML =
        "<div class=\"row\"><h3>Session Timeline</h3><button class=\"tiny\" onclick=\"closeSessionTimeline()\">Close</button></div>" +
        "<div class=\"muted\">session=<code>" + esc(d.session || "") + "</code> user=" + ownerCell(d.user_id) + " ip=" + ipCell(d.ip) + " start=<code>" + esc(d.start_time || "") + "</code> end=<code>" + esc(d.end_time || "") + "</code></div>" +
        renderSimpleTable(["Time", "Event", "Path", "Meta"], rows);
    }

    async function loadUploads() {
      const q = document.getElementById("uploads-q").value.trim();
      const d = await api(withRange("/admin/api/uploads/recent?q=" + encodeURIComponent(q) + "&limit=1200"));
      state.uploads = d.uploads || [];
      setTabCount("uploads", state.uploads.length);
      renderUploads();
    }
    function renderUploads() {
      const rows = (state.uploads || []).map(function(u) {
        return {
          sort: {
            id: Number(u.id || 0),
            time: Number(u.timestamp || 0),
            user: u.user_id || "",
            ip: u.ip || "",
            delta: Number(u.delta || 0),
            size: Number(u.size || 0),
            path: u.path || ""
          },
          cells: [
            "<code>" + esc(u.time || "") + "</code>",
            ownerCell(u.user_id),
            ipCell(u.ip),
            "<code>" + esc(u.path || "") + "</code>",
            esc(formatBytes(u.delta || 0)),
            esc(formatBytes(u.size || 0)),
            sessionCell(u.session)
          ]
        };
      });
      document.getElementById("uploads-out").innerHTML = renderSmartTable(
        "uploads",
        [
          {label:"Time", key:"time"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Path", key:"path"},
          {label:"Delta", key:"delta"},
          {label:"Size", key:"size"},
          {label:"Session", key:"id"}
        ],
        rows,
        "time",
        "desc"
      );
    }

    async function loadBanned() {
      const d = await api("/admin/api/banned");
      state.banned = { hashes: d.hashes || [], ips: d.ips || [] };
      setTabCount("banned", state.banned.hashes.length + state.banned.ips.length);
      renderBanned();
    }
    function renderBanned() {
      const hashRows = (state.banned.hashes || []).map(function(x) {
        return [ownerCell(x.hash), esc(x.banned_at || ""), "<button class=\"btn-good tiny\" onclick=\"userAction('" + esc(x.hash) + "','unban')\">Unban</button>"];
      });
      const ipRows = (state.banned.ips || []).map(function(x) {
        return [ipCell(x.ip), esc(x.banned_at || ""), "<button class=\"btn-good tiny\" onclick=\"unbanIP('" + esc(x.ip) + "')\">Unban</button>"];
      });
      document.getElementById("banned-out").innerHTML =
        "<h3>Pubkey bans</h3>" + renderSimpleTable(["Hash", "Banned At", "Action"], hashRows) +
        "<h3>IP bans</h3>" + renderSimpleTable(["IP", "Banned At", "Action"], ipRows);
    }

    async function openActor(type, value) {
      if (!value) return;
      const d = await api(withRange("/admin/api/actor?type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value)));
      state.actor = d || null;
      renderActorDrawer();
      document.getElementById("actor-drawer").classList.remove("hidden");
    }
    function renderActorDrawer() {
      if (!state.actor) return;
      const d = state.actor;
      const s = d.summary || {};
      const stats = s.user_stats || {};
      const isUser = d.actor_type === "user";

      const uploadRows = (d.recent_uploads || []).slice(0, 20).map(function(u) {
        return ["<code>" + esc(u.time || "") + "</code>", "<code>" + esc(u.path || "") + "</code>", esc(formatBytes(u.delta || 0)), sessionCell(u.session)];
      });
      const sessionRows = (d.sessions || []).slice(0, 20).map(function(x) {
        return [sessionCell(x.session), esc((x.event_count || 0)), esc((x.duration_sec || 0) + "s"), esc(x.denied_count || 0)];
      });
      const eventRows = (d.events || []).slice(0, 30).map(function(e) {
        return ["<code>" + esc(e.time || "") + "</code>", "<code>" + esc(e.event || "") + "</code>", "<code>" + esc(e.path || "") + "</code>", sessionCell(e.session)];
      });

      const actionButtons = isUser ?
        "<button class=\"btn-danger tiny\" onclick=\"userAction('" + esc(d.actor) + "','ban')\">Ban</button> " +
        "<button class=\"btn-good tiny\" onclick=\"userAction('" + esc(d.actor) + "','unban')\">Unban</button> " +
        "<button class=\"btn-danger tiny\" onclick=\"userAction('" + esc(d.actor) + "','purge')\">Purge</button>"
        :
        "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(d.actor) + "')\">Ban IP</button> " +
        "<button class=\"btn-good tiny\" onclick=\"unbanIP('" + esc(d.actor) + "')\">Unban IP</button>";

      document.getElementById("actor-out").innerHTML =
        "<div class=\"row\"><h3>Actor Drawer</h3><button class=\"tiny\" onclick=\"closeActorDrawer()\">Close</button></div>" +
        "<div class=\"row\"><span class=\"pill\">" + esc(d.actor_type || "") + "</span><b><code>" + esc(d.actor || "") + "</code></b>" +
          "<span class=\"tag " + (s.is_banned ? "bad" : "ok") + "\">" + (s.is_banned ? "BANNED" : "ACTIVE") + "</span>" +
          actionButtons +
        "</div>" +
        (isUser ? "<div class=\"muted\">upload_count=" + esc(stats.upload_count || 0) + " upload_bytes=" + esc(formatBytes(stats.upload_bytes || 0)) +
          " download_count=" + esc(stats.download_count || 0) + " download_bytes=" + esc(formatBytes(stats.download_bytes || 0)) +
          " last_login=<code>" + esc(stats.last_login || "") + "</code></div>" : "") +
        "<h3>Recent Uploads</h3>" + renderSimpleTable(["Time", "Path", "Delta", "Session"], uploadRows) +
        "<h3>Sessions</h3>" + renderSimpleTable(["Session", "Events", "Duration", "Denied"], sessionRows) +
        "<h3>Recent Events</h3>" + renderSimpleTable(["Time", "Event", "Path", "Session"], eventRows);
    }

    async function userAction(hash, action) {
      if (!hash || hash === "system") return;
      if (action === "purge" && !confirm("Purge " + hash + "? This deletes files and metadata.")) return;
      await api("/admin/api/users/" + encodeURIComponent(hash) + "/" + action, { method: "POST" });
      toast((action + " " + hash).toUpperCase());
      addHistory(action + " owner " + hash);
      await Promise.all([loadUsers(), loadBanned(), loadAudit(), loadSessions(), loadUploads()]);
      if (state.actor && state.actor.actor_type === "user" && state.actor.actor === hash) {
        await openActor("user", hash);
      }
    }

    async function banIP() {
      const ip = document.getElementById("ban-ip").value.trim();
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: ip }) });
      document.getElementById("ban-ip").value = "";
      toast("BANNED IP " + ip);
      addHistory("banned ip " + ip);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
    }
    async function banIPDirect(ip) {
      const value = String(ip || "").trim();
      if (!value) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: value }) });
      toast("BANNED IP " + value);
      addHistory("banned ip " + value);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
      if (state.actor && state.actor.actor_type === "ip" && state.actor.actor === value) {
        await openActor("ip", value);
      }
    }
    async function unbanIP(ip) {
      await api("/admin/api/banned/ip/" + encodeURIComponent(ip), { method: "DELETE" });
      toast("UNBANNED IP " + ip);
      addHistory("unbanned ip " + ip);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
      if (state.actor && state.actor.actor_type === "ip" && state.actor.actor === ip) {
        await openActor("ip", ip);
      }
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
    function quickOpenOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      openActor("user", hash).catch(function(err) { setStatus("error: " + err.message); });
    }
    async function quickBanIP() {
      const ip = document.getElementById("quick-ip").value.trim();
      if (!ip) return;
      await banIPDirect(ip);
      document.getElementById("quick-ip").value = "";
    }
    function quickOpenIP() {
      const ip = document.getElementById("quick-ip").value.trim();
      if (!ip) return;
      openActor("ip", ip).catch(function(err) { setStatus("error: " + err.message); });
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
      const lines = ["id,time,event,user_id,ip,session,path,meta"];
      (state.audit || []).forEach(function(e) {
        lines.push([
          csvEscape(e.id), csvEscape(e.time), csvEscape(e.event), csvEscape(e.user_id), csvEscape(e.ip),
          csvEscape(e.session), csvEscape(e.path), csvEscape(e.meta)
        ].join(","));
      });
      download("sftpguy-audit.csv", lines.join("\n"));
      addHistory("exported audit csv");
      toast("Exported audit CSV");
    }

    function changeRange() {
      state.timeRange = document.getElementById("time-range").value;
      localStorage.setItem("sftpguy_admin_range", state.timeRange);
      Object.keys(state.table).forEach(function(k) { state.table[k].page = 1; });
      addHistory("changed range to " + state.timeRange);
      refreshAll();
    }
    function changePageSize() {
      state.pageSize = Number(document.getElementById("table-page-size").value || "50");
      localStorage.setItem("sftpguy_admin_page_size", String(state.pageSize));
      Object.keys(state.table).forEach(function(k) { state.table[k].page = 1; });
      addHistory("changed rows/page to " + state.pageSize);
      rerenderCurrent();
    }

    function rerenderCurrent() {
      if (state.activeTab === "summary") renderSummary();
      if (state.activeTab === "users") renderUsers();
      if (state.activeTab === "files") renderFiles();
      if (state.activeTab === "audit") renderAudit();
      if (state.activeTab === "logs") renderLogs();
      if (state.activeTab === "sessions") renderSessions();
      if (state.activeTab === "uploads") renderUploads();
      if (state.activeTab === "banned") renderBanned();
      renderActorDrawer();
      renderSessionTimeline();
    }

    async function refreshAll() {
      try {
        await Promise.all([loadSummary(), loadUsers(), loadFiles(), loadAudit(), loadLogs(), loadSessions(), loadUploads(), loadBanned()]);
        if (state.actor) {
          await openActor(state.actor.actor_type, state.actor.actor);
        }
        if (state.sessionTimeline && state.sessionTimeline.session) {
          await openSessionTimeline(state.sessionTimeline.session);
        }
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
            state.activeTab === "logs" ? loadLogs :
            state.activeTab === "sessions" ? loadSessions :
            state.activeTab === "uploads" ? loadUploads : loadBanned;
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
      ["summary","users","files","audit","logs","sessions","uploads","banned"].forEach(function(p) {
        document.getElementById("tab-" + p).classList.toggle("hidden", p !== name);
      });
      const fn = name === "summary" ? loadSummary :
        name === "users" ? loadUsers :
        name === "files" ? loadFiles :
        name === "audit" ? loadAudit :
        name === "logs" ? loadLogs :
        name === "sessions" ? loadSessions :
        name === "uploads" ? loadUploads : loadBanned;
      fn().catch(function(err) { setStatus("error: " + err.message); });
    }

    document.getElementById("tabs").addEventListener("click", function(e) {
      const tab = e.target.closest(".tab");
      if (tab) switchTab(tab.dataset.tab);
    });

    window.addEventListener("keydown", function(e) {
      if (e.altKey && ["1","2","3","4","5","6","7","8"].includes(e.key)) {
        const map = {"1":"summary","2":"users","3":"files","4":"audit","5":"logs","6":"sessions","7":"uploads","8":"banned"};
        switchTab(map[e.key]);
      }
      if (e.key === "Escape") {
        closeActorDrawer();
        closeSessionTimeline();
      }
      if (e.shiftKey && e.key.toLowerCase() === "r") {
        refreshAll();
      }
      if (e.shiftKey && e.key.toLowerCase() === "l") {
        const cb = document.getElementById("logs-live");
        cb.checked = !cb.checked;
        toggleLogLive();
      }
    });

    (async function boot() {
      document.getElementById("time-range").value = state.timeRange;
      document.getElementById("table-page-size").value = String(state.pageSize);
      try {
        await refreshAll();
      } catch (err) {
        setStatus("error: " + err.message);
      }
    })();
  </script>
</body>
</html>`
