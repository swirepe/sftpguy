package main

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

func (s *Server) handleAdminFileSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	qRaw := strings.TrimSpace(r.URL.Query().Get("q"))
	if qRaw == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"q":       "",
			"results": []any{},
			"total":   0,
		})
		return
	}
	limit := parseIntQuery(r, "limit", 200, 10, 2000)
	offset := parseIntQuery(r, "offset", 0, 0, 1000000)
	q := "%" + qRaw + "%"

	type resultRow struct {
		Path      string `json:"path"`
		Name      string `json:"name"`
		Owner     string `json:"owner"`
		Size      int64  `json:"size"`
		SizeHuman string `json:"size_human"`
		IsDir     bool   `json:"is_dir"`
	}

	var total int64
	if err := s.store.db.QueryRow(`
		SELECT COUNT(*)
		FROM files
		WHERE path LIKE ? OR owner_hash LIKE ?`, q, q).Scan(&total); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := s.store.db.Query(`
		SELECT path, IFNULL(owner_hash,''), IFNULL(size,0), is_dir
		FROM files
		WHERE path LIKE ? OR owner_hash LIKE ?
		ORDER BY is_dir DESC, size DESC, path ASC
		LIMIT ? OFFSET ?`, q, q, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	results := make([]resultRow, 0, limit)
	for rows.Next() {
		var row resultRow
		var isDir int
		if err := rows.Scan(&row.Path, &row.Owner, &row.Size, &isDir); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.IsDir = isDir == 1
		row.SizeHuman = formatBytes(row.Size)
		row.Name = filepath.Base(row.Path)
		results = append(results, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"q":       qRaw,
		"results": results,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}
