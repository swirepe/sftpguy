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
	mux.HandleFunc("/admin/api/system-log", s.adminAuth(s.handleAdminSystemLog))
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
		writeJSON(w, http.StatusOK, map[string]any{
			"hash":      hash,
			"is_banned": s.store.IsBanned(hash),
			"stats":     stats,
			"files":     files,
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
      --bg: #0b1016;
      --panel: rgba(15, 24, 34, 0.92);
      --line: #2a3e56;
      --text: #dce6f3;
      --dim: #8fa4bc;
      --good: #56d897;
      --warn: #ffbf52;
      --bad: #ff6e79;
      --accent: #5ec7ff;
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
    .shell { max-width: 1200px; margin: 0 auto; display: grid; gap: 12px; }
    .card { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 12px; backdrop-filter: blur(4px); }
    h1 { margin: 0 0 8px; font-size: 18px; letter-spacing: .08em; text-transform: uppercase; }
    .muted { color: var(--dim); font-size: 12px; }
    .tabs { display: flex; flex-wrap: wrap; gap: 8px; }
    .tab { border: 1px solid var(--line); background: transparent; color: var(--dim); border-radius: 8px; padding: 6px 10px; cursor: pointer; }
    .tab.active { color: var(--text); border-color: var(--accent); box-shadow: inset 0 0 0 1px rgba(94,199,255,.25); }
    .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 8px; }
    input, button {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0f1722;
      color: var(--text);
      padding: 8px 10px;
      font: inherit;
    }
    button { cursor: pointer; }
    button:hover { border-color: var(--accent); }
    .btn-danger { border-color: rgba(255,110,121,.4); color: #ffd0d5; }
    .btn-good { border-color: rgba(86,216,151,.5); color: #cbffe4; }
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
    pre { margin: 0; white-space: pre-wrap; font-size: 12px; line-height: 1.4; color: var(--text); }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1>sftpguy web admin console</h1>
      <div class="muted" id="status">loading...</div>
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

  <script>
    const state = { token: localStorage.getItem("sftpguy_admin_token") || "" };

    function setStatus(msg) { document.getElementById("status").textContent = msg; }
    function esc(s) {
      return String(s ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
    }

    async function api(path, opts = {}) {
      const headers = Object.assign({"Accept": "application/json"}, opts.headers || {});
      if (state.token) headers["Authorization"] = "Bearer " + state.token;
      if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const res = await fetch(path, Object.assign({}, opts, { headers }));
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
	      const h = headers.map(x => "<th>" + esc(x) + "</th>").join("");
	      const b = rows.map(cols => "<tr>" + cols.map(c => "<td>" + c + "</td>").join("") + "</tr>").join("");
	      return "<table><thead><tr>" + h + "</tr></thead><tbody>" + b + "</tbody></table>";
	    }

    async function loadSummary() {
      const d = await api("/admin/api/summary");
	      setStatus("archive=" + d.archive + " version=" + d.version + " ssh=:" + d.ssh_port + " admin=" + d.admin_http);
      const entries = [
        ["Users", d.users],
        ["Contributors", d.contributors],
        ["Files", d.files],
        ["Directories", d.directories],
        ["Total Disk", d.formatted_bytes],
        ["Contrib Threshold", d.contributor_threshold + " bytes"]
      ];
	      document.getElementById("tab-summary").innerHTML = "<div class=\"grid\">" +
	        entries.map(([k,v]) => "<div class=\"metric\"><div class=\"k\">" + esc(k) + "</div><div class=\"v\">" + esc(v) + "</div></div>").join("") +
	        "</div>";
	    }

    async function loadUsers() {
      const q = document.getElementById("user-q").value.trim();
	      const d = await api("/admin/api/users?q=" + encodeURIComponent(q) + "&limit=300");
	      const rows = d.users.map(u => [
	        "<code>" + esc(u.hash) + "</code>",
	        esc(u.last_login || ""),
	        esc((u.upload_bytes || 0) + " bytes"),
	        esc((u.download_bytes || 0) + " bytes"),
	        "<span class=\"tag " + (u.is_banned ? "bad" : "ok") + "\">" + (u.is_banned ? "BANNED" : "ACTIVE") + "</span>",
	        "<button onclick=\"userAction('" + u.hash + "','ban')\" class=\"btn-danger\">Ban</button>" +
	         " <button onclick=\"userAction('" + u.hash + "','unban')\" class=\"btn-good\">Unban</button>" +
	         " <button onclick=\"userAction('" + u.hash + "','purge')\" class=\"btn-danger\">Purge</button>" +
	         " <button onclick=\"inspectUser('" + u.hash + "')\">Inspect</button>"
	      ]);
      document.getElementById("users-out").innerHTML = renderTable(
        ["User", "Last Login", "Uploaded", "Downloaded", "Status", "Actions"],
        rows
      );
    }

    async function inspectUser(hash) {
	      const d = await api("/admin/api/users/" + encodeURIComponent(hash));
	      const files = (d.files || []).slice(0, 50).map(x => "<li><code>" + esc(x) + "</code></li>").join("");
	      alert("User " + hash + "\n\nUploads: " + d.stats.upload_bytes + " bytes\nDownloads: " + d.stats.download_bytes + " bytes\nOwned files: " + d.files.length + "\n\nTop paths:\n" + (d.files || []).slice(0, 10).join("\n"));
	      if (files) {
	        document.getElementById("users-out").insertAdjacentHTML("beforeend",
	          "<div style=\"margin-top:8px\"><b>Owned paths for " + esc(hash) + ":</b><ul>" + files + "</ul></div>");
	      }
	    }

    async function userAction(hash, action) {
	      if (action === "purge" && !confirm("Purge " + hash + "? This deletes their files and metadata.")) return;
	      await api("/admin/api/users/" + encodeURIComponent(hash) + "/" + action, { method: "POST" });
      await Promise.all([loadUsers(), loadBanned(), loadAudit()]);
    }

    async function loadFiles() {
      const p = document.getElementById("files-path").value.trim() || ".";
	      const d = await api("/admin/api/files?path=" + encodeURIComponent(p));
	      document.getElementById("files-path").value = d.path;
	      const rows = d.entries.map(e => [
	        e.is_dir ? "<button onclick=\"openPath('" + esc(e.path) + "')\">" + esc(e.name) + "/</button>" : esc(e.name),
	        "<code>" + esc(e.owner || "-") + "</code>",
	        esc(e.size_human)
	      ]);
      document.getElementById("files-out").innerHTML = renderTable(["Name", "Owner", "Size"], rows);
    }

    function openPath(path) {
      document.getElementById("files-path").value = path;
      loadFiles();
    }

    async function loadAudit() {
      const q = document.getElementById("audit-q").value.trim();
	      const d = await api("/admin/api/audit?q=" + encodeURIComponent(q) + "&limit=150");
	      const rows = d.events.map(e => [
	        esc(e.time),
	        esc(e.event),
	        "<code>" + esc(e.user_id) + "</code>",
	        "<code>" + esc(e.ip) + "</code>",
	        esc(e.path || ""),
	        "<code>" + esc(e.meta || "") + "</code>"
	      ]);
      document.getElementById("audit-out").innerHTML = renderTable(["Time", "Event", "User", "IP", "Path", "Meta"], rows);
    }

    async function loadLogs() {
      const q = document.getElementById("log-q").value.trim();
	      const d = await api("/admin/api/system-log?q=" + encodeURIComponent(q) + "&limit=150");
	      document.getElementById("logs-out").innerHTML = "<pre>" + esc((d.lines || []).join("\n")) + "</pre>";
    }

    async function loadBanned() {
      const d = await api("/admin/api/banned");
      const hashRows = (d.hashes || []).map(x => [
	        "<code>" + esc(x.hash) + "</code>",
	        esc(x.banned_at || ""),
	        "<button class=\"btn-good\" onclick=\"userAction('" + x.hash + "','unban')\">Unban</button>"
	      ]);
	      const ipRows = (d.ips || []).map(x => [
	        "<code>" + esc(x.ip) + "</code>",
	        esc(x.banned_at || ""),
	        "<button class=\"btn-good\" onclick=\"unbanIP('" + x.ip + "')\">Unban</button>"
	      ]);
	      document.getElementById("banned-out").innerHTML =
	        "<h3>Pubkey bans</h3>" + renderTable(["Hash", "Banned At", "Action"], hashRows) +
	        "<h3>IP bans</h3>" + renderTable(["IP", "Banned At", "Action"], ipRows);
    }

    async function banIP() {
      const ip = document.getElementById("ban-ip").value.trim();
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip }) });
      document.getElementById("ban-ip").value = "";
      await Promise.all([loadBanned(), loadAudit()]);
    }

    async function unbanIP(ip) {
	      await api("/admin/api/banned/ip/" + encodeURIComponent(ip), { method: "DELETE" });
      await Promise.all([loadBanned(), loadAudit()]);
    }

    function switchTab(name) {
      for (const btn of document.querySelectorAll(".tab")) btn.classList.toggle("active", btn.dataset.tab === name);
      for (const p of ["summary","users","files","audit","logs","banned"]) {
        document.getElementById("tab-" + p).classList.toggle("hidden", p !== name);
      }
      if (name === "summary") loadSummary();
      if (name === "users") loadUsers();
      if (name === "files") loadFiles();
      if (name === "audit") loadAudit();
      if (name === "logs") loadLogs();
      if (name === "banned") loadBanned();
    }

    document.getElementById("tabs").addEventListener("click", (e) => {
      const tab = e.target.closest(".tab");
      if (tab) switchTab(tab.dataset.tab);
    });

    (async function boot() {
      try {
        await loadSummary();
        await Promise.all([loadUsers(), loadFiles(), loadAudit(), loadLogs(), loadBanned()]);
      } catch (err) {
        setStatus("error: " + err.message);
      }
    })();
  </script>
</body>
</html>`
