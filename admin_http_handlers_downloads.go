package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

func (s *Server) handleAdminDownloads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	window := parseTimeWindow(r, "24h")
	qRaw := strings.TrimSpace(r.URL.Query().Get("q"))
	q := "%" + qRaw + "%"
	selectedPath := ""
	if raw := strings.TrimSpace(r.URL.Query().Get("path")); raw != "" {
		clean, err := cleanRelativePath(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if clean != "." {
			selectedPath = clean
		}
	}
	fileLimit := parseIntQuery(r, "file_limit", 600, 10, 2000)
	downloaderLimit := parseIntQuery(r, "downloader_limit", 250, 10, 1000)
	recentLimit := parseIntQuery(r, "recent_limit", 250, 10, 1000)
	historyLimit := parseIntQuery(r, "download_history_limit", 200, 1, 1000)

	filterArgs := []any{qRaw, q, q, q, q, q}
	rangeFilter := `(? = '' OR user_id LIKE ? OR ip_address LIKE ? OR path LIKE ? OR meta LIKE ? OR user_session LIKE ?)`
	rangeFilterJoined := `(? = '' OR l.user_id LIKE ? OR l.ip_address LIKE ? OR l.path LIKE ? OR l.meta LIKE ? OR l.user_session LIKE ?)`

	scalar := func(query string, args ...any) int64 {
		var n int64
		_ = s.store.db.QueryRow(query, args...).Scan(&n)
		return n
	}

	type downloadSummary struct {
		RangeDownloads      int64 `json:"range_downloads"`
		RangeUniqueFiles    int64 `json:"range_unique_files"`
		RangeUniqueUsers    int64 `json:"range_unique_users"`
		RangeUniqueIPs      int64 `json:"range_unique_ips"`
		FilesEverDownloaded int64 `json:"files_ever_downloaded"`
		AllTimeDownloads    int64 `json:"all_time_downloads"`
	}

	summaryArgs := append([]any{window.SinceUnix}, filterArgs...)
	summary := downloadSummary{
		RangeDownloads: scalar(`
			SELECT COUNT(*) FROM log
			WHERE event = 'download' AND timestamp >= ? AND `+rangeFilter, summaryArgs...),
		RangeUniqueFiles: scalar(`
			SELECT COUNT(DISTINCT path) FROM log
			WHERE event = 'download' AND timestamp >= ? AND path != '' AND `+rangeFilter, summaryArgs...),
		RangeUniqueUsers: scalar(`
			SELECT COUNT(DISTINCT user_id) FROM log
			WHERE event = 'download' AND timestamp >= ? AND user_id != '' AND `+rangeFilter, summaryArgs...),
		RangeUniqueIPs: scalar(`
			SELECT COUNT(DISTINCT ip_address) FROM log
			WHERE event = 'download' AND timestamp >= ? AND ip_address != '' AND `+rangeFilter, summaryArgs...),
		FilesEverDownloaded: scalar(`
			SELECT COUNT(*) FROM files
			WHERE is_dir = 0 AND IFNULL(downloads, 0) > 0`),
		AllTimeDownloads: scalar(`
			SELECT IFNULL(SUM(downloads), 0) FROM files
			WHERE is_dir = 0`),
	}

	type downloadFileRow struct {
		Path               string `json:"path"`
		Name               string `json:"name"`
		Owner              string `json:"owner"`
		Size               int64  `json:"size"`
		SizeHuman          string `json:"size_human"`
		DownloadsTotal     int64  `json:"downloads_total"`
		DownloadsInRange   int64  `json:"downloads_in_range"`
		UniqueUsersInRange int64  `json:"unique_users_in_range"`
		UniqueIPsInRange   int64  `json:"unique_ips_in_range"`
		LastDownloadAt     int64  `json:"last_download_at"`
		LastDownloadTime   string `json:"last_download_time"`
		LastDownloader     string `json:"last_downloader"`
		LastIP             string `json:"last_ip"`
	}

	fileRows, err := s.store.db.Query(`
		WITH recent AS (
			SELECT
				path,
				COUNT(*) AS downloads_in_range,
				COUNT(DISTINCT NULLIF(user_id, '')) AS unique_users_in_range,
				COUNT(DISTINCT NULLIF(ip_address, '')) AS unique_ips_in_range
			FROM log
			WHERE event = 'download' AND timestamp >= ?
			GROUP BY path
		),
		latest AS (
			SELECT path, MAX(id) AS latest_id
			FROM log
			WHERE event = 'download' AND path != ''
			GROUP BY path
		)
		SELECT
			f.path,
			IFNULL(f.owner_hash, ''),
			IFNULL(f.size, 0),
			IFNULL(f.downloads, 0),
			IFNULL(r.downloads_in_range, 0),
			IFNULL(r.unique_users_in_range, 0),
			IFNULL(r.unique_ips_in_range, 0),
			IFNULL(l.timestamp, 0),
			IFNULL(l.user_id, ''),
			IFNULL(l.ip_address, '')
		FROM files f
		LEFT JOIN recent r ON r.path = f.path
		LEFT JOIN latest latest_download ON latest_download.path = f.path
		LEFT JOIN log l ON l.id = latest_download.latest_id
		WHERE f.is_dir = 0
		  AND IFNULL(f.downloads, 0) > 0
		  AND (? = '' OR f.path LIKE ? OR IFNULL(f.owner_hash, '') LIKE ? OR IFNULL(l.user_id, '') LIKE ? OR IFNULL(l.ip_address, '') LIKE ?)
		ORDER BY IFNULL(f.downloads, 0) DESC, f.path ASC
		LIMIT ?`, window.SinceUnix, qRaw, q, q, q, q, fileLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer fileRows.Close()

	files := make([]downloadFileRow, 0, fileLimit)
	for fileRows.Next() {
		var row downloadFileRow
		if err := fileRows.Scan(
			&row.Path,
			&row.Owner,
			&row.Size,
			&row.DownloadsTotal,
			&row.DownloadsInRange,
			&row.UniqueUsersInRange,
			&row.UniqueIPsInRange,
			&row.LastDownloadAt,
			&row.LastDownloader,
			&row.LastIP,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.Name = filepath.Base(row.Path)
		row.SizeHuman = formatBytes(row.Size)
		row.LastDownloadTime = formatUnix(row.LastDownloadAt)
		files = append(files, row)
	}

	type downloaderRow struct {
		UserID         string `json:"user_id"`
		DownloadCount  int64  `json:"download_count"`
		UniqueFiles    int64  `json:"unique_files"`
		UniqueIPs      int64  `json:"unique_ips"`
		LastDownloadAt int64  `json:"last_download_at"`
		LastDownload   string `json:"last_download"`
		LastIP         string `json:"last_ip"`
	}

	downloaderArgs := append([]any{window.SinceUnix}, filterArgs...)
	downloaderArgs = append(downloaderArgs, window.SinceUnix)
	downloaderArgs = append(downloaderArgs, filterArgs...)
	downloaderArgs = append(downloaderArgs, downloaderLimit)
	downloaderRows, err := s.store.db.Query(`
		WITH latest_user AS (
			SELECT user_id, MAX(id) AS latest_id
			FROM log
			WHERE event = 'download'
			  AND timestamp >= ?
			  AND user_id != ''
			  AND `+rangeFilter+`
			GROUP BY user_id
		)
		SELECT
			l.user_id,
			COUNT(*) AS download_count,
			COUNT(DISTINCT NULLIF(l.path, '')) AS unique_files,
			COUNT(DISTINCT NULLIF(l.ip_address, '')) AS unique_ips,
			MAX(l.timestamp) AS last_download_at,
			IFNULL(last_log.ip_address, '') AS last_ip
		FROM log l
		JOIN latest_user lu ON lu.user_id = l.user_id
		JOIN log last_log ON last_log.id = lu.latest_id
		WHERE l.event = 'download'
		  AND l.timestamp >= ?
		  AND l.user_id != ''
		  AND `+rangeFilterJoined+`
		GROUP BY l.user_id, last_log.ip_address
		ORDER BY download_count DESC, last_download_at DESC, l.user_id ASC
		LIMIT ?`, downloaderArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer downloaderRows.Close()

	downloaders := make([]downloaderRow, 0, downloaderLimit)
	for downloaderRows.Next() {
		var row downloaderRow
		if err := downloaderRows.Scan(
			&row.UserID,
			&row.DownloadCount,
			&row.UniqueFiles,
			&row.UniqueIPs,
			&row.LastDownloadAt,
			&row.LastIP,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row.LastDownload = formatUnix(row.LastDownloadAt)
		downloaders = append(downloaders, row)
	}

	type recentDownloadRow struct {
		ID             int64  `json:"id"`
		Timestamp      int64  `json:"timestamp"`
		Time           string `json:"time"`
		UserID         string `json:"user_id"`
		IP             string `json:"ip"`
		Path           string `json:"path"`
		Size           int64  `json:"size"`
		DurationMS     float64 `json:"duration_ms"`
		AvgBytesPerSec int64  `json:"avg_bytes_per_sec"`
		Session        string `json:"session"`
	}

	recentArgs := append([]any{window.SinceUnix}, filterArgs...)
	recentArgs = append(recentArgs, recentLimit)
	recentRows, err := s.store.db.Query(`
		SELECT
			id,
			timestamp,
			IFNULL(user_id, ''),
			IFNULL(ip_address, ''),
			IFNULL(path, ''),
			IFNULL(meta, ''),
			IFNULL(user_session, '')
		FROM log
		WHERE event = 'download'
		  AND timestamp >= ?
		  AND `+rangeFilter+`
		ORDER BY id DESC
		LIMIT ?`, recentArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer recentRows.Close()

	recent := make([]recentDownloadRow, 0, recentLimit)
	for recentRows.Next() {
		var row recentDownloadRow
		var meta string
		if err := recentRows.Scan(
			&row.ID,
			&row.Timestamp,
			&row.UserID,
			&row.IP,
			&row.Path,
			&meta,
			&row.Session,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metaObj := parseJSONMap(meta)
		row.Size = int64FromAny(metaObj["size"])
		row.DurationMS = float64FromAny(metaObj["duration_ms"])
		row.AvgBytesPerSec = int64FromAny(metaObj["avg_bytes_per_sec"])
		row.Time = formatUnix(row.Timestamp)
		recent = append(recent, row)
	}

	var selectedFile *downloadFileRow
	selectedHistory := []recentDownloadRow(nil)
	if selectedPath != "" {
		row := downloadFileRow{
			Path: selectedPath,
			Name: filepath.Base(selectedPath),
		}

		_ = s.store.db.QueryRow(`
			SELECT IFNULL(owner_hash, ''), IFNULL(size, 0)
			FROM files
			WHERE path = ?`, selectedPath).Scan(&row.Owner, &row.Size)

		row.DownloadsTotal = scalar(`
			SELECT COUNT(*) FROM log
			WHERE event = 'download' AND path = ?`, selectedPath)
		row.DownloadsInRange = scalar(`
			SELECT COUNT(*) FROM log
			WHERE event = 'download' AND path = ? AND timestamp >= ?`, selectedPath, window.SinceUnix)
		row.UniqueUsersInRange = scalar(`
			SELECT COUNT(DISTINCT NULLIF(user_id, '')) FROM log
			WHERE event = 'download' AND path = ? AND timestamp >= ?`, selectedPath, window.SinceUnix)
		row.UniqueIPsInRange = scalar(`
			SELECT COUNT(DISTINCT NULLIF(ip_address, '')) FROM log
			WHERE event = 'download' AND path = ? AND timestamp >= ?`, selectedPath, window.SinceUnix)
		_ = s.store.db.QueryRow(`
			SELECT IFNULL(timestamp, 0), IFNULL(user_id, ''), IFNULL(ip_address, '')
			FROM log
			WHERE event = 'download' AND path = ?
			ORDER BY id DESC
			LIMIT 1`, selectedPath).Scan(&row.LastDownloadAt, &row.LastDownloader, &row.LastIP)

		row.SizeHuman = formatBytes(row.Size)
		row.LastDownloadTime = formatUnix(row.LastDownloadAt)
		selectedFile = &row

		selectedRows, err := s.store.db.Query(`
			SELECT
				id,
				timestamp,
				IFNULL(user_id, ''),
				IFNULL(ip_address, ''),
				IFNULL(path, ''),
				IFNULL(meta, ''),
				IFNULL(user_session, '')
			FROM log
			WHERE event = 'download'
			  AND path = ?
			  AND timestamp >= ?
			ORDER BY id DESC
			LIMIT ?`, selectedPath, window.SinceUnix, historyLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer selectedRows.Close()

		selectedHistory = make([]recentDownloadRow, 0, historyLimit)
		for selectedRows.Next() {
			var row recentDownloadRow
			var meta string
			if err := selectedRows.Scan(
				&row.ID,
				&row.Timestamp,
				&row.UserID,
				&row.IP,
				&row.Path,
				&meta,
				&row.Session,
			); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			metaObj := parseJSONMap(meta)
			row.Size = int64FromAny(metaObj["size"])
			row.DurationMS = float64FromAny(metaObj["duration_ms"])
			row.AvgBytesPerSec = int64FromAny(metaObj["avg_bytes_per_sec"])
			row.Time = formatUnix(row.Timestamp)
			selectedHistory = append(selectedHistory, row)
		}
		if err := selectedRows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"q":                qRaw,
		"summary":          summary,
		"files":            files,
		"downloaders":      downloaders,
		"recent":           recent,
		"selected_path":    selectedPath,
		"selected_file":    selectedFile,
		"selected_history": selectedHistory,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
		},
	})
}
