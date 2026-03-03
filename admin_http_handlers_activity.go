package main

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

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

func (s *Server) handleAdminAuthAttempts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window := parseTimeWindow(r, "24h")
	limit := parseIntQuery(r, "limit", 500, 10, 3000)
	comboLimit := parseIntQuery(r, "combo_limit", 120, 10, 500)
	qRaw := strings.TrimSpace(r.URL.Query().Get("q"))
	q := "%" + qRaw + "%"

	rows, err := s.store.db.Query(`
		SELECT id, timestamp, IFNULL(ip_address,''), IFNULL(user_id,''), IFNULL(user_session,''), IFNULL(meta,'')
		FROM log
		WHERE event = ?
		  AND timestamp >= ?
		  AND (? = '' OR ip_address LIKE ? OR user_id LIKE ? OR meta LIKE ?)
		ORDER BY id DESC
		LIMIT ?`, string(EventAuthAttempt), window.SinceUnix, qRaw, q, q, q, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type authAttemptRow struct {
		ID          int64  `json:"id"`
		Timestamp   int64  `json:"timestamp"`
		Time        string `json:"time"`
		IP          string `json:"ip"`
		UserID      string `json:"user_id"`
		Session     string `json:"session"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		GeneratedID string `json:"generated_hash"`
	}
	type comboRow struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Count         int64  `json:"count"`
		LastTimestamp int64  `json:"last_timestamp"`
		LastTime      string `json:"last_time"`
		LastIP        string `json:"last_ip"`
	}

	type comboAgg struct {
		Username      string
		Password      string
		Count         int64
		LastTimestamp int64
		LastIP        string
	}

	attempts := make([]authAttemptRow, 0, limit)
	comboByKey := map[string]*comboAgg{}
	for rows.Next() {
		var row authAttemptRow
		var meta string
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.IP, &row.UserID, &row.Session, &meta); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metaObj := parseJSONMap(meta)
		row.Username = stringFromAny(metaObj["username"])
		row.Password = stringFromAny(metaObj["password"])
		row.GeneratedID = stringFromAny(metaObj["generated_hash"])
		row.Time = formatUnix(row.Timestamp)

		key := row.Username + "\x00" + row.Password
		agg := comboByKey[key]
		if agg == nil {
			agg = &comboAgg{
				Username:      row.Username,
				Password:      row.Password,
				Count:         0,
				LastTimestamp: row.Timestamp,
				LastIP:        row.IP,
			}
			comboByKey[key] = agg
		}
		agg.Count++
		if row.Timestamp > agg.LastTimestamp {
			agg.LastTimestamp = row.Timestamp
			agg.LastIP = row.IP
		}
		attempts = append(attempts, row)
	}

	combos := make([]comboRow, 0, len(comboByKey))
	for _, agg := range comboByKey {
		combos = append(combos, comboRow{
			Username:      agg.Username,
			Password:      agg.Password,
			Count:         agg.Count,
			LastTimestamp: agg.LastTimestamp,
			LastTime:      formatUnix(agg.LastTimestamp),
			LastIP:        agg.LastIP,
		})
	}
	sort.Slice(combos, func(i, j int) bool {
		if combos[i].Count == combos[j].Count {
			if combos[i].LastTimestamp == combos[j].LastTimestamp {
				if combos[i].Username == combos[j].Username {
					return combos[i].Password < combos[j].Password
				}
				return combos[i].Username < combos[j].Username
			}
			return combos[i].LastTimestamp > combos[j].LastTimestamp
		}
		return combos[i].Count > combos[j].Count
	})
	if len(combos) > comboLimit {
		combos = combos[:comboLimit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"attempts": attempts,
		"combos":   combos,
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": window.SinceUnix,
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
	beforeID := parseInt64Query(r, "before_id", 0)
	order := "DESC"
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("order")), "asc") {
		order = "ASC"
	}

	query := `
		SELECT id, timestamp, event, IFNULL(user_id, ''), IFNULL(ip_address, ''), IFNULL(path, ''), IFNULL(meta, ''), IFNULL(user_session, '')
		FROM log
		WHERE timestamp >= ?
		  AND (user_id LIKE ? OR event LIKE ? OR path LIKE ? OR meta LIKE ? OR ip_address LIKE ? OR user_session LIKE ?)`
	args := []any{window.SinceUnix, q, q, q, q, q, q}
	if beforeID > 0 {
		query += `
		  AND id < ?`
		args = append(args, beforeID)
	}
	query += `
		ORDER BY id ` + order + `
		LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.store.db.Query(query, args...)
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

	out := make([]eventRow, 0, limit+1)
	var lastID int64
	var oldestID int64
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
		if oldestID == 0 || row.ID < oldestID {
			oldestID = row.ID
		}
		out = append(out, row)
	}
	hasMore := false
	if len(out) > limit {
		hasMore = true
		out = out[:limit]
		oldestID = 0
		for _, row := range out {
			if oldestID == 0 || row.ID < oldestID {
				oldestID = row.ID
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events":           out,
		"last_id":          lastID,
		"has_more":         hasMore,
		"next_before_id":   oldestID,
		"requested_before": beforeID,
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
