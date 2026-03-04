package main

import (
	"net/http"
)

func (s *Server) handleAdminExplorer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	window := parseTimeWindow(r, "24h")
	since := window.SinceUnix
	sessionLimit := parseIntQuery(r, "sessions_limit", 200, 10, 2000)
	pathLimit := parseIntQuery(r, "paths_limit", 20, 5, 200)
	reasonLimit := parseIntQuery(r, "reasons_limit", 20, 5, 200)
	rateLimitRows := parseIntQuery(r, "rate_limit_rows", 20, 5, 200)

	scalar := func(query string, args ...any) int64 {
		var n int64
		_ = s.store.db.QueryRow(query, args...).Scan(&n)
		return n
	}

	snapshot := s.ExplorerRuntimeSnapshot()
	activity := map[string]any{
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": since,
			"hours":      int(window.Duration.Hours()),
		},
		"events":            scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%'`, since),
		"users":             scalar(`SELECT COUNT(DISTINCT user_id) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND user_id != ''`, since),
		"uploads":           scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'upload'`, since),
		"downloads":         scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'download'`, since),
		"denied":            scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event LIKE 'denied%'`, since),
		"sessions":          scalar(`SELECT COUNT(DISTINCT user_session) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND user_session != ''`, since),
		"rate_limit_hits":   scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'denied/rate-limit'`, since),
		"contributor_locks": scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'denied/contributor-lock'`, since),
	}

	sessions := make([]map[string]any, 0, sessionLimit)
	if rows, err := s.store.db.Query(`
		SELECT
			user_session,
			IFNULL(MAX(NULLIF(user_id, '')), '') AS user_id,
			IFNULL(MAX(NULLIF(ip_address, '')), '') AS ip,
			MIN(timestamp) AS started_at,
			MAX(timestamp) AS ended_at,
			COUNT(*) AS event_count,
			SUM(CASE WHEN event = 'upload' THEN 1 ELSE 0 END) AS uploads,
			SUM(CASE WHEN event = 'download' THEN 1 ELSE 0 END) AS downloads,
			SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied,
			SUM(CASE WHEN event = 'denied/rate-limit' THEN 1 ELSE 0 END) AS rate_limit_hits
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND user_session != ''
		GROUP BY user_session
		ORDER BY ended_at DESC
		LIMIT ?`, since, sessionLimit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var sessionID, userID, ip string
			var startedAt, endedAt int64
			var eventCount, uploads, downloads, denied, rateLimitHits int64
			if err := rows.Scan(
				&sessionID,
				&userID,
				&ip,
				&startedAt,
				&endedAt,
				&eventCount,
				&uploads,
				&downloads,
				&denied,
				&rateLimitHits,
			); err == nil {
				duration := endedAt - startedAt
				if duration < 0 {
					duration = 0
				}
				sessions = append(sessions, map[string]any{
					"session":         sessionID,
					"user_id":         userID,
					"ip":              ip,
					"started_at":      startedAt,
					"start_time":      formatUnix(startedAt),
					"ended_at":        endedAt,
					"end_time":        formatUnix(endedAt),
					"duration_sec":    duration,
					"event_count":     eventCount,
					"uploads":         uploads,
					"downloads":       downloads,
					"denied":          denied,
					"rate_limit_hits": rateLimitHits,
				})
			}
		}
	}

	topPaths := make([]map[string]any, 0, pathLimit)
	if rows, err := s.store.db.Query(`
		SELECT
			path,
			COUNT(*) AS c,
			SUM(CASE WHEN event = 'upload' THEN 1 ELSE 0 END) AS uploads,
			SUM(CASE WHEN event = 'download' THEN 1 ELSE 0 END) AS downloads,
			SUM(CASE WHEN event LIKE 'denied%' THEN 1 ELSE 0 END) AS denied
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND path != ''
		GROUP BY path
		ORDER BY c DESC
		LIMIT ?`, since, pathLimit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var pathName string
			var count, uploads, downloads, denied int64
			if err := rows.Scan(&pathName, &count, &uploads, &downloads, &denied); err == nil {
				topPaths = append(topPaths, map[string]any{
					"path":      pathName,
					"count":     count,
					"uploads":   uploads,
					"downloads": downloads,
					"denied":    denied,
				})
			}
		}
	}

	deniedReasons := make([]map[string]any, 0, reasonLimit)
	if rows, err := s.store.db.Query(`
		SELECT event, COUNT(*) AS c
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND event LIKE 'denied%'
		GROUP BY event
		ORDER BY c DESC
		LIMIT ?`, since, reasonLimit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var event string
			var count int64
			if err := rows.Scan(&event, &count); err == nil {
				deniedReasons = append(deniedReasons, map[string]any{
					"reason": event,
					"count":  count,
				})
			}
		}
	}

	type namedCount struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}
	rateByUser := make([]namedCount, 0, rateLimitRows)
	if rows, err := s.store.db.Query(`
		SELECT IFNULL(user_id, '') AS name, COUNT(*) AS c
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND event = 'denied/rate-limit'
		  AND user_id != ''
		GROUP BY user_id
		ORDER BY c DESC
		LIMIT ?`, since, rateLimitRows); err == nil {
		defer rows.Close()
		for rows.Next() {
			var row namedCount
			if err := rows.Scan(&row.Name, &row.Count); err == nil {
				rateByUser = append(rateByUser, row)
			}
		}
	}
	rateByIP := make([]namedCount, 0, rateLimitRows)
	if rows, err := s.store.db.Query(`
		SELECT IFNULL(ip_address, '') AS name, COUNT(*) AS c
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND event = 'denied/rate-limit'
		  AND ip_address != ''
		GROUP BY ip_address
		ORDER BY c DESC
		LIMIT ?`, since, rateLimitRows); err == nil {
		defer rows.Close()
		for rows.Next() {
			var row namedCount
			if err := rows.Scan(&row.Name, &row.Count); err == nil {
				rateByIP = append(rateByIP, row)
			}
		}
	}
	rateByPath := make([]namedCount, 0, rateLimitRows)
	if rows, err := s.store.db.Query(`
		SELECT IFNULL(path, '') AS name, COUNT(*) AS c
		FROM log
		WHERE timestamp >= ?
		  AND user_session LIKE 'explorer:%'
		  AND event = 'denied/rate-limit'
		  AND path != ''
		GROUP BY path
		ORDER BY c DESC
		LIMIT ?`, since, rateLimitRows); err == nil {
		defer rows.Close()
		for rows.Next() {
			var row namedCount
			if err := rows.Scan(&row.Name, &row.Count); err == nil {
				rateByPath = append(rateByPath, row)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"explorer":       snapshot,
		"activity":       activity,
		"sessions":       sessions,
		"top_paths":      topPaths,
		"denied_reasons": deniedReasons,
		"rate_limit": map[string]any{
			"total":   activity["rate_limit_hits"],
			"by_user": rateByUser,
			"by_ip":   rateByIP,
			"by_path": rateByPath,
		},
	})
}
