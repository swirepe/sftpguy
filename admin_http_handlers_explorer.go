package main

import "net/http"

func (s *Server) handleAdminExplorer(w http.ResponseWriter, r *http.Request) {
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

	snapshot := s.ExplorerRuntimeSnapshot()
	activity := map[string]any{
		"window": map[string]any{
			"label":      window.Label,
			"since_unix": since,
			"hours":      int(window.Duration.Hours()),
		},
		"events":    scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%'`, since),
		"users":     scalar(`SELECT COUNT(DISTINCT user_id) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND user_id != ''`, since),
		"uploads":   scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'upload'`, since),
		"downloads": scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event = 'download'`, since),
		"denied":    scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND user_session LIKE 'explorer:%' AND event LIKE 'denied%'`, since),
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"explorer": snapshot,
		"activity": activity,
	})
}
