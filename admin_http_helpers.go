package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	case "all":
		dur = 0
	default:
		dur = 24 * time.Hour
		label = "24h"
	}

	sinceUnix := time.Now().Add(-dur).Unix()
	if label == "all" {
		sinceUnix = 0
	}

	return adminTimeWindow{
		Label:     label,
		Duration:  dur,
		SinceUnix: sinceUnix,
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

func stringFromAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case fmt.Stringer:
		return x.String()
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func formatUnix(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

var kvPattern = regexp.MustCompile(`([A-Za-z0-9_.-]+)=("([^"\\]|\\.)*"|[^\s]+)`)

type parsedSystemLogEntry struct {
	Raw       string `json:"raw"`
	Time      string `json:"time"`
	Level     string `json:"level"`
	Msg       string `json:"msg"`
	UserID    string `json:"user_id"`
	IP        string `json:"ip"`
	Component string `json:"component"`
	Panic     string `json:"panic"`
	Stack     string `json:"stack"`
	IsPanic   bool   `json:"is_panic"`
}

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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func isPanicSystemLog(fields map[string]string, line string) bool {
	msg := strings.ToLower(strings.TrimSpace(fields["msg"]))
	panicValue := strings.TrimSpace(fields["panic"])
	lowerLine := strings.ToLower(line)

	if panicValue != "" {
		return true
	}
	if strings.Contains(msg, "panic") || strings.Contains(msg, "fatal error") {
		return true
	}
	if strings.Contains(lowerLine, "panic recovered; re-panicking") {
		return true
	}
	if strings.Contains(lowerLine, "panic:") || strings.Contains(lowerLine, "fatal error:") {
		return true
	}
	return false
}

func parseSystemLogEntry(line string) parsedSystemLogEntry {
	fields := parseLogKV(line)
	return parsedSystemLogEntry{
		Raw:       line,
		Time:      fields["time"],
		Level:     strings.ToUpper(fields["level"]),
		Msg:       fields["msg"],
		UserID:    pickLogUser(fields),
		IP:        pickLogIP(fields),
		Component: firstNonEmpty(fields["component"], fields["scope"], fields["source"]),
		Panic:     fields["panic"],
		Stack:     fields["stack"],
		IsPanic:   isPanicSystemLog(fields, line),
	}
}

func readParsedSystemLog(filename string, limit int, filter string, panicOnly bool) ([]parsedSystemLogEntry, map[string]int, int, int, error) {
	if limit < 1 {
		limit = 1
	}
	scanLimit := limit
	if panicOnly {
		if scanLimit < limit*12 {
			scanLimit = limit * 12
		}
		if scanLimit < 300 {
			scanLimit = 300
		}
		if scanLimit > 5000 {
			scanLimit = 5000
		}
	}

	lines, err := tailFile(filename, scanLimit, filter)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	out := make([]parsedSystemLogEntry, 0, min(limit, len(lines)))
	levelCount := map[string]int{}
	panicCount := 0
	for _, line := range lines {
		entry := parseSystemLogEntry(line)
		if entry.Level != "" {
			levelCount[entry.Level]++
		}
		if entry.IsPanic {
			panicCount++
		}
		if panicOnly && !entry.IsPanic {
			continue
		}
		if len(out) >= limit {
			continue
		}
		out = append(out, entry)
	}

	return out, levelCount, len(lines), panicCount, nil
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

type adminUserStats struct {
	LastLogin     string `json:"last_login"`
	LastAddress   string `json:"last_address"`
	Seen          int64  `json:"seen"`
	UploadCount   int64  `json:"upload_count"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadCount int64  `json:"download_count"`
	DownloadBytes int64  `json:"download_bytes"`
	FirstTimer    bool   `json:"first_timer"`
	IsBanned      bool   `json:"is_banned"`
}

func adminUserStatsPayload(stats userStats) adminUserStats {
	return adminUserStats{
		LastLogin:     stats.LastLogin,
		LastAddress:   stats.LastAddress,
		Seen:          stats.Seen,
		UploadCount:   stats.UploadCount,
		UploadBytes:   stats.UploadBytes,
		DownloadCount: stats.DownloadCount,
		DownloadBytes: stats.DownloadBytes,
		FirstTimer:    stats.FirstTimer,
		IsBanned:      stats.IsBanned,
	}
}

var (
	errAdminLookupNotFound  = errors.New("identifier not found")
	errAdminLookupAmbiguous = errors.New("identifier is ambiguous")
)

func normalizeAdminLookupToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.ReplaceAll(token, "…", "")
	token = strings.ReplaceAll(token, "..", "")
	return strings.TrimSpace(token)
}

func resolveAdminUserHash(db *sql.DB, token string) (string, error) {
	token = normalizeAdminLookupToken(token)
	if token == "" {
		return "", errAdminLookupNotFound
	}
	if token == systemOwner {
		return token, nil
	}

	// Exact match across known user-id sources.
	var exact string
	_ = db.QueryRow(`
		SELECT hash FROM (
			SELECT pubkey_hash AS hash FROM users
			UNION
			SELECT pubkey_hash AS hash FROM shadow_banned
			UNION
			SELECT user_id AS hash FROM log WHERE user_id != ''
		)
		WHERE hash = ?
		LIMIT 1`, token).Scan(&exact)
	if exact != "" {
		return exact, nil
	}

	rows, err := db.Query(`
		SELECT hash FROM (
			SELECT pubkey_hash AS hash FROM users
			UNION
			SELECT pubkey_hash AS hash FROM shadow_banned
			UNION
			SELECT user_id AS hash FROM log WHERE user_id != ''
		)
		WHERE hash LIKE ?
		ORDER BY hash
		LIMIT 3`, token+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	matches := make([]string, 0, 3)
	for rows.Next() {
		var m string
		if scanErr := rows.Scan(&m); scanErr == nil && strings.TrimSpace(m) != "" {
			matches = append(matches, strings.TrimSpace(m))
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	if len(matches) == 0 {
		return "", errAdminLookupNotFound
	}
	if len(matches) > 1 {
		return "", errAdminLookupAmbiguous
	}
	return matches[0], nil
}

func resolveAdminSessionID(db *sql.DB, token string) (string, error) {
	token = normalizeAdminLookupToken(token)
	if token == "" {
		return "", errAdminLookupNotFound
	}

	var exact string
	_ = db.QueryRow(`
		SELECT user_session
		FROM log
		WHERE user_session = ? AND user_session != ''
		LIMIT 1`, token).Scan(&exact)
	if exact != "" {
		return exact, nil
	}

	rows, err := db.Query(`
		SELECT DISTINCT user_session
		FROM log
		WHERE user_session LIKE ? AND user_session != ''
		ORDER BY user_session
		LIMIT 3`, token+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	matches := make([]string, 0, 3)
	for rows.Next() {
		var m string
		if scanErr := rows.Scan(&m); scanErr == nil && strings.TrimSpace(m) != "" {
			matches = append(matches, strings.TrimSpace(m))
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	if len(matches) == 0 {
		return "", errAdminLookupNotFound
	}
	if len(matches) > 1 {
		return "", errAdminLookupAmbiguous
	}
	return matches[0], nil
}
