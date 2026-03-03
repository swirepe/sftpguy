package main

import (
	"encoding/json"
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
