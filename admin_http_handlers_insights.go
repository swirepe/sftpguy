package main

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"sftpguy/internal/geoip"
)

var (
	ipBanTimestampPattern      = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b`)
	ipBanLegacyBannedAtPattern = regexp.MustCompile(`\bbanned_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\b`)
)

type adminUserAgentStat struct {
	UserAgent string `json:"user_agent"`
	Device    string `json:"device"`
	Browser   string `json:"browser"`
	OS        string `json:"os"`
	Count     int64  `json:"count"`
	Uploads   int64  `json:"uploads"`
	Downloads int64  `json:"downloads"`
	Denied    int64  `json:"denied"`
	Mutations int64  `json:"mutations"`
	Sessions  int64  `json:"sessions"`
	Explorer  int64  `json:"explorer"`
	LastTime  string `json:"last_time"`
	LastIP    string `json:"last_ip"`
	TopEvent  string `json:"top_event"`
}

type adminDeviceStat struct {
	Name      string `json:"name"`
	Count     int64  `json:"count"`
	Uploads   int64  `json:"uploads"`
	Downloads int64  `json:"downloads"`
	Denied    int64  `json:"denied"`
	Mutations int64  `json:"mutations"`
	Sessions  int64  `json:"sessions"`
	Explorer  int64  `json:"explorer"`
	TopEvent  string `json:"top_event"`
}

type adminUAProfile struct {
	Device  string
	Browser string
	OS      string
}

func (s *Server) handleAdminInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.flushConnectionLimitAggregatesForAdmin()

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
		Name   string          `json:"name"`
		Count  int64           `json:"count"`
		Denied int64           `json:"denied"`
		Geo    *geoip.Location `json:"geo,omitempty"`
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
				if loc, ok := s.geoLocation(item.Name); ok {
					item.Geo = loc
				}
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
	recentPanics := make([]parsedSystemLogEntry, 0, 6)
	panicCount := 0
	for _, line := range lines {
		entry := parseSystemLogEntry(line)
		if entry.Level != "" {
			levelCount[entry.Level]++
		}
		if entry.UserID != "" {
			userCount[entry.UserID]++
		}
		if entry.IP != "" {
			ipCount[entry.IP]++
		}
		if entry.IsPanic {
			panicCount++
			if len(recentPanics) < cap(recentPanics) {
				recentPanics = append(recentPanics, entry)
			}
		}
	}

	userAgents, deviceTypes := s.adminUserAgentInsights(since)
	geoCountryCount := map[string]int{}
	geoCityCount := map[string]int{}
	for _, item := range topIPs {
		if item.Geo == nil {
			continue
		}
		country := firstNonEmpty(item.Geo.Country, item.Geo.CountryCode)
		if country != "" {
			geoCountryCount[country] += int(item.Count)
		}
		city := item.Geo.City
		if city != "" && item.Geo.CountryCode != "" {
			city += ", " + item.Geo.CountryCode
		}
		if city != "" {
			geoCityCount[city] += int(item.Count)
		}
	}
	geoCountries := mapCountPairs(geoCountryCount, 12)
	geoCities := mapCountPairs(geoCityCount, 12)
	connectionLimitHits := s.adminConnectionLimitHits(since)

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
			"conn_max_hits":  connectionLimitHits,
			"conn_max_rows":  scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = ?`, since, string(EventDeniedConnectionLimit)),
			"admin_actions":  scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event LIKE 'admin/%'`, since),
			"session_starts": scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'session/start'`, since),
			"session_ends":   scalar(`SELECT COUNT(*) FROM log WHERE timestamp >= ? AND event = 'session/end'`, since),
		},
		"top_events":              topEvents,
		"top_users":               topUsers,
		"top_ips":                 topIPs,
		"suspicious_ips":          suspiciousIPs,
		"geo_countries":           geoCountries,
		"geo_cities":              geoCities,
		"geoip":                   s.geoStatus(),
		"parsed_levels":           mapCountPairs(levelCount, 6),
		"parsed_users_recent":     mapCountPairs(userCount, 12),
		"parsed_ips_recent":       mapCountPairs(ipCount, 12),
		"parsed_lines_considered": len(lines),
		"parsed_panics":           panicCount,
		"recent_panics":           recentPanics,
		"user_agents":             userAgents,
		"device_types":            deviceTypes,
	})
}

func (s *Server) adminConnectionLimitHits(since int64) int64 {
	rows, err := s.store.db.Query(`
		SELECT IFNULL(meta, '')
		FROM log
		WHERE timestamp >= ? AND event = ?`, since, string(EventDeniedConnectionLimit))
	if err != nil {
		return 0
	}
	defer rows.Close()

	var total int64
	for rows.Next() {
		var rawMeta string
		if err := rows.Scan(&rawMeta); err != nil {
			continue
		}
		hits := int64FromAny(parseJSONMap(rawMeta)["hits"])
		if hits < 1 {
			hits = 1
		}
		total += hits
	}
	return total
}

func (s *Server) adminUserAgentInsights(since int64) ([]adminUserAgentStat, []adminDeviceStat) {
	rows, err := s.store.db.Query(`
		SELECT timestamp, event, IFNULL(ip_address, ''), IFNULL(meta, '')
		FROM log
		WHERE timestamp >= ? AND IFNULL(meta, '') != ''
		ORDER BY id DESC
		LIMIT 5000`, since)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	agents := map[string]*adminUserAgentStat{}
	devices := map[string]*adminDeviceStat{}
	agentEvents := map[string]map[string]int64{}
	deviceEvents := map[string]map[string]int64{}

	for rows.Next() {
		var ts int64
		var event, ip, meta string
		if err := rows.Scan(&ts, &event, &ip, &meta); err != nil {
			continue
		}
		metaObj := parseJSONMap(meta)
		ua := userAgentFromMeta(metaObj)
		if ua == "" {
			continue
		}
		profile := classifyUserAgent(ua)
		agent := agents[ua]
		if agent == nil {
			agent = &adminUserAgentStat{
				UserAgent: ua,
				Device:    profile.Device,
				Browser:   profile.Browser,
				OS:        profile.OS,
			}
			agents[ua] = agent
		}
		device := devices[profile.Device]
		if device == nil {
			device = &adminDeviceStat{Name: profile.Device}
			devices[profile.Device] = device
		}

		applyUserAgentActivity(agent, event)
		applyDeviceActivity(device, event)
		agent.Count++
		device.Count++
		if ts > 0 && (agent.LastTime == "" || formatUnix(ts) > agent.LastTime) {
			agent.LastTime = formatUnix(ts)
			agent.LastIP = ip
		}
		if sourceFromEventMeta(event, metaObj) == "explorer" {
			agent.Explorer++
			device.Explorer++
		}
		if agentEvents[ua] == nil {
			agentEvents[ua] = map[string]int64{}
		}
		if deviceEvents[profile.Device] == nil {
			deviceEvents[profile.Device] = map[string]int64{}
		}
		agentEvents[ua][event]++
		deviceEvents[profile.Device][event]++
	}

	agentOut := make([]adminUserAgentStat, 0, len(agents))
	for ua, item := range agents {
		item.TopEvent = topEventName(agentEvents[ua])
		agentOut = append(agentOut, *item)
	}
	sort.Slice(agentOut, func(i, j int) bool {
		if agentOut[i].Count == agentOut[j].Count {
			return agentOut[i].UserAgent < agentOut[j].UserAgent
		}
		return agentOut[i].Count > agentOut[j].Count
	})
	if len(agentOut) > 12 {
		agentOut = agentOut[:12]
	}

	deviceOut := make([]adminDeviceStat, 0, len(devices))
	for name, item := range devices {
		item.TopEvent = topEventName(deviceEvents[name])
		deviceOut = append(deviceOut, *item)
	}
	sort.Slice(deviceOut, func(i, j int) bool {
		if deviceOut[i].Count == deviceOut[j].Count {
			return deviceOut[i].Name < deviceOut[j].Name
		}
		return deviceOut[i].Count > deviceOut[j].Count
	})
	return agentOut, deviceOut
}

func userAgentFromMeta(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	for _, key := range []string{"user_agent", "user-agent", "User-Agent", "userAgent"} {
		if value := userAgentValue(meta[key]); value != "" {
			return value
		}
	}
	if value := userAgentFromHeaders(meta["headers"]); value != "" {
		return value
	}
	if nested, ok := meta["explorer_meta"].(map[string]any); ok {
		for _, key := range []string{"user_agent", "user-agent", "User-Agent", "userAgent"} {
			if value := userAgentValue(nested[key]); value != "" {
				return value
			}
		}
		if value := userAgentFromHeaders(nested["headers"]); value != "" {
			return value
		}
	}
	return ""
}

func userAgentFromHeaders(raw any) string {
	headers, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	for key, value := range headers {
		if strings.EqualFold(key, "User-Agent") {
			if ua := userAgentValue(value); ua != "" {
				return ua
			}
		}
	}
	return ""
}

func userAgentValue(raw any) string {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case []string:
		if len(value) == 0 {
			return ""
		}
		return strings.TrimSpace(value[0])
	case []any:
		if len(value) == 0 {
			return ""
		}
		return strings.TrimSpace(stringFromAny(value[0]))
	default:
		return strings.TrimSpace(stringFromAny(value))
	}
}

func classifyUserAgent(ua string) adminUAProfile {
	lower := strings.ToLower(ua)
	profile := adminUAProfile{
		Device:  "unknown",
		Browser: "unknown",
		OS:      "unknown",
	}

	switch {
	case strings.Contains(lower, "bot") || strings.Contains(lower, "spider") || strings.Contains(lower, "crawler"):
		profile.Device = "bot"
	case strings.Contains(lower, "curl") || strings.Contains(lower, "wget") || strings.Contains(lower, "python-requests") ||
		strings.Contains(lower, "go-http-client") || strings.Contains(lower, "httpie") || strings.Contains(lower, "okhttp"):
		profile.Device = "cli"
	case strings.Contains(lower, "ipad") || strings.Contains(lower, "tablet") || (strings.Contains(lower, "android") && !strings.Contains(lower, "mobile")):
		profile.Device = "tablet"
	case strings.Contains(lower, "mobile") || strings.Contains(lower, "iphone") || strings.Contains(lower, "android"):
		profile.Device = "mobile"
	case strings.Contains(lower, "windows") || strings.Contains(lower, "macintosh") || strings.Contains(lower, "x11") || strings.Contains(lower, "linux"):
		profile.Device = "desktop"
	}

	switch {
	case strings.Contains(lower, "edg/") || strings.Contains(lower, "edge/"):
		profile.Browser = "Edge"
	case strings.Contains(lower, "firefox/"):
		profile.Browser = "Firefox"
	case strings.Contains(lower, "chrome/") || strings.Contains(lower, "chromium/"):
		profile.Browser = "Chrome"
	case strings.Contains(lower, "safari/") && strings.Contains(lower, "version/"):
		profile.Browser = "Safari"
	case strings.Contains(lower, "curl/"):
		profile.Browser = "curl"
	case strings.Contains(lower, "wget/"):
		profile.Browser = "wget"
	case strings.Contains(lower, "python-requests"):
		profile.Browser = "python-requests"
	case strings.Contains(lower, "go-http-client"):
		profile.Browser = "go-http-client"
	case profile.Device == "bot":
		profile.Browser = "bot"
	}

	switch {
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") || strings.Contains(lower, "cpu os"):
		profile.OS = "iOS"
	case strings.Contains(lower, "android"):
		profile.OS = "Android"
	case strings.Contains(lower, "windows"):
		profile.OS = "Windows"
	case strings.Contains(lower, "mac os x") || strings.Contains(lower, "macintosh"):
		profile.OS = "macOS"
	case strings.Contains(lower, "linux") || strings.Contains(lower, "x11"):
		profile.OS = "Linux"
	case profile.Device == "bot":
		profile.OS = "bot"
	}

	return profile
}

func applyUserAgentActivity(row *adminUserAgentStat, event string) {
	if row == nil {
		return
	}
	kind := adminEventActivityKind(event)
	switch kind {
	case "upload":
		row.Uploads++
	case "download":
		row.Downloads++
	case "denied":
		row.Denied++
	case "mutation":
		row.Mutations++
	case "session":
		row.Sessions++
	}
}

func applyDeviceActivity(row *adminDeviceStat, event string) {
	if row == nil {
		return
	}
	kind := adminEventActivityKind(event)
	switch kind {
	case "upload":
		row.Uploads++
	case "download":
		row.Downloads++
	case "denied":
		row.Denied++
	case "mutation":
		row.Mutations++
	case "session":
		row.Sessions++
	}
}

func adminEventActivityKind(event string) string {
	name := strings.ToLower(strings.TrimSpace(event))
	switch {
	case strings.Contains(name, "denied"):
		return "denied"
	case strings.Contains(name, "upload"):
		return "upload"
	case strings.Contains(name, "download"):
		return "download"
	case strings.Contains(name, "session"):
		return "session"
	case strings.Contains(name, "delete") || strings.Contains(name, "rename") || strings.Contains(name, "ban") || strings.Contains(name, "write"):
		return "mutation"
	default:
		return "other"
	}
}

func sourceFromEventMeta(event string, meta map[string]any) string {
	source := strings.ToLower(strings.TrimSpace(stringFromAny(meta["source"])))
	if source == "explorer" || source == "admin" || source == "sftp" {
		return source
	}
	name := strings.ToLower(strings.TrimSpace(event))
	if strings.HasPrefix(name, "explorer_") {
		return "explorer"
	}
	if strings.HasPrefix(name, "admin/") {
		return "admin"
	}
	return "sftp"
}

func topEventName(counts map[string]int64) string {
	var best string
	var bestCount int64
	for name, count := range counts {
		if count > bestCount || (count == bestCount && (best == "" || name < best)) {
			best = name
			bestCount = count
		}
	}
	return best
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
	panicOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("panic_only")), "1") ||
		strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("panic_only")), "true")
	entries, levelCount, scannedLines, panicCount, err := readParsedSystemLog(s.cfg.LogFile, limit, filter, panicOnly)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries":       entries,
		"levels":        mapCountPairs(levelCount, 10),
		"panic_count":   panicCount,
		"scanned_lines": scannedLines,
		"has_more":      panicCount > len(entries),
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

	type bannedIP struct {
		IP       string          `json:"ip"`
		BannedAt string          `json:"banned_at"`
		Comment  string          `json:"comment,omitempty"`
		Geo      *geoip.Location `json:"geo,omitempty"`
	}
	ips := make([]bannedIP, 0)
	if s.store.blacklist != nil {
		entries, err := s.store.blacklist.ExactEntries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i := len(entries) - 1; i >= 0; i-- {
			entry := entries[i]
			ips = append(ips, bannedIP{
				IP:       entry.ExactIP,
				BannedAt: extractIPBanTimestamp(entry.Comment),
				Comment:  entry.Comment,
				Geo:      geoLocationOrNil(s, entry.ExactIP),
			})
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
	parsedIP := net.ParseIP(payload.IP)
	if parsedIP == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	payload.IP = parsedIP.String()
	added, err := s.store.blacklist.AddExactIPWithComment(payload.IP, adminIPBanComment(time.Now()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminBan, systemOwner, "admin-http", nil, "target", payload.IP, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": payload.IP, "added": added})
}

func (s *Server) handleAdminUnbanIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/admin/api/banned/ip/"))
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	ip = parsedIP.String()
	removed, err := s.store.blacklist.RemoveExactIP(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.LogEvent(EventAdminUnban, systemOwner, "admin-http", nil, "target", ip, "type", "ip")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip, "removed": removed})
}

func extractIPBanTimestamp(comment string) string {
	if match := ipBanLegacyBannedAtPattern.FindStringSubmatch(comment); len(match) == 2 {
		return match[1]
	}
	return ipBanTimestampPattern.FindString(comment)
}
