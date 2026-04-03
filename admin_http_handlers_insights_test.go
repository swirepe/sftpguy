package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestHandleAdminBanIPUsesBlacklistWithTimestamp(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ip = "203.0.113.10"

	body, _ := json.Marshal(map[string]string{"ip": ip})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/banned/ip", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAdminBanIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/banned/ip status=%d body=%s", w.Code, w.Body.String())
	}

	var banResp struct {
		OK    bool   `json:"ok"`
		IP    string `json:"ip"`
		Added bool   `json:"added"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &banResp); err != nil {
		t.Fatalf("decode ban response: %v", err)
	}
	if !banResp.OK || banResp.IP != ip || !banResp.Added {
		t.Fatalf("unexpected ban response: %+v", banResp)
	}

	if !srv.store.IsIPBanned(ip) {
		t.Fatalf("expected %s to be banned via blacklist", ip)
	}

	entries, err := srv.store.blacklist.ExactEntries()
	if err != nil {
		t.Fatalf("read exact blacklist entries: %v", err)
	}
	var count int
	var comment string
	for _, entry := range entries {
		if entry.ExactIP == ip {
			count++
			comment = entry.Comment
		}
	}
	if count != 1 {
		t.Fatalf("expected one exact blacklist entry for %s, got %d", ip, count)
	}

	timestamp := extractIPBanTimestamp(comment)
	if timestamp == "" {
		t.Fatalf("expected timestamp in blacklist comment, got %q", comment)
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		t.Fatalf("parse blacklist timestamp %q: %v", timestamp, err)
	}

	content, err := os.ReadFile(srv.store.blacklistPath)
	if err != nil {
		t.Fatalf("read blacklist file: %v", err)
	}
	if !bytes.Contains(content, []byte(ip+" # admin ban at "+timestamp)) {
		t.Fatalf("expected timestamped admin ban comment in blacklist file, got %q", string(content))
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/admin/api/banned/ip", bytes.NewReader(body))
	secondW := httptest.NewRecorder()
	srv.handleAdminBanIP(secondW, secondReq)
	if secondW.Code != http.StatusOK {
		t.Fatalf("second POST /admin/api/banned/ip status=%d body=%s", secondW.Code, secondW.Body.String())
	}

	var secondResp struct {
		Added bool `json:"added"`
	}
	if err := json.Unmarshal(secondW.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("decode second ban response: %v", err)
	}
	if secondResp.Added {
		t.Fatal("expected duplicate admin IP ban to be ignored")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/api/banned", nil)
	getW := httptest.NewRecorder()
	srv.handleAdminBanned(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/banned status=%d body=%s", getW.Code, getW.Body.String())
	}

	var bannedResp struct {
		IPs []struct {
			IP       string `json:"ip"`
			BannedAt string `json:"banned_at"`
			Comment  string `json:"comment"`
		} `json:"ips"`
	}
	if err := json.Unmarshal(getW.Body.Bytes(), &bannedResp); err != nil {
		t.Fatalf("decode banned response: %v", err)
	}
	if len(bannedResp.IPs) != 1 {
		t.Fatalf("expected 1 banned IP, got %d", len(bannedResp.IPs))
	}
	if bannedResp.IPs[0].IP != ip {
		t.Fatalf("unexpected banned IP: got=%q want=%q", bannedResp.IPs[0].IP, ip)
	}
	if bannedResp.IPs[0].BannedAt != timestamp {
		t.Fatalf("unexpected banned_at: got=%q want=%q", bannedResp.IPs[0].BannedAt, timestamp)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/api/banned/ip/"+ip, nil)
	deleteW := httptest.NewRecorder()
	srv.handleAdminUnbanIP(deleteW, deleteReq)
	if deleteW.Code != http.StatusOK {
		t.Fatalf("DELETE /admin/api/banned/ip/:ip status=%d body=%s", deleteW.Code, deleteW.Body.String())
	}

	var unbanResp struct {
		Removed bool `json:"removed"`
	}
	if err := json.Unmarshal(deleteW.Body.Bytes(), &unbanResp); err != nil {
		t.Fatalf("decode unban response: %v", err)
	}
	if !unbanResp.Removed {
		t.Fatal("expected exact IP blacklist entry to be removed")
	}
	if srv.store.IsIPBanned(ip) {
		t.Fatalf("expected %s to be unbanned after blacklist removal", ip)
	}
}

func TestHandleAdminIPTestIgnoresLegacyDBBans(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ip = "203.0.113.77"

	if _, err := srv.store.exec(`CREATE TABLE ip_banned (ip_address TEXT PRIMARY KEY, banned_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create legacy ip_banned table: %v", err)
	}
	if _, err := srv.store.exec(`INSERT INTO ip_banned (ip_address) VALUES (?)`, ip); err != nil {
		t.Fatalf("insert legacy ip ban: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"ip": ip})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/ip-lists/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAdminIPListTest(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/ip-lists/test status=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		IP      string            `json:"ip"`
		Matches map[string]bool   `json:"matches"`
		Notes   map[string]string `json:"notes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ip test response: %v", err)
	}
	if resp.IP != ip {
		t.Fatalf("unexpected tested ip: got=%q want=%q", resp.IP, ip)
	}
	if resp.Matches["effective_banned"] {
		t.Fatal("expected legacy db-only IP bans to have no effect")
	}
	if _, ok := resp.Matches["db_banned"]; ok {
		t.Fatalf("expected response to omit db_banned after blacklist-only migration, got %+v", resp.Matches)
	}
	if got := resp.Notes["precedence"]; got != "whitelist overrides blacklist" {
		t.Fatalf("unexpected precedence note: got=%q", got)
	}
}

func TestNewServerMigratesLegacyIPBansToBlacklist(t *testing.T) {
	srv := newMaintenanceTestServer(t)

	const ip = "198.51.100.9"
	const bannedAt = "2026-03-18 14:05:06"

	if _, err := srv.store.exec(`CREATE TABLE ip_banned (ip_address TEXT PRIMARY KEY, banned_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create legacy ip_banned table: %v", err)
	}
	if _, err := srv.store.exec(`INSERT INTO ip_banned (ip_address, banned_at) VALUES (?, ?)`, ip, bannedAt); err != nil {
		t.Fatalf("insert legacy ip ban: %v", err)
	}

	cfg := srv.cfg
	logger := srv.logger
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("shutdown original server: %v", err)
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("reopen server: %v", err)
	}
	defer srv.Shutdown()

	if !srv.store.IsIPBanned(ip) {
		t.Fatalf("expected migrated legacy IP ban to be enforced for %s", ip)
	}

	entries, err := srv.store.blacklist.ExactEntries()
	if err != nil {
		t.Fatalf("read migrated blacklist entries: %v", err)
	}
	var count int
	var comment string
	for _, entry := range entries {
		if entry.ExactIP == ip {
			count++
			comment = entry.Comment
		}
	}
	if count != 1 {
		t.Fatalf("expected one migrated blacklist entry for %s, got %d", ip, count)
	}
	if got := extractIPBanTimestamp(comment); got != "2026-03-18T14:05:06Z" {
		t.Fatalf("unexpected migrated timestamp: got=%q comment=%q", got, comment)
	}
}

func TestHandleAdminParsedSystemLogReturnsStructuredPanics(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	logLines := []byte(
		"time=2026-03-26T15:01:02Z level=INFO msg=\"background tick\"\n" +
			"time=2026-03-26T15:02:03Z level=ERROR msg=\"panic recovered; re-panicking\" component=\"ssh listener\" panic=\"boom\" stack=\"goroutine 1 [running]\\nmain.main()\" user.id=user123 remote_addr=203.0.113.25\n",
	)
	if err := os.WriteFile(srv.cfg.LogFile, logLines, permFile); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/system-log/parsed?panic_only=1&limit=5", nil)
	w := httptest.NewRecorder()
	srv.handleAdminParsedSystemLog(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/system-log/parsed status=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Entries []struct {
			Time      string `json:"time"`
			Level     string `json:"level"`
			Msg       string `json:"msg"`
			UserID    string `json:"user_id"`
			IP        string `json:"ip"`
			Component string `json:"component"`
			Panic     string `json:"panic"`
			Stack     string `json:"stack"`
			IsPanic   bool   `json:"is_panic"`
		} `json:"entries"`
		PanicCount  int  `json:"panic_count"`
		ScannedRows int  `json:"scanned_lines"`
		HasMore     bool `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode parsed system log response: %v", err)
	}
	if resp.PanicCount != 1 {
		t.Fatalf("expected panic_count=1, got %d", resp.PanicCount)
	}
	if resp.ScannedRows != 2 {
		t.Fatalf("expected scanned_lines=2, got %d", resp.ScannedRows)
	}
	if resp.HasMore {
		t.Fatal("expected has_more=false for single panic entry")
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 parsed panic entry, got %d", len(resp.Entries))
	}
	if !resp.Entries[0].IsPanic {
		t.Fatal("expected parsed entry to be marked as panic")
	}
	if resp.Entries[0].Component != "ssh listener" {
		t.Fatalf("unexpected component: got=%q", resp.Entries[0].Component)
	}
	if resp.Entries[0].Panic != "boom" {
		t.Fatalf("unexpected panic value: got=%q", resp.Entries[0].Panic)
	}
	if resp.Entries[0].UserID != "user123" {
		t.Fatalf("unexpected user_id: got=%q", resp.Entries[0].UserID)
	}
	if resp.Entries[0].IP != "203.0.113.25" {
		t.Fatalf("unexpected ip: got=%q", resp.Entries[0].IP)
	}
	if resp.Entries[0].Stack != "goroutine 1 [running]\nmain.main()" {
		t.Fatalf("unexpected stack: got=%q", resp.Entries[0].Stack)
	}
}

func TestHandleAdminInsightsIncludesRecentPanics(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	logLines := []byte(
		"time=2026-03-26T15:01:02Z level=INFO msg=\"background tick\"\n" +
			"time=2026-03-26T15:02:03Z level=ERROR msg=\"panic recovered; re-panicking\" component=\"maintenance loop\" panic=\"boom\" stack=\"goroutine 1 [running]\\nmain.main()\"\n",
	)
	if err := os.WriteFile(srv.cfg.LogFile, logLines, permFile); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/insights?range=24h", nil)
	w := httptest.NewRecorder()
	srv.handleAdminInsights(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/insights status=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		ParsedPanics int `json:"parsed_panics"`
		RecentPanics []struct {
			Component string `json:"component"`
			Panic     string `json:"panic"`
			IsPanic   bool   `json:"is_panic"`
		} `json:"recent_panics"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode insights response: %v", err)
	}
	if resp.ParsedPanics != 1 {
		t.Fatalf("expected parsed_panics=1, got %d", resp.ParsedPanics)
	}
	if len(resp.RecentPanics) != 1 {
		t.Fatalf("expected 1 recent panic, got %d", len(resp.RecentPanics))
	}
	if !resp.RecentPanics[0].IsPanic {
		t.Fatal("expected recent panic entry to be marked as panic")
	}
	if resp.RecentPanics[0].Component != "maintenance loop" {
		t.Fatalf("unexpected recent panic component: got=%q", resp.RecentPanics[0].Component)
	}
	if resp.RecentPanics[0].Panic != "boom" {
		t.Fatalf("unexpected recent panic value: got=%q", resp.RecentPanics[0].Panic)
	}
}
