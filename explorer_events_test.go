package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sftpguy/internal/explorerevents"
)

func TestRecordExplorerUploadUsesAnonAuthFromClientIP(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	evt := explorerevents.Event{
		Kind:           explorerevents.KindUpload,
		ClientIP:       "198.51.100.23",
		RemoteAddr:     "198.51.100.23:49152",
		Session:        "explorer-browser-session",
		Path:           "web/report.txt",
		Bytes:          7,
		Size:           7,
		Delta:          7,
		DurationMS:     5,
		AvgBytesPerSec: 1400,
		Method:         "POST",
		URLPath:        "/web",
		Meta: map[string]any{
			"headers": map[string][]string{
				"X-Custom-Audit": {"one", "two"},
				"User-Agent":     {"explorer-test"},
			},
		},
	}

	if err := srv.recordExplorerEvent(evt); err != nil {
		t.Fatalf("record explorer upload: %v", err)
	}

	hash := anonAuthHashForIP("198.51.100.23")
	stats, err := srv.store.GetUserStats(hash)
	if err != nil {
		t.Fatalf("get explorer user stats: %v", err)
	}
	if stats.UploadCount != 1 || stats.UploadBytes != 7 {
		t.Fatalf("unexpected upload stats: count=%d bytes=%d", stats.UploadCount, stats.UploadBytes)
	}
	if stats.Seen != 1 || stats.LastAddress != "198.51.100.23" {
		t.Fatalf("unexpected identity stats: seen=%d last_address=%q", stats.Seen, stats.LastAddress)
	}
	if owner, err := srv.store.GetFileOwner("web/report.txt"); err != nil {
		t.Fatalf("get file owner: %v", err)
	} else if owner != hash {
		t.Fatalf("file owner = %q, want %q", owner, hash)
	}

	var userID, ip, path, session, meta string
	if err := srv.store.db.QueryRow(`
		SELECT IFNULL(user_id,''), IFNULL(ip_address,''), IFNULL(path,''), IFNULL(user_session,''), IFNULL(meta,'')
		FROM log
		WHERE event = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventUpload)).Scan(&userID, &ip, &path, &session, &meta); err != nil {
		t.Fatalf("query upload log: %v", err)
	}
	if userID != hash || ip != "198.51.100.23" || path != "web/report.txt" || session != "explorer-browser-session" {
		t.Fatalf("unexpected log row: user=%q ip=%q path=%q session=%q", userID, ip, path, session)
	}
	metaObj := parseJSONMap(meta)
	if got := stringFromAny(metaObj["source"]); got != "explorer" {
		t.Fatalf("source meta = %q, want explorer", got)
	}
	if got := int64FromAny(metaObj["duration_ms"]); got != 5 {
		t.Fatalf("duration_ms = %d, want 5", got)
	}
	if got := int64FromAny(metaObj["delta"]); got != 7 {
		t.Fatalf("delta = %d, want 7", got)
	}
	if got := int64FromAny(metaObj["avg_bytes_per_sec"]); got != 1400 {
		t.Fatalf("avg_bytes_per_sec = %d, want 1400", got)
	}
	if got := stringFromAny(metaObj["file"]); got != "web/report.txt" {
		t.Fatalf("file meta = %q, want web/report.txt", got)
	}
	if got := stringFromAny(metaObj["filename"]); got != "report.txt" {
		t.Fatalf("filename meta = %q, want report.txt", got)
	}
	explorerMeta, ok := metaObj["explorer_meta"].(map[string]any)
	if !ok {
		t.Fatalf("explorer_meta missing or wrong type: %#v", metaObj["explorer_meta"])
	}
	headers, ok := explorerMeta["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers missing or wrong type: %#v", explorerMeta["headers"])
	}
	if got := stringSliceFromAny(headers["X-Custom-Audit"]); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("X-Custom-Audit headers = %#v", got)
	}
}

func TestExplorerEventRPCCheckIPUsesWhitelistPrecedence(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	if err := srv.store.blacklist.AddRange("198.51.100.0", 24, "test blacklist"); err != nil {
		t.Fatalf("add blacklist range: %v", err)
	}
	if _, _, err := srv.store.blacklist.Reload(); err != nil {
		t.Fatalf("reload blacklist: %v", err)
	}
	if _, err := srv.store.whitelist.AddExactIPWithComment("198.51.100.50", "test whitelist"); err != nil {
		t.Fatalf("add whitelist ip: %v", err)
	}

	socketPath := startExplorerEventRPCTestServer(t, srv)
	client := explorerevents.NewClient(socketPath, nil)
	defer client.Close(time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	banned, err := client.CheckIP(ctx, "198.51.100.51")
	if err != nil {
		t.Fatalf("check banned ip: %v", err)
	}
	if banned == nil || !banned.Blacklisted || banned.Whitelisted || !banned.EffectiveBanned || banned.UploadAllowed || banned.ThrottleBytesPerSec != shadowBanBytesPerSec {
		t.Fatalf("unexpected banned policy: %#v", banned)
	}

	allowed, err := client.CheckIP(ctx, "198.51.100.50")
	if err != nil {
		t.Fatalf("check whitelisted ip: %v", err)
	}
	if allowed == nil || !allowed.Blacklisted || !allowed.Whitelisted || allowed.EffectiveBanned || !allowed.UploadAllowed || allowed.ThrottleBytesPerSec != 0 {
		t.Fatalf("unexpected whitelist policy: %#v", allowed)
	}
}

func TestExplorerEventRPCRecordEvent(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	socketPath := startExplorerEventRPCTestServer(t, srv)
	client := explorerevents.NewClient(socketPath, nil)

	client.Emit(explorerevents.Event{
		Kind:       explorerevents.KindUpload,
		ClientIP:   "198.51.100.60",
		RemoteAddr: "198.51.100.60:49152",
		Path:       "rpc/upload.txt",
		Bytes:      9,
		Size:       9,
		Delta:      9,
		Method:     "POST",
		URLPath:    "/rpc",
		Meta: map[string]any{
			"headers": map[string][]string{"User-Agent": {"rpc-test"}},
		},
	})
	client.Close(time.Second)

	hash := anonAuthHashForIP("198.51.100.60")
	stats, err := srv.store.GetUserStats(hash)
	if err != nil {
		t.Fatalf("get rpc upload stats: %v", err)
	}
	if stats.UploadCount != 1 || stats.UploadBytes != 9 {
		t.Fatalf("unexpected rpc upload stats: count=%d bytes=%d", stats.UploadCount, stats.UploadBytes)
	}
}

func TestRecordExplorerEventDefaultsLegacySession(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	if err := srv.recordExplorerEvent(explorerevents.Event{
		Kind:       explorerevents.KindRequest,
		ClientIP:   "198.51.100.61",
		RemoteAddr: "198.51.100.61:49152",
		Method:     "GET",
		URLPath:    "/legacy",
		Status:     http.StatusOK,
	}); err != nil {
		t.Fatalf("record explorer request: %v", err)
	}

	var session string
	if err := srv.store.db.QueryRow(`
		SELECT IFNULL(user_session, '')
		FROM log
		WHERE event = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventExplorerRequest)).Scan(&session); err != nil {
		t.Fatalf("query explorer request log: %v", err)
	}
	if session != "explorer" {
		t.Fatalf("session = %q, want explorer", session)
	}
}

func TestExplorerSessionReachesAdminSessionsAPI(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const sessionID = "explorer-browser-session"
	evt := explorerevents.Event{
		Kind:       explorerevents.KindRequest,
		ClientIP:   "198.51.100.42",
		RemoteAddr: "198.51.100.42:49152",
		Session:    sessionID,
		URLPath:    "/public/readme.txt",
		Method:     http.MethodGet,
		Status:     http.StatusOK,
	}
	if err := srv.recordExplorerEvent(evt); err != nil {
		t.Fatalf("record explorer request: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/sessions?range=24h&q=explorer-browser", nil)
	w := httptest.NewRecorder()
	srv.handleAdminSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/sessions status=%d body=%s", w.Code, w.Body.String())
	}

	var sessionsPayload struct {
		Sessions []struct {
			Session    string `json:"session"`
			UserID     string `json:"user_id"`
			IP         string `json:"ip"`
			EventCount int64  `json:"event_count"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sessionsPayload); err != nil {
		t.Fatalf("decode sessions payload: %v", err)
	}
	if len(sessionsPayload.Sessions) != 1 {
		t.Fatalf("unexpected sessions length: got=%d want=1 payload=%s", len(sessionsPayload.Sessions), w.Body.String())
	}
	row := sessionsPayload.Sessions[0]
	if row.Session != sessionID || row.UserID != anonAuthHashForIP("198.51.100.42") || row.IP != "198.51.100.42" || row.EventCount != 1 {
		t.Fatalf("unexpected session row: %#v", row)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/api/sessions/explorer-browser?limit=20", nil)
	w = httptest.NewRecorder()
	srv.handleAdminSessionTimeline(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/sessions/{id} status=%d body=%s", w.Code, w.Body.String())
	}

	var timelinePayload struct {
		Session string `json:"session"`
		Events  []struct {
			Event string `json:"event"`
			Path  string `json:"path"`
		} `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &timelinePayload); err != nil {
		t.Fatalf("decode timeline payload: %v", err)
	}
	if timelinePayload.Session != sessionID || len(timelinePayload.Events) != 1 || timelinePayload.Events[0].Event != string(EventExplorerRequest) || timelinePayload.Events[0].Path != "public/readme.txt" {
		t.Fatalf("unexpected timeline payload: %#v", timelinePayload)
	}
}

func startExplorerEventRPCTestServer(t *testing.T, srv *Server) string {
	t.Helper()

	socketPath := filepath.Join("/tmp", fmt.Sprintf("sftpguy-events-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	rpcServer := rpc.NewServer()
	if err := rpcServer.RegisterName(explorerevents.RPCServiceName, &explorerEventRPC{srv: srv}); err != nil {
		t.Fatalf("register rpc server: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	return socketPath
}

func TestRecordExplorerUploadStoresClientIPWhenRemoteAddrIsProxy(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	evt := explorerevents.Event{
		Kind:       explorerevents.KindUpload,
		ClientIP:   "198.51.100.25",
		RemoteAddr: "127.0.0.1:58050",
		Path:       "web/proxied.txt",
		Bytes:      5,
		Size:       5,
		Delta:      5,
		Method:     "POST",
		URLPath:    "/web",
	}

	if err := srv.recordExplorerEvent(evt); err != nil {
		t.Fatalf("record explorer upload: %v", err)
	}

	hash := anonAuthHashForIP("198.51.100.25")
	stats, err := srv.store.GetUserStats(hash)
	if err != nil {
		t.Fatalf("get explorer user stats: %v", err)
	}
	if stats.LastAddress != "198.51.100.25" {
		t.Fatalf("last address = %q, want client IP", stats.LastAddress)
	}

	var ip string
	if err := srv.store.db.QueryRow(`
		SELECT IFNULL(ip_address,'')
		FROM log
		WHERE event = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventUpload)).Scan(&ip); err != nil {
		t.Fatalf("query upload log: %v", err)
	}
	if ip != "198.51.100.25" {
		t.Fatalf("log ip = %q, want client IP", ip)
	}
}

func TestRecordExplorerDownloadUpdatesAnonUserAndFileDownloads(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const relPath = "public/readme.txt"
	owner := anonAuthHashForIP("203.0.113.10")
	if _, err := srv.store.UpsertUserSession(owner, &net.TCPAddr{IP: net.ParseIP("203.0.113.10")}); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	if err := srv.store.UpdateFileWrite(owner, owner, relPath, 11, 11); err != nil {
		t.Fatalf("register file: %v", err)
	}

	evt := explorerevents.Event{
		Kind:       explorerevents.KindDownload,
		ClientIP:   "198.51.100.24",
		RemoteAddr: "198.51.100.24:49153",
		Path:       relPath,
		Bytes:      11,
		Method:     "GET",
		URLPath:    "/" + relPath,
	}
	if err := srv.recordExplorerEvent(evt); err != nil {
		t.Fatalf("record explorer download: %v", err)
	}

	hash := anonAuthHashForIP("198.51.100.24")
	stats, err := srv.store.GetUserStats(hash)
	if err != nil {
		t.Fatalf("get downloader stats: %v", err)
	}
	if stats.DownloadCount != 1 || stats.DownloadBytes != 11 {
		t.Fatalf("unexpected download stats: count=%d bytes=%d", stats.DownloadCount, stats.DownloadBytes)
	}
	meta, err := srv.store.GetFileAdminMeta(relPath)
	if err != nil {
		t.Fatalf("get file meta: %v", err)
	}
	if meta.Downloads != 1 {
		t.Fatalf("file downloads = %d, want 1", meta.Downloads)
	}

	var rawMeta string
	if err := srv.store.db.QueryRow(`
		SELECT IFNULL(meta, '')
		FROM log
		WHERE event = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventDownload)).Scan(&rawMeta); err != nil {
		t.Fatalf("query download log: %v", err)
	}
	metaObj := parseJSONMap(rawMeta)
	if got := int64FromAny(metaObj["delta"]); got != 0 {
		t.Fatalf("download delta = %d, want 0", got)
	}
}

func stringSliceFromAny(v any) []string {
	switch values := v.(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
