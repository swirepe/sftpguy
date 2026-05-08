package main

import (
	"net"
	"testing"

	"sftpguy/internal/explorerevents"
)

func TestRecordExplorerUploadUsesAnonAuthFromClientIP(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	evt := explorerevents.Event{
		Kind:           explorerevents.KindUpload,
		ClientIP:       "198.51.100.23",
		RemoteAddr:     "198.51.100.23:49152",
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
	if userID != hash || ip != "198.51.100.23" || path != "web/report.txt" || session != "explorer" {
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
