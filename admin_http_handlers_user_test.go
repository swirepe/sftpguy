package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleAdminUserReturnsSnakeCaseStats(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "admin-user-json-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.44"),
		Port: 2222,
	}); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, "owned.txt", 5, 5); err != nil {
		t.Fatalf("register owned file: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, "owned.txt", 9); err != nil {
		t.Fatalf("record download: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users/"+ownerHash, nil)
	w := httptest.NewRecorder()

	srv.handleAdminUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/users/:hash status=%d body=%s", w.Code, w.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	stats, ok := payload["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats payload missing or wrong type: %#v", payload["stats"])
	}
	if _, ok := stats["LastAddress"]; ok {
		t.Fatalf("expected snake_case stats keys, got legacy key in %#v", stats)
	}
	if got := stringFromAny(stats["last_address"]); got != "203.0.113.44" {
		t.Fatalf("unexpected last_address: got=%q want=%q", got, "203.0.113.44")
	}
	if got := int64FromAny(stats["seen"]); got != 1 {
		t.Fatalf("unexpected seen: got=%d want=%d", got, 1)
	}
	if got := int64FromAny(stats["upload_count"]); got != 1 {
		t.Fatalf("unexpected upload_count: got=%d want=%d", got, 1)
	}
	if got := int64FromAny(stats["upload_bytes"]); got != 5 {
		t.Fatalf("unexpected upload_bytes: got=%d want=%d", got, 5)
	}
	if got := int64FromAny(stats["download_count"]); got != 1 {
		t.Fatalf("unexpected download_count: got=%d want=%d", got, 1)
	}
	if got := int64FromAny(stats["download_bytes"]); got != 9 {
		t.Fatalf("unexpected download_bytes: got=%d want=%d", got, 9)
	}
}

func TestAdminExplorerPreviewIncludesOwnerDetailsURL(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "explorer-preview-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.88"),
		Port: 2222,
	}); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}

	const relPath = "nested/report.txt"
	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		t.Fatalf("mkdir nested dir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte("hello"), permFile); err != nil {
		t.Fatalf("write explorer file: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "nested"); err != nil {
		t.Fatalf("ensure nested dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, relPath, 5, 5); err != nil {
		t.Fatalf("register file metadata: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, relPath, 5); err != nil {
		t.Fatalf("record file download: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/explorer/"+relPath+"?preview=true", nil)
	w := httptest.NewRecorder()

	srv.handleAdminExplorer(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET preview status=%d body=%s", w.Code, w.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode preview payload: %v", err)
	}

	if got := stringFromAny(payload["owner"]); got != ownerHash {
		t.Fatalf("unexpected owner: got=%q want=%q", got, ownerHash)
	}
	if got := int64FromAny(payload["downloads"]); got != 1 {
		t.Fatalf("unexpected downloads: got=%d want=%d", got, 1)
	}
	if got := stringFromAny(payload["owner_details_url"]); got != "/admin/api/users/"+url.PathEscape(ownerHash) {
		t.Fatalf("unexpected owner_details_url: got=%q want=%q", got, "/admin/api/users/"+url.PathEscape(ownerHash))
	}
}

func TestHandleAdminUsersAndFilesExposeSeenAndDownloads(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "admin-user-list-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.60"),
		Port: 2222,
	}); err != nil {
		t.Fatalf("upsert first owner session: %v", err)
	}
	if _, err := srv.store.UpsertUserSession(ownerHash, &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.60"),
		Port: 2222,
	}); err != nil {
		t.Fatalf("upsert second owner session: %v", err)
	}

	const relPath = "downloads/report.txt"
	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		t.Fatalf("mkdir download dir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte("report"), permFile); err != nil {
		t.Fatalf("write report file: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "downloads"); err != nil {
		t.Fatalf("ensure download dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, relPath, int64(len("report")), int64(len("report"))); err != nil {
		t.Fatalf("register report file: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, relPath, int64(len("report"))); err != nil {
		t.Fatalf("record first report download: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, relPath, int64(len("report"))); err != nil {
		t.Fatalf("record second report download: %v", err)
	}

	usersReq := httptest.NewRequest(http.MethodGet, "/admin/api/users?q="+ownerHash, nil)
	usersW := httptest.NewRecorder()
	srv.handleAdminUsers(usersW, usersReq)
	if usersW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/users status=%d body=%s", usersW.Code, usersW.Body.String())
	}

	var usersPayload map[string]any
	if err := json.Unmarshal(usersW.Body.Bytes(), &usersPayload); err != nil {
		t.Fatalf("decode users payload: %v", err)
	}
	users, ok := usersPayload["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("unexpected users payload: %#v", usersPayload["users"])
	}
	userRow, ok := users[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected user row payload: %#v", users[0])
	}
	if got := int64FromAny(userRow["seen"]); got != 2 {
		t.Fatalf("unexpected users.seen: got=%d want=%d", got, 2)
	}

	filesReq := httptest.NewRequest(http.MethodGet, "/admin/api/files?path=downloads", nil)
	filesW := httptest.NewRecorder()
	srv.handleAdminFiles(filesW, filesReq)
	if filesW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/files status=%d body=%s", filesW.Code, filesW.Body.String())
	}

	var filesPayload map[string]any
	if err := json.Unmarshal(filesW.Body.Bytes(), &filesPayload); err != nil {
		t.Fatalf("decode files payload: %v", err)
	}
	entries, ok := filesPayload["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected file entries payload: %#v", filesPayload["entries"])
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected file entry payload: %#v", entries[0])
	}
	if got := int64FromAny(entry["downloads"]); got != 2 {
		t.Fatalf("unexpected file downloads: got=%d want=%d", got, 2)
	}

	searchReq := httptest.NewRequest(http.MethodGet, "/admin/api/files/search?owner="+url.QueryEscape(ownerHash), nil)
	searchW := httptest.NewRecorder()
	srv.handleAdminFileSearch(searchW, searchReq)
	if searchW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/files/search status=%d body=%s", searchW.Code, searchW.Body.String())
	}

	var searchPayload map[string]any
	if err := json.Unmarshal(searchW.Body.Bytes(), &searchPayload); err != nil {
		t.Fatalf("decode file search payload: %v", err)
	}
	results, ok := searchPayload["results"].([]any)
	if !ok || len(results) != 2 {
		t.Fatalf("unexpected file search results payload: %#v", searchPayload["results"])
	}

	foundFile := false
	for _, raw := range results {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if stringFromAny(row["path"]) != relPath {
			continue
		}
		foundFile = true
		if got := int64FromAny(row["downloads"]); got != 2 {
			t.Fatalf("unexpected search downloads: got=%d want=%d", got, 2)
		}
	}
	if !foundFile {
		t.Fatalf("expected %q in search results, got %#v", relPath, searchPayload["results"])
	}
}
