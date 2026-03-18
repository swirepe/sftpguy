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
	if err := srv.store.RecordDownload(ownerHash, 9); err != nil {
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
	if got := stringFromAny(payload["owner_details_url"]); got != "/admin/api/users/"+url.PathEscape(ownerHash) {
		t.Fatalf("unexpected owner_details_url: got=%q want=%q", got, "/admin/api/users/"+url.PathEscape(ownerHash))
	}
}
