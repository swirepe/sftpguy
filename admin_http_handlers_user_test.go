package main

import (
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

func TestAdminPreviewAPIIncludesMetadataAndThumbnail(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "admin-preview-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, &net.TCPAddr{
		IP:   net.ParseIP("203.0.113.89"),
		Port: 2222,
	}); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}

	const relPath = "nested/pixel.png"
	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		t.Fatalf("mkdir nested dir: %v", err)
	}
	if err := writeTestPNG(fullPath); err != nil {
		t.Fatalf("write png: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat png: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "nested"); err != nil {
		t.Fatalf("ensure nested dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, relPath, info.Size(), info.Size()); err != nil {
		t.Fatalf("register file metadata: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, relPath, info.Size()); err != nil {
		t.Fatalf("record first download: %v", err)
	}
	if err := srv.store.RecordDownload(ownerHash, relPath, info.Size()); err != nil {
		t.Fatalf("record second download: %v", err)
	}

	previewReq := httptest.NewRequest(http.MethodGet, "/admin/api/preview?path="+url.QueryEscape(relPath), nil)
	previewW := httptest.NewRecorder()
	srv.handleAdminPreview(previewW, previewReq)

	if previewW.Code != http.StatusOK {
		t.Fatalf("GET admin preview status=%d body=%s", previewW.Code, previewW.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(previewW.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode preview payload: %v", err)
	}
	if got := stringFromAny(payload["owner"]); got != ownerHash {
		t.Fatalf("unexpected owner: got=%q want=%q", got, ownerHash)
	}
	if got := int64FromAny(payload["downloads"]); got != 2 {
		t.Fatalf("unexpected downloads: got=%d want=%d", got, 2)
	}
	if got := stringFromAny(payload["download_url"]); got != "/admin/explorer/nested/pixel.png" {
		t.Fatalf("unexpected download_url: got=%q", got)
	}
	thumbURL := stringFromAny(payload["thumb_url"])
	if thumbURL == "" {
		t.Fatalf("expected thumb_url in preview payload: %#v", payload)
	}
	parsedThumb, err := url.Parse(thumbURL)
	if err != nil {
		t.Fatalf("parse thumb_url: %v", err)
	}
	if parsedThumb.Path != "/admin/api/thumbnail" || parsedThumb.Query().Get("path") != relPath {
		t.Fatalf("unexpected thumb_url: %q", thumbURL)
	}

	thumbReq := httptest.NewRequest(http.MethodGet, thumbURL, nil)
	thumbW := httptest.NewRecorder()
	srv.handleAdminThumbnail(thumbW, thumbReq)
	if thumbW.Code != http.StatusOK {
		t.Fatalf("GET thumbnail status=%d body=%s", thumbW.Code, thumbW.Body.String())
	}
	if got := thumbW.Header().Get("Content-Type"); got != "image/jpeg" {
		t.Fatalf("unexpected thumbnail content-type: %q", got)
	}
	if got := thumbW.Header().Get("Last-Modified"); got == "" {
		t.Fatalf("expected Last-Modified header on thumbnail")
	}
	if got := thumbW.Header().Get("Cache-Control"); !strings.Contains(got, "max-age") {
		t.Fatalf("expected cache header on thumbnail, got %q", got)
	}

	cachedReq := httptest.NewRequest(http.MethodGet, thumbURL, nil)
	cachedReq.Header.Set("If-Modified-Since", thumbW.Header().Get("Last-Modified"))
	cachedW := httptest.NewRecorder()
	srv.handleAdminThumbnail(cachedW, cachedReq)
	if cachedW.Code != http.StatusNotModified {
		t.Fatalf("expected cached thumbnail 304, got %d", cachedW.Code)
	}
}

func TestAdminPreviewAPIRejectsTraversalAndMissingPaths(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	traversalReq := httptest.NewRequest(http.MethodGet, "/admin/api/preview?path=../secret.txt", nil)
	traversalW := httptest.NewRecorder()
	srv.handleAdminPreview(traversalW, traversalReq)
	if traversalW.Code != http.StatusBadRequest {
		t.Fatalf("expected traversal preview request to return 400, got %d", traversalW.Code)
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/admin/api/preview?path=missing.txt", nil)
	missingW := httptest.NewRecorder()
	srv.handleAdminPreview(missingW, missingReq)
	if missingW.Code != http.StatusNotFound {
		t.Fatalf("expected missing preview request to return 404, got %d", missingW.Code)
	}

	thumbReq := httptest.NewRequest(http.MethodGet, "/admin/api/thumbnail?path=../secret.png", nil)
	thumbW := httptest.NewRecorder()
	srv.handleAdminThumbnail(thumbW, thumbReq)
	if thumbW.Code != http.StatusBadRequest {
		t.Fatalf("expected traversal thumbnail request to return 400, got %d", thumbW.Code)
	}
}

func writeTestPNG(path string) error {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 240, G: 80, B: 40, A: 255})
	img.Set(1, 0, color.RGBA{R: 40, G: 160, B: 120, A: 255})
	img.Set(0, 1, color.RGBA{R: 40, G: 80, B: 200, A: 255})
	img.Set(1, 1, color.RGBA{R: 245, G: 210, B: 80, A: 255})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
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
