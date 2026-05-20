package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleAdminRecentUploadsIncludesMeta(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 2222}
	srv.store.LogEvent(EventUpload, "upload-user", "sess-upload", addr,
		"path", "web/report.txt",
		"size", int64(12),
		"delta", int64(7),
		"source", "explorer",
		"explorer_meta", map[string]any{
			"headers": map[string][]string{
				"X-Explorer-Test": []string{"recent-upload"},
			},
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/uploads/recent?range=24h", nil)
	w := httptest.NewRecorder()

	srv.handleAdminRecentUploads(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/uploads/recent status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		Uploads []struct {
			Path    string `json:"path"`
			Size    int64  `json:"size"`
			Delta   int64  `json:"delta"`
			Session string `json:"session"`
			Meta    string `json:"meta"`
		} `json:"uploads"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload.Uploads) != 1 {
		t.Fatalf("unexpected uploads length: got=%d want=%d", len(payload.Uploads), 1)
	}
	if payload.Uploads[0].Path != "web/report.txt" || payload.Uploads[0].Size != 12 || payload.Uploads[0].Delta != 7 || payload.Uploads[0].Session != "sess-upload" {
		t.Fatalf("unexpected upload row: %#v", payload.Uploads[0])
	}
	assertMetaHeader(t, payload.Uploads[0].Meta, "X-Explorer-Test", "recent-upload")
}

func TestHandleAdminActorIncludesTouchedFiles(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const relPath = "actor/report.txt"
	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		t.Fatalf("mkdir actor dir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte("actor report"), permFile); err != nil {
		t.Fatalf("write actor file: %v", err)
	}
	if _, err := srv.store.UpsertUserSession("actor-user", &net.TCPAddr{IP: net.ParseIP("198.51.100.21"), Port: 2222}); err != nil {
		t.Fatalf("upsert actor user: %v", err)
	}
	if err := srv.store.EnsureDirectory("actor-user", "actor"); err != nil {
		t.Fatalf("ensure actor dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite("actor-user", "actor-user", relPath, int64(len("actor report")), int64(len("actor report"))); err != nil {
		t.Fatalf("register actor file: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.21"), Port: 2222}
	srv.store.LogEvent(EventUpload, "actor-user", "actor-session", addr, "path", relPath, "size", int64(12))
	srv.store.LogEvent(EventDownload, "actor-user", "actor-session", addr, "path", relPath, "size", int64(12))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/actor?type=ip&value=198.51.100.21&range=24h", nil)
	w := httptest.NewRecorder()
	srv.handleAdminActor(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/actor status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		Summary map[string]any `json:"summary"`
		Files   []struct {
			Path          string `json:"path"`
			Size          int64  `json:"size"`
			SizeHuman     string `json:"size_human"`
			EventCount    int64  `json:"event_count"`
			UploadCount   int64  `json:"upload_count"`
			DownloadCount int64  `json:"download_count"`
			LastEvent     string `json:"last_event"`
		} `json:"files"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode actor payload: %v", err)
	}
	if got := int64FromAny(payload.Summary["files"]); got != 1 {
		t.Fatalf("unexpected actor summary files: got=%d", got)
	}
	if len(payload.Files) != 1 {
		t.Fatalf("expected one touched file, got %#v", payload.Files)
	}
	file := payload.Files[0]
	if file.Path != relPath || file.Size <= 0 || file.SizeHuman == "" || file.EventCount != 2 || file.UploadCount != 1 || file.DownloadCount != 1 {
		t.Fatalf("unexpected touched file row: %#v", file)
	}
	if file.LastEvent != string(EventDownload) {
		t.Fatalf("unexpected last event: got=%q want=%q", file.LastEvent, EventDownload)
	}
}
