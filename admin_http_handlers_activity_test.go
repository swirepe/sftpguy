package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
