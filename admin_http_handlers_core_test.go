package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHandleAdminSummaryIncludesStorageVolumes(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	if err := os.WriteFile(srv.cfg.LogFile+".1", []byte("rotated one"), permFile); err != nil {
		t.Fatalf("write rotated log: %v", err)
	}
	if err := os.WriteFile(srv.cfg.LogFile+".2.gz", []byte("rotated two"), permFile); err != nil {
		t.Fatalf("write compressed rotated log: %v", err)
	}
	if err := os.WriteFile(srv.cfg.LogFile+"-20260519", []byte("dated rotated log"), permFile); err != nil {
		t.Fatalf("write dated rotated log: %v", err)
	}
	if err := os.WriteFile(srv.cfg.LogFile+".old", []byte("not a logrotate file"), permFile); err != nil {
		t.Fatalf("write unrelated log sibling: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/summary", nil)
	w := httptest.NewRecorder()

	srv.handleAdminSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/summary status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		Storage []struct {
			ID         string `json:"id"`
			Label      string `json:"label"`
			Path       string `json:"path"`
			FileBytes  int64  `json:"file_bytes"`
			FileSize   string `json:"file_size"`
			FileExists bool   `json:"file_exists"`
			Sidecars   []struct {
				Label     string `json:"label"`
				Path      string `json:"path"`
				SizeBytes int64  `json:"size_bytes"`
				Size      string `json:"size"`
				Exists    bool   `json:"exists"`
			} `json:"sidecars"`
			TotalBytes int64  `json:"total_bytes"`
			FreeBytes  int64  `json:"free_bytes"`
			Error      string `json:"error"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode summary payload: %v", err)
	}
	if len(payload.Storage) != 3 {
		t.Fatalf("expected upload, log, and database storage rows, got %d: %#v", len(payload.Storage), payload.Storage)
	}

	seen := map[string]bool{}
	logSidecars := map[string]bool{}
	for _, row := range payload.Storage {
		seen[row.ID] = true
		if row.Label == "" {
			t.Fatalf("storage row %q missing label", row.ID)
		}
		if row.Path == "" {
			t.Fatalf("storage row %q missing path", row.ID)
		}
		if row.Error != "" {
			t.Fatalf("storage row %q returned error: %s", row.ID, row.Error)
		}
		if row.TotalBytes <= 0 {
			t.Fatalf("storage row %q has invalid total bytes: %d", row.ID, row.TotalBytes)
		}
		if row.FreeBytes < 0 {
			t.Fatalf("storage row %q has invalid free bytes: %d", row.ID, row.FreeBytes)
		}
		if row.FreeBytes > row.TotalBytes {
			t.Fatalf("storage row %q has free bytes greater than total bytes: free=%d total=%d", row.ID, row.FreeBytes, row.TotalBytes)
		}
		if row.ID == "log" || row.ID == "database" {
			if !row.FileExists {
				t.Fatalf("storage row %q should report its backing file exists", row.ID)
			}
			if row.FileSize == "" {
				t.Fatalf("storage row %q missing formatted file size", row.ID)
			}
			if row.FileBytes < 0 {
				t.Fatalf("storage row %q has invalid file bytes: %d", row.ID, row.FileBytes)
			}
		}
		if row.ID == "log" {
			for _, file := range row.Sidecars {
				if !file.Exists {
					t.Fatalf("log sidecar %q should report that it exists", file.Path)
				}
				if file.Size == "" {
					t.Fatalf("log sidecar %q missing formatted file size", file.Path)
				}
				if file.SizeBytes <= 0 {
					t.Fatalf("log sidecar %q has invalid file bytes: %d", file.Path, file.SizeBytes)
				}
				logSidecars[strings.TrimPrefix(file.Path, srv.cfg.LogFile)] = true
			}
		}
	}
	for _, id := range []string{"uploads", "log", "database"} {
		if !seen[id] {
			t.Fatalf("summary storage rows missing %q: %#v", id, payload.Storage)
		}
	}
	for _, suffix := range []string{".1", ".2.gz", "-20260519"} {
		if !logSidecars[suffix] {
			t.Fatalf("log storage row missing rotated sidecar suffix %q: %#v", suffix, logSidecars)
		}
	}
	if logSidecars[".old"] {
		t.Fatalf("log storage row included unrelated sibling as sidecar: %#v", logSidecars)
	}
}
