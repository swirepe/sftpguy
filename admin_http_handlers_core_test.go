package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAdminSummaryIncludesStorageVolumes(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

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
	}
	for _, id := range []string{"uploads", "log", "database"} {
		if !seen[id] {
			t.Fatalf("summary storage rows missing %q: %#v", id, payload.Storage)
		}
	}
}
