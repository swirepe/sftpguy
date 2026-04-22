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

func TestHandleAdminDownloadsReturnsFileAndRecentDownloadStats(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "download-owner-hash"
	const downloaderA = "download-user-a"
	const downloaderB = "download-user-b"

	ownerAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 2222}
	userAAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 2222}
	userBAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.11"), Port: 2222}

	for _, entry := range []struct {
		hash string
		addr *net.TCPAddr
	}{
		{ownerHash, ownerAddr},
		{downloaderA, userAAddr},
		{downloaderB, userBAddr},
	} {
		if _, err := srv.store.UpsertUserSession(entry.hash, entry.addr); err != nil {
			t.Fatalf("upsert user session for %s: %v", entry.hash, err)
		}
	}

	type fileSeed struct {
		relPath string
		size    int64
	}
	files := []fileSeed{
		{relPath: "reports/q1.csv", size: 12},
		{relPath: "reports/q2.csv", size: 18},
	}
	for _, file := range files {
		fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(file.relPath))
		if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
			t.Fatalf("mkdir for %s: %v", file.relPath, err)
		}
		if err := os.WriteFile(fullPath, make([]byte, file.size), permFile); err != nil {
			t.Fatalf("write file %s: %v", file.relPath, err)
		}
		dir := filepath.Dir(file.relPath)
		if dir != "." {
			if err := srv.store.EnsureDirectory(ownerHash, dir); err != nil {
				t.Fatalf("ensure dir %s: %v", dir, err)
			}
		}
		if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, file.relPath, file.size, file.size); err != nil {
			t.Fatalf("register file %s: %v", file.relPath, err)
		}
	}

	recordDownload := func(hash string, addr net.Addr, sessionID, relPath string, size int64) {
		t.Helper()
		srv.store.LogEvent(EventDownload, hash, sessionID, addr,
			"path", relPath,
			"size", size,
			"duration_ms", 25,
			"avg_bytes_per_sec", size*40,
		)
		if err := srv.store.RecordDownload(hash, relPath, size); err != nil {
			t.Fatalf("record download for %s: %v", relPath, err)
		}
	}

	recordDownload(downloaderA, userAAddr, "sess-a-1", "reports/q1.csv", 12)
	recordDownload(downloaderB, userBAddr, "sess-b-1", "reports/q1.csv", 12)
	recordDownload(downloaderA, userAAddr, "sess-a-2", "reports/q2.csv", 18)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/downloads?range=24h", nil)
	w := httptest.NewRecorder()

	srv.handleAdminDownloads(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/downloads status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		Summary struct {
			RangeDownloads      int64 `json:"range_downloads"`
			RangeUniqueFiles    int64 `json:"range_unique_files"`
			RangeUniqueUsers    int64 `json:"range_unique_users"`
			RangeUniqueIPs      int64 `json:"range_unique_ips"`
			FilesEverDownloaded int64 `json:"files_ever_downloaded"`
			AllTimeDownloads    int64 `json:"all_time_downloads"`
		} `json:"summary"`
		Files []struct {
			Path               string `json:"path"`
			DownloadsTotal     int64  `json:"downloads_total"`
			DownloadsInRange   int64  `json:"downloads_in_range"`
			UniqueUsersInRange int64  `json:"unique_users_in_range"`
			LastDownloader     string `json:"last_downloader"`
		} `json:"files"`
		Downloaders []struct {
			UserID        string `json:"user_id"`
			DownloadCount int64  `json:"download_count"`
			UniqueFiles   int64  `json:"unique_files"`
		} `json:"downloaders"`
		Recent []struct {
			Path           string `json:"path"`
			Size           int64  `json:"size"`
			DurationMS     int64  `json:"duration_ms"`
			AvgBytesPerSec int64  `json:"avg_bytes_per_sec"`
			Session        string `json:"session"`
		} `json:"recent"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if got := payload.Summary.RangeDownloads; got != 3 {
		t.Fatalf("unexpected range_downloads: got=%d want=%d", got, 3)
	}
	if got := payload.Summary.RangeUniqueFiles; got != 2 {
		t.Fatalf("unexpected range_unique_files: got=%d want=%d", got, 2)
	}
	if got := payload.Summary.RangeUniqueUsers; got != 2 {
		t.Fatalf("unexpected range_unique_users: got=%d want=%d", got, 2)
	}
	if got := payload.Summary.RangeUniqueIPs; got != 2 {
		t.Fatalf("unexpected range_unique_ips: got=%d want=%d", got, 2)
	}
	if got := payload.Summary.FilesEverDownloaded; got != 2 {
		t.Fatalf("unexpected files_ever_downloaded: got=%d want=%d", got, 2)
	}
	if got := payload.Summary.AllTimeDownloads; got != 3 {
		t.Fatalf("unexpected all_time_downloads: got=%d want=%d", got, 3)
	}

	if len(payload.Files) != 2 {
		t.Fatalf("unexpected files payload length: got=%d want=%d", len(payload.Files), 2)
	}

	var reportRowFound bool
	for _, row := range payload.Files {
		if row.Path != "reports/q1.csv" {
			continue
		}
		reportRowFound = true
		if got := row.DownloadsTotal; got != 2 {
			t.Fatalf("unexpected downloads_total for q1: got=%d want=%d", got, 2)
		}
		if got := row.DownloadsInRange; got != 2 {
			t.Fatalf("unexpected downloads_in_range for q1: got=%d want=%d", got, 2)
		}
		if got := row.UniqueUsersInRange; got != 2 {
			t.Fatalf("unexpected unique_users_in_range for q1: got=%d want=%d", got, 2)
		}
		if got := row.LastDownloader; got != downloaderB {
			t.Fatalf("unexpected last_downloader for q1: got=%q want=%q", got, downloaderB)
		}
	}
	if !reportRowFound {
		t.Fatalf("expected q1 file row in payload: %#v", payload.Files)
	}

	if len(payload.Downloaders) != 2 {
		t.Fatalf("unexpected downloaders payload length: got=%d want=%d", len(payload.Downloaders), 2)
	}
	if payload.Downloaders[0].UserID != downloaderA || payload.Downloaders[0].DownloadCount != 2 || payload.Downloaders[0].UniqueFiles != 2 {
		t.Fatalf("unexpected top downloader row: %#v", payload.Downloaders[0])
	}

	if len(payload.Recent) != 3 {
		t.Fatalf("unexpected recent payload length: got=%d want=%d", len(payload.Recent), 3)
	}
	if payload.Recent[0].Path != "reports/q2.csv" {
		t.Fatalf("expected newest recent path to be q2, got %#v", payload.Recent[0])
	}
	if payload.Recent[0].Size != 18 || payload.Recent[0].DurationMS != 25 || payload.Recent[0].AvgBytesPerSec != 720 || payload.Recent[0].Session != "sess-a-2" {
		t.Fatalf("unexpected recent row payload: %#v", payload.Recent[0])
	}
}

func TestHandleAdminDownloadsIncludesSelectedFileHistory(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "download-history-owner"
	const downloaderA = "download-history-user-a"
	const downloaderB = "download-history-user-b"
	const relPath = "reports/q1.csv"

	ownerAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 2222}
	userAAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 2222}
	userBAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.11"), Port: 2222}

	for _, entry := range []struct {
		hash string
		addr *net.TCPAddr
	}{
		{ownerHash, ownerAddr},
		{downloaderA, userAAddr},
		{downloaderB, userBAddr},
	} {
		if _, err := srv.store.UpsertUserSession(entry.hash, entry.addr); err != nil {
			t.Fatalf("upsert user session for %s: %v", entry.hash, err)
		}
	}

	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		t.Fatalf("mkdir for %s: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, []byte("quarterly-report"), permFile); err != nil {
		t.Fatalf("write file %s: %v", relPath, err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "reports"); err != nil {
		t.Fatalf("ensure dir reports: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, relPath, int64(len("quarterly-report")), int64(len("quarterly-report"))); err != nil {
		t.Fatalf("register file %s: %v", relPath, err)
	}

	recordDownload := func(hash string, addr net.Addr, sessionID string, size int64) {
		t.Helper()
		srv.store.LogEvent(EventDownload, hash, sessionID, addr,
			"path", relPath,
			"size", size,
			"duration_ms", 25,
			"avg_bytes_per_sec", size*40,
		)
		if err := srv.store.RecordDownload(hash, relPath, size); err != nil {
			t.Fatalf("record download for %s: %v", relPath, err)
		}
	}

	recordDownload(downloaderA, userAAddr, "sess-a-1", 16)
	recordDownload(downloaderB, userBAddr, "sess-b-1", 16)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/downloads?range=24h&path=reports/q1.csv&download_history_limit=1", nil)
	w := httptest.NewRecorder()

	srv.handleAdminDownloads(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/downloads selected file status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		SelectedPath string `json:"selected_path"`
		SelectedFile struct {
			Path               string `json:"path"`
			Owner              string `json:"owner"`
			DownloadsTotal     int64  `json:"downloads_total"`
			DownloadsInRange   int64  `json:"downloads_in_range"`
			UniqueUsersInRange int64  `json:"unique_users_in_range"`
			LastDownloader     string `json:"last_downloader"`
			LastIP             string `json:"last_ip"`
		} `json:"selected_file"`
		SelectedHistory []struct {
			UserID  string `json:"user_id"`
			IP      string `json:"ip"`
			Path    string `json:"path"`
			Session string `json:"session"`
		} `json:"selected_history"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if payload.SelectedPath != relPath {
		t.Fatalf("unexpected selected_path: got=%q want=%q", payload.SelectedPath, relPath)
	}
	if payload.SelectedFile.Path != relPath {
		t.Fatalf("unexpected selected_file.path: got=%q want=%q", payload.SelectedFile.Path, relPath)
	}
	if payload.SelectedFile.Owner != ownerHash {
		t.Fatalf("unexpected selected_file.owner: got=%q want=%q", payload.SelectedFile.Owner, ownerHash)
	}
	if payload.SelectedFile.DownloadsTotal != 2 {
		t.Fatalf("unexpected selected_file.downloads_total: got=%d want=%d", payload.SelectedFile.DownloadsTotal, 2)
	}
	if payload.SelectedFile.DownloadsInRange != 2 {
		t.Fatalf("unexpected selected_file.downloads_in_range: got=%d want=%d", payload.SelectedFile.DownloadsInRange, 2)
	}
	if payload.SelectedFile.UniqueUsersInRange != 2 {
		t.Fatalf("unexpected selected_file.unique_users_in_range: got=%d want=%d", payload.SelectedFile.UniqueUsersInRange, 2)
	}
	if payload.SelectedFile.LastDownloader != downloaderB {
		t.Fatalf("unexpected selected_file.last_downloader: got=%q want=%q", payload.SelectedFile.LastDownloader, downloaderB)
	}
	if payload.SelectedFile.LastIP != "198.51.100.11" {
		t.Fatalf("unexpected selected_file.last_ip: got=%q want=%q", payload.SelectedFile.LastIP, "198.51.100.11")
	}
	if len(payload.SelectedHistory) != 1 {
		t.Fatalf("unexpected selected_history length: got=%d want=%d", len(payload.SelectedHistory), 1)
	}
	if payload.SelectedHistory[0].UserID != downloaderB || payload.SelectedHistory[0].Session != "sess-b-1" || payload.SelectedHistory[0].Path != relPath || payload.SelectedHistory[0].IP != "198.51.100.11" {
		t.Fatalf("unexpected selected history row: %#v", payload.SelectedHistory[0])
	}
}
