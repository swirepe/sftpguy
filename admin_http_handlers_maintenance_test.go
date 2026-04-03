package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleAdminBadFilesGetSaveAndMark(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	getReq := httptest.NewRequest(http.MethodGet, "/admin/api/maintenance/bad-files", nil)
	getW := httptest.NewRecorder()
	srv.handleAdminBadFiles(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/maintenance/bad-files status = %d, body=%s", getW.Code, getW.Body.String())
	}

	var getResp struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(getW.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode bad files GET response: %v", err)
	}
	if getResp.Path != srv.store.badFilesPath {
		t.Fatalf("unexpected bad files path: got=%q want=%q", getResp.Path, srv.store.badFilesPath)
	}

	saveBody, _ := json.Marshal(map[string]any{"content": "not-a-hash\n"})
	saveReq := httptest.NewRequest(http.MethodPost, "/admin/api/maintenance/bad-files", bytes.NewReader(saveBody))
	saveW := httptest.NewRecorder()
	srv.handleAdminBadFiles(saveW, saveReq)
	if saveW.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/maintenance/bad-files status = %d, body=%s", saveW.Code, saveW.Body.String())
	}

	var saveResp struct {
		BadFiles struct {
			InvalidCount int `json:"invalid_count"`
		} `json:"bad_files"`
	}
	if err := json.Unmarshal(saveW.Body.Bytes(), &saveResp); err != nil {
		t.Fatalf("decode bad files save response: %v", err)
	}
	if saveResp.BadFiles.InvalidCount != 1 {
		t.Fatalf("expected invalid_count=1, got %d", saveResp.BadFiles.InvalidCount)
	}

	relPath := "badme.bin"
	fullPath := filepath.Join(srv.absUploadDir, relPath)
	if err := os.WriteFile(fullPath, []byte("definitely bad"), permFile); err != nil {
		t.Fatalf("write upload file: %v", err)
	}

	markBody, _ := json.Marshal(map[string]any{"path": relPath})
	markReq := httptest.NewRequest(http.MethodPost, "/admin/api/maintenance/mark-bad", bytes.NewReader(markBody))
	markW := httptest.NewRecorder()
	srv.handleAdminMarkBadFile(markW, markReq)
	if markW.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/maintenance/mark-bad status = %d, body=%s", markW.Code, markW.Body.String())
	}

	var markResp struct {
		Hash           string `json:"hash"`
		AlreadyPresent bool   `json:"already_present"`
	}
	if err := json.Unmarshal(markW.Body.Bytes(), &markResp); err != nil {
		t.Fatalf("decode mark-bad response: %v", err)
	}
	if markResp.Hash == "" {
		t.Fatal("expected mark-bad response to include hash")
	}
	if markResp.AlreadyPresent {
		t.Fatal("expected first mark-bad call to add a new hash")
	}
	if matchedName, matched, err := srv.store.badFileList.MatchFile(fullPath); err != nil {
		t.Fatalf("match marked file: %v", err)
	} else if !matched {
		t.Fatal("expected marked file to be present in bad file list")
	} else if matchedName != filepath.Base(relPath) {
		t.Fatalf("unexpected bad-file name: got=%q want=%q", matchedName, filepath.Base(relPath))
	}

	markAgainReq := httptest.NewRequest(http.MethodPost, "/admin/api/maintenance/mark-bad", bytes.NewReader(markBody))
	markAgainW := httptest.NewRecorder()
	srv.handleAdminMarkBadFile(markAgainW, markAgainReq)
	if markAgainW.Code != http.StatusOK {
		t.Fatalf("second POST /admin/api/maintenance/mark-bad status = %d, body=%s", markAgainW.Code, markAgainW.Body.String())
	}

	var markAgainResp struct {
		AlreadyPresent bool `json:"already_present"`
	}
	if err := json.Unmarshal(markAgainW.Body.Bytes(), &markAgainResp); err != nil {
		t.Fatalf("decode second mark-bad response: %v", err)
	}
	if !markAgainResp.AlreadyPresent {
		t.Fatal("expected second mark-bad call to report already_present=true")
	}
}

func TestHandleAdminMarkBadFileRejectsZeroLengthFile(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const relPath = "empty.bin"
	fullPath := filepath.Join(srv.absUploadDir, relPath)
	if err := os.WriteFile(fullPath, nil, permFile); err != nil {
		t.Fatalf("write empty upload file: %v", err)
	}

	markBody, _ := json.Marshal(map[string]any{"path": relPath})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/maintenance/mark-bad", bytes.NewReader(markBody))
	w := httptest.NewRecorder()
	srv.handleAdminMarkBadFile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/api/maintenance/mark-bad status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != errZeroLengthBadFile.Error() {
		t.Fatalf("unexpected mark-bad error: got=%q want=%q", got, errZeroLengthBadFile.Error())
	}

	content, err := os.ReadFile(srv.store.badFilesPath)
	if err != nil {
		t.Fatalf("read bad files content: %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("expected empty bad files content after rejected mark-bad, got %q", string(content))
	}
}

func TestHandleAdminMaintenanceRunAndStatus(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	srv.store.RegisterFile("gone.txt", systemOwner, 0, false)
	const ownerHash = "maintenance-http-sshdbot-owner"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.77"), Port: 2222}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert sshdbot owner session: %v", err)
	}

	const sshdbotRel = ".13579/sshd"
	sshdbotPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(sshdbotRel))
	if err := os.MkdirAll(filepath.Dir(sshdbotPath), permDir); err != nil {
		t.Fatalf("mkdir sshdbot dir: %v", err)
	}
	if err := os.WriteFile(sshdbotPath, []byte("sshdbot payload"), permFile); err != nil {
		t.Fatalf("write sshdbot payload: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, ".13579"); err != nil {
		t.Fatalf("ensure sshdbot dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, sshdbotRel, int64(len("sshdbot payload")), int64(len("sshdbot payload"))); err != nil {
		t.Fatalf("register sshdbot payload: %v", err)
	}

	runReq := httptest.NewRequest(http.MethodPost, "/admin/api/maintenance/run", nil)
	runW := httptest.NewRecorder()
	srv.handleAdminMaintenanceRun(runW, runReq)
	if runW.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/maintenance/run status = %d, body=%s", runW.Code, runW.Body.String())
	}

	var runResp struct {
		OK     bool                     `json:"ok"`
		Status MaintenanceStateSnapshot `json:"status"`
	}
	if err := json.Unmarshal(runW.Body.Bytes(), &runResp); err != nil {
		t.Fatalf("decode maintenance run response: %v", err)
	}
	if !runResp.OK {
		t.Fatal("expected maintenance run response ok=true")
	}
	if runResp.Status.LastRun == nil {
		t.Fatal("expected maintenance status to include last_run")
	}
	if runResp.Status.LastRun.Result.CleanDeleted.Deleted != 1 {
		t.Fatalf("unexpected deleted count in maintenance result: %+v", runResp.Status.LastRun.Result.CleanDeleted)
	}
	if len(runResp.Status.LastRun.Result.PurgeSSHDBot.Matches) != 1 || runResp.Status.LastRun.Result.PurgeSSHDBot.Purges != 1 {
		t.Fatalf("unexpected purge sshdbot result in maintenance status: %+v", runResp.Status.LastRun.Result.PurgeSSHDBot)
	}
	if got := runResp.Status.LastRun.Result.PurgeSSHDBot.Matches[0].Path; got != sshdbotRel {
		t.Fatalf("unexpected sshdbot match path in run response: got=%q want=%q", got, sshdbotRel)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/admin/api/maintenance", nil)
	statusW := httptest.NewRecorder()
	srv.handleAdminMaintenance(statusW, statusReq)
	if statusW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/maintenance status = %d, body=%s", statusW.Code, statusW.Body.String())
	}

	var statusResp MaintenanceStateSnapshot
	if err := json.Unmarshal(statusW.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode maintenance status response: %v", err)
	}
	if statusResp.Running {
		t.Fatal("expected maintenance status to be idle after synchronous run")
	}
	if statusResp.LastRun == nil || statusResp.LastRun.Trigger != "admin-http" {
		t.Fatalf("unexpected maintenance status last_run: %+v", statusResp.LastRun)
	}
	if len(statusResp.LastRun.Result.PurgeSSHDBot.Matches) != 1 || statusResp.LastRun.Result.PurgeSSHDBot.Purges != 1 {
		t.Fatalf("unexpected purge sshdbot status result: %+v", statusResp.LastRun.Result.PurgeSSHDBot)
	}
	if got := statusResp.LastRun.Result.PurgeSSHDBot.Matches[0].IP; got != ownerAddr.IP.String() {
		t.Fatalf("unexpected sshdbot match ip in status response: got=%q want=%q", got, ownerAddr.IP.String())
	}
}

func TestHandleAdminMaintenanceLogsFiltersMaintenanceGroup(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	logContent := strings.Join([]string{
		`time=2026-03-13T10:00:00-04:00 level=INFO msg="maintenance pass completed" maintenance.operation=pass maintenance.trigger=admin-http`,
		`time=2026-03-13T10:00:01-04:00 level=INFO msg="Finished cleaning deleted files" maintenance.operation=clean_deleted maintenance.deleted=2`,
		`time=2026-03-13T10:00:02-04:00 level=INFO msg="regular log line" component=web`,
	}, "\n") + "\n"
	if err := os.WriteFile(srv.cfg.LogFile, []byte(logContent), permFile); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/maintenance/logs?q=clean_deleted", nil)
	w := httptest.NewRecorder()
	srv.handleAdminMaintenanceLogs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/maintenance/logs status = %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Entries []adminMaintenanceLogEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode maintenance logs response: %v", err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 maintenance log entry, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Operation != "clean_deleted" {
		t.Fatalf("unexpected maintenance log operation: got=%q want=%q", resp.Entries[0].Operation, "clean_deleted")
	}
	if resp.Entries[0].Fields["deleted"] != "2" {
		t.Fatalf("unexpected maintenance log fields: %+v", resp.Entries[0].Fields)
	}
}

func TestHandleAdminMaintenanceLogsAcceptsLongLines(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	longMsg := strings.Repeat("x", 70*1024)
	logLine := `time=2026-03-13T10:00:01-04:00 level=INFO msg="` + longMsg + `" maintenance.operation=clean_deleted maintenance.deleted=2`
	if err := os.WriteFile(srv.cfg.LogFile, []byte(logLine+"\n"), permFile); err != nil {
		t.Fatalf("write long log file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/maintenance/logs?q=clean_deleted", nil)
	w := httptest.NewRecorder()
	srv.handleAdminMaintenanceLogs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/maintenance/logs status = %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Entries []adminMaintenanceLogEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode maintenance logs response: %v", err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 maintenance log entry, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Operation != "clean_deleted" {
		t.Fatalf("unexpected maintenance log operation: got=%q want=%q", resp.Entries[0].Operation, "clean_deleted")
	}
	if resp.Entries[0].Fields["deleted"] != "2" {
		t.Fatalf("unexpected maintenance log fields: %+v", resp.Entries[0].Fields)
	}
}

func TestHashListReloadAcceptsLongFilenames(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	longName := strings.Repeat("x", 70*1024)
	content := hash + "  " + longName + "\n"
	if err := os.WriteFile(srv.store.badFilesPath, []byte(content), permFile); err != nil {
		t.Fatalf("write bad files content: %v", err)
	}

	entries, err := srv.store.badFileList.Reload()
	if err != nil {
		t.Fatalf("reload bad file list: %v", err)
	}
	if entries != 1 {
		t.Fatalf("unexpected bad file entry count: got=%d want=1", entries)
	}

	name, ok := srv.store.badFileList.Lookup(hash)
	if !ok {
		t.Fatal("expected hash lookup to succeed after reload")
	}
	if name != longName {
		t.Fatalf("unexpected stored filename length: got=%d want=%d", len(name), len(longName))
	}
}
