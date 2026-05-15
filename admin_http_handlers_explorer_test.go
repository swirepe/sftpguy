package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandleAdminExplorerDeleteWaitsForTransientDBLock(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const relPath = "locked-delete.txt"
	fullPath := filepath.Join(srv.absUploadDir, relPath)
	if err := os.WriteFile(fullPath, []byte("delete me"), permFile); err != nil {
		t.Fatalf("write upload file: %v", err)
	}
	srv.store.RegisterFile(relPath, systemOwner, int64(len("delete me")), false)

	lockDB, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatalf("open lock db: %v", err)
	}
	defer lockDB.Close()

	ctx := context.Background()
	lockConn, err := lockDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open lock db conn: %v", err)
	}
	defer lockConn.Close()

	if _, err := lockConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("begin immediate transaction: %v", err)
	}

	releaseDone := make(chan struct{})
	go func() {
		time.Sleep(75 * time.Millisecond)
		_, _ = lockConn.ExecContext(ctx, "ROLLBACK")
		close(releaseDone)
	}()

	body, err := json.Marshal(map[string]any{"path": relPath})
	if err != nil {
		t.Fatalf("marshal delete body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/api/explorer/delete", bytes.NewReader(body))
	w := httptest.NewRecorder()

	start := time.Now()
	srv.handleAdminExplorerDelete(w, req)
	duration := time.Since(start)

	<-releaseDone

	if w.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/explorer/delete status = %d, body=%s", w.Code, w.Body.String())
	}
	if duration < 50*time.Millisecond {
		t.Fatalf("expected handler to wait for transient DB lock, duration=%s", duration)
	}

	if _, err := os.Stat(fullPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected deleted file to be removed from disk, got err=%v", err)
	}
	if srv.store.FileExistsInDB(relPath) {
		t.Fatal("expected deleted file metadata to be removed from the database")
	}

	var resp struct {
		OK   bool   `json:"ok"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !resp.OK {
		t.Fatal("expected delete response ok=true")
	}
	if resp.Path != relPath {
		t.Fatalf("unexpected deleted path: got=%q want=%q", resp.Path, relPath)
	}
}

func TestHandleAdminExplorerRenameFile(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = systemOwner
	const oldRel = "docs/report.txt"
	const newRel = "docs/report-final.txt"
	oldFull := filepath.Join(srv.absUploadDir, filepath.FromSlash(oldRel))
	newFull := filepath.Join(srv.absUploadDir, filepath.FromSlash(newRel))
	if err := os.MkdirAll(filepath.Dir(oldFull), permDir); err != nil {
		t.Fatalf("mkdir upload dir: %v", err)
	}
	if err := os.WriteFile(oldFull, []byte("report"), permFile); err != nil {
		t.Fatalf("write upload file: %v", err)
	}
	srv.store.RegisterFile(oldRel, ownerHash, int64(len("report")), false)
	if err := srv.store.RecordDownload(ownerHash, oldRel, 6); err != nil {
		t.Fatalf("record download: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"path":     oldRel,
		"new_name": "report-final.txt",
	})
	if err != nil {
		t.Fatalf("marshal rename body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/explorer/rename", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAdminExplorerRename(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/explorer/rename status = %d, body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(oldFull); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected source file to be gone after rename, got err=%v", err)
	}
	if data, err := os.ReadFile(newFull); err != nil || string(data) != "report" {
		t.Fatalf("unexpected renamed file data=%q err=%v", string(data), err)
	}
	if srv.store.FileExistsInDB(oldRel) {
		t.Fatal("expected old path metadata to be removed after rename")
	}
	meta, err := srv.store.GetFileAdminMeta(newRel)
	if err != nil {
		t.Fatalf("get renamed file metadata: %v", err)
	}
	if meta.OwnerHash != ownerHash || meta.Downloads != 1 {
		t.Fatalf("unexpected renamed metadata: %#v", meta)
	}

	var resp struct {
		OK     bool   `json:"ok"`
		Path   string `json:"path"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rename response: %v", err)
	}
	if !resp.OK || resp.Path != oldRel || resp.Target != newRel {
		t.Fatalf("unexpected rename response: %#v", resp)
	}
}

func TestHandleAdminExplorerRenameDirectoryUpdatesNestedMetadata(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = systemOwner
	const oldRel = "album"
	const newRel = "archive"
	tracks := []string{
		"album/track.txt",
		"album/nested/cover.txt",
	}
	for _, rel := range tracks {
		full := filepath.Join(srv.absUploadDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), permDir); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(rel), permFile); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	srv.store.RegisterFile(oldRel, ownerHash, 0, true)
	srv.store.RegisterFile("album/nested", ownerHash, 0, true)
	for _, rel := range tracks {
		srv.store.RegisterFile(rel, ownerHash, int64(len(rel)), false)
	}

	body, err := json.Marshal(map[string]any{
		"path":     oldRel,
		"new_name": newRel,
	})
	if err != nil {
		t.Fatalf("marshal rename body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/explorer/rename", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAdminExplorerRename(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/explorer/rename status = %d, body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(srv.absUploadDir, oldRel)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected old directory to be gone after rename, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(srv.absUploadDir, "archive", "nested", "cover.txt")); err != nil {
		t.Fatalf("expected nested renamed file on disk: %v", err)
	}
	for _, rel := range []string{oldRel, "album/track.txt", "album/nested", "album/nested/cover.txt"} {
		if srv.store.FileExistsInDB(rel) {
			t.Fatalf("old metadata path still exists after rename: %s", rel)
		}
	}
	for _, rel := range []string{newRel, "archive/track.txt", "archive/nested", "archive/nested/cover.txt"} {
		if !srv.store.FileExistsInDB(rel) {
			t.Fatalf("renamed metadata path missing: %s", rel)
		}
	}
}

func TestHandleAdminExplorerRenameRejectsExistingTarget(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const oldRel = "docs/source.txt"
	const targetRel = "docs/target.txt"
	for _, rel := range []string{oldRel, targetRel} {
		full := filepath.Join(srv.absUploadDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), permDir); err != nil {
			t.Fatalf("mkdir upload dir: %v", err)
		}
		if err := os.WriteFile(full, []byte(rel), permFile); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		srv.store.RegisterFile(rel, systemOwner, int64(len(rel)), false)
	}

	body, err := json.Marshal(map[string]any{
		"path":     oldRel,
		"new_name": "target.txt",
	})
	if err != nil {
		t.Fatalf("marshal rename body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/explorer/rename", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAdminExplorerRename(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("POST /admin/api/explorer/rename status = %d, want %d, body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(srv.absUploadDir, filepath.FromSlash(oldRel))); err != nil {
		t.Fatalf("source file should remain after conflict: %v", err)
	}
	if !srv.store.FileExistsInDB(oldRel) || !srv.store.FileExistsInDB(targetRel) {
		t.Fatal("expected metadata to remain unchanged after conflict")
	}
}
