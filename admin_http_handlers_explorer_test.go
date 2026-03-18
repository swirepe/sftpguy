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
