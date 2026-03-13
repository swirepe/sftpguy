package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanDeletedRemovesMissingPaths(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	presentPath := filepath.Join(srv.absUploadDir, "present.txt")
	if err := os.WriteFile(presentPath, []byte("hello"), permFile); err != nil {
		t.Fatalf("write present file: %v", err)
	}
	srv.store.RegisterFile("present.txt", systemOwner, 5, false)

	srv.store.RegisterFile("gone.txt", systemOwner, 0, false)
	if err := srv.store.EnsureDirectory(systemOwner, "gone-dir"); err != nil {
		t.Fatalf("ensure stale dir record: %v", err)
	}
	srv.store.RegisterFile("gone-dir/child.txt", systemOwner, 0, false)

	srv.cleanDeleted()

	if !srv.store.FileExistsInDB("present.txt") {
		t.Fatal("present file was removed from the database")
	}
	if srv.store.FileExistsInDB("gone.txt") {
		t.Fatal("stale file record was not removed")
	}
	if srv.store.FileExistsInDB("gone-dir") {
		t.Fatal("stale directory record was not removed")
	}
	if srv.store.FileExistsInDB("gone-dir/child.txt") {
		t.Fatal("stale child record was not removed with its parent")
	}
}

func TestMaintenanceLoopRunsAndStopsOnShutdown(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	srv.startMaintenanceLoop(20 * time.Millisecond)

	srv.store.RegisterFile("tick-cleanup.txt", systemOwner, 0, false)

	waitForCondition(t, time.Second, func() bool {
		return !srv.store.FileExistsInDB("tick-cleanup.txt")
	}, "maintenance loop did not remove stale row")

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.Shutdown()
	}()

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not stop maintenance loop")
	}
}

func TestUpdateFileWriteUpsertsMissingRow(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const userHash = "user-upsert-hash"
	if _, err := srv.store.UpsertUserSession(userHash); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}

	relPath := "upserted.txt"
	fullPath := filepath.Join(srv.absUploadDir, relPath)
	if err := os.WriteFile(fullPath, []byte("hello"), permFile); err != nil {
		t.Fatalf("write disk file: %v", err)
	}

	if err := srv.store.UpdateFileWrite(userHash, userHash, relPath, 5, 5); err != nil {
		t.Fatalf("update file write: %v", err)
	}

	owner, err := srv.store.GetFileOwner(relPath)
	if err != nil {
		t.Fatalf("get file owner: %v", err)
	}
	if owner != userHash {
		t.Fatalf("unexpected owner: got=%q want=%q", owner, userHash)
	}

	stats, err := srv.store.GetUserStats(userHash)
	if err != nil {
		t.Fatalf("get user stats: %v", err)
	}
	if stats.UploadBytes != 5 {
		t.Fatalf("unexpected upload bytes: got=%d want=%d", stats.UploadBytes, 5)
	}
}

func TestUpdateFileWriteOwnerHintOverridesSystemOwnerRow(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const victimHash = "victim-owner-hash"
	if _, err := srv.store.UpsertUserSession(victimHash); err != nil {
		t.Fatalf("upsert victim session: %v", err)
	}

	relPath := "reconciled-race.txt"
	fullPath := filepath.Join(srv.absUploadDir, relPath)
	if err := os.WriteFile(fullPath, []byte("abcdef"), permFile); err != nil {
		t.Fatalf("write disk file: %v", err)
	}

	srv.reconcileOrphans()

	owner, err := srv.store.GetFileOwner(relPath)
	if err != nil {
		t.Fatalf("get file owner after reconcile: %v", err)
	}
	if owner != systemOwner {
		t.Fatalf("unexpected owner after reconcile: got=%q want=%q", owner, systemOwner)
	}

	if err := srv.store.UpdateFileWrite(systemOwner, victimHash, relPath, 6, 0); err != nil {
		t.Fatalf("update file write: %v", err)
	}

	owner, err = srv.store.GetFileOwner(relPath)
	if err != nil {
		t.Fatalf("get file owner after repair: %v", err)
	}
	if owner != victimHash {
		t.Fatalf("unexpected owner after repair: got=%q want=%q", owner, victimHash)
	}
}

func newMaintenanceTestServer(t *testing.T) *Server {
	t.Helper()

	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := Config{
		Name:          "sftpguy-maintenance-test",
		Port:          2222,
		HostKeyFile:   filepath.Join(tmpDir, "host_key"),
		DBPath:        filepath.Join(tmpDir, "sftp.db"),
		UploadDir:     filepath.Join(tmpDir, "uploads"),
		BlacklistPath: filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath: filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath: filepath.Join(tmpDir, "admin_keys.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath} {
		if err := os.WriteFile(p, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", p, err)
		}
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	return srv
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal(message)
}
