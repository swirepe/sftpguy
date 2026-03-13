package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
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

	result := srv.cleanDeleted()

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
	if result.StaleRoots != 2 {
		t.Fatalf("unexpected stale roots: got=%d want=%d", result.StaleRoots, 2)
	}
	if result.Deleted != 3 {
		t.Fatalf("unexpected deleted rows: got=%d want=%d", result.Deleted, 3)
	}
	if result.Error != "" {
		t.Fatalf("unexpected cleanDeleted error: %s", result.Error)
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

func TestMaintenanceLoopSkipsBadFilePurge(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "scheduled-bad-file-owner"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.19"), Port: 2222}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	const badRel = "scheduled/bad.bin"
	badPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(badRel))
	if err := os.MkdirAll(filepath.Dir(badPath), permDir); err != nil {
		t.Fatalf("mkdir scheduled dir: %v", err)
	}
	if err := os.WriteFile(badPath, []byte("malware payload"), permFile); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	if err := srv.store.EnsureDirectory(ownerHash, "scheduled"); err != nil {
		t.Fatalf("ensure scheduled dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, badRel, int64(len("malware payload")), int64(len("malware payload"))); err != nil {
		t.Fatalf("register bad file: %v", err)
	}
	if err := srv.store.badFileList.AddFile(badPath); err != nil {
		t.Fatalf("add bad file hash: %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("reload bad file hashes: %v", err)
	}

	srv.store.RegisterFile("gone.txt", systemOwner, 0, false)
	srv.startMaintenanceLoop(20 * time.Millisecond)

	waitForCondition(t, time.Second, func() bool {
		return !srv.store.FileExistsInDB("gone.txt")
	}, "maintenance loop did not remove stale row")

	time.Sleep(60 * time.Millisecond)

	if _, err := os.Stat(badPath); err != nil {
		t.Fatalf("expected scheduled maintenance to leave bad file in place, got err=%v", err)
	}
	if !srv.store.FileExistsInDB(badRel) {
		t.Fatal("expected scheduled maintenance to leave bad file record in place")
	}
	if srv.store.blacklist.Matches(ownerAddr.IP.String()) {
		t.Fatal("expected scheduled maintenance to skip blacklisting bad file owner")
	}

	snap := srv.maintenanceStatusSnapshot()
	if snap.LastRun == nil {
		t.Fatal("expected maintenance loop to record a last run")
	}
	if snap.LastRun.Result.PurgeBlacklistedFiles.Matches != 0 || snap.LastRun.Result.PurgeBlacklistedFiles.Purges != 0 {
		t.Fatalf("expected scheduled maintenance to skip purge result, got %+v", snap.LastRun.Result.PurgeBlacklistedFiles)
	}
}

func TestUpdateFileWriteUpsertsMissingRow(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const userHash = "user-upsert-hash"
	if _, err := srv.store.UpsertUserSession(userHash, nil); err != nil {
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
	if _, err := srv.store.UpsertUserSession(victimHash, nil); err != nil {
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

func TestGetUserStatsHandlesNullLastAddress(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const userHash = "null-last-address-user"
	if _, err := srv.store.exec(`INSERT INTO users (pubkey_hash, last_login) VALUES (?, NULL)`, userHash); err != nil {
		t.Fatalf("insert user with null last_address: %v", err)
	}

	stats, err := srv.store.GetUserStats(userHash)
	if err != nil {
		t.Fatalf("get user stats: %v", err)
	}
	if stats.LastAddress != "" {
		t.Fatalf("expected empty last_address, got %q", stats.LastAddress)
	}
	if stats.LastLogin != "Never" {
		t.Fatalf("expected normalized last_login %q, got %q", "Never", stats.LastLogin)
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
		LogFile:       filepath.Join(tmpDir, "sftp.log"),
		UploadDir:     filepath.Join(tmpDir, "uploads"),
		BlacklistPath: filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath: filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath: filepath.Join(tmpDir, "admin_keys.txt"),
		BadFilesPath:  filepath.Join(tmpDir, "bad_files.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath, cfg.BadFilesPath, cfg.LogFile} {
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

func TestPurgeBlacklistedFilesPurgesOwnerAndBlacklistsRange(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "bad-file-owner-hash"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 2222}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	const badRel = "nested/bad.bin"
	const otherRel = "nested/other.txt"

	if err := os.MkdirAll(filepath.Join(srv.absUploadDir, "nested"), permDir); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	badPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(badRel))
	otherPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(otherRel))
	if err := os.WriteFile(badPath, []byte("malware payload"), permFile); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if err := os.WriteFile(otherPath, []byte("innocent bystander"), permFile); err != nil {
		t.Fatalf("write other file: %v", err)
	}

	if err := srv.store.EnsureDirectory(ownerHash, "nested"); err != nil {
		t.Fatalf("ensure nested dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, badRel, int64(len("malware payload")), int64(len("malware payload"))); err != nil {
		t.Fatalf("register bad file: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, otherRel, int64(len("innocent bystander")), int64(len("innocent bystander"))); err != nil {
		t.Fatalf("register other file: %v", err)
	}

	if err := srv.store.badFileList.AddFile(badPath); err != nil {
		t.Fatalf("add bad file hash: %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("reload bad file hashes: %v", err)
	}

	result := srv.purgeBlacklistedFiles()

	for _, p := range []string{badPath, otherPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be removed, got err=%v", p, err)
		}
	}
	for _, rel := range []string{badRel, otherRel, "nested"} {
		if srv.store.FileExistsInDB(rel) {
			t.Fatalf("expected %s to be removed from the database", rel)
		}
	}

	stats, err := srv.store.GetUserStats(ownerHash)
	if err != nil {
		t.Fatalf("get user stats after purge: %v", err)
	}
	if !stats.FirstTimer {
		t.Fatalf("expected purged user %q to be removed from users table", ownerHash)
	}

	if !srv.store.blacklist.Matches("203.0.113.9") {
		t.Fatal("expected uploader IP to be blacklisted")
	}

	blacklistContent, err := os.ReadFile(srv.store.blacklistPath)
	if err != nil {
		t.Fatalf("read blacklist file: %v", err)
	}
	if !strings.Contains(string(blacklistContent), "203.0.113.0/24") {
		t.Fatalf("expected /24 network to be persisted, got %q", string(blacklistContent))
	}
	if result.Matches != 1 {
		t.Fatalf("unexpected match count: got=%d want=%d", result.Matches, 1)
	}
	if result.Purges != 1 {
		t.Fatalf("unexpected purge count: got=%d want=%d", result.Purges, 1)
	}
	if result.OwnersPurged != 1 {
		t.Fatalf("unexpected owner purge count: got=%d want=%d", result.OwnersPurged, 1)
	}
	if result.BlacklistUpdates != 1 {
		t.Fatalf("unexpected blacklist update count: got=%d want=%d", result.BlacklistUpdates, 1)
	}
	if result.Error != "" {
		t.Fatalf("unexpected purgeBlacklistedFiles error: %s", result.Error)
	}
}

func TestFilewritePurgesBadUploadsImmediately(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "live-bad-file-owner"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.33"), Port: 2022}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	samplePath := filepath.Join(t.TempDir(), "sample-bad.bin")
	if err := os.WriteFile(samplePath, []byte("malware payload"), permFile); err != nil {
		t.Fatalf("write bad sample: %v", err)
	}
	if err := srv.store.badFileList.AddFile(samplePath); err != nil {
		t.Fatalf("add bad file hash: %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("reload bad file hashes: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(srv.absUploadDir, "live"), permDir); err != nil {
		t.Fatalf("mkdir live dir: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "live"); err != nil {
		t.Fatalf("ensure live dir: %v", err)
	}

	handler := &fsHandler{
		srv:        srv,
		pubHash:    ownerHash,
		stderr:     io.Discard,
		logger:     *slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		remoteAddr: ownerAddr,
		sessionID:  "sess-bad-upload",
	}

	writer, err := handler.Filewrite(sftp.NewRequest("Put", "/live/bad.bin"))
	if err != nil {
		t.Fatalf("open upload writer: %v", err)
	}
	if _, err := writer.WriteAt([]byte("malware payload"), 0); err != nil {
		t.Fatalf("write upload payload: %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("close upload writer: %v", err)
	}

	badPath := filepath.Join(srv.absUploadDir, "live", "bad.bin")
	if _, err := os.Stat(badPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected uploaded bad file to be purged, got err=%v", err)
	}
	if srv.store.FileExistsInDB("live/bad.bin") {
		t.Fatal("expected uploaded bad file record to be removed")
	}
	if !srv.store.blacklist.Matches(ownerAddr.IP.String()) {
		t.Fatal("expected uploaded bad file owner IP to be blacklisted")
	}

	stats, err := srv.store.GetUserStats(ownerHash)
	if err != nil {
		t.Fatalf("get user stats after purge: %v", err)
	}
	if !stats.FirstTimer {
		t.Fatalf("expected purged uploader %q to be removed from users table", ownerHash)
	}
}

func TestRunMaintenancePassReturnsAggregatedResults(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "maintenance-run-owner"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.44"), Port: 2022}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	if err := os.WriteFile(filepath.Join(srv.absUploadDir, "orphan.txt"), []byte("orphan"), permFile); err != nil {
		t.Fatalf("write orphan file: %v", err)
	}

	srv.store.RegisterFile("gone.txt", systemOwner, 0, false)

	const badRel = "bad.bin"
	badPath := filepath.Join(srv.absUploadDir, badRel)
	if err := os.WriteFile(badPath, []byte("malware payload"), permFile); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, badRel, int64(len("malware payload")), int64(len("malware payload"))); err != nil {
		t.Fatalf("register bad file: %v", err)
	}
	if err := srv.store.badFileList.AddFile(badPath); err != nil {
		t.Fatalf("add bad file hash: %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("reload bad file hashes: %v", err)
	}

	halted, result := srv.RunMaintenancePass(context.Background())
	if !halted {
		t.Fatal("expected maintenance pass to complete")
	}

	if result.CleanDeleted.StaleRoots != 1 || result.CleanDeleted.Deleted != 1 {
		t.Fatalf("unexpected cleanDeleted result: %+v", result.CleanDeleted)
	}
	if result.ReconcileOrphans.Candidates != 2 || len(result.ReconcileOrphans.Unorphaned) != 1 {
		t.Fatalf("unexpected reconcileOrphans result: %+v", result.ReconcileOrphans)
	}
	if got := result.ReconcileOrphans.Unorphaned[0].Path; got != "orphan.txt" {
		t.Fatalf("unexpected unorphaned path: got=%q want=%q", got, "orphan.txt")
	}
	if result.PurgeBlacklistedFiles.Matches != 1 || result.PurgeBlacklistedFiles.Purges != 1 || result.PurgeBlacklistedFiles.BlacklistUpdates != 1 {
		t.Fatalf("unexpected purgeBlacklistedFiles result: %+v", result.PurgeBlacklistedFiles)
	}
}

func TestNewServerSeedsWhitelistRanges(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := Config{
		Name:          "sftpguy-whitelist-seed-test",
		Port:          2222,
		HostKeyFile:   filepath.Join(tmpDir, "host_key"),
		DBPath:        filepath.Join(tmpDir, "sftp.db"),
		LogFile:       filepath.Join(tmpDir, "sftp.log"),
		UploadDir:     filepath.Join(tmpDir, "uploads"),
		BlacklistPath: filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath: filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath: filepath.Join(tmpDir, "admin_keys.txt"),
		BadFilesPath:  filepath.Join(tmpDir, "bad_files.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.AdminKeysPath, cfg.BadFilesPath, cfg.LogFile} {
		if err := os.WriteFile(p, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", p, err)
		}
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer srv.Shutdown()

	content, err := os.ReadFile(cfg.WhitelistPath)
	if err != nil {
		t.Fatalf("read whitelist file: %v", err)
	}
	for _, want := range []string{"127.0.0.0/8", "192.168.0.0/16", "::1/128"} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("expected seeded whitelist to contain %q, got %q", want, string(content))
		}
	}
	if !srv.store.whitelist.Matches("192.168.1.2") {
		t.Fatal("expected private IPv4 address to be whitelisted")
	}
	if !srv.store.whitelist.Matches("::1") {
		t.Fatal("expected IPv6 loopback to be whitelisted")
	}
	if srv.store.whitelist.Matches("8.8.8.8") {
		t.Fatal("did not expect public address to be whitelisted")
	}
}

func TestCleanAndReconcileLogsWhenResultChanges(t *testing.T) {
	tmpDir := t.TempDir()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := Config{
		Name:          "sftpguy-maintenance-log-test",
		Port:          2222,
		HostKeyFile:   filepath.Join(tmpDir, "host_key"),
		DBPath:        filepath.Join(tmpDir, "sftp.db"),
		LogFile:       filepath.Join(tmpDir, "sftp.log"),
		UploadDir:     filepath.Join(tmpDir, "uploads"),
		BlacklistPath: filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath: filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath: filepath.Join(tmpDir, "admin_keys.txt"),
		BadFilesPath:  filepath.Join(tmpDir, "bad_files.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath, cfg.BadFilesPath, cfg.LogFile} {
		if err := os.WriteFile(p, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", p, err)
		}
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer srv.Shutdown()

	started, halted, _ := srv.runTrackedMaintenancePass(context.Background(), "startup", false)
	if !started || !halted {
		t.Fatalf("expected initial tracked maintenance pass to complete: started=%v halted=%v", started, halted)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		srv.cleanAndReconcile(ctx, 20*time.Millisecond)
		close(done)
	}()

	time.Sleep(35 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(srv.absUploadDir, "changed.txt"), []byte("hello"), permFile); err != nil {
		t.Fatalf("write changed file: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		return strings.Contains(logBuf.String(), "maintenance pass result changed")
	}, "maintenance loop did not log changed result")

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanAndReconcile did not stop after cancel")
	}
}
