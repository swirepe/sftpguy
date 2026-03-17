package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSFTPRenameOwnFileInPublicDirectory(t *testing.T) {
	port := testFreeTCPPort(t)
	tmpDir := t.TempDir()

	unrestricted := make(map[string]bool, len(defaultUnrestrictedPaths))
	for _, p := range defaultUnrestrictedPaths {
		unrestricted[p] = true
	}

	cfg := Config{
		Name:                 "sftpguy-public-rename-test",
		Port:                 port,
		HostKeyFile:          filepath.Join(tmpDir, "id_ed25519"),
		DBPath:               filepath.Join(tmpDir, "sftp.db"),
		LogFile:              filepath.Join(tmpDir, "sftp.log"),
		UploadDir:            filepath.Join(tmpDir, "uploads"),
		BannerFile:           filepath.Join(tmpDir, "BANNER.txt"),
		MkdirRate:            100.0,
		MaxDirs:              10000,
		ContributorThreshold: 16 * 1024,
		unrestrictedMap:      unrestricted,
		BlacklistPath:        filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath:        filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath:        filepath.Join(tmpDir, "admin_keys.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath} {
		if err := os.WriteFile(p, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", p, err)
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	srv.reconcileOrphans()

	listenDone := make(chan error, 1)
	go func() {
		listenDone <- srv.Listen()
	}()

	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("shutdown failed: %v", err)
		}

		select {
		case listenErr := <-listenDone:
			if listenErr != nil && !isExpectedListenerClose(listenErr) {
				t.Errorf("listener exited with unexpected error: %v", listenErr)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("listener did not exit after shutdown")
		}
	})

	if !stWaitReady(cfg.Port, 10*time.Second) {
		t.Fatal("server did not become ready within timeout")
	}

	publicOwner, err := srv.store.GetFileOwner("public")
	if err != nil {
		t.Fatalf("get public owner: %v", err)
	}
	if publicOwner != systemOwner {
		t.Fatalf("expected public directory to be system-owned, got %q", publicOwner)
	}

	runner := &selfTestRunner{
		srv: srv,
		cfg: cfg,
		log: logger.WithGroup("test"),
	}

	auth, _, ownerHash := runner.newPubKeyAuth()
	sshCli, sftpCli, err := runner.openSFTP(auth)
	if err != nil {
		t.Fatalf("open sftp: %v", err)
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	const original = "public/owned.txt"
	const renamed = "public/owned-renamed.txt"

	if err := stWrite(sftpCli, original, []byte("hello public")); err != nil {
		t.Fatalf("write user-owned file in public/: %v", err)
	}

	owner, err := srv.store.GetFileOwner(original)
	if err != nil {
		t.Fatalf("get file owner before rename: %v", err)
	}
	if owner != ownerHash {
		t.Fatalf("unexpected owner before rename: got=%q want=%q", owner, ownerHash)
	}

	if err := sftpCli.Rename(original, renamed); err != nil {
		t.Fatalf("rename own file inside public/: %v", err)
	}

	if _, err := os.Stat(filepath.Join(srv.absUploadDir, filepath.FromSlash(original))); !os.IsNotExist(err) {
		t.Fatalf("expected source file to be gone after rename, got err=%v", err)
	}

	renamedData, err := os.ReadFile(filepath.Join(srv.absUploadDir, filepath.FromSlash(renamed)))
	if err != nil {
		t.Fatalf("read renamed file: %v", err)
	}
	if string(renamedData) != "hello public" {
		t.Fatalf("unexpected renamed file contents: got=%q want=%q", string(renamedData), "hello public")
	}

	owner, err = srv.store.GetFileOwner(renamed)
	if err != nil {
		t.Fatalf("get file owner after rename: %v", err)
	}
	if owner != ownerHash {
		t.Fatalf("unexpected owner after rename: got=%q want=%q", owner, ownerHash)
	}
	if srv.store.FileExistsInDB(original) {
		t.Fatal("expected old path metadata to be removed after rename")
	}
}
