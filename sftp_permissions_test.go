package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startPermissionsTestServer(t *testing.T, name string) (*Server, *selfTestRunner) {
	t.Helper()

	port := testFreeTCPPort(t)
	tmpDir := t.TempDir()

	unrestricted := make(map[string]bool, len(defaultUnrestrictedPaths))
	for _, p := range defaultUnrestrictedPaths {
		unrestricted[p] = true
	}

	cfg := Config{
		Name:                 name,
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
		BadFilesPath:         filepath.Join(tmpDir, "bad_files.txt"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath, cfg.BadFilesPath} {
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

	return srv, &selfTestRunner{
		srv: srv,
		cfg: cfg,
		log: logger.WithGroup("test"),
	}
}

func requireSystemOwnedPublicDir(t *testing.T, srv *Server) {
	t.Helper()

	publicOwner, err := srv.store.GetFileOwner("public")
	if err != nil {
		t.Fatalf("get public owner: %v", err)
	}
	if publicOwner != systemOwner {
		t.Fatalf("expected public directory to be system-owned, got %q", publicOwner)
	}
}

func TestSFTPRenameOwnFileInPublicDirectory(t *testing.T) {
	srv, runner := startPermissionsTestServer(t, "sftpguy-public-rename-test")
	requireSystemOwnedPublicDir(t, srv)

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

func TestSFTPOwnershipEnforcedInPublicDirectory(t *testing.T) {
	srv, runner := startPermissionsTestServer(t, "sftpguy-public-ownership-test")
	requireSystemOwnedPublicDir(t, srv)

	ownerAuth, _, ownerHash := runner.newPubKeyAuth()
	otherAuth, _, _ := runner.newPubKeyAuth()

	ownerSSH, ownerSFTP, err := runner.openSFTP(ownerAuth)
	if err != nil {
		t.Fatalf("open owner sftp: %v", err)
	}
	defer ownerSSH.Close()
	defer ownerSFTP.Close()

	otherSSH, otherSFTP, err := runner.openSFTP(otherAuth)
	if err != nil {
		t.Fatalf("open non-owner sftp: %v", err)
	}
	defer otherSSH.Close()
	defer otherSFTP.Close()

	publicPath := "public/owned-" + stRandHex() + ".txt"
	fullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(publicPath))
	initial := []byte("hello public")
	updated := []byte("updated by owner")

	if err := stWrite(ownerSFTP, publicPath, initial); err != nil {
		t.Fatalf("write user-owned file in public/: %v", err)
	}

	owner, err := srv.store.GetFileOwner(publicPath)
	if err != nil {
		t.Fatalf("get file owner after create: %v", err)
	}
	if owner != ownerHash {
		t.Fatalf("unexpected owner after create: got=%q want=%q", owner, ownerHash)
	}

	if err := stWrite(otherSFTP, publicPath, []byte("intruder overwrite")); err == nil {
		t.Fatal("expected non-owner overwrite in public/ to be denied")
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read public file after non-owner overwrite attempt: %v", err)
	}
	if string(data) != string(initial) {
		t.Fatalf("unexpected file contents after non-owner overwrite attempt: got=%q want=%q", string(data), string(initial))
	}

	owner, err = srv.store.GetFileOwner(publicPath)
	if err != nil {
		t.Fatalf("get file owner after non-owner overwrite attempt: %v", err)
	}
	if owner != ownerHash {
		t.Fatalf("unexpected owner after non-owner overwrite attempt: got=%q want=%q", owner, ownerHash)
	}

	if err := otherSFTP.Remove(publicPath); err == nil {
		t.Fatal("expected non-owner delete in public/ to be denied")
	}

	if _, err := os.Stat(fullPath); err != nil {
		t.Fatalf("expected public file to remain after non-owner delete attempt, got err=%v", err)
	}

	if err := stWrite(ownerSFTP, publicPath, updated); err != nil {
		t.Fatalf("owner overwrite in public/: %v", err)
	}

	data, err = os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read public file after owner overwrite: %v", err)
	}
	if string(data) != string(updated) {
		t.Fatalf("unexpected file contents after owner overwrite: got=%q want=%q", string(data), string(updated))
	}

	if err := ownerSFTP.Remove(publicPath); err != nil {
		t.Fatalf("owner delete in public/: %v", err)
	}

	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("expected public file to be removed after owner delete, got err=%v", err)
	}
	if srv.store.FileExistsInDB(publicPath) {
		t.Fatal("expected deleted public file metadata to be removed from the database")
	}
}
