package main

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreMatchBadFileMatchesCAIDDatabase(t *testing.T) {
	caidPath := createCAIDTestDB(t)
	srv := newMaintenanceTestServerWithConfig(t, func(cfg *Config) {
		cfg.CAIDDBPath = caidPath
	})
	defer srv.Shutdown()

	fullPath := filepath.Join(srv.absUploadDir, "caid-match.bin")
	content := []byte(strings.Repeat("malware payload", 128))
	if err := os.WriteFile(fullPath, content, permFile); err != nil {
		t.Fatalf("write CAID candidate: %v", err)
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(fullPath)
	if err != nil {
		t.Fatalf("hash CAID candidate: %v", err)
	}
	insertCAIDRow(t, caidPath, "exe", md5Hex, sha1Hex, int64(len(content)), 7)

	matchName, matched, err := srv.store.MatchBadFile(fullPath)
	if err != nil {
		t.Fatalf("MatchBadFile(CAID) error = %v", err)
	}
	if !matched {
		t.Fatal("expected CAID-backed file to match")
	}
	if matchName != "caid:exe (category 7)" {
		t.Fatalf("unexpected CAID match name: got=%q want=%q", matchName, "caid:exe (category 7)")
	}
}

func TestStoreMatchBadFileSkipsCAIDForSmallFilesButKeepsHashList(t *testing.T) {
	caidPath := createCAIDTestDB(t)
	srv := newMaintenanceTestServerWithConfig(t, func(cfg *Config) {
		cfg.CAIDDBPath = caidPath
	})
	defer srv.Shutdown()

	fullPath := filepath.Join(srv.absUploadDir, "small.bin")
	content := []byte("tiny but still locally blocked")
	if err := os.WriteFile(fullPath, content, permFile); err != nil {
		t.Fatalf("write small candidate: %v", err)
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(fullPath)
	if err != nil {
		t.Fatalf("hash small candidate: %v", err)
	}
	insertCAIDRow(t, caidPath, "ignored", md5Hex, sha1Hex, int64(len(content)), 9)

	matchName, matched, err := srv.store.MatchBadFile(fullPath)
	if err != nil {
		t.Fatalf("MatchBadFile(small, no list) error = %v", err)
	}
	if matched {
		t.Fatalf("expected CAID to ignore small file, got match %q", matchName)
	}

	hash, err := srv.store.badFileList.AddFile(fullPath)
	if err != nil {
		t.Fatalf("AddFile(small) error = %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	matchName, matched, err = srv.store.MatchBadFile(fullPath)
	if err != nil {
		t.Fatalf("MatchBadFile(small, hash list) error = %v", err)
	}
	if !matched {
		t.Fatal("expected small file to still match SHA-256 bad file list")
	}
	if matchName != filepath.Base(fullPath) {
		t.Fatalf("unexpected hash-list match name: got=%q want=%q", matchName, filepath.Base(fullPath))
	}
	if hash == "" {
		t.Fatal("expected AddFile to return a hash")
	}
}

func TestPurgeBlacklistedFilesPurgesCAIDMatches(t *testing.T) {
	caidPath := createCAIDTestDB(t)
	srv := newMaintenanceTestServerWithConfig(t, func(cfg *Config) {
		cfg.CAIDDBPath = caidPath
	})
	defer srv.Shutdown()

	const ownerHash = "caid-bad-file-owner"
	ownerAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.45"), Port: 2222}
	if _, err := srv.store.UpsertUserSession(ownerHash, ownerAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	const badRel = "caid/bad.bin"
	const otherRel = "caid/other.txt"
	if err := os.MkdirAll(filepath.Join(srv.absUploadDir, "caid"), permDir); err != nil {
		t.Fatalf("mkdir CAID dir: %v", err)
	}

	badContent := []byte(strings.Repeat("malware payload", 128))
	badPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(badRel))
	otherPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(otherRel))
	if err := os.WriteFile(badPath, badContent, permFile); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if err := os.WriteFile(otherPath, []byte("innocent bystander"), permFile); err != nil {
		t.Fatalf("write other file: %v", err)
	}

	if err := srv.store.EnsureDirectory(ownerHash, "caid"); err != nil {
		t.Fatalf("ensure CAID dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, badRel, int64(len(badContent)), int64(len(badContent))); err != nil {
		t.Fatalf("register bad file: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, otherRel, int64(len("innocent bystander")), int64(len("innocent bystander"))); err != nil {
		t.Fatalf("register other file: %v", err)
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(badPath)
	if err != nil {
		t.Fatalf("hash bad file: %v", err)
	}
	insertCAIDRow(t, caidPath, "exe", md5Hex, sha1Hex, int64(len(badContent)), 42)

	result := srv.purgeBlacklistedFiles()

	for _, p := range []string{badPath, otherPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, got err=%v", p, err)
		}
	}
	for _, rel := range []string{badRel, otherRel, "caid"} {
		if srv.store.FileExistsInDB(rel) {
			t.Fatalf("expected %s to be removed from the database", rel)
		}
	}
	if !srv.store.blacklist.Matches("203.0.113.45") {
		t.Fatal("expected CAID-matched owner IP to be blacklisted")
	}
	if result.Matches != 1 || result.Purges != 1 || result.OwnersPurged != 1 || result.BlacklistUpdates != 1 {
		t.Fatalf("unexpected purge result: %+v", result)
	}
	if result.Error != "" {
		t.Fatalf("unexpected purge error: %s", result.Error)
	}
}

func TestNewCAIDMatcherOpensReadOnlyDatabase(t *testing.T) {
	caidPath := createCAIDTestDB(t)
	if err := os.Chmod(caidPath, 0400); err != nil {
		t.Fatalf("chmod CAID db readonly: %v", err)
	}

	matcher, err := NewCAIDMatcher(caidPath)
	if err != nil {
		t.Fatalf("NewCAIDMatcher(readonly) error = %v, want nil", err)
	}
	defer matcher.Close()
}

func TestNewServerContinuesWhenCAIDDatabaseMissing(t *testing.T) {
	tmpDir := t.TempDir()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := Config{
		Name:          "sftpguy-caid-missing-test",
		Port:          2222,
		HostKeyFile:   filepath.Join(tmpDir, "host_key"),
		DBPath:        filepath.Join(tmpDir, "sftp.db"),
		LogFile:       filepath.Join(tmpDir, "sftp.log"),
		UploadDir:     filepath.Join(tmpDir, "uploads"),
		BlacklistPath: filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath: filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath: filepath.Join(tmpDir, "admin_keys.txt"),
		BadFilesPath:  filepath.Join(tmpDir, "bad_files.txt"),
		CAIDDBPath:    filepath.Join(tmpDir, "missing-caid.db"),
	}

	for _, p := range []string{cfg.BlacklistPath, cfg.WhitelistPath, cfg.AdminKeysPath, cfg.BadFilesPath, cfg.LogFile} {
		if err := os.WriteFile(p, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", p, err)
		}
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer() error = %v, want nil", err)
	}
	defer srv.Shutdown()

	if srv.store.caidMatcher != nil {
		t.Fatal("expected missing CAID database to leave matcher disabled")
	}
	if !strings.Contains(logBuf.String(), "failed to init CAID matcher; continuing without CAID database") {
		t.Fatalf("expected warning log for missing CAID database, got %q", logBuf.String())
	}
}

func createCAIDTestDB(t *testing.T) string {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "caid.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open CAID db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS caid_hashes (
			filetype TEXT NOT NULL,
			md5      TEXT NOT NULL,
			sha1     TEXT NOT NULL,
			size     INTEGER NOT NULL,
			category INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_caid_hashes_md5 ON caid_hashes(md5);
		CREATE INDEX IF NOT EXISTS idx_caid_hashes_sha1 ON caid_hashes(sha1);
		CREATE INDEX IF NOT EXISTS idx_caid_hashes_size ON caid_hashes(size);
	`); err != nil {
		t.Fatalf("create CAID schema: %v", err)
	}

	return dbPath
}

func insertCAIDRow(t *testing.T, dbPath, fileType, md5Hex, sha1Hex string, size int64, category int) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open CAID db for insert: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO caid_hashes (filetype, md5, sha1, size, category) VALUES (?, ?, ?, ?, ?)`,
		fileType, md5Hex, sha1Hex, size, category,
	); err != nil {
		t.Fatalf("insert CAID row: %v", err)
	}
}
