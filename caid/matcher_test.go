package caid

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMatchFileSetsIsAllZero(t *testing.T) {
	dbPath := createMatcherTestDB(t)

	root := t.TempDir()
	matchedPath := filepath.Join(root, "zeros.bin")
	if err := os.WriteFile(matchedPath, make([]byte, 2048), 0644); err != nil {
		t.Fatalf("write zero file: %v", err)
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(matchedPath)
	if err != nil {
		t.Fatalf("hash zero file: %v", err)
	}
	insertMatcherRow(t, dbPath, "blob", md5Hex, sha1Hex, 2048, 7)

	matcher, err := NewMatcher(dbPath)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	defer matcher.Close()

	match, matched, err := matcher.MatchFile(matchedPath)
	if err != nil {
		t.Fatalf("MatchFile() error = %v", err)
	}
	if !matched {
		t.Fatalf("expected zero file to match")
	}
	if !match.IsAllZero {
		t.Fatalf("expected match.IsAllZero to be true")
	}
	if match.Md5Hex != md5Hex || match.Sha1Hex != sha1Hex {
		t.Fatalf("unexpected hashes: got md5=%q sha1=%q", match.Md5Hex, match.Sha1Hex)
	}
}

func createMatcherTestDB(t *testing.T) string {
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
		CREATE INDEX IF NOT EXISTS idx_caid_hashes_size_md5_sha1 ON caid_hashes(size, md5, sha1);
	`); err != nil {
		t.Fatalf("create CAID schema: %v", err)
	}

	return dbPath
}

func insertMatcherRow(t *testing.T, dbPath, fileType, md5Hex, sha1Hex string, size int64, category int) {
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
