package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestRunLogsMatchedPaths(t *testing.T) {
	dbPath := createCAIDTestDB(t)

	root := t.TempDir()
	matchedPath := writeMatchCandidate(t, root, "nested/match.bin", strings.Repeat("malware payload", 128))
	writeMatchCandidate(t, root, "nested/clean.bin", strings.Repeat("clean payload", 128))

	md5Hex, sha1Hex, err := hashFileMD5SHA1(matchedPath)
	if err != nil {
		t.Fatalf("hash matched path: %v", err)
	}
	insertCAIDRow(t, dbPath, "exe", md5Hex, sha1Hex, int64(len(strings.Repeat("malware payload", 128))), 9)

	var logBuf bytes.Buffer
	logger := newTestLogger(&logBuf)

	if err := run([]string{dbPath, root}, logger, &logBuf); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	out := logBuf.String()
	if !strings.Contains(out, `match path="nested/match.bin"`) {
		t.Fatalf("expected match log, got %q", out)
	}
	if strings.Contains(out, `nested/clean.bin`) {
		t.Fatalf("expected clean file to stay out of logs, got %q", out)
	}
	if !strings.Contains(out, `scan complete`) {
		t.Fatalf("expected completion log, got %q", out)
	}
}

func TestRunVerboseLogsMatchDetails(t *testing.T) {
	dbPath := createCAIDTestDB(t)

	root := t.TempDir()
	matchedPath := writeMatchCandidate(t, root, "nested/match.bin", strings.Repeat("malware payload", 128))
	modTime := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(matchedPath, modTime, modTime); err != nil {
		t.Fatalf("set matched path modtime: %v", err)
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(matchedPath)
	if err != nil {
		t.Fatalf("hash matched path: %v", err)
	}
	insertCAIDRow(t, dbPath, "exe", md5Hex, sha1Hex, int64(len(strings.Repeat("malware payload", 128))), 9)

	tests := []struct {
		name string
		flag string
	}{
		{name: "short", flag: "-v"},
		{name: "long", flag: "--verbose"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := newTestLogger(&logBuf)

			if err := run([]string{tt.flag, dbPath, root}, logger, &logBuf); err != nil {
				t.Fatalf("run() error = %v", err)
			}

			out := logBuf.String()
			for _, want := range []string{
				`match path="nested/match.bin"`,
				`label="caid:exe (category 9):sha1-` + sha1Hex + `"`,
				`size=1920`,
				`modtime="2026-01-02T03:04:05Z"`,
				`filetype="exe"`,
				`category=9`,
				`md5="` + md5Hex + `"`,
				`sha1="` + sha1Hex + `"`,
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("expected %q in verbose output, got %q", want, out)
				}
			}
		})
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

func writeMatchCandidate(t *testing.T, root, relPath, content string) string {
	t.Helper()

	fullPath := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir candidate parent: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	return fullPath
}

func hashFileMD5SHA1(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()

	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1), f); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(hMD5.Sum(nil)), hex.EncodeToString(hSHA1.Sum(nil)), nil
}

func newTestLogger(w io.Writer) *log.Logger {
	return log.New(w, "", 0)
}
