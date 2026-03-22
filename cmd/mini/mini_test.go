package main

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

func TestSafePathRejectsTraversal(t *testing.T) {
	env := newMiniTestEnv(t)

	full, err := env.h.safePath("docs/note.txt")
	if err != nil {
		t.Fatalf("safePath valid path error = %v", err)
	}
	if !strings.HasPrefix(full, env.h.cfg.Dir+string(filepath.Separator)) {
		t.Fatalf("safePath valid path = %q, want under %q", full, env.h.cfg.Dir)
	}

	if _, err := env.h.safePath("../escape.txt"); err == nil {
		t.Fatal("safePath traversal unexpectedly succeeded")
	}
}

func TestFilereadHonorsThresholdAndUnrestrictedPaths(t *testing.T) {
	env := newMiniTestEnv(t)
	mustWriteMiniFile(t, filepath.Join(env.h.cfg.Dir, "locked.txt"), "private")
	mustWriteMiniFile(t, filepath.Join(env.h.cfg.Dir, "public", "hello.txt"), "hello")

	if _, err := env.h.Fileread(sftp.NewRequest("Get", "/locked.txt")); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("Fileread locked file error = %v, want permission denied", err)
	}
	if got := env.stderr.String(); !strings.Contains(got, "Upload 1024 more bytes to unlock.") {
		t.Fatalf("locked file stderr = %q, want threshold message", got)
	}

	reader, err := env.h.Fileread(sftp.NewRequest("Get", "/public/hello.txt"))
	if err != nil {
		t.Fatalf("Fileread unrestricted path error = %v", err)
	}
	if got := mustReadAllFromReaderAt(t, reader); got != "hello" {
		t.Fatalf("Fileread unrestricted contents = %q, want %q", got, "hello")
	}

	env.mustExec(t, "UPDATE users SET uploaded = ? WHERE hash = ?", env.h.cfg.Threshold, env.h.hash)
	reader, err = env.h.Fileread(sftp.NewRequest("Get", "/locked.txt"))
	if err != nil {
		t.Fatalf("Fileread unlocked file error = %v", err)
	}
	if got := mustReadAllFromReaderAt(t, reader); got != "private" {
		t.Fatalf("Fileread unlocked contents = %q, want %q", got, "private")
	}
}

func TestFilewriteCloseOnlyCreditsGrowthOnOverwrite(t *testing.T) {
	env := newMiniTestEnv(t)

	writeMiniUpload(t, env.h, "/docs/report.txt", "hello")
	if got := env.uploadedBytes(t); got != 5 {
		t.Fatalf("uploaded after first write = %d, want 5", got)
	}
	if got := env.fileSize(t, "docs/report.txt"); got != 5 {
		t.Fatalf("file size after first write = %d, want 5", got)
	}

	writeMiniUpload(t, env.h, "/docs/report.txt", "hello world")
	if got := env.uploadedBytes(t); got != 11 {
		t.Fatalf("uploaded after grow overwrite = %d, want 11", got)
	}
	if got := env.fileSize(t, "docs/report.txt"); got != 11 {
		t.Fatalf("file size after grow overwrite = %d, want 11", got)
	}

	writeMiniUpload(t, env.h, "/docs/report.txt", "hi")
	if got := env.uploadedBytes(t); got != 11 {
		t.Fatalf("uploaded after shrink overwrite = %d, want 11", got)
	}
	if got := env.fileSize(t, "docs/report.txt"); got != 2 {
		t.Fatalf("file size after shrink overwrite = %d, want 2", got)
	}
	if got := mustReadMiniFile(t, filepath.Join(env.h.cfg.Dir, "docs", "report.txt")); got != "hi" {
		t.Fatalf("report.txt contents = %q, want %q", got, "hi")
	}
}

func TestFilecmdRenameUpdatesNestedDatabasePaths(t *testing.T) {
	env := newMiniTestEnv(t)

	if err := env.h.Filecmd(sftp.NewRequest("Mkdir", "/album")); err != nil {
		t.Fatalf("mkdir album: %v", err)
	}
	writeMiniUpload(t, env.h, "/album/track.txt", "track")
	writeMiniUpload(t, env.h, "/album/nested/cover.txt", "cover")

	req := sftp.NewRequest("Rename", "/album")
	req.Target = "/archive"
	if err := env.h.Filecmd(req); err != nil {
		t.Fatalf("rename album: %v", err)
	}

	if _, err := os.Stat(filepath.Join(env.h.cfg.Dir, "archive", "track.txt")); err != nil {
		t.Fatalf("renamed track missing on disk: %v", err)
	}
	if env.fileExists(t, "album") || env.fileExists(t, "album/track.txt") || env.fileExists(t, "album/nested/cover.txt") {
		t.Fatal("old album paths still present in database after rename")
	}
	if !env.fileExists(t, "archive") || !env.fileExists(t, "archive/track.txt") || !env.fileExists(t, "archive/nested/cover.txt") {
		t.Fatal("renamed archive paths missing from database after rename")
	}
}

type miniTestEnv struct {
	db     *sql.DB
	h      *fsHandler
	stderr *bytes.Buffer
}

func newMiniTestEnv(t *testing.T) *miniTestEnv {
	t.Helper()

	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(root, "mini.db"))
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if _, err := db.Exec(Schema); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	const hash = "mini-test-user"
	if _, err := db.Exec("INSERT OR IGNORE INTO users (hash, uploaded) VALUES (?, 0)", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	uploadDir := filepath.Join(root, "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		t.Fatalf("create upload dir: %v", err)
	}

	stderr := &bytes.Buffer{}
	return &miniTestEnv{
		db: db,
		h: &fsHandler{
			db:     db,
			hash:   hash,
			cfg:    Config{Dir: uploadDir, Threshold: 1024, Unrestricted: "README.txt,public/"},
			stderr: stderr,
		},
		stderr: stderr,
	}
}

func (e *miniTestEnv) mustExec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := e.db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func (e *miniTestEnv) uploadedBytes(t *testing.T) int64 {
	t.Helper()
	var uploaded int64
	if err := e.db.QueryRow("SELECT uploaded FROM users WHERE hash = ?", e.h.hash).Scan(&uploaded); err != nil {
		t.Fatalf("query uploaded bytes: %v", err)
	}
	return uploaded
}

func (e *miniTestEnv) fileExists(t *testing.T, rel string) bool {
	t.Helper()
	var count int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM files WHERE path = ?", rel).Scan(&count); err != nil {
		t.Fatalf("query file existence for %q: %v", rel, err)
	}
	return count > 0
}

func (e *miniTestEnv) fileSize(t *testing.T, rel string) int64 {
	t.Helper()
	var size int64
	if err := e.db.QueryRow("SELECT size FROM files WHERE path = ?", rel).Scan(&size); err != nil {
		t.Fatalf("query file size for %q: %v", rel, err)
	}
	return size
}

func writeMiniUpload(t *testing.T, h *fsHandler, requestPath, contents string) {
	t.Helper()

	writer, err := h.Filewrite(sftp.NewRequest("Put", requestPath))
	if err != nil {
		t.Fatalf("open writer for %s: %v", requestPath, err)
	}
	if _, err := writer.WriteAt([]byte(contents), 0); err != nil {
		t.Fatalf("write %s: %v", requestPath, err)
	}
	closer, ok := writer.(io.Closer)
	if !ok {
		t.Fatalf("writer for %s does not implement io.Closer", requestPath)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close writer for %s: %v", requestPath, err)
	}
}

func mustReadAllFromReaderAt(t *testing.T, reader io.ReaderAt) string {
	t.Helper()

	data, err := io.ReadAll(io.NewSectionReader(reader, 0, 1<<20))
	if err != nil {
		t.Fatalf("read readerAt contents: %v", err)
	}
	return string(data)
}

func mustWriteMiniFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func mustReadMiniFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data)
}
