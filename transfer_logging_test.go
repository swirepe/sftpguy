package main

import (
	"bytes"
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

func TestUploadLogIncludesDurationAndAverageSpeed(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	var logBuf bytes.Buffer
	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.88"), Port: 2022}
	const ownerHash = "upload-log-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, addr); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}

	handler := &fsHandler{
		srv:        srv,
		pubHash:    ownerHash,
		stderr:     io.Discard,
		logger:     *slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})),
		remoteAddr: addr,
		sessionID:  "sess-upload-log",
	}

	writer, err := handler.Filewrite(sftp.NewRequest("Put", "/speed.txt"))
	if err != nil {
		t.Fatalf("open upload writer: %v", err)
	}
	payload := []byte("hello world")
	if _, err := writer.WriteAt(payload, 0); err != nil {
		t.Fatalf("write upload payload: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("close upload writer: %v", err)
	}

	line := logBuf.String()
	if !strings.Contains(line, "msg=upload") {
		t.Fatalf("expected upload log line, got %q", line)
	}
	if !strings.Contains(line, "duration=") {
		t.Fatalf("expected duration in upload log, got %q", line)
	}
	if !strings.Contains(line, "avg=") {
		t.Fatalf("expected avg in upload log, got %q", line)
	}
	if !strings.Contains(line, "transferred=11") {
		t.Fatalf("expected transferred bytes in upload log, got %q", line)
	}

	meta := latestEventMeta(t, srv, EventUpload)
	if got := int64FromAny(meta["transferred"]); got != int64(len(payload)) {
		t.Fatalf("unexpected upload transferred bytes: got=%d want=%d", got, len(payload))
	}
	if got := int64FromAny(meta["duration_ms"]); got <= 0 {
		t.Fatalf("expected positive upload duration_ms, got %d", got)
	}
	if got := int64FromAny(meta["avg_bytes_per_sec"]); got <= 0 {
		t.Fatalf("expected positive upload avg_bytes_per_sec, got %d", got)
	}
}

func TestDownloadLogIncludesDurationAndAverageSpeed(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	var logBuf bytes.Buffer
	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.99"), Port: 2022}
	const ownerHash = "download-log-owner"
	if _, err := srv.store.UpsertUserSession(ownerHash, addr); err != nil {
		t.Fatalf("upsert user session: %v", err)
	}

	payload := []byte("download me")
	fullPath := filepath.Join(srv.absUploadDir, "probe.txt")
	if err := os.WriteFile(fullPath, payload, permFile); err != nil {
		t.Fatalf("write probe file: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, "probe.txt", int64(len(payload)), int64(len(payload))); err != nil {
		t.Fatalf("register probe file: %v", err)
	}

	handler := &fsHandler{
		srv:        srv,
		pubHash:    ownerHash,
		stderr:     io.Discard,
		logger:     *slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})),
		remoteAddr: addr,
		sessionID:  "sess-download-log",
		isAdmin:    true,
	}

	reader, err := handler.Fileread(sftp.NewRequest("Get", "/probe.txt"))
	if err != nil {
		t.Fatalf("open download reader: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := reader.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatalf("read download payload: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := reader.(io.Closer).Close(); err != nil {
		t.Fatalf("close download reader: %v", err)
	}

	line := logBuf.String()
	if !strings.Contains(line, "msg=download") {
		t.Fatalf("expected download log line, got %q", line)
	}
	if !strings.Contains(line, "duration=") {
		t.Fatalf("expected duration in download log, got %q", line)
	}
	if !strings.Contains(line, "avg=") {
		t.Fatalf("expected avg in download log, got %q", line)
	}
	if !strings.Contains(line, "size=11") {
		t.Fatalf("expected transferred size in download log, got %q", line)
	}

	meta := latestEventMeta(t, srv, EventDownload)
	if got := int64FromAny(meta["size"]); got != int64(len(payload)) {
		t.Fatalf("unexpected download size: got=%d want=%d", got, len(payload))
	}
	if got := int64FromAny(meta["duration_ms"]); got <= 0 {
		t.Fatalf("expected positive download duration_ms, got %d", got)
	}
	if got := int64FromAny(meta["avg_bytes_per_sec"]); got <= 0 {
		t.Fatalf("expected positive download avg_bytes_per_sec, got %d", got)
	}

	stats, err := srv.store.GetUserStats(ownerHash)
	if err != nil {
		t.Fatalf("get user stats: %v", err)
	}
	if stats.DownloadCount != 1 {
		t.Fatalf("unexpected download count: got=%d want=%d", stats.DownloadCount, 1)
	}
	if stats.DownloadBytes != int64(len(payload)) {
		t.Fatalf("unexpected download bytes: got=%d want=%d", stats.DownloadBytes, len(payload))
	}
}

func latestEventMeta(t *testing.T, srv *Server, event EventKind) map[string]any {
	t.Helper()

	var meta string
	if err := srv.store.db.QueryRow(`SELECT IFNULL(meta, '') FROM log WHERE event = ? ORDER BY id DESC LIMIT 1`, string(event)).Scan(&meta); err != nil {
		t.Fatalf("query latest %s event: %v", event, err)
	}
	return parseJSONMap(meta)
}
