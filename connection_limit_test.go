package main

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerMaxConnectionsPerIPRejectsExcessAndReleases(t *testing.T) {
	port := testFreeTCPPort(t)
	tmpDir := t.TempDir()

	unrestricted := make(map[string]bool, len(defaultUnrestrictedPaths))
	for _, p := range defaultUnrestrictedPaths {
		unrestricted[p] = true
	}

	cfg := Config{
		Name:                 "sftpguy-conn-limit-test",
		Port:                 port,
		MaxConnectionsPerIP:  1,
		HostKeyFile:          filepath.Join(tmpDir, "id_ed25519"),
		DBPath:               filepath.Join(tmpDir, "sftp.db"),
		LogFile:              filepath.Join(tmpDir, "sftp.log"),
		UploadDir:            filepath.Join(tmpDir, "uploads"),
		BannerFile:           filepath.Join(tmpDir, "BANNER.txt"),
		MkdirRate:            100.0,
		MaxDirs:              10000,
		ContributorThreshold: 0,
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

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	first := dialTCPWithRetry(t, addr, 10*time.Second)
	defer first.Close()
	waitForActiveIPCount(t, srv, "127.0.0.1", 1, 3*time.Second)

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial second connection: %v", err)
	}
	assertConnectionClosedSoon(t, second, "second connection")

	thirdRejected, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial third rejected connection: %v", err)
	}
	assertConnectionClosedSoon(t, thirdRejected, "third rejected connection")
	assertConnectionLimitAudit(t, srv.store.db, "127.0.0.1", 1, 1, 1)
	if err := srv.store.FlushConnectionLimitAggregates(); err != nil {
		t.Fatalf("flush connection limit audit: %v", err)
	}
	assertConnectionLimitAudit(t, srv.store.db, "127.0.0.1", 2, 1, 1)

	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	waitForActiveIPCount(t, srv, "127.0.0.1", 0, 3*time.Second)

	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	defer third.Close()
	waitForActiveIPCount(t, srv, "127.0.0.1", 1, 3*time.Second)
}

func TestConnectionLimitAuditFlushesOnShutdown(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	dbPath := srv.cfg.DBPath
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.45"), Port: 55223}

	srv.store.LogConnectionLimitExceeded(addr, 4, 4)
	srv.store.LogConnectionLimitExceeded(addr, 4, 4)
	assertConnectionLimitAudit(t, srv.store.db, "203.0.113.45", 1, 4, 4)

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("shutdown server: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db after shutdown: %v", err)
	}
	defer db.Close()
	assertConnectionLimitAudit(t, db, "203.0.113.45", 2, 4, 4)
}

func dialTCPWithRetry(t *testing.T, addr string, timeout time.Duration) net.Conn {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("dial %s before timeout: %v", addr, lastErr)
	return nil
}

func waitForActiveIPCount(t *testing.T, srv *Server, ip string, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := activeIPCount(srv, ip); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("active connection count for %s = %d, want %d", ip, activeIPCount(srv, ip), want)
}

func activeIPCount(srv *Server, ip string) int {
	srv.activeConnMu.Lock()
	defer srv.activeConnMu.Unlock()
	return srv.activeConnByIP[ip]
}

func assertConnectionLimitAudit(t *testing.T, db *sql.DB, ip string, wantHits, wantActive, wantLimit int64) {
	t.Helper()

	var rows int64
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM log
		WHERE event = ? AND ip_address = ?`, string(EventDeniedConnectionLimit), ip).Scan(&rows); err != nil {
		t.Fatalf("count connection limit audit rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("connection limit audit rows for %s = %d, want 1", ip, rows)
	}

	var timestamp int64
	var port int
	var rawMeta string
	if err := db.QueryRow(`
		SELECT timestamp, port, IFNULL(meta, '')
		FROM log
		WHERE event = ? AND ip_address = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventDeniedConnectionLimit), ip).Scan(&timestamp, &port, &rawMeta); err != nil {
		t.Fatalf("query connection limit audit row: %v", err)
	}
	if timestamp <= 0 {
		t.Fatalf("connection limit audit timestamp = %d, want positive", timestamp)
	}
	if port <= 0 {
		t.Fatalf("connection limit audit port = %d, want remote port", port)
	}

	meta := parseJSONMap(rawMeta)
	if meta == nil {
		t.Fatalf("connection limit audit meta was not JSON: %q", rawMeta)
	}
	if got := int64FromAny(meta["hits"]); got != wantHits {
		t.Fatalf("connection limit hits = %d, want %d; meta=%s", got, wantHits, rawMeta)
	}
	if got := int64FromAny(meta["active_connections"]); got != wantActive {
		t.Fatalf("connection limit active_connections = %d, want %d; meta=%s", got, wantActive, rawMeta)
	}
	if got := int64FromAny(meta["max_connections"]); got != wantLimit {
		t.Fatalf("connection limit max_connections = %d, want %d; meta=%s", got, wantLimit, rawMeta)
	}
	if got := int64FromAny(meta["first_timestamp"]); got != timestamp {
		t.Fatalf("connection limit first_timestamp = %d, want row timestamp %d; meta=%s", got, timestamp, rawMeta)
	}
	if got := int64FromAny(meta["window_seconds"]); got != int64(connectionLimitWindow/time.Second) {
		t.Fatalf("connection limit window_seconds = %d, want %d; meta=%s", got, int64(connectionLimitWindow/time.Second), rawMeta)
	}
	if meta["first_time"] == "" || meta["last_time"] == "" || meta["window_end_time"] == "" {
		t.Fatalf("connection limit audit meta missing formatted times: %s", rawMeta)
	}
}

func assertConnectionClosedSoon(t *testing.T, conn net.Conn, label string) {
	t.Helper()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline for %s: %v", label, err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); err == nil {
		t.Fatalf("%s stayed readable after it should have been rejected", label)
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("%s was not closed before the read deadline", label)
	}
}
