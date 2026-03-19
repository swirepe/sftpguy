package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerSelfTestSuite(t *testing.T) {
	port := testFreeTCPPort(t)
	tmpDir := t.TempDir()

	unrestricted := make(map[string]bool, len(defaultUnrestrictedPaths))
	for _, p := range defaultUnrestrictedPaths {
		unrestricted[p] = true
	}

	cfg := Config{
		Name:                 "sftpguy-test",
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
		AdminSFTP:            true,
		SshNoAuth:            false,
		SelfTest:             true,
		BlacklistPath:        filepath.Join(tmpDir, "blacklist.txt"),
		WhitelistPath:        filepath.Join(tmpDir, "whitelist.txt"),
		AdminKeysPath:        filepath.Join(tmpDir, "admin_keys.txt"),
		BadFilesPath:         filepath.Join(tmpDir, "bad_files.txt"),
	}

	// Create list files so reloaders start cleanly.
	if err := os.WriteFile(cfg.BlacklistPath, []byte(""), permFile); err != nil {
		t.Fatalf("write blacklist file: %v", err)
	}
	if err := os.WriteFile(cfg.WhitelistPath, []byte(""), permFile); err != nil {
		t.Fatalf("write whitelist file: %v", err)
	}
	if err := os.WriteFile(cfg.AdminKeysPath, []byte(""), permFile); err != nil {
		t.Fatalf("write admin keys file: %v", err)
	}
	if err := os.WriteFile(cfg.BadFilesPath, []byte(""), permFile); err != nil {
		t.Fatalf("write bad files file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Mirror runtime startup ordering so ownership/system path registration
	// behavior matches the normal server process.
	srv.reconcileOrphans()

	listenDone := make(chan error, 1)
	go func() {
		listenDone <- srv.Listen()
	}()

	report := RunSelfTestWithReport(srv, cfg, logger)

	shutdownErr := srv.Shutdown()
	if shutdownErr != nil {
		t.Fatalf("shutdown failed: %v", shutdownErr)
	}

	select {
	case listenErr := <-listenDone:
		if listenErr != nil && !isExpectedListenerClose(listenErr) {
			t.Fatalf("listener exited with unexpected error: %v", listenErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("listener did not exit after shutdown")
	}

	if report.Failed > 0 || strings.TrimSpace(report.Error) != "" {
		t.Fatalf("self-test failed: failed=%d error=%q details=%s", report.Failed, report.Error, summarizeSelfTestFailures(report))
	}
}

func testFreeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate test port: %v", err)
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", l.Addr())
	}
	return addr.Port
}

func isExpectedListenerClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection")
}

func summarizeSelfTestFailures(report SelfTestReport) string {
	if report.Failed <= 0 {
		return ""
	}
	failures := make([]string, 0, report.Failed)
	for _, suite := range report.Suites {
		for _, step := range suite.Steps {
			if step.Skipped || step.Passed {
				continue
			}
			errText := strings.TrimSpace(step.Error)
			if errText == "" {
				errText = "unknown error"
			}
			failures = append(failures, suite.Name+" :: "+step.Name+" :: "+errText)
		}
	}
	return strings.Join(failures, " | ")
}
