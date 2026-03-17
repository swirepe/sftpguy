package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPrometheusMetricsExposeSFTPTraffic(t *testing.T) {
	port := testFreeTCPPort(t)
	adminPort := testFreeTCPPort(t)
	tmpDir := t.TempDir()

	unrestricted := make(map[string]bool, len(defaultUnrestrictedPaths))
	for _, p := range defaultUnrestrictedPaths {
		unrestricted[p] = true
	}

	cfg := Config{
		Name:                 "sftpguy-prometheus-test",
		Port:                 port,
		AdminHTTP:            fmt.Sprintf("127.0.0.1:%d", adminPort),
		EnablePrometheus:     true,
		PrometheusRoot:       "/metrics",
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

	sshDone := make(chan error, 1)
	go func() {
		sshDone <- srv.Listen()
	}()

	adminDone := make(chan error, 1)
	go func() {
		adminDone <- srv.ListenAdminHTTP()
	}()

	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("shutdown failed: %v", err)
		}

		select {
		case err := <-sshDone:
			if err != nil && !isExpectedListenerClose(err) {
				t.Errorf("ssh listener exited with unexpected error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("ssh listener did not exit after shutdown")
		}

		select {
		case err := <-adminDone:
			if err != nil && !isExpectedListenerClose(err) {
				t.Errorf("admin listener exited with unexpected error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("admin listener did not exit after shutdown")
		}
	})

	if !stWaitReady(cfg.Port, 10*time.Second) {
		t.Fatal("ssh server did not become ready within timeout")
	}

	metricsURL := fmt.Sprintf("http://127.0.0.1:%d%s", adminPort, cfg.PrometheusRoot)
	waitForHTTPOK(t, metricsURL, 10*time.Second)

	runner := &selfTestRunner{
		srv: srv,
		cfg: cfg,
		log: logger.WithGroup("test"),
	}

	auth, _, _ := runner.newPubKeyAuth()
	sshCli, sftpCli, err := runner.openSFTP(auth)
	if err != nil {
		t.Fatalf("open sftp: %v", err)
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	payload := []byte("hello prometheus")
	if err := stWrite(sftpCli, "probe.txt", payload); err != nil {
		t.Fatalf("write probe file: %v", err)
	}

	reader, err := sftpCli.Open("/probe.txt")
	if err != nil {
		t.Fatalf("open probe file for download: %v", err)
	}
	readBack, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil {
		t.Fatalf("read probe file: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close probe file: %v", closeErr)
	}
	if string(readBack) != string(payload) {
		t.Fatalf("unexpected probe payload: got=%q want=%q", string(readBack), string(payload))
	}

	metricsBody := scrapeMetricsBody(t, metricsURL)

	requireMetricAtLeast(t, metricsBody, "sftpguy_users_total", nil, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sessions_total", map[string]string{
		"login_type": "pubkey_hash",
		"admin":      "false",
		"banned":     "false",
	}, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_requests_total", map[string]string{
		"operation": "write",
		"outcome":   "success",
		"admin":     "false",
		"banned":    "false",
	}, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_requests_total", map[string]string{
		"operation": "read",
		"outcome":   "success",
		"admin":     "false",
		"banned":    "false",
	}, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_transfers_total", map[string]string{
		"direction": "upload",
		"admin":     "false",
		"banned":    "false",
	}, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_transfers_total", map[string]string{
		"direction": "download",
		"admin":     "false",
		"banned":    "false",
	}, 1)
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_transfer_bytes_total", map[string]string{
		"direction": "upload",
		"admin":     "false",
		"banned":    "false",
	}, float64(len(payload)))
	requireMetricAtLeast(t, metricsBody, "sftpguy_sftp_transfer_bytes_total", map[string]string{
		"direction": "download",
		"admin":     "false",
		"banned":    "false",
	}, float64(len(payload)))
}

func waitForHTTPOK(t *testing.T, url string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", url)
}

func scrapeMetricsBody(t *testing.T, url string) string {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape metrics returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	return string(body)
}

func requireMetricAtLeast(t *testing.T, body string, name string, labels map[string]string, min float64) {
	t.Helper()

	value, ok := metricValue(body, name, labels)
	if !ok {
		t.Fatalf("metric %q with labels %v not found", name, labels)
	}
	if value < min {
		t.Fatalf("metric %q with labels %v = %v, want at least %v", name, labels, value, min)
	}
}

func metricValue(body, name string, labels map[string]string) (float64, bool) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	labelPrefix := name + "{"
	plainPrefix := name + " "

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if len(labels) == 0 {
			if !strings.HasPrefix(line, plainPrefix) {
				continue
			}
		} else {
			if !strings.HasPrefix(line, labelPrefix) {
				continue
			}
			matched := true
			for key, expected := range labels {
				if !strings.Contains(line, fmt.Sprintf(`%s=%q`, key, expected)) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		return value, true
	}

	return 0, false
}
