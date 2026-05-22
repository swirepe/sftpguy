package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSeedAdminDemoDataAddsFilesHostnamesAndSecurityActivity(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	srv.store.eventHostnameLookup = func(context.Context, string) ([]string, error) {
		return nil, nil
	}

	stats, err := seedAdminDemoData(srv.store, srv.absUploadDir, time.Date(2026, time.May, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("seed admin demo data: %v", err)
	}
	if stats.Users != 5 || stats.Files != 2 || stats.Events < 10 || stats.BannedIPs != 1 {
		t.Fatalf("unexpected seed stats: %+v", stats)
	}

	const relPath = "demo/reports/connection-hostnames.csv"
	if !srv.store.FileExistsInDB(relPath) {
		t.Fatalf("expected %s in files table", relPath)
	}
	if _, err := os.Stat(filepath.Join(srv.absUploadDir, filepath.FromSlash(relPath))); err != nil {
		t.Fatalf("stat seeded file: %v", err)
	}

	var meta string
	if err := srv.store.db.QueryRow(`
		SELECT IFNULL(meta, '')
		FROM log
		WHERE event = ? AND path = ?
		ORDER BY id DESC
		LIMIT 1`, string(EventUpload), relPath).Scan(&meta); err != nil {
		t.Fatalf("read seeded upload meta: %v", err)
	}
	if !strings.Contains(meta, `"hosts":["dns.google"]`) || !strings.Contains(meta, `"demo_seed":true`) {
		t.Fatalf("expected demo hostname metadata in %q", meta)
	}

	var denied int
	if err := srv.store.db.QueryRow(`SELECT COUNT(*) FROM log WHERE user_id = ? AND event LIKE 'denied%'`, "demo-map-scanner").Scan(&denied); err != nil {
		t.Fatalf("count seeded denied activity: %v", err)
	}
	if denied < 3 {
		t.Fatalf("expected denied scanner activity, got %d rows", denied)
	}

	entries, err := srv.store.blacklist.ExactEntries()
	if err != nil {
		t.Fatalf("read seeded blacklist entries: %v", err)
	}
	var foundBannedIP bool
	for _, entry := range entries {
		if entry.ExactIP == adminDemoBannedIP {
			foundBannedIP = true
			break
		}
	}
	if !foundBannedIP {
		t.Fatalf("expected demo banned IP %s", adminDemoBannedIP)
	}
}
