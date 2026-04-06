package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestWelcomeListsOnlyRecentOwnedFiles(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "banner-owner"
	srv.cfg.ContributorThreshold = 1 << 20

	if _, err := srv.store.UpsertUserSession(ownerHash, nil); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, "nested"); err != nil {
		t.Fatalf("ensure nested dir: %v", err)
	}

	for i := 1; i <= 12; i++ {
		rel := fmt.Sprintf("nested/file-%02d.txt", i)
		if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, rel, int64(i), int64(i)); err != nil {
			t.Fatalf("register %s: %v", rel, err)
		}
	}

	var buf bytes.Buffer
	srv.Welcome(&buf, ownerHash, userStats{
		LastLogin:   "2026-04-06 12:00:00",
		UploadCount: 12,
		UploadBytes: 120,
	})

	body := buf.String()
	if !strings.Contains(body, "* You have created 12 files, 1 directories.") {
		t.Fatalf("welcome body missing owned file summary:\n%s", body)
	}
	if !strings.Contains(body, "* Your last 10 owned files:") {
		t.Fatalf("welcome body missing recent owned files header:\n%s", body)
	}
	if !strings.Contains(body, "... and 2 older files.") {
		t.Fatalf("welcome body missing older files summary:\n%s", body)
	}

	for i := 3; i <= 12; i++ {
		rel := fmt.Sprintf("nested/file-%02d.txt", i)
		if !strings.Contains(body, rel) {
			t.Fatalf("welcome body missing recent file %q:\n%s", rel, body)
		}
	}

	for i := 1; i <= 2; i++ {
		rel := fmt.Sprintf("nested/file-%02d.txt", i)
		if strings.Contains(body, rel) {
			t.Fatalf("welcome body unexpectedly included older file %q:\n%s", rel, body)
		}
	}
}
