package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHashListSkipsZeroLengthFiles(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	emptyPath := filepath.Join(srv.absUploadDir, "empty.bin")
	if err := os.WriteFile(emptyPath, nil, permFile); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	if _, err := srv.store.badFileList.AddFile(emptyPath); !errors.Is(err, errZeroLengthBadFile) {
		t.Fatalf("AddFile(empty) error = %v, want %v", err, errZeroLengthBadFile)
	}

	matchedName, matched, err := srv.store.badFileList.MatchFile(emptyPath)
	if err != nil {
		t.Fatalf("MatchFile(empty) error = %v", err)
	}
	if matched {
		t.Fatalf("MatchFile(empty) matched = true, name=%q", matchedName)
	}
	if matchedName != "" {
		t.Fatalf("MatchFile(empty) name = %q, want empty", matchedName)
	}

	content := emptyFileSHA256Hex + "  empty.bin\n"
	if err := os.WriteFile(srv.store.badFilesPath, []byte(content), permFile); err != nil {
		t.Fatalf("write bad files content: %v", err)
	}

	entries, err := srv.store.badFileList.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if entries != 0 {
		t.Fatalf("Reload() entries = %d, want 0", entries)
	}
	if name, ok := srv.store.badFileList.Lookup(emptyFileSHA256Hex); ok || name != "" {
		t.Fatalf("Lookup(empty hash) = (%q, %v), want (\"\", false)", name, ok)
	}
}
