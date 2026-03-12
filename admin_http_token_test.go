package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateAdminHTTPToken_CreatesWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "admin_http_token.txt")

	token, wrote, err := loadOrCreateAdminHTTPToken(path)
	if err != nil {
		t.Fatalf("loadOrCreateAdminHTTPToken returned error: %v", err)
	}
	if !wrote {
		t.Fatal("expected wrote=true when token file is missing")
	}
	if strings.TrimSpace(token) == "" {
		t.Fatal("expected generated token")
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated token file: %v", err)
	}
	if strings.TrimSpace(string(onDisk)) != token {
		t.Fatalf("token mismatch: file=%q returned=%q", strings.TrimSpace(string(onDisk)), token)
	}
}

func TestLoadOrCreateAdminHTTPToken_UsesExistingToken(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "admin_http_token.txt")
	if err := os.WriteFile(path, []byte("existing-token\n"), permFile); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	token, wrote, err := loadOrCreateAdminHTTPToken(path)
	if err != nil {
		t.Fatalf("loadOrCreateAdminHTTPToken returned error: %v", err)
	}
	if wrote {
		t.Fatal("expected wrote=false when token already exists")
	}
	if token != "existing-token" {
		t.Fatalf("unexpected token: got=%q want=%q", token, "existing-token")
	}
}

func TestLoadOrCreateAdminHTTPToken_ReplacesEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "admin_http_token.txt")
	if err := os.WriteFile(path, []byte("\n"), permFile); err != nil {
		t.Fatalf("write empty token file: %v", err)
	}

	token, wrote, err := loadOrCreateAdminHTTPToken(path)
	if err != nil {
		t.Fatalf("loadOrCreateAdminHTTPToken returned error: %v", err)
	}
	if !wrote {
		t.Fatal("expected wrote=true for empty token file")
	}
	if strings.TrimSpace(token) == "" {
		t.Fatal("expected generated token")
	}
}
