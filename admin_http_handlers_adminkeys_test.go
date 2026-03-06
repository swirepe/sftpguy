package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHandleAdminKeys_GetAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	blacklistPath := filepath.Join(tmpDir, "blacklist.txt")
	whitelistPath := filepath.Join(tmpDir, "whitelist.txt")
	adminKeysPath := filepath.Join(tmpDir, "admin_keys.txt")
	hostKeyPath := filepath.Join(tmpDir, "host_key")
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadDir := filepath.Join(tmpDir, "uploads")

	if err := os.WriteFile(blacklistPath, []byte(""), permFile); err != nil {
		t.Fatalf("write blacklist: %v", err)
	}
	if err := os.WriteFile(whitelistPath, []byte(""), permFile); err != nil {
		t.Fatalf("write whitelist: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := Config{
		Name:          "sftpguy-test",
		Port:          2222,
		HostKeyFile:   hostKeyPath,
		DBPath:        dbPath,
		UploadDir:     uploadDir,
		BlacklistPath: blacklistPath,
		WhitelistPath: whitelistPath,
		AdminKeysPath: adminKeysPath,
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer srv.Shutdown()

	// GET should succeed even when file does not exist yet.
	getReq := httptest.NewRequest(http.MethodGet, "/admin/api/admin-keys", nil)
	getW := httptest.NewRecorder()
	srv.handleAdminKeys(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/admin-keys status = %d, body=%s", getW.Code, getW.Body.String())
	}

	var getResp map[string]any
	if err := json.Unmarshal(getW.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if gotPath, _ := getResp["path"].(string); gotPath != adminKeysPath {
		t.Fatalf("unexpected admin keys path: got=%q want=%q", gotPath, adminKeysPath)
	}

	// POST a new key through the admin endpoint.
	adminSigner := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))
	body, _ := json.Marshal(map[string]any{"content": pubLine})
	postReq := httptest.NewRequest(http.MethodPost, "/admin/api/admin-keys", bytes.NewReader(body))
	postW := httptest.NewRecorder()
	srv.handleAdminKeys(postW, postReq)
	if postW.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/admin-keys status = %d, body=%s", postW.Code, postW.Body.String())
	}

	if srv.store.adminKeys == nil || !srv.store.adminKeys.ContainsKey(adminSigner.PublicKey()) {
		t.Fatal("saved admin key was not loaded into admin key list")
	}

	savedContent, err := os.ReadFile(adminKeysPath)
	if err != nil {
		t.Fatalf("read saved admin key file: %v", err)
	}
	if !strings.Contains(string(savedContent), pubLine) {
		t.Fatalf("saved admin key file missing expected key line")
	}
}
