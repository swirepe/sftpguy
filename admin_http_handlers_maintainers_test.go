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

func TestHandleAdminMaintainers_GetAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	blacklistPath := filepath.Join(tmpDir, "blacklist.txt")
	whitelistPath := filepath.Join(tmpDir, "whitelist.txt")
	adminKeysPath := filepath.Join(tmpDir, "admin_keys.txt")
	maintainersPath := filepath.Join(tmpDir, "maintainers.txt")
	badFilesPath := filepath.Join(tmpDir, "bad_files.txt")
	hostKeyPath := filepath.Join(tmpDir, "host_key")
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadDir := filepath.Join(tmpDir, "uploads")

	for _, path := range []string{blacklistPath, whitelistPath, adminKeysPath, badFilesPath} {
		if err := os.WriteFile(path, []byte(""), permFile); err != nil {
			t.Fatalf("write support file %s: %v", path, err)
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := Config{
		Name:            "sftpguy-test",
		Port:            2222,
		HostKeyFile:     hostKeyPath,
		DBPath:          dbPath,
		UploadDir:       uploadDir,
		BlacklistPath:   blacklistPath,
		WhitelistPath:   whitelistPath,
		AdminKeysPath:   adminKeysPath,
		MaintainersPath: maintainersPath,
		BadFilesPath:    badFilesPath,
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer srv.Shutdown()

	getReq := httptest.NewRequest(http.MethodGet, "/admin/api/maintainers", nil)
	getW := httptest.NewRecorder()
	srv.handleAdminMaintainers(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/maintainers status = %d, body=%s", getW.Code, getW.Body.String())
	}

	var getResp map[string]any
	if err := json.Unmarshal(getW.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if gotPath, _ := getResp["path"].(string); gotPath != maintainersPath {
		t.Fatalf("unexpected maintainers path: got=%q want=%q", gotPath, maintainersPath)
	}

	maintainerSigner := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(maintainerSigner.PublicKey())))
	body, _ := json.Marshal(map[string]any{"content": "public/audiobooks " + pubLine})
	postReq := httptest.NewRequest(http.MethodPost, "/admin/api/maintainers", bytes.NewReader(body))
	postW := httptest.NewRecorder()
	srv.handleAdminMaintainers(postW, postReq)
	if postW.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/maintainers status = %d, body=%s", postW.Code, postW.Body.String())
	}

	maintainerHash := publicKeyHash(maintainerSigner.PublicKey())
	if srv.store.scopedMaintainers == nil || !srv.store.scopedMaintainers.Maintains(maintainerHash, "public/audiobooks/book.mp3") {
		t.Fatal("saved maintainer grant was not loaded into scoped maintainer list")
	}

	savedContent, err := os.ReadFile(maintainersPath)
	if err != nil {
		t.Fatalf("read saved maintainers file: %v", err)
	}
	if !strings.Contains(string(savedContent), "public/audiobooks "+pubLine) {
		t.Fatalf("saved maintainers file missing expected grant line")
	}
}
