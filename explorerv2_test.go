package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestExplorerCookieNamesAreUnique(t *testing.T) {
	cfgA := Config{Name: "archive-a", Port: 2222, UploadDir: "./uploads", ExplorerHTTP: "127.0.0.1:8081"}
	cfgB := Config{Name: "archive-b", Port: 2222, UploadDir: "./uploads", ExplorerHTTP: "127.0.0.1:8081"}

	idA, csrfA := explorerCookieNames(cfgA)
	idB, csrfB := explorerCookieNames(cfgB)

	if idA == "explorer_unlocked" || csrfA == "explorer_csrf" {
		t.Fatalf("cookie names must not use static legacy names: id=%q csrf=%q", idA, csrfA)
	}
	if idA == idB || csrfA == csrfB {
		t.Fatalf("cookie names should differ across archive identities: A=(%q,%q) B=(%q,%q)", idA, csrfA, idB, csrfB)
	}
	if !strings.HasPrefix(idA, "sftpguy_exp_") || !strings.HasPrefix(csrfA, "sftpguy_exp_") {
		t.Fatalf("cookie names should use sftpguy prefix: id=%q csrf=%q", idA, csrfA)
	}
}

func TestExplorerPermissionsBoundToSignedIdentityCookie(t *testing.T) {
	srv := newExplorerTestServer(t)
	defer func() {
		_ = srv.Shutdown()
	}()

	lockedPath := filepath.Join(srv.absUploadDir, "locked.txt")
	if err := os.WriteFile(lockedPath, []byte("locked-content"), permFile); err != nil {
		t.Fatalf("write locked file: %v", err)
	}
	srv.store.RegisterFile("locked.txt", systemOwner, int64(len("locked-content")), false)

	h, err := srv.ExplorerHandler()
	if err != nil {
		t.Fatalf("explorer handler: %v", err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	clientA := newExplorerHTTPClient(t)
	clientB := newExplorerHTTPClient(t)

	if _, _, err := explorerGET(clientA, ts.URL+"/"); err != nil {
		t.Fatalf("client A bootstrap: %v", err)
	}
	if _, _, err := explorerGET(clientB, ts.URL+"/"); err != nil {
		t.Fatalf("client B bootstrap: %v", err)
	}

	resp, body, err := explorerGET(clientA, ts.URL+"/locked.txt")
	if err != nil {
		t.Fatalf("client A pre-contrib download: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client A pre-contrib expected 403, got %d body=%q", resp.StatusCode, body)
	}

	csrfA, err := explorerFetchCSRF(clientA, ts.URL+"/")
	if err != nil {
		t.Fatalf("fetch csrf for client A: %v", err)
	}
	payload := bytes.Repeat([]byte("x"), 96)
	if err := explorerUpload(clientA, ts.URL+"/", csrfA, "contrib.bin", payload); err != nil {
		t.Fatalf("client A upload: %v", err)
	}

	resp, _, err = explorerGET(clientA, ts.URL+"/locked.txt")
	if err != nil {
		t.Fatalf("client A post-contrib download: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client A post-contrib expected 200, got %d", resp.StatusCode)
	}

	resp, _, err = explorerGET(clientB, ts.URL+"/locked.txt")
	if err != nil {
		t.Fatalf("client B pre-contrib download: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client B should remain locked, got %d", resp.StatusCode)
	}

	identityCookieName, _ := srv.ExplorerCookieNames()
	u, _ := url.Parse(ts.URL)
	clientA.Jar.SetCookies(u, []*http.Cookie{{
		Name:  identityCookieName,
		Value: "v1.tampered.bad-signature",
		Path:  "/",
	}})

	resp, _, err = explorerGET(clientA, ts.URL+"/locked.txt")
	if err != nil {
		t.Fatalf("client A tampered-cookie download: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered identity cookie should lose contributor access, got %d", resp.StatusCode)
	}
}

func TestExplorerResumeUploadAppendsContent(t *testing.T) {
	srv := newExplorerTestServer(t)
	defer func() {
		_ = srv.Shutdown()
	}()

	h, err := srv.ExplorerHandler()
	if err != nil {
		t.Fatalf("explorer handler: %v", err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	client := newExplorerHTTPClient(t)
	csrf, err := explorerFetchCSRF(client, ts.URL+"/")
	if err != nil {
		t.Fatalf("fetch csrf: %v", err)
	}

	// Cross contributor threshold first so file downloads are permitted.
	if err := explorerUpload(client, ts.URL+"/", csrf, "unlock.bin", bytes.Repeat([]byte("u"), 96)); err != nil {
		t.Fatalf("unlock upload: %v", err)
	}

	base := []byte("resume-a:")
	appendPart := []byte("resume-b")
	if err := explorerUpload(client, ts.URL+"/", csrf, "resume.txt", base); err != nil {
		t.Fatalf("base upload: %v", err)
	}
	if err := explorerUpload(client, ts.URL+"/?resume=1", csrf, "resume.txt", appendPart); err != nil {
		t.Fatalf("resume upload: %v", err)
	}

	resp, got, err := explorerDownload(client, ts.URL+"/resume.txt")
	if err != nil {
		t.Fatalf("download resumed file: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	want := append(append([]byte{}, base...), appendPart...)
	if !bytes.Equal(got, want) {
		t.Fatalf("resume mismatch: got %q want %q", string(got), string(want))
	}
}

func newExplorerTestServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	uploadDir := filepath.Join(root, "uploads")
	if err := os.MkdirAll(uploadDir, permDir); err != nil {
		t.Fatalf("mkdir upload dir: %v", err)
	}
	cfg := Config{
		Name:                    "sftpguy-test",
		Port:                    2222,
		AdminHTTP:               "",
		AdminHTTPToken:          "",
		ExplorerHTTP:            "127.0.0.1:0",
		ExplorerCookieSecret:    "unit-test-secret",
		HostKeyFile:             filepath.Join(root, "id_ed25519"),
		DBPath:                  filepath.Join(root, "sftp.db"),
		LogFile:                 filepath.Join(root, "sftp.log"),
		UploadDir:               uploadDir,
		BannerFile:              filepath.Join(root, "BANNER.txt"),
		BannerStats:             false,
		MkdirRate:               100,
		MaxDirs:                 10000,
		Unrestricted:            strings.Join(defaultUnrestrictedPaths, ","),
		LockDirectoriesToOwners: false,
		PrettyLog:               false,
		Debug:                   false,
		QuietConsole:            true,
		MaxFileSize:             8 << 30,
		ExplorerMaxFileSize:     8 << 20,
		ContributorThreshold:    64,
		unrestrictedMap:         map[string]bool{},
		BootstrapSrc:            false,
		AdminEnabled:            false,
		SshNoAuth:               false,
		SelfTest:                false,
		SelfTestContinue:        false,
		BlacklistPath:           filepath.Join(root, "blacklist.txt"),
		WhitelistPath:           filepath.Join(root, "whitelist.txt"),
	}
	for _, p := range strings.Split(cfg.Unrestricted, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cfg.unrestrictedMap[p] = true
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

func newExplorerHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func explorerGET(client *http.Client, rawURL string) (*http.Response, string, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

func explorerFetchCSRF(client *http.Client, pageURL string) (string, error) {
	resp, body, err := explorerGET(client, pageURL)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	re := regexp.MustCompile(`value="([a-f0-9]{64})"`)
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("csrf token not found in explorer page")
	}
	return m[1], nil
}

func explorerUpload(client *http.Client, postURL, csrfToken, filename string, payload []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("csrf_token", csrfToken); err != nil {
		return err
	}
	fw, err := mw.CreateFormFile("uploadFiles", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(payload); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, postURL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func explorerDownload(client *http.Client, rawURL string) (*http.Response, []byte, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body, nil
}
