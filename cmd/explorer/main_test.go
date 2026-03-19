package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestHandleDirectoryListingHighlightsPublicDirectoriesAndLockedFiles(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustMkdir(t, filepath.Join(root, "public"))
	mustMkdir(t, filepath.Join(root, "private"))
	mustWriteFile(t, filepath.Join(root, "secret.txt"), "shh")

	w := serveExplorerRequest(http.MethodGet, "/", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body=%s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !regexp.MustCompile(`(?s)<tr class="public-row dir-link-public">\s*<td class="col-name">\s*<a href="/public" class="dir-link">`).MatchString(body) {
		t.Fatalf("expected public directory highlight, body=%s", body)
	}
	if regexp.MustCompile(`(?s)<tr class="public-row dir-link-public">\s*<td class="col-name">\s*<a href="/private" class="dir-link">`).MatchString(body) {
		t.Fatalf("did not expect non-public directory highlight, body=%s", body)
	}
	if !strings.Contains(body, `<span style="color:#57606a">secret.txt</span>`) {
		t.Fatalf("expected locked file rendering, body=%s", body)
	}
	if strings.Contains(body, `<a href="/secret.txt" download>secret.txt</a>`) {
		t.Fatalf("did not expect locked file download link, body=%s", body)
	}
}

func TestHandlePublicDirectoryRendersBannerAndPublicDownloads(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustMkdir(t, filepath.Join(root, "public", "assets"))
	mustWriteFile(t, filepath.Join(root, "public", "readme.txt"), "hello")

	w := serveExplorerRequest(http.MethodGet, "/public", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /public status = %d, body=%s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, `class="banner banner-public"`) {
		t.Fatalf("expected public directory banner, body=%s", body)
	}
	if !strings.Contains(body, `<a href="/public/readme.txt" download>readme.txt</a>`) {
		t.Fatalf("expected public file download link, body=%s", body)
	}
	if !regexp.MustCompile(`(?s)<tr class="public-row dir-link-public">\s*<td class="col-name">\s*<a href="/public/assets" class="dir-link">`).MatchString(body) {
		t.Fatalf("expected nested public directory highlight, body=%s", body)
	}
}

func TestHandleLockedFileRedirectsToParentDirectory(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "docs", "private.txt"), "secret")

	w := serveExplorerRequest(http.MethodGet, "/docs/private.txt", nil)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("GET /docs/private.txt status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/docs?error=locked&wanted=private.txt" {
		t.Fatalf("redirect location = %q, want %q", got, "/docs?error=locked&wanted=private.txt")
	}
}

func TestHandlePublicFileServesWithoutUnlock(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "public", "hello.txt"), "hello world")

	w := serveExplorerRequest(http.MethodGet, "/public/hello.txt", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /public/hello.txt status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "hello.txt") {
		t.Fatalf("Content-Disposition = %q, want filename for hello.txt", got)
	}
	if got := w.Body.String(); got != "hello world" {
		t.Fatalf("body = %q, want %q", got, "hello world")
	}
}

func setupExplorerTestRoot(t *testing.T) string {
	t.Helper()

	oldRootDir := rootDir
	oldHeaderHTML := headerHTML
	oldFooterHTML := footerHTML

	rootDir = t.TempDir()
	headerHTML = ""
	footerHTML = ""

	t.Cleanup(func() {
		rootDir = oldRootDir
		headerHTML = oldHeaderHTML
		footerHTML = oldFooterHTML
	})

	return rootDir
}

func serveExplorerRequest(method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	handle(w, req, "test-nonce")
	return w
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, contents string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
