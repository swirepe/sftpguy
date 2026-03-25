package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

func TestHandleHeadDirectoryListingReturnsHeadersOnly(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustMkdir(t, filepath.Join(root, "public"))
	mustWriteFile(t, filepath.Join(root, "notes.txt"), "hello")

	get := serveExplorerRequest(http.MethodGet, "/", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body=%s", get.Code, get.Body.String())
	}

	head := serveExplorerRequest(http.MethodHead, "/", nil)
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD / status = %d, body=%s", head.Code, head.Body.String())
	}
	if got := head.Body.String(); got != "" {
		t.Fatalf("HEAD / body = %q, want empty body", got)
	}
	if got := head.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("HEAD / Content-Type = %q, want html content type", got)
	}
	if got := head.Header().Get("Content-Length"); got == "" {
		t.Fatalf("HEAD / Content-Length is empty")
	} else if _, err := strconv.Atoi(got); err != nil {
		t.Fatalf("HEAD / Content-Length = %q, want numeric value", got)
	}
}

func TestHandleHeadPublicFileServesHeadersOnly(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "public", "hello.txt"), "hello world")

	w := serveExplorerRequest(http.MethodHead, "/public/hello.txt", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("HEAD /public/hello.txt status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "hello.txt") {
		t.Fatalf("Content-Disposition = %q, want filename for hello.txt", got)
	}
	if got := w.Body.String(); got != "" {
		t.Fatalf("body = %q, want empty body", got)
	}
}

func TestReadDirSkipsHiddenSystemDirectoriesAndCountsOnlyVisibleEntries(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustMkdir(t, filepath.Join(root, "#recycle"))
	mustMkdir(t, filepath.Join(root, "@eaDir"))
	mustMkdir(t, filepath.Join(root, "visible", "#recycle"))
	mustMkdir(t, filepath.Join(root, "visible", "@eaDir"))
	mustMkdir(t, filepath.Join(root, "visible", "nested"))
	mustWriteFile(t, filepath.Join(root, "keep.txt"), "hello")

	entries, err := readDir(root, "")
	if err != nil {
		t.Fatalf("readDir: %v", err)
	}

	names := make([]string, 0, len(entries))
	var visible entry
	for _, ent := range entries {
		names = append(names, ent.Name)
		if ent.Name == "visible" {
			visible = ent
		}
	}
	slices.Sort(names)

	want := []string{"keep.txt", "visible"}
	if !slices.Equal(names, want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	if visible.Size != 1 {
		t.Fatalf("visible entry size = %d, want 1", visible.Size)
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
