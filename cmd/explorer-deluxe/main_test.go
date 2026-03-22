package main

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServePreviewJSONUsesSeparateLockedAndUnlockedCacheEntriesForImages(t *testing.T) {
	root := setupExplorerDeluxeTestRoot(t)
	imagePath := filepath.Join(root, "photo.png")
	mustWritePNG(t, imagePath, 4, 3)

	locked := serveDeluxeRequest(t, http.MethodGet, "/photo.png?preview=true", nil, nil, nil)
	if locked.Code != http.StatusOK {
		t.Fatalf("locked preview status = %d, body=%s", locked.Code, locked.Body.String())
	}

	var lockedPayload previewPayload
	if err := json.Unmarshal(locked.Body.Bytes(), &lockedPayload); err != nil {
		t.Fatalf("decode locked preview: %v", err)
	}
	if lockedPayload.IsImage {
		t.Fatalf("locked preview unexpectedly marked image: %+v", lockedPayload)
	}
	if lockedPayload.DownloadURL != "" {
		t.Fatalf("locked preview download_url = %q, want empty", lockedPayload.DownloadURL)
	}
	if lockedPayload.ThumbURL != "" {
		t.Fatalf("locked preview thumb_url = %q, want empty", lockedPayload.ThumbURL)
	}

	unlocked := serveDeluxeRequest(t, http.MethodGet, "/photo.png?preview=true", nil, nil, []*http.Cookie{{
		Name:  cookieUnlock,
		Value: "true",
	}})
	if unlocked.Code != http.StatusOK {
		t.Fatalf("unlocked preview status = %d, body=%s", unlocked.Code, unlocked.Body.String())
	}

	var unlockedPayload previewPayload
	if err := json.Unmarshal(unlocked.Body.Bytes(), &unlockedPayload); err != nil {
		t.Fatalf("decode unlocked preview: %v", err)
	}
	if !unlockedPayload.IsImage {
		t.Fatalf("unlocked preview not marked image: %+v", unlockedPayload)
	}
	if unlockedPayload.DownloadURL != "/photo.png" {
		t.Fatalf("unlocked preview download_url = %q, want %q", unlockedPayload.DownloadURL, "/photo.png")
	}
	if unlockedPayload.ThumbURL != "/photo.png?thumb=1" {
		t.Fatalf("unlocked preview thumb_url = %q, want %q", unlockedPayload.ThumbURL, "/photo.png?thumb=1")
	}
	if unlockedPayload.ImageWidth != 4 || unlockedPayload.ImageHeight != 3 {
		t.Fatalf("unlocked preview dimensions = %dx%d, want 4x3", unlockedPayload.ImageWidth, unlockedPayload.ImageHeight)
	}

	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatalf("stat image: %v", err)
	}
	if _, ok := getPreview(imagePath, info.ModTime()); !ok {
		t.Fatal("expected locked preview cache entry")
	}
	if _, ok := getPreview(imagePath+":unlocked", info.ModTime()); !ok {
		t.Fatal("expected unlocked preview cache entry")
	}
	if _, ok := getThumb(imagePath, info.ModTime()); !ok {
		t.Fatal("expected unlocked preview to warm thumbnail cache")
	}
}

func TestHandleUploadRenamesConflictingTopLevelFileAndSetsUnlockCookie(t *testing.T) {
	root := setupExplorerDeluxeTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "report.txt"), "original")

	w := serveDeluxeMultipartUpload(t, "/?sort=size&order=desc", "csrf-file", []*uploadPart{
		{filename: "report.txt", contents: "replacement"},
	})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}

	location := mustLocation(t, w)
	if location.Path != "/" {
		t.Fatalf("redirect path = %q, want /", location.Path)
	}
	if got := location.Query().Get("new"); got != "report (1).txt" {
		t.Fatalf("redirect new = %q, want %q", got, "report (1).txt")
	}
	if got := location.Query().Get("sort"); got != "size" {
		t.Fatalf("redirect sort = %q, want size", got)
	}
	if got := location.Query().Get("order"); got != "desc" {
		t.Fatalf("redirect order = %q, want desc", got)
	}

	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie == nil || cookie.Value != "true" {
		t.Fatalf("expected unlock cookie, got %+v", cookie)
	}

	if got := mustReadFile(t, filepath.Join(root, "report.txt")); got != "original" {
		t.Fatalf("original file contents = %q, want %q", got, "original")
	}
	if got := mustReadFile(t, filepath.Join(root, "report (1).txt")); got != "replacement" {
		t.Fatalf("renamed file contents = %q, want %q", got, "replacement")
	}
}

func TestHandleUploadRemapsConflictingTopLevelDirectory(t *testing.T) {
	root := setupExplorerDeluxeTestRoot(t)
	mustMkdir(t, filepath.Join(root, "album"))
	mustWriteFile(t, filepath.Join(root, "album", "keep.txt"), "keep")

	w := serveDeluxeMultipartUpload(t, "/", "csrf-dir", []*uploadPart{
		{filename: "album/one.txt", contents: "one"},
		{filename: "album/nested/two.txt", contents: "two"},
	})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}

	location := mustLocation(t, w)
	if got := location.Query().Get("new"); got != "album (1)" {
		t.Fatalf("redirect new = %q, want %q", got, "album (1)")
	}
	if got := mustReadFile(t, filepath.Join(root, "album", "keep.txt")); got != "keep" {
		t.Fatalf("original directory file contents = %q, want %q", got, "keep")
	}
	if got := mustReadFile(t, filepath.Join(root, "album (1)", "one.txt")); got != "one" {
		t.Fatalf("remapped file contents = %q, want %q", got, "one")
	}
	if got := mustReadFile(t, filepath.Join(root, "album (1)", "nested", "two.txt")); got != "two" {
		t.Fatalf("remapped nested file contents = %q, want %q", got, "two")
	}
}

func TestHandleTogglePreviewStripsQueryAndUpdatesCookie(t *testing.T) {
	setupExplorerDeluxeTestRoot(t)

	w := serveDeluxeRequest(t, http.MethodGet, "/docs?toggle-preview=1&sort=name", nil, nil, []*http.Cookie{{
		Name:  cookiePreview,
		Value: "closed",
	}})

	if w.Code != http.StatusSeeOther {
		t.Fatalf("toggle preview status = %d, body=%s", w.Code, w.Body.String())
	}

	location := mustLocation(t, w)
	if location.Path != "/docs" {
		t.Fatalf("redirect path = %q, want %q", location.Path, "/docs")
	}
	if location.Query().Get("toggle-preview") != "" {
		t.Fatalf("redirect query still has toggle-preview: %q", location.RawQuery)
	}
	if location.Query().Get("sort") != "name" {
		t.Fatalf("redirect sort = %q, want name", location.Query().Get("sort"))
	}
	if cookie := findCookie(w.Result().Cookies(), cookiePreview); cookie == nil || cookie.Value != "open" {
		t.Fatalf("expected preview cookie to open, got %+v", cookie)
	}
}

func TestServeStaticAssetUsesExplicitJavaScriptContentType(t *testing.T) {
	setupExplorerDeluxeTestRoot(t)

	w := serveDeluxeRequest(t, http.MethodGet, "/?static=video.js", nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("static asset status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/javascript" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/javascript")
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control = %q, want immutable cache", got)
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected embedded asset body")
	}
}

func TestHandleRejectsCrossSiteDirectFileAccess(t *testing.T) {
	root := setupExplorerDeluxeTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "note.txt"), "hello")

	headers := http.Header{}
	headers.Set("Sec-Fetch-Site", "cross-site")

	w := serveDeluxeRequest(t, http.MethodGet, "/note.txt", nil, headers, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site direct access status = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Direct access only") {
		t.Fatalf("cross-site direct access body = %q, want direct-access message", w.Body.String())
	}
}

type uploadPart struct {
	filename string
	contents string
}

func setupExplorerDeluxeTestRoot(t *testing.T) string {
	t.Helper()

	oldRootDir := rootDir
	oldMaxFileSize := maxFileSize
	oldEmbedAssets := embedAssets
	oldThumbCache := thumbCache
	oldPreviewCache := previewCache
	oldDirSizeCache := dirSizeCache

	rootDir = t.TempDir()
	maxFileSize = 10 << 20
	embedAssets = false
	thumbCache = newBytesCache(thumbCacheCapacity)
	previewCache = newBytesCache(previewCacheCapacity)
	dirSizeCache = newLRU[int64](dirSizeCacheCapacity)

	t.Cleanup(func() {
		rootDir = oldRootDir
		maxFileSize = oldMaxFileSize
		embedAssets = oldEmbedAssets
		thumbCache = oldThumbCache
		previewCache = oldPreviewCache
		dirSizeCache = oldDirSizeCache
	})

	return rootDir
}

func serveDeluxeRequest(t *testing.T, method, target string, body []byte, headers http.Header, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for k, values := range headers {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	handle(w, req)
	return w
}

func serveDeluxeMultipartUpload(t *testing.T, target, csrf string, parts []*uploadPart) *httptest.ResponseRecorder {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("csrf_token", csrf); err != nil {
		t.Fatalf("write csrf field: %v", err)
	}
	for _, part := range parts {
		fw, err := writer.CreateFormFile("file", part.filename)
		if err != nil {
			t.Fatalf("create form file %q: %v", part.filename, err)
		}
		if _, err := fw.Write([]byte(part.contents)); err != nil {
			t.Fatalf("write form file %q: %v", part.filename, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	headers := http.Header{}
	headers.Set("Content-Type", writer.FormDataContentType())

	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body.Bytes()))
	for k, values := range headers {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: csrf})

	w := httptest.NewRecorder()
	handle(w, req)
	return w
}

func mustLocation(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()

	location, err := w.Result().Location()
	if err != nil {
		t.Fatalf("response location: %v", err)
	}
	return location
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
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

func mustWritePNG(t *testing.T, path string, width, height int) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(40 * x), G: uint8(60 * y), B: 180, A: 255})
		}
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create png %s: %v", path, err)
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode png %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data)
}
