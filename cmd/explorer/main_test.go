package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"sftpguy/internal/explorerevents"
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

func TestHandleDirectoryListingCarriesSortQueryOnDirectoryLinks(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustMkdir(t, filepath.Join(root, "docs", "manuals"))
	mustMkdir(t, filepath.Join(root, "docs", "notes"))
	mustWriteFile(t, filepath.Join(root, "docs", "readme.txt"), "hello")

	w := serveExplorerRequest(http.MethodGet, "/docs?sort=modified&order=desc", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /docs status = %d, body=%s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	for _, want := range []string{
		`<a href="/docs/manuals?order=desc&amp;sort=modified" class="dir-link">`,
		`<a href="/docs/notes?order=desc&amp;sort=modified" class="dir-link">`,
		`<a href="/?order=desc&amp;sort=modified">↑ Parent Directory</a>`,
		`<a href="/?order=desc&amp;sort=modified">root</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected sorted directory link %q, body=%s", want, body)
		}
	}
	if strings.Contains(body, `href="/docs/readme.txt?`) {
		t.Fatalf("did not expect file download link to carry sort query, body=%s", body)
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

func TestHandleDirectoryListingRendersHeaderAndFooterTemplateFilesWithNonce(t *testing.T) {
	setupExplorerTestRoot(t)

	fragmentDir := t.TempDir()
	headerPath := filepath.Join(fragmentDir, "header.html")
	footerPath := filepath.Join(fragmentDir, "footer.html")
	mustWriteFile(t, headerPath, `<script nonce="{{.Nonce}}">window.headerLoaded = true;</script>`)
	mustWriteFile(t, footerPath, `<script nonce="{{.Nonce}}">window.footerLoaded = true;</script>`)
	headerFragment = &htmlFragmentSource{name: "header", path: headerPath}
	footerFragment = &htmlFragmentSource{name: "footer", path: footerPath}

	w := serveExplorerRequest(http.MethodGet, "/", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`<script nonce="test-nonce">window.headerLoaded = true;</script>`,
		`<script nonce="test-nonce">window.footerLoaded = true;</script>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered fragment %q, body=%s", want, body)
		}
	}
	if strings.Contains(body, "{{.Nonce}}") {
		t.Fatalf("fragment template nonce was not evaluated, body=%s", body)
	}

	mustWriteFile(t, headerPath, `<script nonce="{{.Nonce}}">window.headerReloaded = true;</script>`)
	w = serveExplorerRequest(http.MethodGet, "/", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / after header change status = %d, body=%s", w.Code, w.Body.String())
	}
	body = w.Body.String()
	if !strings.Contains(body, `<script nonce="test-nonce">window.headerReloaded = true;</script>`) {
		t.Fatalf("expected reloaded header fragment, body=%s", body)
	}
	if strings.Contains(body, "window.headerLoaded = true") {
		t.Fatalf("expected updated header fragment to replace old contents, body=%s", body)
	}
}

func TestHandleDirectoryListingSkipsMissingFragmentAndLogsFirstFailure(t *testing.T) {
	setupExplorerTestRoot(t)

	headerFragment = &htmlFragmentSource{name: "header", path: filepath.Join(t.TempDir(), "missing-header.html")}
	logBuf := captureExplorerLogs(t)

	for i := 0; i < 2; i++ {
		w := serveExplorerRequest(http.MethodGet, "/", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET / attempt %d status = %d, body=%s", i+1, w.Code, w.Body.String())
		}
	}

	logs := logBuf.String()
	if got := strings.Count(logs, "optional template fragment unavailable"); got != 1 {
		t.Fatalf("fragment failure log count = %d, want 1; logs=%s", got, logs)
	}
	if !strings.Contains(logs, "fragment=header") {
		t.Fatalf("fragment failure log missing header name, logs=%s", logs)
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

func TestHandleFaviconServesWithoutUnlock(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "favicon.ico"), "icon")

	w := serveExplorerRequest(http.MethodGet, "/favicon.ico", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /favicon.ico status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "icon" {
		t.Fatalf("body = %q, want %q", got, "icon")
	}
}

func TestHandlePublicFileReadLogIncludesTransferStats(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "public", "hello.txt"), "hello world")

	logBuf := captureExplorerLogs(t)

	w := serveExplorerRequest(http.MethodGet, "/public/hello.txt", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /public/hello.txt status = %d, body=%s", w.Code, w.Body.String())
	}

	line := logBuf.String()
	if !strings.Contains(line, "msg=download") {
		t.Fatalf("log line missing read message, got %q", line)
	}
	if !strings.Contains(line, "file=public/hello.txt") {
		t.Fatalf("log line missing file, got %q", line)
	}
	if !strings.Contains(line, "duration=") {
		t.Fatalf("log line missing duration, got %q", line)
	}
	if !strings.Contains(line, "bytes=11") || !strings.Contains(line, `size="11 B"`) {
		t.Fatalf("log line missing size, got %q", line)
	}
	if !strings.Contains(line, "rate=") {
		t.Fatalf("log line missing avg transfer rate, got %q", line)
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

func TestClientIPFormatting(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    http.Header
		want       string
	}{
		{
			name:       "direct client without proxy headers",
			remoteAddr: "98.159.36.136:12345",
			want:       "98.159.36.136",
		},
		{
			name:       "loopback proxy omits peer",
			remoteAddr: "127.0.0.1:9112",
			headers: http.Header{
				"X-Forwarded-For": []string{"98.159.36.136, 127.0.0.1"},
				"X-Real-IP":       []string{"98.159.36.136"},
			},
			want: "98.159.36.136",
		},
		{
			name:       "private proxy keeps informative hop",
			remoteAddr: "10.0.0.5:443",
			headers: http.Header{
				"X-Forwarded-For": []string{"98.159.36.136, 10.0.0.5"},
			},
			want: "98.159.36.136 via 10.0.0.5",
		},
		{
			name:       "untrusted peer ignores forwarded headers",
			remoteAddr: "203.0.113.7:443",
			headers: http.Header{
				"X-Forwarded-For": []string{"98.159.36.136"},
				"X-Real-IP":       []string{"98.159.36.136"},
			},
			want: "203.0.113.7",
		},
		{
			name:       "real ip falls back when xff missing",
			remoteAddr: "[::1]:443",
			headers: http.Header{
				"X-Real-IP": []string{"98.159.36.136"},
			},
			want: "98.159.36.136",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for name, values := range tt.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}

			if got := clientIP(req); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleUploadStoresFileAndSetsUnlockCookie(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "report.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("replacement")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-upload"},
	}, csrfHeaders("csrf-upload"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("location = %q, want %q", got, "/")
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie == nil || cookie.Value != "true" {
		t.Fatalf("expected unlock cookie, got %+v", cookie)
	}
	if got := mustReadFile(t, filepath.Join(root, "report.txt")); got != "replacement" {
		t.Fatalf("uploaded file contents = %q, want %q", got, "replacement")
	}
}

func TestHandleUploadWriteLogIncludesTransferStats(t *testing.T) {
	setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "report.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("replacement")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	logBuf := captureExplorerLogs(t)

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-upload"},
	}, csrfHeaders("csrf-upload"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}

	line := logBuf.String()
	if !strings.Contains(line, "msg=upload") {
		t.Fatalf("log line missing write message, got %q", line)
	}
	if !strings.Contains(line, "file=report.txt") {
		t.Fatalf("log line missing file, got %q", line)
	}
	if !strings.Contains(line, "duration=") {
		t.Fatalf("log line missing duration, got %q", line)
	}
	if !strings.Contains(line, "bytes=11") || !strings.Contains(line, `size="11 B"`) {
		t.Fatalf("log line missing size, got %q", line)
	}
	if !strings.Contains(line, "rate=") {
		t.Fatalf("log line missing avg transfer rate, got %q", line)
	}
}

func TestTransferEventIncludesStatsAndAllRequestHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/album?sort=name", nil)
	req.RemoteAddr = "198.51.100.77:43210"
	req.Header.Set("User-Agent", "audit-test")
	req.Header.Add("X-Custom-Audit", "one")
	req.Header.Add("X-Custom-Audit", "two")
	req.Header.Set("Downlink", "10")

	evt := transferEvent(explorerevents.KindUpload, req, "album/report.txt", 12, 20, 8, 25*time.Millisecond)

	if evt.Kind != explorerevents.KindUpload {
		t.Fatalf("kind = %q, want %q", evt.Kind, explorerevents.KindUpload)
	}
	if evt.ClientIP != "198.51.100.77" {
		t.Fatalf("client ip = %q, want 198.51.100.77", evt.ClientIP)
	}
	if evt.Path != "album/report.txt" || evt.Bytes != 12 || evt.Size != 20 || evt.Delta != 8 {
		t.Fatalf("unexpected transfer stats: path=%q bytes=%d size=%d delta=%d", evt.Path, evt.Bytes, evt.Size, evt.Delta)
	}
	if evt.DurationMS != 25 || evt.AvgBytesPerSec != 480 {
		t.Fatalf("unexpected timing stats: duration_ms=%v avg=%d", evt.DurationMS, evt.AvgBytesPerSec)
	}
	headers, ok := evt.Meta["headers"].(map[string][]string)
	if !ok {
		t.Fatalf("headers meta missing or wrong type: %#v", evt.Meta["headers"])
	}
	if !slices.Equal(headers["X-Custom-Audit"], []string{"one", "two"}) {
		t.Fatalf("X-Custom-Audit headers = %#v", headers["X-Custom-Audit"])
	}
	if got := headers["User-Agent"]; !slices.Equal(got, []string{"audit-test"}) {
		t.Fatalf("User-Agent header = %#v", got)
	}
	if got := headers["Downlink"]; !slices.Equal(got, []string{"10"}) {
		t.Fatalf("Downlink header = %#v", got)
	}
	if got := evt.Meta["file"]; got != "album/report.txt" {
		t.Fatalf("file meta = %#v, want album/report.txt", got)
	}
	if got := evt.Meta["filename"]; got != "report.txt" {
		t.Fatalf("filename meta = %#v, want report.txt", got)
	}

	fast := transferEvent(explorerevents.KindUpload, req, "fast.bin", 1, 1, 1, time.Nanosecond)
	if fast.DurationMS <= 0 || fast.DurationMS >= 1 {
		t.Fatalf("fast duration_ms = %v, want decimal below 1", fast.DurationMS)
	}
}

func TestRequestEventIncludesDurationAndAllRequestHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/public/readme.txt?download=1", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.44, 127.0.0.1")
	req.Header.Set("X-Real-IP", "203.0.113.44")
	req.Header.Set("Referer", "https://example.test/from")
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.AddCookie(&http.Cookie{Name: cookieUnlock, Value: "true"})

	evt := requestEvent(req, http.StatusSeeOther, 42*time.Millisecond)

	if evt.Kind != explorerevents.KindRequest {
		t.Fatalf("kind = %q, want %q", evt.Kind, explorerevents.KindRequest)
	}
	if evt.ClientIP != "203.0.113.44" {
		t.Fatalf("client ip = %q, want forwarded client", evt.ClientIP)
	}
	if evt.Status != http.StatusSeeOther || evt.DurationMS != 42 {
		t.Fatalf("unexpected request stats: status=%d duration_ms=%v", evt.Status, evt.DurationMS)
	}
	headers, ok := evt.Meta["headers"].(map[string][]string)
	if !ok {
		t.Fatalf("headers meta missing or wrong type: %#v", evt.Meta["headers"])
	}
	if got := headers["X-Forwarded-For"]; !slices.Equal(got, []string{"203.0.113.44, 127.0.0.1"}) {
		t.Fatalf("X-Forwarded-For header = %#v", got)
	}
	if got := headers["Sec-Ch-Ua-Mobile"]; !slices.Equal(got, []string{"?0"}) {
		t.Fatalf("Sec-CH-UA-Mobile header = %#v", got)
	}
	if unlocked, ok := evt.Meta["unlocked"].(bool); !ok || !unlocked {
		t.Fatalf("unlocked meta = %#v, want true", evt.Meta["unlocked"])
	}
}

func TestWriteFileAtomicReportsSizeAndPositiveDelta(t *testing.T) {
	root := setupExplorerTestRoot(t)
	target := filepath.Join(root, "overwrite.txt")
	mustWriteFile(t, target, "0123456789")

	finalPath, transferred, size, delta, _, err := writeFileAtomic(strings.NewReader("tiny"), target, false)
	if err != nil {
		t.Fatalf("writeFileAtomic overwrite: %v", err)
	}
	if finalPath != target || transferred != 4 || size != 4 || delta != 0 {
		t.Fatalf("overwrite stats: final=%q transferred=%d size=%d delta=%d", finalPath, transferred, size, delta)
	}

	finalPath, transferred, size, delta, _, err = writeFileAtomic(strings.NewReader("larger"), target, false)
	if err != nil {
		t.Fatalf("writeFileAtomic grow: %v", err)
	}
	if finalPath != target || transferred != 6 || size != 6 || delta != 2 {
		t.Fatalf("grow stats: final=%q transferred=%d size=%d delta=%d", finalPath, transferred, size, delta)
	}
}

func TestHandleUploadAcceptsMultipartCSRFWithoutHeader(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		if err := writer.WriteField("csrf_token", "csrf-form"); err != nil {
			t.Fatalf("write csrf field: %v", err)
		}
		fw, err := writer.CreateFormFile("uploadFiles", "form.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("native")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-form"},
	}, nil)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie == nil || cookie.Value != "true" {
		t.Fatalf("expected unlock cookie, got %+v", cookie)
	}
	if got := mustReadFile(t, filepath.Join(root, "form.txt")); got != "native" {
		t.Fatalf("uploaded file contents = %q, want %q", got, "native")
	}
}

func TestHandleUploadAcceptsLateMultipartCSRFFieldWithHeader(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "late.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("late")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
		if err := writer.WriteField("csrf_token", "csrf-late"); err != nil {
			t.Fatalf("write csrf field: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-late"},
	}, csrfHeaders("csrf-late"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie == nil || cookie.Value != "true" {
		t.Fatalf("expected unlock cookie, got %+v", cookie)
	}
	if got := mustReadFile(t, filepath.Join(root, "late.txt")); got != "late" {
		t.Fatalf("uploaded file contents = %q, want %q", got, "late")
	}
}

func TestHandleUploadRejectsMissingCSRFHeaderAndField(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "missing-header.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("missing")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-missing"},
	}, nil)

	if w.Code != http.StatusForbidden {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
	if _, err := os.Stat(filepath.Join(root, "missing-header.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no uploaded file, stat err=%v", err)
	}
}

func TestHandleUploadRejectsEmptyUpload(t *testing.T) {
	setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-empty"},
	}, csrfHeaders("csrf-empty"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
}

func TestHandleUploadRejectsFileTarget(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "notes.txt"), "keep")

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "report.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("replacement")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/notes.txt", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-file-target"},
	}, csrfHeaders("csrf-file-target"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
	if got := mustReadFile(t, filepath.Join(root, "notes.txt")); got != "keep" {
		t.Fatalf("target file contents = %q, want %q", got, "keep")
	}
}

func TestHandleUploadRejectsMissingTargetDirectory(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "report.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("replacement")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/missing", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-missing-target"},
	}, csrfHeaders("csrf-missing-target"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatalf("expected missing target to remain absent, stat err=%v", err)
	}
}

func TestHandleUploadRejectsOversizeContentLengthEarly(t *testing.T) {
	setupExplorerTestRoot(t)
	maxFileSize = 64

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "report.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte(strings.Repeat("x", 256))); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-too-large"},
	}, csrfHeaders("csrf-too-large"))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
}

func TestHandleUploadAllowsUnlimitedMaxSize(t *testing.T) {
	root := setupExplorerTestRoot(t)
	maxFileSize = 0

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "large.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte(strings.Repeat("x", 256))); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-unlimited"},
	}, csrfHeaders("csrf-unlimited"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if got := mustReadFile(t, filepath.Join(root, "large.txt")); got != strings.Repeat("x", 256) {
		t.Fatalf("uploaded file contents length = %d, want 256", len(got))
	}
}

func TestHandleUploadDoesNotUnlockOnTruncatedMultipart(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "broken.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("partial")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	cutoff := len(body) - 8
	if cutoff < 1 {
		t.Fatalf("multipart body unexpectedly short: %d", len(body))
	}

	w := serveExplorerBodyRequest(http.MethodPost, "/", &failingReader{
		data:   body,
		cutoff: cutoff,
	}, contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-broken"},
	}, csrfHeaders("csrf-broken"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
	if _, err := os.Stat(filepath.Join(root, "broken.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected partial file cleanup, stat err=%v", err)
	}
}

func TestHandleUploadRollsBackEarlierFilesOnLaterFailure(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "good.txt")
		if err != nil {
			t.Fatalf("create first form file: %v", err)
		}
		if _, err := fw.Write([]byte("good")); err != nil {
			t.Fatalf("write first form file: %v", err)
		}
		fw, err = writer.CreateFormFile("uploadFiles", "broken.txt")
		if err != nil {
			t.Fatalf("create second form file: %v", err)
		}
		if _, err := fw.Write([]byte("partial")); err != nil {
			t.Fatalf("write second form file: %v", err)
		}
	})

	cutoff := len(body) - 8
	if cutoff < 1 {
		t.Fatalf("multipart body unexpectedly short: %d", len(body))
	}

	w := serveExplorerBodyRequest(http.MethodPost, "/", &failingReader{
		data:   body,
		cutoff: cutoff,
	}, contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-rollback"},
	}, csrfHeaders("csrf-rollback"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "good.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected rollback of earlier file, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "broken.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected rollback of failing file, stat err=%v", err)
	}
}

func TestHandleUploadCleansUpEmptyNestedDirectoryOnFailure(t *testing.T) {
	root := setupExplorerTestRoot(t)

	body, contentType := buildMultipartBody(t, func(writer *multipart.Writer) {
		fw, err := writer.CreateFormFile("uploadFiles", "album/one.txt")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte("partial")); err != nil {
			t.Fatalf("write form file: %v", err)
		}
	})

	cutoff := len(body) - 8
	if cutoff < 1 {
		t.Fatalf("multipart body unexpectedly short: %d", len(body))
	}

	w := serveExplorerBodyRequest(http.MethodPost, "/", &failingReader{
		data:   body,
		cutoff: cutoff,
	}, contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-nested-broken"},
	}, csrfHeaders("csrf-nested-broken"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}
	if cookie := findCookie(w.Result().Cookies(), cookieUnlock); cookie != nil {
		t.Fatalf("did not expect unlock cookie, got %+v", cookie)
	}
	if _, err := os.Stat(filepath.Join(root, "album")); !os.IsNotExist(err) {
		t.Fatalf("expected empty nested directory cleanup, stat err=%v", err)
	}
}

func TestHandleDirectoryListingIncludesUploadFailureScript(t *testing.T) {
	setupExplorerTestRoot(t)

	w := serveExplorerRequest(http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body=%s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "xhr.onerror = () => {") {
		t.Fatalf("expected xhr error handling script, body=%s", body)
	}
	if !strings.Contains(body, "function getUploadErrorMessage(xhr) {") {
		t.Fatalf("expected upload error message helper in script, body=%s", body)
	}
	if !strings.Contains(body, "formData.append('csrf_token', csrfToken);") {
		t.Fatalf("expected multipart csrf field in script, body=%s", body)
	}
	if !strings.Contains(body, "xhr.setRequestHeader('X-CSRF-Token', csrfToken);") {
		t.Fatalf("expected xhr csrf header in script, body=%s", body)
	}
	if !strings.Contains(body, "function retryWithStandardSubmit(source) {") {
		t.Fatalf("expected standard submit fallback helper in script, body=%s", body)
	}
	if !strings.Contains(body, "HTMLFormElement.prototype.submit.call(form);") {
		t.Fatalf("expected standard submit fallback call in script, body=%s", body)
	}
	if !strings.Contains(body, "const readAllEntries = async (reader) => {") {
		t.Fatalf("expected readAllEntries helper in script, body=%s", body)
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

func TestRotationAwareLogWriterReopensAfterRenameRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "explorer.log")

	writer, err := newRotationAwareLogWriter(logPath)
	if err != nil {
		t.Fatalf("newRotationAwareLogWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Fatalf("close log writer: %v", err)
		}
	})

	if _, err := writer.Write([]byte("before rotation\n")); err != nil {
		t.Fatalf("write before rotation: %v", err)
	}

	rotatedPath := filepath.Join(filepath.Dir(logPath), "explorer.log.1")
	if err := os.Rename(logPath, rotatedPath); err != nil {
		t.Fatalf("rotate log file: %v", err)
	}
	if err := os.WriteFile(logPath, nil, 0644); err != nil {
		t.Fatalf("create replacement log file: %v", err)
	}

	if _, err := writer.Write([]byte("after rotation\n")); err != nil {
		t.Fatalf("write after rotation: %v", err)
	}

	if got := mustReadFile(t, rotatedPath); got != "before rotation\n" {
		t.Fatalf("rotated file contents = %q, want %q", got, "before rotation\n")
	}
	if got := mustReadFile(t, logPath); got != "after rotation\n" {
		t.Fatalf("replacement file contents = %q, want %q", got, "after rotation\n")
	}
}

func TestWaitForShutdownStopsSignalNotifications(t *testing.T) {
	serverErr := make(chan error)
	quit := make(chan os.Signal, 1)
	quit <- syscall.SIGTERM

	stopCalled := false
	sig, err := waitForShutdown(serverErr, quit, func(ch chan<- os.Signal) {
		stopCalled = true
	})
	if err != nil {
		t.Fatalf("waitForShutdown error = %v, want nil", err)
	}
	if sig != syscall.SIGTERM {
		t.Fatalf("waitForShutdown signal = %v, want %v", sig, syscall.SIGTERM)
	}
	if !stopCalled {
		t.Fatalf("waitForShutdown did not stop signal notifications")
	}
}

func TestWaitForShutdownReturnsServerErrorWithoutStoppingSignals(t *testing.T) {
	wantErr := errors.New("listen failed")
	serverErr := make(chan error, 1)
	serverErr <- wantErr
	quit := make(chan os.Signal)

	stopCalled := false
	sig, err := waitForShutdown(serverErr, quit, func(ch chan<- os.Signal) {
		stopCalled = true
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("waitForShutdown error = %v, want %v", err, wantErr)
	}
	if sig != nil {
		t.Fatalf("waitForShutdown signal = %v, want nil", sig)
	}
	if stopCalled {
		t.Fatalf("waitForShutdown stopped signal notifications on server error")
	}
}

func setupExplorerTestRoot(t *testing.T) string {
	t.Helper()

	oldRootDir := rootDir
	oldHeaderFragment := headerFragment
	oldFooterFragment := footerFragment
	oldMaxFileSize := maxFileSize

	rootDir = t.TempDir()
	headerFragment = &htmlFragmentSource{name: "header"}
	footerFragment = &htmlFragmentSource{name: "footer"}
	maxFileSize = 10 << 20

	t.Cleanup(func() {
		rootDir = oldRootDir
		headerFragment = oldHeaderFragment
		footerFragment = oldFooterFragment
		maxFileSize = oldMaxFileSize
	})

	return rootDir
}

func captureExplorerLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logBuf bytes.Buffer
	oldLogger := logger
	logger = slog.New(slog.NewTextHandler(&logBuf, nil))
	t.Cleanup(func() { logger = oldLogger })

	return &logBuf
}

func serveExplorerRequest(method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	handle(requestLogger(logger, req), w, req, "test-nonce")
	return w
}

func serveExplorerBodyRequest(method, target string, body io.Reader, contentType string, cookies []*http.Cookie, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	handle(requestLogger(logger, req), w, req, "test-nonce")
	return w
}

func csrfHeaders(token string) http.Header {
	if token == "" {
		return nil
	}
	return http.Header{headerCSRF: []string{token}}
}

func buildMultipartBody(t *testing.T, build func(*multipart.Writer)) ([]byte, string) {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	build(writer)
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data)
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

type failingReader struct {
	data   []byte
	cutoff int
	offset int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.offset >= r.cutoff {
		return 0, io.ErrUnexpectedEOF
	}

	n := copy(p, r.data[r.offset:r.cutoff])
	r.offset += n
	if r.offset >= r.cutoff {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
