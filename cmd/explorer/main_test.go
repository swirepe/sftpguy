package main

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
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

func TestHandlePublicFileReadLogIncludesTransferStats(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "public", "hello.txt"), "hello world")

	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	w := serveExplorerRequest(http.MethodGet, "/public/hello.txt", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /public/hello.txt status = %d, body=%s", w.Code, w.Body.String())
	}

	line := logBuf.String()
	if !strings.Contains(line, "READ public/hello.txt duration=") {
		t.Fatalf("log line missing duration, got %q", line)
	}
	if !strings.Contains(line, "size=11 B") {
		t.Fatalf("log line missing size, got %q", line)
	}
	if !regexp.MustCompile(`avg=(?:n/a|[0-9.]+ [KMGTPE]?B/s)`).MatchString(line) {
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

	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	w := serveExplorerBodyRequest(http.MethodPost, "/", bytes.NewReader(body), contentType, []*http.Cookie{
		{Name: cookieCSRF, Value: "csrf-upload"},
	}, csrfHeaders("csrf-upload"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d, body=%s", w.Code, w.Body.String())
	}

	line := logBuf.String()
	if !strings.Contains(line, "WRITE report.txt duration=") {
		t.Fatalf("log line missing duration, got %q", line)
	}
	if !strings.Contains(line, "size=11 B") {
		t.Fatalf("log line missing size, got %q", line)
	}
	if !regexp.MustCompile(`avg=(?:0 B/s|[0-9.]+ [KMGTPE]?B/s)`).MatchString(line) {
		t.Fatalf("log line missing avg transfer rate, got %q", line)
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

func setupExplorerTestRoot(t *testing.T) string {
	t.Helper()

	oldRootDir := rootDir
	oldHeaderHTML := headerHTML
	oldFooterHTML := footerHTML
	oldMaxFileSize := maxFileSize

	rootDir = t.TempDir()
	headerHTML = ""
	footerHTML = ""
	maxFileSize = 10 << 20

	t.Cleanup(func() {
		rootDir = oldRootDir
		headerHTML = oldHeaderHTML
		footerHTML = oldFooterHTML
		maxFileSize = oldMaxFileSize
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
	handle(w, req, "test-nonce")
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
