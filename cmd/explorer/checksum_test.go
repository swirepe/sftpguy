package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"
)

func TestHeadSHA256OptIn(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "public", "checksum.txt"), "preserved archival contents")
	expected := sha256.Sum256([]byte("preserved archival contents"))

	checked := serveExplorerRequest(http.MethodHead, "/public/checksum.txt?sha256=1", nil)
	if checked.Code != http.StatusOK {
		t.Fatalf("checksum HEAD status=%d, body=%q", checked.Code, checked.Body.String())
	}
	if got, want := checked.Header().Get("X-Content-SHA256"), hex.EncodeToString(expected[:]); got != want {
		t.Fatalf("SHA-256=%q, want %q", got, want)
	}
	if checked.Body.Len() != 0 {
		t.Fatalf("HEAD returned file contents")
	}

	ordinary := serveExplorerRequest(http.MethodHead, "/public/checksum.txt", nil)
	if got := ordinary.Header().Get("X-Content-SHA256"); got != "" {
		t.Fatalf("ordinary HEAD unexpectedly hashed file: %q", got)
	}
	get := serveExplorerRequest(http.MethodGet, "/public/checksum.txt?sha256=1", nil)
	if got := get.Header().Get("X-Content-SHA256"); got != "" {
		t.Fatalf("GET unexpectedly hashed file: %q", got)
	}
}

func TestHeadSHA256RespectsExistingFileAccess(t *testing.T) {
	root := setupExplorerTestRoot(t)
	mustWriteFile(t, filepath.Join(root, "restricted.txt"), "private archival contents")

	locked := serveExplorerRequest(http.MethodHead, "/restricted.txt?sha256=1", nil)
	if locked.Code != http.StatusSeeOther {
		t.Fatalf("locked HEAD status=%d, want redirect", locked.Code)
	}
	if got := locked.Header().Get("X-Content-SHA256"); got != "" {
		t.Fatalf("locked file leaked SHA-256: %q", got)
	}

	unlocked := serveExplorerRequest(http.MethodHead, "/restricted.txt?please&sha256=1", nil)
	if unlocked.Code != http.StatusOK || unlocked.Header().Get("X-Content-SHA256") == "" {
		t.Fatalf("unlocked HEAD status=%d, checksum=%q", unlocked.Code, unlocked.Header().Get("X-Content-SHA256"))
	}
}
