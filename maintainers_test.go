package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseScopedMaintainersContent(t *testing.T) {
	signer := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	pubHash := publicKeyHash(signer.PublicKey())
	hashLine := strings.Repeat("c", 64)

	content := strings.Join([]string{
		"# scoped maintainers",
		"public/audiobooks " + pubLine + " audiobook laptop",
		"/private/books\t" + hashLine + " # friend",
		"../escape " + hashLine,
		"public/missing-key",
		"",
	}, "\n")

	grants, invalid := parseScopedMaintainersContent(content)
	if len(invalid) != 2 {
		t.Fatalf("expected 2 invalid lines, got %#v", invalid)
	}

	if got := grants[pubHash]; len(got) != 1 || got[0] != "public/audiobooks" {
		t.Fatalf("unexpected public-key grants: %#v", got)
	}
	if got := grants[hashLine]; len(got) != 1 || got[0] != "private/books" {
		t.Fatalf("unexpected hash grants: %#v", got)
	}
}

func TestScopedMaintainerList_MatchesSubtreeOnly(t *testing.T) {
	hashLine := strings.Repeat("d", 64)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "maintainers.txt")
	if err := os.WriteFile(tmpFile, []byte("public/audiobooks "+hashLine+"\n"), permFile); err != nil {
		t.Fatalf("write maintainers: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	list := NewScopedMaintainerList(ctx, tmpFile, logger)
	defer list.Stop()

	if !list.Maintains(hashLine, "public/audiobooks") {
		t.Fatal("expected exact folder match")
	}
	if !list.Maintains(hashLine, "public/audiobooks/book.mp3") {
		t.Fatal("expected child path match")
	}
	if list.Maintains(hashLine, "public/audiobooks2/book.mp3") {
		t.Fatal("unexpected sibling-prefix match")
	}
	if list.Maintains(strings.Repeat("e", 64), "public/audiobooks/book.mp3") {
		t.Fatal("unexpected match for different hash")
	}
}
