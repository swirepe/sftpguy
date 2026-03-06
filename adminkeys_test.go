package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testAdminSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	return signer
}

func TestParseAdminKeysContent(t *testing.T) {
	signer := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	pubHash := publicKeyHash(signer.PublicKey())
	hashLine := strings.Repeat("a", 64)

	content := strings.Join([]string{
		"# admin keys",
		pubLine + " admin-laptop",
		hashLine,
		"this-is-not-a-key",
		"",
	}, "\n")

	hashes, invalid := parseAdminKeysContent(content)
	if len(hashes) != 2 {
		t.Fatalf("expected 2 parsed entries, got %d", len(hashes))
	}
	if _, ok := hashes[pubHash]; !ok {
		t.Fatalf("expected parsed pubkey hash %s", pubHash)
	}
	if _, ok := hashes[hashLine]; !ok {
		t.Fatalf("expected parsed hash line %s", hashLine)
	}
	if len(invalid) != 1 || invalid[0] != "this-is-not-a-key" {
		t.Fatalf("unexpected invalid lines: %#v", invalid)
	}
}

func TestAdminKeyList_Matches(t *testing.T) {
	signer := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	pubHash := publicKeyHash(signer.PublicKey())
	hashLine := strings.Repeat("b", 64)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "admin_keys.txt")
	content := pubLine + "\n" + hashLine + "\n"
	if err := os.WriteFile(tmpFile, []byte(content), permFile); err != nil {
		t.Fatalf("write admin keys: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	list := NewAdminKeyList(ctx, tmpFile, logger)
	defer list.Stop()

	if !list.ContainsKey(signer.PublicKey()) {
		t.Fatal("expected configured public key to match admin key list")
	}
	if !list.ContainsHash(pubHash) {
		t.Fatal("expected configured public key hash to match admin key list")
	}
	if !list.ContainsHash(hashLine) {
		t.Fatal("expected literal hash entry to match admin key list")
	}
}

func TestAdminKeyList_ReloadFaultTolerance(t *testing.T) {
	signer := testAdminSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	pubHash := publicKeyHash(signer.PublicKey())

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "admin_keys_fault.txt")
	if err := os.WriteFile(tmpFile, []byte(pubLine+"\n"), permFile); err != nil {
		t.Fatalf("write admin keys: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	list := NewAdminKeyList(ctx, tmpFile, slog.Default())
	defer list.Stop()

	if !list.ContainsHash(pubHash) {
		t.Fatal("expected initial admin key hash to be present")
	}

	if err := os.Remove(tmpFile); err != nil {
		t.Fatalf("remove admin key file: %v", err)
	}

	if _, err := list.Reload(tmpFile); err == nil {
		t.Fatal("expected reload to fail for missing file")
	}

	// Failed reload should keep the last successful key set active.
	if !list.ContainsHash(pubHash) {
		t.Fatal("admin key list was cleared on failed reload")
	}
}
