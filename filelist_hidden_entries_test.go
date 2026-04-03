package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pkg/sftp"
)

func TestFSHandlerFilelistSkipsHiddenSystemDirectories(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	for _, dir := range []string{"#recycle", "@eaDir", "visible"} {
		if err := os.MkdirAll(filepath.Join(srv.absUploadDir, dir), permDir); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(srv.absUploadDir, "keep.txt"), []byte("hello"), permFile); err != nil {
		t.Fatalf("write keep.txt: %v", err)
	}

	handler := &fsHandler{
		srv:    srv,
		stderr: io.Discard,
		logger: *slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	lister, err := handler.Filelist(&sftp.Request{Method: "List", Filepath: "/"})
	if err != nil {
		t.Fatalf("Filelist(/): %v", err)
	}

	buf := make([]os.FileInfo, 8)
	n, listErr := lister.ListAt(buf, 0)
	if listErr != nil && listErr != io.EOF {
		t.Fatalf("ListAt: %v", listErr)
	}

	names := make([]string, 0, n)
	for _, fi := range buf[:n] {
		names = append(names, fi.Name())
	}
	slices.Sort(names)

	want := []string{"keep.txt", "visible"}
	if !slices.Equal(names, want) {
		t.Fatalf("listed names = %v, want %v", names, want)
	}
}
