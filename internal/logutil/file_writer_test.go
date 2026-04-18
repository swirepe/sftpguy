package logutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileWriterReopensAfterRenameRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "explorer.log")

	writer, err := NewFileWriter(logPath, 0644)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Fatalf("close writer: %v", err)
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

func TestFileWriterReopenCreatesReplacementFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "sftpguy.log")

	writer, err := NewFileWriter(logPath, 0644)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Fatalf("close writer: %v", err)
		}
	})

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove log path: %v", err)
	}
	if err := writer.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if _, err := writer.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write after reopen: %v", err)
	}

	if got := mustReadFile(t, logPath); got != "hello\n" {
		t.Fatalf("replacement file contents = %q, want %q", got, "hello\n")
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
