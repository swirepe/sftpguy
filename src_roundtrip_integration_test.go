package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSourceSnapshotBuildAndSelfTest(t *testing.T) {
	repoDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	tmpDir := t.TempDir()
	exportRoot := filepath.Join(tmpDir, "export")

	runCommand(t, repoDir, 2*time.Minute, "go", "run", ".", "-src.out", exportRoot)

	moduleDir := findExportedModuleDir(t, exportRoot)
	rebuiltDir := filepath.Join(tmpDir, "rebuilt")
	if err := os.MkdirAll(rebuiltDir, permDir); err != nil {
		t.Fatalf("create rebuild directory: %v", err)
	}

	rebuiltBinary := filepath.Join(rebuiltDir, "sftpguy")
	if runtime.GOOS == "windows" {
		rebuiltBinary += ".exe"
	}

	runCommand(t, moduleDir, 2*time.Minute, "go", "build", "-o", rebuiltBinary, ".")

	rebuiltVersionOutput := runCommand(t, rebuiltDir, 2*time.Minute, rebuiltBinary, "-version")
	rebuiltVersion := normalizeVersion(reportedVersion(rebuiltVersionOutput))
	currentVersion := normalizeVersion(AppVersion)
	if rebuiltVersion == "" || rebuiltVersion != currentVersion {
		t.Logf(
			"warning: rebuilt binary reported version %q; current program version is %q",
			strings.TrimSpace(rebuiltVersionOutput),
			AppVersion,
		)
	}

	runtimeDir := filepath.Join(tmpDir, "runtime")
	if err := os.MkdirAll(runtimeDir, permDir); err != nil {
		t.Fatalf("create runtime directory: %v", err)
	}

	runCommand(
		t,
		runtimeDir,
		2*time.Minute,
		rebuiltBinary,
		"-test",
		"-admin.sftp",
		"-name", "sftpguy-src-roundtrip",
		"-dir", filepath.Join(runtimeDir, "uploads"),
		"-db.path", filepath.Join(runtimeDir, "sftp.db"),
		"-logfile", filepath.Join(runtimeDir, "sftp.log"),
		"-hostkey", filepath.Join(runtimeDir, "id_ed25519"),
		"-blacklist", filepath.Join(runtimeDir, "blacklist.txt"),
		"-whitelist", filepath.Join(runtimeDir, "whitelist.txt"),
		"-admin.keys", filepath.Join(runtimeDir, "admin_keys.txt"),
		"-bad", filepath.Join(runtimeDir, "bad_files.txt"),
	)
}

func findExportedModuleDir(t *testing.T, root string) string {
	t.Helper()

	if fi, err := os.Stat(filepath.Join(root, "go.mod")); err == nil && !fi.IsDir() {
		return root
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read export root %q: %v", root, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(root, entry.Name())
		if fi, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil && !fi.IsDir() {
			return candidate
		}
	}

	t.Fatalf("could not find exported module directory with go.mod under %q", root)
	return ""
}

func runCommand(t *testing.T, dir string, timeout time.Duration, name string, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	err := cmd.Run()
	output := combined.String()
	cmdline := fmt.Sprintf("%s %s", name, strings.Join(args, " "))

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("command timed out after %s: %s\noutput:\n%s", timeout, cmdline, output)
	}
	if err != nil {
		t.Fatalf("command failed: %s: %v\noutput:\n%s", cmdline, err, output)
	}

	return output
}

func reportedVersion(output string) string {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 {
		return ""
	}

	return fields[len(fields)-1]
}

func normalizeVersion(version string) string {
	return strings.TrimLeft(strings.TrimSpace(version), "v")
}
