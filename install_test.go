package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInstalledServicesAreSocketActivatedUnits(t *testing.T) {
	serviceContent, err := renderUnit(serviceTemplate, serviceParams{
		Description:              "sftpguy",
		Name:                     "sftpguy",
		User:                     "anonymous",
		Group:                    "ftp",
		InstallDir:               "/var/lib/sftpguy",
		BinaryPath:               "/var/lib/sftpguy/sftpguy",
		SFTPSocketName:           "sftpguy.socket",
		ExplorerEventsSocketName: "sftpguy-explorer-events.socket",
	})
	if err != nil {
		t.Fatalf("render service unit: %v", err)
	}
	explorerContent, err := renderUnit(explorerServiceTemplate, explorerServiceParams{
		Description:      "sftpguy",
		Name:             "sftpguy-explorer",
		User:             "anonymous",
		Group:            "ftp",
		InstallDir:       "/var/lib/sftpguy",
		BinaryPath:       "/var/lib/sftpguy/sftpguy-explorer",
		SocketName:       "sftpguy-explorer.socket",
		EventsSocketName: "sftpguy-explorer-events.socket",
	})
	if err != nil {
		t.Fatalf("render explorer service unit: %v", err)
	}

	for name, content := range map[string]string{
		"service":  serviceContent,
		"explorer": explorerContent,
	} {
		if strings.Contains(content, "[Install]") || strings.Contains(content, "WantedBy=multi-user.target") {
			t.Fatalf("%s service should not be directly enableable:\n%s", name, content)
		}
		if !strings.Contains(content, "Sockets=") {
			t.Fatalf("%s service missing Sockets=:\n%s", name, content)
		}
		if !strings.Contains(content, "KillSignal=SIGTERM") || !strings.Contains(content, "TimeoutStopSec=infinity") {
			t.Fatalf("%s service missing graceful handoff stop settings:\n%s", name, content)
		}
	}
}

func TestInstallExplorerArgsIncludesMaxSizeAndCopiesFragments(t *testing.T) {
	installDir := t.TempDir()
	fragmentDir := t.TempDir()
	headerSrc := filepath.Join(fragmentDir, "header.html")
	footerSrc := filepath.Join(fragmentDir, "footer.html")
	writeInstallTestFile(t, headerSrc, "<header>hello</header>")
	writeInstallTestFile(t, footerSrc, "<footer>bye</footer>")

	args, err := installExplorerArgs(installOptions{
		UploadDir:            "/srv/sftpguy/uploads",
		ExplorerLogFile:      "/var/log/sftpguy-explorer.log",
		ExplorerEventsSocket: "/run/sftpguy/explorer-events.sock",
		ExplorerHeaderPath:   headerSrc,
		ExplorerFooterPath:   footerSrc,
		ExplorerMaxSizeMB:    2500,
	}, installDir)
	if err != nil {
		t.Fatalf("installExplorerArgs() error = %v", err)
	}

	headerDst := filepath.Join(installDir, "explorer-header.html")
	footerDst := filepath.Join(installDir, "explorer-footer.html")
	want := []string{
		"-dir", "/srv/sftpguy/uploads",
		"-log", "/var/log/sftpguy-explorer.log",
		"-events", "/run/sftpguy/explorer-events.sock",
		"-maxsize", "2500",
		"-systemd.socket",
		"-header", headerDst,
		"-footer", footerDst,
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("explorer args = %#v, want %#v", args, want)
	}
	if got := readInstallTestFile(t, headerDst); got != "<header>hello</header>" {
		t.Fatalf("copied header = %q", got)
	}
	if got := readInstallTestFile(t, footerDst); got != "<footer>bye</footer>" {
		t.Fatalf("copied footer = %q", got)
	}
}

func TestInstallExplorerArgsCopiesDefaultFragmentsWhenPresent(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeInstallTestFile(t, filepath.Join(cwd, "header.html"), "default header")
	writeInstallTestFile(t, filepath.Join(cwd, "footer.html"), "default footer")
	installDir := t.TempDir()

	args, err := installExplorerArgs(installOptions{
		UploadDir:            "/srv/sftpguy/uploads",
		ExplorerLogFile:      "/var/log/sftpguy-explorer.log",
		ExplorerEventsSocket: "/run/sftpguy/explorer-events.sock",
		ExplorerMaxSizeMB:    128,
	}, installDir)
	if err != nil {
		t.Fatalf("installExplorerArgs() error = %v", err)
	}

	headerDst := filepath.Join(installDir, "explorer-header.html")
	footerDst := filepath.Join(installDir, "explorer-footer.html")
	if !reflect.DeepEqual(args[len(args)-4:], []string{"-header", headerDst, "-footer", footerDst}) {
		t.Fatalf("fragment args tail = %#v", args[len(args)-4:])
	}
	if got := readInstallTestFile(t, headerDst); got != "default header" {
		t.Fatalf("copied default header = %q", got)
	}
	if got := readInstallTestFile(t, footerDst); got != "default footer" {
		t.Fatalf("copied default footer = %q", got)
	}
}

func TestInstallExplorerArgsSkipsMissingDefaultFragments(t *testing.T) {
	t.Chdir(t.TempDir())

	args, err := installExplorerArgs(installOptions{
		UploadDir:            "/srv/sftpguy/uploads",
		ExplorerLogFile:      "/var/log/sftpguy-explorer.log",
		ExplorerEventsSocket: "/run/sftpguy/explorer-events.sock",
		ExplorerMaxSizeMB:    64,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("installExplorerArgs() error = %v", err)
	}
	want := []string{
		"-dir", "/srv/sftpguy/uploads",
		"-log", "/var/log/sftpguy-explorer.log",
		"-events", "/run/sftpguy/explorer-events.sock",
		"-maxsize", "64",
		"-systemd.socket",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("explorer args = %#v, want %#v", args, want)
	}
}

func writeInstallTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readInstallTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
