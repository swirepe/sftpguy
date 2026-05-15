package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	_ "modernc.org/sqlite"
)

// serviceParams holds the values interpolated into serviceTemplate.
type serviceParams struct {
	Description              string   // human-readable archive name
	Name                     string   // sanitized service / binary name
	User                     string   // system user the service runs as
	Group                    string   // system group the service runs as
	InstallDir               string   // /var/lib/<name>
	BinaryPath               string   // InstallDir/<name>
	LogFile                  string   // /var/log/<name>.log
	Args                     []string // flags to pass on restart (os.Args minus -install)
	UseSyslog                bool
	SFTPSocketName           string
	ExplorerEventsSocketName string
}

type tcpSocketParams struct {
	Description string
	ServiceName string
	FDName      string
	Port        int
}

type unixSocketParams struct {
	Description string
	ServiceName string
	FDName      string
	Path        string
	User        string
	Group       string
}

type explorerServiceParams struct {
	Description      string
	Name             string
	User             string
	Group            string
	InstallDir       string
	BinaryPath       string
	Args             []string
	SocketName       string
	EventsSocketName string
}

// serviceTemplate is the systemd unit file template.
var serviceTemplate = template.Must(template.New("service").Parse(`[Unit]
Description={{.Description}} — Anonymous SFTP Server
Requires={{.SFTPSocketName}} {{.ExplorerEventsSocketName}}
After=network.target {{.SFTPSocketName}} {{.ExplorerEventsSocketName}}

[Service]
Type=simple
User={{.User}}
Group={{.Group}}
WorkingDirectory={{.InstallDir}}
Sockets={{.SFTPSocketName}} {{.ExplorerEventsSocketName}}
ExecStart={{.BinaryPath}}{{range .Args}} {{.}}{{end}}
KillSignal=SIGTERM
TimeoutStopSec=infinity

# If server handles syslog internally, discard stdout to avoid duplicate logs in journal
StandardOutput={{if .UseSyslog}}null{{else}}journal{{end}}
StandardError={{if .UseSyslog}}null{{else}}journal{{end}}
SyslogIdentifier={{.Name}}
`))

var tcpSocketTemplate = template.Must(template.New("tcp-socket").Parse(`[Unit]
Description={{.Description}}

[Socket]
ListenStream={{.Port}}
FileDescriptorName={{.FDName}}
Service={{.ServiceName}}

[Install]
WantedBy=sockets.target
`))

var unixSocketTemplate = template.Must(template.New("unix-socket").Parse(`[Unit]
Description={{.Description}}

[Socket]
ListenStream={{.Path}}
FileDescriptorName={{.FDName}}
Service={{.ServiceName}}
SocketUser={{.User}}
SocketGroup={{.Group}}
SocketMode=0660
DirectoryMode=0755

[Install]
WantedBy=sockets.target
`))

var explorerServiceTemplate = template.Must(template.New("explorer-service").Parse(`[Unit]
Description={{.Description}} — HTTP Explorer
Requires={{.SocketName}} {{.EventsSocketName}}
After=network.target {{.SocketName}} {{.EventsSocketName}}

[Service]
Type=simple
User={{.User}}
Group={{.Group}}
WorkingDirectory={{.InstallDir}}
Sockets={{.SocketName}}
ExecStart={{.BinaryPath}}{{range .Args}} {{.}}{{end}}
KillSignal=SIGTERM
TimeoutStopSec=infinity
StandardOutput=journal
StandardError=journal
SyslogIdentifier={{.Name}}
`))

// sanitizeName returns a filesystem/service-safe version of the archive name:
// lowercase, only letters/digits/hyphens, no leading/trailing hyphens.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// installOptions controls how runInstall behaves.
type installOptions struct {
	// The sanitized service/binary name.
	Name string

	// TCP port exposed by the systemd SFTP socket.
	Port int

	// Service user and group.
	User  string
	Group string

	// Ensure creates User/Group if they don't already exist.
	// When false, runInstall fails if they are missing.
	Ensure bool

	// Args are the flags forwarded verbatim into ExecStart — os.Args[1:]
	// with all -install* flags stripped.
	Args []string

	// UploadDir is passed to the standalone explorer service when installed.
	UploadDir string

	// Optional standalone explorer binary and socket settings.
	ExplorerBinary       string
	ExplorerPort         int
	ExplorerLogFile      string
	ExplorerEventsSocket string
	ExplorerHeaderPath   string
	ExplorerFooterPath   string
	ExplorerMaxSizeMB    int64
}

// runInstall installs this binary as a systemd service.  Must be run as root.
func runInstall(opts installOptions) error {
	if opts.User == "" {
		opts.User = "anonymous"
	}
	if opts.Group == "" {
		opts.Group = "ftp"
	}
	if opts.Name == "" {
		opts.Name = "sftpguy"
	}
	if opts.Port == 0 {
		opts.Port = 2222
	}
	if opts.ExplorerPort == 0 {
		opts.ExplorerPort = 8080
	}
	if opts.ExplorerMaxSizeMB < 0 {
		return fmt.Errorf("explorer maxsize must be >= 0")
	}
	if strings.TrimSpace(opts.UploadDir) == "" {
		opts.UploadDir = "./uploads"
	}
	if strings.TrimSpace(opts.ExplorerLogFile) == "" {
		opts.ExplorerLogFile = "/var/log/" + opts.Name + "-explorer.log"
	}
	if strings.TrimSpace(opts.ExplorerEventsSocket) == "" {
		opts.ExplorerEventsSocket = "/run/" + opts.Name + "/explorer-events.sock"
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	// Resolve symlinks so we copy the real binary.
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}

	installDir := "/var/lib/" + opts.Name
	binaryDst := filepath.Join(installDir, opts.Name)
	serviceName := opts.Name + ".service"
	socketName := opts.Name + ".socket"
	explorerEventsSocketName := opts.Name + "-explorer-events.socket"
	explorerServiceName := opts.Name + "-explorer.service"
	explorerSocketName := opts.Name + "-explorer.socket"
	serviceDst := "/etc/systemd/system/" + serviceName
	socketDst := "/etc/systemd/system/" + socketName
	explorerEventsSocketDst := "/etc/systemd/system/" + explorerEventsSocketName
	explorerServiceDst := "/etc/systemd/system/" + explorerServiceName
	explorerSocketDst := "/etc/systemd/system/" + explorerSocketName

	useSyslog := false
	for _, arg := range opts.Args {
		// Match -syslog or --syslog (and variants like -syslog=true)
		if strings.HasPrefix(arg, "-syslog") || strings.HasPrefix(arg, "--syslog") {
			useSyslog = true
			break
		}
	}
	serviceArgs := append([]string{}, opts.Args...)
	serviceArgs = append(serviceArgs, "-systemd.socket")

	params := serviceParams{
		Description:              opts.Name,
		Name:                     opts.Name,
		User:                     opts.User,
		Group:                    opts.Group,
		InstallDir:               installDir,
		BinaryPath:               binaryDst,
		Args:                     serviceArgs,
		UseSyslog:                useSyslog,
		SFTPSocketName:           socketName,
		ExplorerEventsSocketName: explorerEventsSocketName,
	}

	svcContent, err := renderUnit(serviceTemplate, params)
	if err != nil {
		return fmt.Errorf("render service unit: %w", err)
	}
	socketContent, err := renderUnit(tcpSocketTemplate, tcpSocketParams{
		Description: opts.Name + " SFTP Socket",
		ServiceName: serviceName,
		FDName:      "sftp",
		Port:        opts.Port,
	})
	if err != nil {
		return fmt.Errorf("render sftp socket unit: %w", err)
	}
	eventSocketContent, err := renderUnit(unixSocketTemplate, unixSocketParams{
		Description: opts.Name + " Explorer RPC Socket",
		ServiceName: serviceName,
		FDName:      "explorer-events",
		Path:        opts.ExplorerEventsSocket,
		User:        opts.User,
		Group:       opts.Group,
	})
	if err != nil {
		return fmt.Errorf("render explorer RPC socket unit: %w", err)
	}

	run := func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		return cmd.Run()
	}

	if err := os.MkdirAll(installDir, permDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", installDir, err)
	}
	if err := copyExecutable(self, binaryDst); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.WriteFile(serviceDst, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}
	if err := os.WriteFile(socketDst, []byte(socketContent), 0644); err != nil {
		return fmt.Errorf("write sftp socket file: %w", err)
	}
	if err := os.WriteFile(explorerEventsSocketDst, []byte(eventSocketContent), 0644); err != nil {
		return fmt.Errorf("write explorer RPC socket file: %w", err)
	}

	// Ensure the service user/group exist before we try to chown anything.
	if err := ensureUserGroup(opts.User, opts.Group, opts.Ensure); err != nil {
		return fmt.Errorf("ensure user/group: %w", err)
	}

	explorerInstalled := false
	explorerSrc, err := resolveExplorerBinary(self, opts.ExplorerBinary, opts.Name)
	if err != nil {
		return err
	}
	if explorerSrc != "" {
		explorerDst := filepath.Join(installDir, opts.Name+"-explorer")
		if err := copyExecutable(explorerSrc, explorerDst); err != nil {
			return fmt.Errorf("copy explorer binary: %w", err)
		}
		explorerArgs, err := installExplorerArgs(opts, installDir)
		if err != nil {
			return err
		}
		explorerSvcContent, err := renderUnit(explorerServiceTemplate, explorerServiceParams{
			Description:      opts.Name,
			Name:             opts.Name + "-explorer",
			User:             opts.User,
			Group:            opts.Group,
			InstallDir:       installDir,
			BinaryPath:       explorerDst,
			Args:             explorerArgs,
			SocketName:       explorerSocketName,
			EventsSocketName: explorerEventsSocketName,
		})
		if err != nil {
			return fmt.Errorf("render explorer service unit: %w", err)
		}
		explorerSocketContent, err := renderUnit(tcpSocketTemplate, tcpSocketParams{
			Description: opts.Name + " Explorer HTTP Socket",
			ServiceName: explorerServiceName,
			FDName:      "explorer",
			Port:        opts.ExplorerPort,
		})
		if err != nil {
			return fmt.Errorf("render explorer socket unit: %w", err)
		}
		if err := os.WriteFile(explorerServiceDst, []byte(explorerSvcContent), 0644); err != nil {
			return fmt.Errorf("write explorer service file: %w", err)
		}
		if err := os.WriteFile(explorerSocketDst, []byte(explorerSocketContent), 0644); err != nil {
			return fmt.Errorf("write explorer socket file: %w", err)
		}
		explorerInstalled = true
	} else {
		fmt.Fprintf(os.Stderr, "Explorer binary not found; skipping standalone explorer service. Build one with: go build -o explorer ./cmd/explorer\n")
	}

	if err := chownTree(opts.User, opts.Group, installDir); err != nil {
		return fmt.Errorf("chown: %w", err)
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	_ = run("systemctl", "disable", serviceName)
	_ = os.Remove(filepath.Join("/etc/systemd/system/multi-user.target.wants", serviceName))
	_ = run("systemctl", "reset-failed", serviceName)

	units := []string{socketName, explorerEventsSocketName}
	startUnits := []string{socketName, explorerEventsSocketName}
	if explorerInstalled {
		_ = run("systemctl", "disable", explorerServiceName)
		_ = os.Remove(filepath.Join("/etc/systemd/system/multi-user.target.wants", explorerServiceName))
		_ = run("systemctl", "reset-failed", explorerServiceName)
		units = append(units, explorerSocketName)
		startUnits = append(startUnits, explorerSocketName)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload after service cleanup: %w", err)
	}

	for _, unit := range units {
		if err := run("systemctl", "enable", unit); err != nil {
			return fmt.Errorf("systemctl enable %s: %w", unit, err)
		}
	}
	for _, unit := range startUnits {
		if err := run("systemctl", "start", unit); err != nil {
			return fmt.Errorf("systemctl start %s: %w", unit, err)
		}
	}

	// On upgrades, keep socket units listening and let active services drain.
	// Inactive socket-activated services are left idle for the next connection.
	restartUnits := []string{serviceName}
	if explorerInstalled {
		restartUnits = append(restartUnits, explorerServiceName)
	}
	for _, unit := range restartUnits {
		if err := run("systemctl", "--no-block", "try-restart", unit); err != nil {
			return fmt.Errorf("systemctl try-restart %s: %w", unit, err)
		}
	}

	fmt.Fprintf(os.Stderr,
		"Installed %s\n  binary:  %s\n  service: %s\n  sockets: %s, %s\n  status:  systemctl status %s %s\n",
		opts.Name, binaryDst, serviceDst, socketDst, explorerEventsSocketDst, socketName, explorerEventsSocketName)
	if explorerInstalled {
		fmt.Fprintf(os.Stderr,
			"  explorer service: %s\n  explorer socket:  %s\n  explorer status:  systemctl status %s\n",
			explorerServiceDst, explorerSocketDst, explorerSocketName)
	}
	return nil
}

func renderUnit(t *template.Template, data any) (string, error) {
	var out strings.Builder
	if err := t.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func resolveExplorerBinary(self, explicit, serviceName string) (string, error) {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		p, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("resolve explorer binary: %w", err)
		}
		p, err = filepath.EvalSymlinks(p)
		if err != nil {
			return "", fmt.Errorf("resolve explorer binary symlink: %w", err)
		}
		if st, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("stat explorer binary %q: %w", p, err)
		} else if st.IsDir() {
			return "", fmt.Errorf("explorer binary %q is a directory", p)
		}
		return p, nil
	}

	dir := filepath.Dir(self)
	for _, name := range []string{serviceName + "-explorer", "sftpguy-explorer", "explorer"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if resolved, err := filepath.EvalSymlinks(p); err == nil {
				return resolved, nil
			}
			return p, nil
		}
	}
	return "", nil
}

func installExplorerArgs(opts installOptions, installDir string) ([]string, error) {
	if opts.ExplorerMaxSizeMB < 0 {
		return nil, fmt.Errorf("explorer maxsize must be >= 0")
	}
	args := []string{
		"-dir", opts.UploadDir,
		"-log", opts.ExplorerLogFile,
		"-events", opts.ExplorerEventsSocket,
		"-maxsize", strconv.FormatInt(opts.ExplorerMaxSizeMB, 10),
		"-systemd.socket",
	}
	if headerPath, err := installExplorerFragment(opts.ExplorerHeaderPath, installDir, "header"); err != nil {
		return nil, err
	} else if headerPath != "" {
		args = append(args, "-header", headerPath)
	}
	if footerPath, err := installExplorerFragment(opts.ExplorerFooterPath, installDir, "footer"); err != nil {
		return nil, err
	} else if footerPath != "" {
		args = append(args, "-footer", footerPath)
	}
	return args, nil
}

func installExplorerFragment(explicitPath, installDir, kind string) (string, error) {
	src := strings.TrimSpace(explicitPath)
	required := src != ""
	if src == "" {
		src = kind + ".html"
	}
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return "", fmt.Errorf("resolve explorer %s fragment: %w", kind, err)
	}
	st, err := os.Stat(srcAbs)
	if err != nil {
		if !required && os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat explorer %s fragment %q: %w", kind, srcAbs, err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("explorer %s fragment %q is a directory", kind, srcAbs)
	}
	dst := filepath.Join(installDir, "explorer-"+kind+filepath.Ext(srcAbs))
	if err := copyFile(srcAbs, dst, 0644); err != nil {
		return "", fmt.Errorf("copy explorer %s fragment: %w", kind, err)
	}
	return dst, nil
}

// ensureUserGroup creates the service user and group if they don't already
// exist (when ensure is true), or returns an error if they are missing (when
// ensure is false).
func ensureUserGroup(user, group string, ensure bool) error {
	_, _, err := lookupUIDGID(user, group)
	if err == nil {
		return nil // already exist
	}
	if !ensure {
		return fmt.Errorf("user/group %q/%q not found (use -install.ensure to create them): %w", user, group, err)
	}

	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		_ = cmd.Run()
	}

	// Try Debian-style first, fall back to RHEL-style.
	if _, err := exec.LookPath("addgroup"); err == nil {
		run("addgroup", "--system", group)
		run("adduser", "--system", "--no-create-home", "--ingroup", group, user)
	} else {
		run("groupadd", "--system", group)
		run("useradd", "--system", "--no-create-home", "--gid", group, user)
	}
	return nil
}

func copyExecutable(src, dst string) error {
	return copyFile(src, dst, 0755)
}

func copyFile(src, dst string, mode fs.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Write to a temp file beside dst, then rename for atomicity.
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func touchFile(path string, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	return f.Close()
}

// chownTree sets ownership of each path (and their contents if directories)
// to user:group, resolved via /etc/passwd and /etc/group.
func chownTree(user, group string, paths ...string) error {
	uid, gid, err := lookupUIDGID(user, group)
	if err != nil {
		return err
	}
	for _, root := range paths {
		if err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // skip unreadable entries
			}
			return os.Lchown(p, uid, gid)
		}); err != nil {
			return err
		}
	}
	return nil
}

// lookupUIDGID resolves user and group names to numeric IDs via /etc/passwd
// and /etc/group, avoiding any cgo dependency.
func lookupUIDGID(user, group string) (uid, gid int, err error) {
	uid, gid = -1, -1
	if data, e := os.ReadFile("/etc/passwd"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.SplitN(line, ":", 4); len(f) >= 3 && f[0] == user {
				uid, _ = strconv.Atoi(f[2])
				break
			}
		}
	}
	if data, e := os.ReadFile("/etc/group"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.SplitN(line, ":", 4); len(f) >= 3 && f[0] == group {
				gid, _ = strconv.Atoi(f[2])
				break
			}
		}
	}
	if uid == -1 {
		return 0, 0, fmt.Errorf("user %q not found in /etc/passwd", user)
	}
	if gid == -1 {
		return 0, 0, fmt.Errorf("group %q not found in /etc/group", group)
	}
	return uid, gid, nil
}
