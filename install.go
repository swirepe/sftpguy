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
	Description string   // human-readable archive name
	Name        string   // sanitized service / binary name
	User        string   // system user the service runs as
	Group       string   // system group the service runs as
	InstallDir  string   // /var/lib/<name>
	BinaryPath  string   // InstallDir/<name>
	LogFile     string   // /var/log/<name>.log
	Args        []string // flags to pass on restart (os.Args minus -install)
	UseSyslog   bool
}

// serviceTemplate is the systemd unit file template.
var serviceTemplate = template.Must(template.New("service").Parse(`[Unit]
Description={{.Description}} — Anonymous SFTP Server
After=network.target

[Service]
Type=simple
User={{.User}}
Group={{.Group}}
WorkingDirectory={{.InstallDir}}
ExecStart={{.BinaryPath}}{{range .Args}} {{.}}{{end}}
Restart=always
RestartSec=5

# If server handles syslog internally, discard stdout to avoid duplicate logs in journal
StandardOutput={{if .UseSyslog}}null{{else}}journal{{end}}
StandardError={{if .UseSyslog}}null{{else}}journal{{end}}
SyslogIdentifier={{.Name}}

[Install]
WantedBy=multi-user.target
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

	// Service user and group.
	User  string
	Group string

	// Ensure creates User/Group if they don't already exist.
	// When false, runInstall fails if they are missing.
	Ensure bool

	// Args are the flags forwarded verbatim into ExecStart — os.Args[1:]
	// with all -install* flags stripped.
	Args []string
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
	serviceDst := "/etc/systemd/system/" + serviceName

	useSyslog := false
	for _, arg := range opts.Args {
		// Match -syslog or --syslog (and variants like -syslog=true)
		if strings.HasPrefix(arg, "-syslog") || strings.HasPrefix(arg, "--syslog") {
			useSyslog = true
			break
		}
	}

	params := serviceParams{
		Description: opts.Name,
		Name:        opts.Name,
		User:        opts.User,
		Group:       opts.Group,
		InstallDir:  installDir,
		BinaryPath:  binaryDst,
		Args:        opts.Args,
		UseSyslog:   useSyslog,
	}

	var svcContent strings.Builder
	if err := serviceTemplate.Execute(&svcContent, params); err != nil {
		return fmt.Errorf("render service template: %w", err)
	}

	run := func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		return cmd.Run()
	}

	// Stop existing service (ignore error: may not exist yet).
	_ = run("systemctl", "stop", serviceName)

	if err := os.MkdirAll(installDir, permDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", installDir, err)
	}
	if err := copyExecutable(self, binaryDst); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.WriteFile(serviceDst, []byte(svcContent.String()), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	// Ensure the service user/group exist before we try to chown anything.
	if err := ensureUserGroup(opts.User, opts.Group, opts.Ensure); err != nil {
		return fmt.Errorf("ensure user/group: %w", err)
	}

	if err := chownTree(opts.User, opts.Group, installDir); err != nil {
		return fmt.Errorf("chown: %w", err)
	}

	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", serviceName},
		{"start", serviceName},
	} {
		if err := run("systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %w", args[0], err)
		}
	}

	fmt.Fprintf(os.Stderr,
		"Installed %s\n  binary:  %s\n  service: %s\n  status:  systemctl status %s\n",
		opts.Name, binaryDst, serviceDst, serviceName)
	return nil
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
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Write to a temp file beside dst, then rename for atomicity.
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0755); err != nil {
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
