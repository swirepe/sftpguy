package main

/*

sftpguy - anonymous share-first SFTP server
Copyright (C) 2026 台湾独立运动

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

//go:generate go run . -update-version
//go:embed sftpguy.go admin.go install.go fortunes.txt
var embeddedSource embed.FS

const versionFile = "VERSION"

//go:embed VERSION
var AppVersion string

// Default files that are always downloadable
var defaultUnrestrictedPaths = []string{
	"README.txt",
	"RULES.txt",
	"LICENSE.txt",
	"public/",
}

// ============================================================================
// Constants
// ============================================================================

const (
	envPrefix = "SFTP_"

	// System identifiers
	systemOwner = "system"
	sourceFile  = "sftpguy.go"

	// File permissions
	permDir      = 0755
	permFile     = 0644
	permHostKey  = 0600
	permLogFile  = 0644
	permReadOnly = 0444

	// System defaults
	defaultUID      = 1000
	defaultGID      = 1000
	unrestrictedUID = 1337
	unrestrictedGID = 1337

	// Port limits
	minPort = 1
	maxPort = 65535

	// Database Schema
	Schema = `PRAGMA foreign_keys = ON;

	CREATE TABLE IF NOT EXISTS users ( 
		pubkey_hash TEXT PRIMARY KEY, 
		last_login DATETIME, 
		upload_count INTEGER DEFAULT 0, 
		upload_bytes INTEGER DEFAULT 0,
		download_count INTEGER DEFAULT 0,
		download_bytes INTEGER DEFAULT 0 
	);
	
	INSERT OR IGNORE INTO users (pubkey_hash) VALUES('system');

	CREATE TABLE IF NOT EXISTS files ( 
		path TEXT PRIMARY KEY,
		owner_hash TEXT,
		size INTEGER DEFAULT 0,
		is_dir INTEGER DEFAULT 0,
		    
		FOREIGN KEY (owner_hash) REFERENCES users (pubkey_hash) 
			ON DELETE CASCADE 
			ON UPDATE CASCADE
	);


	-- shadow_banned means 
	--  1.  your connection is severely throttled
	--  2.  you can login and list files as normal
	--  3.  all other operations do nothing for a random period of time, 
	--      then return with a generic error
	CREATE TABLE IF NOT EXISTS shadow_banned (
		pubkey_hash text primary key,
		banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,

		FOREIGN KEY (pubkey_hash) REFERENCES users (pubkey_hash) 
			ON DELETE CASCADE 
			ON UPDATE CASCADE
	);

	CREATE TABLE IF NOT EXISTS ip_banned (
		ip_address TEXT PRIMARY KEY,
		banned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS log (
		id           INTEGER PRIMARY KEY,
		timestamp    INTEGER NOT NULL,
		ip_address   TEXT NOT NULL,
		port         INTEGER NOT NULL,
		user_id      TEXT,
		user_session TEXT,
		event        TEXT NOT NULL,
		path         TEXT,
		meta         TEXT
	);
	CREATE INDEX IF NOT EXISTS log_timestamp_idx ON log (timestamp);
	CREATE INDEX IF NOT EXISTS log_ip_address_idx ON log (ip_address);
	CREATE INDEX IF NOT EXISTS log_user_idx      ON log (user_id, timestamp);
	CREATE INDEX IF NOT EXISTS log_event_idx     ON log (event);
	CREATE INDEX IF NOT EXISTS log_session_idx   ON log (user_session);
`
)

// ============================================================================
// User Permission Errors
// ============================================================================

type EventKind string

const (
	EventShell                 EventKind = "shell"
	EventExec                  EventKind = "exec"
	EventLogin                 EventKind = "login"
	EventUpload                EventKind = "upload"
	EventDownload              EventKind = "download"
	EventDelete                EventKind = "delete"
	EventRename                EventKind = "rename"
	EventDenied                EventKind = "denied"
	EventDeniedSymlink         EventKind = "denied/symlink"
	EventDeniedContributorLock EventKind = "denied/contributor-lock"
	EventDeniedSystemFile      EventKind = "denied/system-file"
	EventDeniedDirOwner        EventKind = "denied/dir-owner"
	EventDeniedFilenameClaimed EventKind = "denied/filename-claimed"
	EventDeniedNotOwner        EventKind = "denied/not-owner"
	EventDeniedRateLimit       EventKind = "denied/rate-limit"
	EventDeniedQuota           EventKind = "denied/quota"
	EventDeniedPathTraversal   EventKind = "denied/path-traversal"
	EventShadowBan             EventKind = "shadow_ban"
)

var errorPrefix = struct {
	EN string
	ZH string
}{
	EN: red.Fmt("DENIED:      "),
	ZH: red.Fmt("访问被拒绝:  "),
}

type UserPermissionError struct {
	Kind EventKind
	EN   string
	ZH   string
	args []any
}

func (e UserPermissionError) Args(args ...any) UserPermissionError {
	e.args = args
	return e
}

func (e UserPermissionError) format(tmpl string) string {
	if len(e.args) > 0 {
		return fmt.Sprintf(tmpl, e.args...)
	}
	return tmpl
}

func (e UserPermissionError) LogString() string { return e.format(e.EN) }

func (e UserPermissionError) Error() string {
	return fmt.Sprintf("%s%s\n%s%s",
		errorPrefix.EN, e.format(e.EN),
		errorPrefix.ZH, e.format(e.ZH))
}

// TODO: fill in these event kinds
var (
	errMsgSymlinksProhibited = UserPermissionError{Kind: EventDeniedSymlink, EN: "Symlinks are prohibited.", ZH: "禁止使用符号链接。"}
	errMsgContributorsLocked = UserPermissionError{Kind: EventDeniedContributorLock,
		EN: "%s is only available to contributors who have uploaded at least %s: upload %d more bytes.",
		ZH: "文件 %s 仅对已上传至少 %s 字节的贡献者可用：再上传 %d 字节。"}
	errMsgFileProtected    = UserPermissionError{Kind: EventDeniedSystemFile, EN: "%s is a protected system file.", ZH: "%s 是受保护的系统文件。"}
	errMsgCannotWriteToDir = UserPermissionError{Kind: EventDeniedDirOwner, EN: "Cannot write to another user's directory.", ZH: "无法写入其他用户的目录。"}
	errMsgFilenameClaimed  = UserPermissionError{Kind: EventDeniedFilenameClaimed, EN: "This filename is already claimed.", ZH: "此文件名已被占用。"}
	errMsgNoPermissionDel  = UserPermissionError{Kind: EventDeniedNotOwner,
		EN: "You do not have permission to delete this. (%s UID [owner] %d != [you] %d)",
		ZH: "您没有删除此项的权限。(%s UID [所有者] %d != [你] %d)"}
	errMsgNotOwner = UserPermissionError{Kind: EventDeniedNotOwner,
		EN: "You do not own the source file or directory. (UID [owner] %d != [you] %d)",
		ZH: "您不是源文件或目录的所有者。(UID [所有者] %d != [你] %d)"}
	errMsgRenameFailed     = UserPermissionError{Kind: EventDenied, EN: "Rename failed.", ZH: "重命名失败。"}
	errMsgMkdirRateLimit   = UserPermissionError{Kind: EventDeniedRateLimit, EN: "Mkdir rate limit reached.", ZH: "已达到创建目录的频率限制。"}
	errMsgMaxDirsReached   = UserPermissionError{Kind: EventDeniedQuota, EN: "Maximum directory limit reached for this archive.", ZH: "已达到此归档的最大目录限制。"}
	errMsgFileSizeExceeded = UserPermissionError{Kind: EventDeniedQuota, EN: "File size limit exceeded. Maximum allowed: %d bytes", ZH: "超过文件大小限制。最大允许：%d 字节"}
	errMsgPathTraversal    = UserPermissionError{Kind: EventDeniedPathTraversal, EN: "Path traversal detected.", ZH: "检测到路径遍历。"}
)

// ============================================================================
// Store (Database Operations)
// ============================================================================

type userStats struct {
	UploadCount   int64
	LastLogin     string
	UploadBytes   int64
	DownloadCount int64
	DownloadBytes int64
	FirstTimer    bool
	IsBanned      bool
}

func (u userStats) IsContributor(threshold int64) (bool, int64) {
	if u.UploadBytes >= threshold {
		return true, 0
	}
	remaining := threshold - u.UploadBytes
	return false, remaining
}

type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewStore(path string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, err
	}

	if _, err := db.Exec(Schema); err != nil {
		return nil, err
	}
	return &Store{db: db, logger: logger}, nil
}

func (s *Store) transact(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("failed to begin transaction", "err", err)
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		s.logger.Error("transaction failed", "err", err)
		return err
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("failed to commit transaction", "err", err)
	}
	return nil
}

func (s *Store) exec(query string, args ...any) (sql.Result, error) {
	res, err := s.db.Exec(query, args...)
	if err != nil {
		s.logger.Error("database exec failed",
			"err", err,
			"query", query,
			"args", args,
		)
		return nil, err
	}
	return res, nil
}

func (s *Store) RegisterFile(path, owner string, size int64, isDir bool) {
	if owner == "" {
		owner = systemOwner
	}

	isDirVal := 0
	if isDir {
		isDirVal = 1
	}

	s.exec(`INSERT OR REPLACE INTO files (path, owner_hash, size, is_dir) 
	        VALUES (?, ?, ?, ?)`, path, owner, size, isDirVal)
}

func (s *Store) RegisterSystemFiles(absBase string, paths []string) {
	for _, p := range paths {
		full := filepath.Join(absBase, filepath.FromSlash(p))
		isDir := false
		if fi, err := os.Stat(full); err == nil {
			isDir = fi.IsDir()
		} else {
			s.logger.Warn("Registering a path that does not exist on disk.  Nobody will be able to upload to this path.", "path", p, "err", err)
		}
		// Register as system-owned
		s.RegisterFile(p, systemOwner, 0, isDir)
	}
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) GetUserStats(hash string) (userStats, error) {
	var u userStats
	err := s.db.QueryRow(`SELECT last_login, upload_count, upload_bytes, download_count, download_bytes 
		FROM users WHERE pubkey_hash = ?`, hash).Scan(&u.LastLogin, &u.UploadCount, &u.UploadBytes, &u.DownloadCount, &u.DownloadBytes)
	if err == sql.ErrNoRows {
		u.FirstTimer = true
		u.LastLogin = "Never"
		return u, nil
	}
	return u, err
}

func (s *Store) UpsertUserSession(hash string) (userStats, error) {
	stats, err := s.GetUserStats(hash)
	if err != nil {
		s.logger.Debug("Error upserting user session", "err", err)
		return userStats{}, err
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = s.exec(`
		INSERT INTO users (pubkey_hash, last_login) VALUES (?, ?)
		ON CONFLICT(pubkey_hash) DO UPDATE SET last_login = excluded.last_login
	`, hash, now)

	if err != nil {
		return stats, err
	}

	return stats, nil
}

func (s *Store) GetFileOwner(relPath string) (string, error) {
	var owner string
	err := s.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return owner, err
}

func (s *Store) ClaimFile(hash, relPath string) error {
	return s.transact(func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)

		if err == sql.ErrNoRows {
			_, insertErr := tx.Exec("INSERT INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, 0, 0)", relPath, hash)
			return insertErr
		}

		if err != nil {
			return err
		}

		if owner != hash {
			return fmt.Errorf("claimed")
		}

		return nil
	})
}

func (s *Store) EnsureDirectory(hash, relPath string) error {
	if relPath == "." || relPath == "" {
		return nil
	}

	return s.transact(func(tx *sql.Tx) error {
		parts := strings.Split(relPath, "/")
		curr := ""
		for _, p := range parts {
			curr = path.Join(curr, p)
			if _, err := tx.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, 0, 1)", curr, hash); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) GetDirectoryCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM files WHERE is_dir = 1").Scan(&count)
	return count, err
}

func (s *Store) UpdateFileWrite(hash, relPath string, newSize, delta int64) error {
	return s.transact(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE files SET size = ? WHERE path = ?", newSize, relPath); err != nil {
			return err
		}
		if delta > 0 {
			if _, err := tx.Exec(`
				UPDATE users 
				SET upload_count = upload_count + 1, 
				    upload_bytes = upload_bytes + ? 
				WHERE pubkey_hash = ?`, delta, hash); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) RecordDownload(hash string, bytes int64) error {
	_, err := s.exec("UPDATE users SET download_count = download_count + 1, download_bytes = download_bytes + ? WHERE pubkey_hash = ?", bytes, hash)
	return err
}

func (s *Store) RenamePath(oldRel, newRel string) error {
	prefixLen := len(oldRel) + 1 // "oldRel" + "/"

	_, err := s.exec(`
		UPDATE files 
		SET path = ? || substr(path, ?)
		WHERE path = ? OR substr(path, 1, ?) = ?`,
		newRel, prefixLen+1,
		oldRel, prefixLen, oldRel+"/")
	return err
}

func (s *Store) DeletePath(relPath string) error {
	prefixLen := len(relPath) + 1 // "relPath" + "/"

	_, err := s.db.Exec(`
		DELETE FROM files 
		WHERE path = ? OR substr(path, 1, ?) = ?`,
		relPath, prefixLen, relPath+"/")
	return err
}

func (s *Store) GetBannerStats(threshold int64) (u, c, f, b uint64) {
	if err := s.db.QueryRow(`
		SELECT 
			COUNT(*) FILTER (WHERE upload_count > 0),
			COUNT(*) FILTER (WHERE upload_bytes > ?)
		FROM users
	`, threshold).Scan(&u, &c); err != nil {
		s.logger.Warn("Could not get user/contributor banner stats", "err", err)
	}
	if err := s.db.QueryRow("SELECT count(*), sum(size) FROM files WHERE is_dir = 0").Scan(&f, &b); err != nil {
		s.logger.Warn("Could not get file size/count banner stats", "err", err)
	}
	return
}

func (s *Store) FileExistsInDB(relPath string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM files WHERE path = ?", relPath).Scan(&exists)
	return exists
}

func (s *Store) FilesByOwner(pubHash string) ([]string, error) {
	rows, err := s.db.Query("SELECT path, is_dir FROM files WHERE owner_hash = ?", pubHash)
	if err != nil {
		s.logger.Error("failed to query files by owner", "err", err, "hash", pubHash)
		return nil, err
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var p string
		var d bool
		if err := rows.Scan(&p, &d); err != nil {
			s.logger.Error("failed to scan path row", "err", err)
			return nil, err
		}
		if d {
			p = strings.TrimSuffix(p, "/") + "/"
		}
		paths = append(paths, p)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	sort.Strings(paths)
	return paths, nil
}

func (s *Store) LogEvent(kind EventKind, pubHash, sessionID string, remoteAddr net.Addr, args ...any) {
	ip := ""
	port := 0
	if remoteAddr != nil {
		host, portStr, err := net.SplitHostPort(remoteAddr.String())
		if err == nil {
			ip = host
			port, _ = strconv.Atoi(portStr)
		}
	}

	// Pull path and meta out of the variadic key-value args
	path := ""
	meta := map[string]any{}
	for i := 0; i+1 < len(args); i += 2 {
		k, _ := args[i].(string)
		v := args[i+1]
		switch k {
		case "path":
			path, _ = v.(string)
		default:
			meta[k] = v
		}
	}

	metaJSON := ""
	if len(meta) > 0 {
		if b, err := json.Marshal(meta); err == nil {
			metaJSON = string(b)
		}
	}

	_, err := s.exec(`
		INSERT INTO log (timestamp, ip_address, port, user_id, user_session, event, path, meta)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(), ip, port, pubHash, sessionID, string(kind), path, metaJSON,
	)
	if err != nil {
		s.logger.Warn("failed to log event", "kind", kind, "err", err)
	}
}

// ============================================================================
// Configuration
// ============================================================================

type Config struct {
	Name                    string
	Port                    int
	HostKeyFile             string
	DBPath                  string
	LogFile                 string
	UploadDir               string
	BannerFile              string
	BannerStats             bool
	MkdirRate               float64
	MaxDirs                 int
	Unrestricted            string
	LockDirectoriesToOwners bool
	Verbose                 bool
	Debug                   bool
	MaxFileSize             int64
	ContributorThreshold    int64
	unrestrictedMap         map[string]bool
	BootstrapSrc            bool
	AdminEnabled            bool
	SshNoAuth               bool
}

func LoadConfig() (Config, error) {
	updateVersion := flag.Bool("update-version", false, "Internal use by go generate")

	cfg := Config{}

	EnvFlag(&cfg.Name, "name", "ARCHIVE_NAME", "sftpguy", "Archive name")
	EnvFlag(&cfg.Port, "port", "PORT", 2222, "SSH port")
	EnvFlag(&cfg.HostKeyFile, "hostkey", "HOST_KEY", "id_ed25519", "SSH host key")
	EnvFlag(&cfg.DBPath, "db.path", "DB_PATH", "sftp.db", "SQLite path")
	EnvFlag(&cfg.LogFile, "logfile", "LOG_FILE", "sftp.log", "Log file path")
	EnvFlag(&cfg.UploadDir, "dir", "UPLOAD_DIR", "./uploads", "Upload directory")
	EnvFlag(&cfg.BannerFile, "banner", "BANNER_FILE", "BANNER.txt", "Banner file")
	EnvFlag(&cfg.BannerStats, "banner.stats", "BANNER_STATS", false, "Show file statistics in the banner")
	EnvFlag(&cfg.MkdirRate, "dir.rate", "MKDIR_RATE", 100.0, "Global mkdir rate limit (dirs/sec)")
	EnvFlag(&cfg.MaxDirs, "dir.max", "MAX_DIRECTORIES", 10000, "Maximum total directories allowed in archive")
	EnvFlag(&cfg.Unrestricted, "unrestricted", "UNRESTRICTED_PATHS", strings.Join(defaultUnrestrictedPaths, ","), "Comma-separated list of paths always available for download")
	EnvFlag(&cfg.LockDirectoriesToOwners, "dir.owners_only", "LOCK_DIRS_TO_OWNERS", false, "Users can only upload to directories they own")
	EnvFlag(&cfg.Verbose, "verbose", "VERBOSE", false, "Enable highlighted and formatted logging for developers.")
	EnvFlag(&cfg.Debug, "debug", "DEBUG", false, "Enable debug logging")
	EnvFlag(&cfg.SshNoAuth, "noauth", "NOAUTH", false, "Offer the NoClientAuth login option over ssh.  User IDs will be generated from ip addresses.")
	EnvFlag(&cfg.AdminEnabled, "admin.ssh", "ADMIN_SSH", false, "Enable the admin console over ssh")
	EnvSizeFlag(&cfg.MaxFileSize, "maxsize", "MAX_FILE_SIZE", "8gb", "Max file size (e.g. 500mb, 2gb, 0=unlimited)")
	EnvSizeFlag(&cfg.ContributorThreshold, "contrib", "CONTRIBUTOR_THRESHOLD", "1mb", "Bytes a user must upload to unlock downloads")

	flag.BoolVar(&cfg.BootstrapSrc, "src", false, "Copy source code to upload directory on boot")
	v := flag.Bool("version", false, "Show version")

	install := flag.Bool("install", false, "Install as a systemd service (requires root)")
	installService := flag.String("install.service", "sftpguy", "Service name to use when installing")
	installUser := flag.String("install.user", "anonymous", "System user the service runs as")
	installGroup := flag.String("install.group", "ftp", "System group the service runs as")
	installEnsure := flag.Bool("install.ensure", true, "Create user/group if they don't exist")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	rawArgs := os.Args[1:]
	flag.Parse()

	if *updateVersion {
		runVersionGenerator()
		os.Exit(0)
	}

	if *v {
		fmt.Printf("%s v%s\n", cfg.Name, AppVersion)
		os.Exit(0)
	}

	if *install {
		opts := installOptions{
			Name:   sanitizeName(*installService),
			User:   *installUser,
			Group:  *installGroup,
			Ensure: *installEnsure,
			Args:   stripInstallFlags(rawArgs),
		}
		if err := runInstall(opts); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Process unrestricted paths
	cfg.unrestrictedMap = make(map[string]bool)
	for _, p := range strings.Split(cfg.Unrestricted, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cfg.unrestrictedMap[p] = true
		}
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func stripInstallFlags(argv []string) []string {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		name := strings.TrimLeft(a, "-")
		// Strip -install=... / -install.foo=...
		if bare, _, ok := strings.Cut(name, "="); ok {
			if bare == "install" || strings.HasPrefix(bare, "install.") {
				continue
			}
		}
		// Strip bare -install / -install.foo and consume the following value
		// token if it isn't itself a flag.
		if name == "install" || strings.HasPrefix(name, "install.") {
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++ // consume the value
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

func (c Config) Validate() error {
	if c.Port < minPort || c.Port > maxPort {
		return fmt.Errorf("port must be between %d and %d", minPort, maxPort)
	}
	if c.Name == "" || c.HostKeyFile == "" || c.DBPath == "" || c.UploadDir == "" {
		return errors.New("required configuration fields missing")
	}
	return nil
}

// ============================================================================
// Server
// ============================================================================
type UserStatus struct {
	IsContributor bool
	BytesNeeded   int64
	Stats         userStats
}

func (s *Server) UserStatus(pubHashash string) (userStatus UserStatus, err error) {
	stats, err := s.store.GetUserStats(pubHashash)
	if err != nil {
		return UserStatus{}, err
	}
	isContributor, remaining := stats.IsContributor(s.cfg.ContributorThreshold)
	userStatus.IsContributor = isContributor
	userStatus.BytesNeeded = remaining
	userStatus.Stats = stats
	return userStatus, nil
}

type FortuneGenerator struct {
	fortunes []string
}

func (f *FortuneGenerator) Random() string {
	if len(f.fortunes) == 0 {
		data, _ := embeddedSource.ReadFile("fortunes.txt")
		f.fortunes = strings.Split(string(data), "\n%\n")
	}
	return strings.TrimSpace(f.fortunes[rand.Intn(len(f.fortunes))])
}

type Server struct {
	store            *Store
	logger           *slog.Logger
	mkdirLimiter     *rate.Limiter
	fortuneGenerator *FortuneGenerator
	cfg              Config
	absUploadDir     string
	listener         net.Listener
	wg               sync.WaitGroup
	shutdown         chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	store, err := NewStore(cfg.DBPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}

	absDir, err := filepath.Abs(cfg.UploadDir)
	if err != nil {
		return nil, err
	}
	os.MkdirAll(absDir, permDir)

	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		store:            store,
		logger:           logger,
		mkdirLimiter:     rate.NewLimiter(rate.Limit(cfg.MkdirRate), 1000),
		fortuneGenerator: &FortuneGenerator{},
		cfg:              cfg,
		absUploadDir:     absDir,
		shutdown:         make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	if cfg.BootstrapSrc {
		srcDir, err := bootstrapSource(cfg.Name, absDir, logger)
		if err != nil {
			logger.Error("failed to bootstrap source", "err", err)
		}

		cfg.unrestrictedMap[srcDir] = true
	}

	return srv, nil
}

func bootstrapSource(name, absDir string, logger *slog.Logger) (srcDir string, err error) {
	logger.Info("bootstrapping embedded files to upload directory")

	srcDir = fmt.Sprintf("%s-%s/", name, appShort())

	return srcDir, fs.WalkDir(embeddedSource, ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := embeddedSource.ReadFile(relPath)
		if err != nil {
			return fmt.Errorf("failed to read embedded file %s: %w", relPath, err)
		}

		//logical path stored in the DB (e.g. "sftpguy-v1.0.0/main.go")
		destName := filepath.Join(srcDir, relPath)
		destPath := filepath.Join(absDir, destName) // the actual location on disk

		if err := os.MkdirAll(filepath.Dir(destPath), permDir); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", destName, err)
		}

		if err := os.WriteFile(destPath, data, permFile); err != nil {
			return fmt.Errorf("failed to write %s to disk: %w", destName, err)
		}

		logger.Debug("bootstrapped file", "file", destName)
		return nil
	})
}

func (s *Server) Shutdown() error {
	close(s.shutdown)
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return s.store.Close()
}

func (s *Server) Listen() error {
	if err := s.ensureHostKey(); err != nil {
		return err
	}

	sshConfig := &ssh.ServerConfig{
		BannerCallback:              s.bannerCallback,
		PublicKeyCallback:           s.publicKeyCallback,
		NoClientAuth:                s.cfg.SshNoAuth,
		NoClientAuthCallback:        s.noClientAuthCallback,
		KeyboardInteractiveCallback: s.keyboardInteractiveCallback,
	}

	keyBytes, _ := os.ReadFile(s.cfg.HostKeyFile)
	key, _ := ssh.ParsePrivateKey(keyBytes)
	sshConfig.AddHostKey(key)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return err
	}
	s.listener = listener

	s.logger.Info("SFTP archive online", "port", s.cfg.Port)
	fmt.Fprintln(os.Stderr, green.Bold("==========  READY  =========="))

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return nil
			default:
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSSH(conn, sshConfig)
		}()
	}
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))

	ext := map[string]string{"pubkey-hash": hash}
	if s.checkAdminKey(key) {
		ext["admin"] = "1"
	}
	return &ssh.Permissions{Extensions: ext}, nil
}

func (s *Server) noClientAuthCallback(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	ip := getHostIp(conn)

	data := fmt.Sprintf("anon-auth:%s", ip)
	hash := fmt.Sprintf("anon-auth:%x", sha256.Sum256([]byte(data)))

	s.logger.Debug("anonymous login attempt", "ip", ip, "generated_hash", hash)

	return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
}

func remoteToPubhash(remoteAddr net.Addr) string {
	ip, _, _ := net.SplitHostPort(remoteAddr.String())
	data := fmt.Sprintf("anon-auth:%s", ip)
	hash := fmt.Sprintf("anon-auth:%x", sha256.Sum256([]byte(data)))
	return hash
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	data := fmt.Sprintf("pwd-auth:%s:%s", conn.User(), string(password))
	hash := fmt.Sprintf("pwd-auth:%x", sha256.Sum256([]byte(data)))

	s.logger.Debug("password login attempt",
		"ip", getHostIp(conn),
		"user", conn.User(),
		"generated_hash", hash,
	)

	return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
}

// KeyboardInteractiveCallback, if non-nil, is called when
// keyboard-interactive authentication is selected (RFC
// 4256). The client object's Challenge function should be
// used to query the user. The callback may offer multiple
// Challenge rounds. To avoid information leaks, the client
// should be presented a challenge even if the user is
// unknown.
// type KeyboardInteractiveChallenge
// 	 func(name, instruction string, questions []string, echos []bool) (answers []string, err error)

// KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
// 			// You can prompt the user for multiple pieces of information.
// 			// The `client.Challenge` function sends the prompts to the client.
// 			questions := []string{"What is your username?", "Enter password:"}
// 			isPassword := []bool{false, true} // Indicate which prompts are sensitive

// 			answers, err := client(conn.User(), "Server Instruction", questions, isPassword)
// 			if err != nil {
// 				return nil, err
// 			}

//		if answers[0] == "validuser" && answers[1] == "validpassword" {
//			return &ssh.Permissions{Extensions: map[string]string{"user_id": "123"}}, nil
//		}
//		return nil, fmt.Errorf("invalid credentials")
//	},

func (s *Server) getRules() string {
	b, err := os.ReadFile(filepath.Join(s.absUploadDir, "RULES.txt"))
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *Server) keyboardInteractiveCallback(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {

	// TODO: better instructions or whatever
	instructions := s.getRules() + `
	Your password is your email address.

	`

	answers, err := client(s.cfg.Name,
		instructions,
		[]string{fmt.Sprintf("\r(anonymous@%s) Password: ", s.cfg.Name)},
		[]bool{true})
	if err != nil {
		s.logger.Warn("password weird lol", "err", err)
		return nil, err
	}

	user := conn.User()
	password := answers[0]

	data := fmt.Sprintf("pwd-auth:%s:%s", user, password)
	hash := fmt.Sprintf("pwd-auth:%x", sha256.Sum256([]byte(data)))
	s.logger.Info("password login attempt",
		"ip", getHostIp(conn),
		"user", user,
		"password", password, // traditionally it's your email address
		"generated_hash", hash,
	)

	// Note: We are effectively "accepting all passwords" here, but
	// treating the credentials as the seed for their unique UID.
	return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
}

func getHostIp(conn ssh.ConnMetadata) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func (s *Server) bannerCallback(conn ssh.ConnMetadata) string {
	banner := ""
	if data, err := os.ReadFile(s.cfg.BannerFile); err == nil {
		banner = string(data)
	} else {
		banner = fmt.Sprintf("=== %s %s ===", s.cfg.Name, appShort())
	}

	if s.cfg.BannerStats {
		u, c, f, b := s.store.GetBannerStats(s.cfg.ContributorThreshold)
		banner += fmt.Sprintf("\r\nUsers: %d | Contributors: %d | Files: %d | Size: %s\r\n", u, c, f, formatBytes(int64(b)))
	}
	return banner
}

func (s *Server) handleSSH(nConn net.Conn, config *ssh.ServerConfig) {
	nConn.SetDeadline(time.Now().Add(30 * time.Second))

	if s.store.IsBannedByIp(nConn.RemoteAddr()) {
		s.logger.Info("blocked banned IP", "remote_address", nConn.RemoteAddr())
		nConn.Close()
		return
	}

	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		nConn.Close()
		return
	}
	nConn.SetDeadline(time.Time{})
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	sessionID := fmt.Sprintf("%x", sConn.SessionID())

	if s.cfg.AdminEnabled && s.isAdminConn(sConn.Permissions) {
		// ── Admin fast-path ───────────────────────────────────────────
		s.logAdminLogin(pubHash, sessionID, sConn.RemoteAddr())
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			ch, chReqs, _ := newCh.Accept()
			go s.handleAdminChannel(ch, chReqs, sessionID)
		}
		return
	}

	stats, _ := s.store.UpsertUserSession(pubHash)
	logger := s.logger.With(userGroup(pubHash, sessionID, sConn.RemoteAddr()))
	isBanned := s.store.IsBanned(pubHash)
	logger.Info("login")
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go s.handleChannel(ch, reqs, pubHash, sessionID, stats, sConn, logger, isBanned)
	}
}

func (s *Server) handleChannel(ch ssh.Channel,
	reqs <-chan *ssh.Request,
	pubHash,
	sessionID string,
	stats userStats,
	sConn *ssh.ServerConn,
	logger *slog.Logger,
	isBanned bool) {

	defer ch.Close()
	for req := range reqs {
		s.logger.Debug("handleChannel", "req", req)
		switch req.Type {
		case "subsystem":
			if string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				s.Welcome(ch.Stderr(), pubHash, stats)

				handler := &fsHandler{
					srv:        s,
					pubHash:    pubHash,
					stderr:     ch.Stderr(),
					logger:     *logger,
					remoteAddr: sConn.RemoteAddr(),
					sessionID:  sessionID,
					isBanned:   isBanned,
				}
				handler.logLogin(stats)
				server := sftp.NewRequestServer(ch, sftp.Handlers{
					FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler,
				})
				server.Serve()
				return
			}
			logger.Debug("rejected subsystem", "subsystem", req.Payload[4:])
			req.Reply(false, nil)

		case "env":
			// Accept environment variables but ignore them
			var kv struct{ Name, Value string }
			if err := ssh.Unmarshal(req.Payload, &kv); err == nil {
				logger.Debug("env request", kv.Name, kv.Value)
			}
			req.Reply(true, nil)

		case "shell":
			s.logShell(pubHash, sessionID, sConn.RemoteAddr())

			// Accept the shell request, tell the user it's SFTP-only, then exit
			req.Reply(true, nil)
			fmt.Fprintln(ch, "This server is SFTP-only. Shell access is not permitted.\r")
			return

		case "pty-req":
			// Some clients request a terminal before a shell
			var pty struct {
				Term          string
				Columns, Rows uint32
				Width, Height uint32
				Modes         string
			}
			ssh.Unmarshal(req.Payload, &pty)
			logger.Debug("pty-req", "term", pty.Term, "cols", pty.Columns, "rows", pty.Rows)

			req.Reply(true, nil)

		case "exec":
			s.logExec(pubHash, sessionID, sConn.RemoteAddr(), req.Payload)

			req.Reply(false, nil)

		default:
			// Reject everything else (exec, x11, etc)
			req.Reply(false, nil)

		}

	}
}

func userGroup(pubHash, sessionID string, remoteAddr net.Addr) slog.Attr {
	return slog.Group("user",
		"id", shortID(pubHash),
		"uid", hashToUid(pubHash),
		"session", sessionID[:16],
		"remote_address", remoteAddr,
	)
}

func (s *Server) logExec(pubHash, sessionID string, remoteAddr net.Addr, payload []byte) {
	var cmd struct{ Value string }
	ssh.Unmarshal(payload, &cmd)
	s.logger.Warn("exec", "cmd", cmd.Value, userGroup(pubHash, sessionID, remoteAddr))
	s.store.LogEvent(EventExec, pubHash, sessionID, remoteAddr)
}

func (s *Server) logShell(pubHash, sessionID string, remoteAddr net.Addr) {
	s.logger.Info("shell", userGroup(pubHash, sessionID, remoteAddr))
	s.store.LogEvent(EventShell, pubHash, sessionID, remoteAddr)
}

func (s *Server) getRandomFortune() string {
	return s.fortuneGenerator.Random()
}

const firstTimeBanner = `
╻ ╻┏━╸╻  ┏━╸┏━┓┏┳┓┏━╸
┃╻┃┣╸ ┃  ┃  ┃ ┃┃┃┃┣╸
┗┻┛┗━╸┗━╸┗━╸┗━┛╹ ╹┗━╸`

const firstTimeMessage = `%s
* You are %s
* This is your first time visiting.
* This is a share-first archive. Upload at least %s to unlock all downloads.
`

const contributorBanner = `
╻ ╻┏━╸╻  ┏━╸┏━┓┏┳┓┏━╸     ┏━╸┏━┓┏┓╻╺┳╸┏━┓╻┏┓ ╻ ╻╺┳╸┏━┓┏━┓
┃╻┃┣╸ ┃  ┃  ┃ ┃┃┃┃┣╸      ┃  ┃ ┃┃┗┫ ┃ ┣┳┛┃┣┻┓┃ ┃ ┃ ┃ ┃┣┳┛
┗┻┛┗━╸┗━╸┗━╸┗━┛╹ ╹┗━╸ ┛   ┗━╸┗━┛╹ ╹ ╹ ╹┗╸╹┗━┛┗━┛ ╹ ┗━┛╹┗╸`

const contributorMessage = `%s
%s
* Welcome back, %s
`

func (s *Server) Welcome(wUnbuf io.Writer, hash string, stats userStats) {
	w := bufio.NewWriter(wUnbuf)
	uid := hashToUid(hash)
	userLabel := fmt.Sprintf("anonymous-%d", uid)
	isContributor, needed := stats.IsContributor(s.cfg.ContributorThreshold)
	color := blue

	welcomeMsg := ""
	if stats.FirstTimer {
		color = magenta
		welcomeMsg = fmt.Sprintf(firstTimeMessage, color.Bold(firstTimeBanner), color.Fmt(userLabel), yellow.Bold(formatBytes(s.cfg.ContributorThreshold)))
	} else if isContributor {
		color = yellow
		welcomeMsg = fmt.Sprintf(contributorMessage, color.Bold(contributorBanner), color.Italic(s.getRandomFortune()), color.Fmt(userLabel))
	} else {
		welcomeMsg = fmt.Sprintf("\r\nWelcome, %s\r\n", color.Bold(userLabel))
	}

	fmt.Fprintf(w, welcomeMsg)
	fmt.Fprintf(w, "* Files and directories you create will have %s\r\n", color.Bold(fmt.Sprintf("UID=%d", uid)))

	if maxSize := s.cfg.MaxFileSize; maxSize > 0 {
		fmt.Fprintf(w, "* The maximum permitted file size is %s\r\n", bold.Fmt(formatBytes(maxSize)))
	}

	fmt.Fprintln(w, "* You may always modify or delete files or directories you have created.")

	files, err := s.store.FilesByOwner(hash)
	if err == nil && len(files) > 0 {
		var buffer bytes.Buffer
		const maxToDisplay = 50
		ownedDirs, shownCount := printGrid(&buffer, files, maxToDisplay)

		fmt.Fprintf(w, "* You have created %d files, %d directories:\r\n", len(files)-ownedDirs, ownedDirs)
		fmt.Fprintln(w, buffer.String())
		if len(files) > shownCount {
			fmt.Fprintf(w, "  ... and %d more items.\r\n", len(files)-shownCount)
		}
	}

	if isContributor {
		fmt.Fprintln(w, color.Bold("* Thank you for contributing."))
		fmt.Fprint(w, green.Bold("* Downloads are unrestricted.\r\n"))
	} else {
		fmt.Fprint(w, red.Bold("* Downloads are restricted.\r\n"))
		fmt.Fprintf(w, "Share %s more to unlock all downloads.\r\n", color.Bold(formatBytes(needed)))
		fmt.Fprintln(w, "You may always download from unrestricted files or directories:")
		for pathName := range s.cfg.unrestrictedMap {
			if _, err := os.Stat(filepath.Join(s.absUploadDir, pathName)); err != nil {
				continue
			}

			if strings.HasSuffix(pathName, "/") {
				fmt.Fprintln(w, "  "+cyan.Bold(pathName))
			} else {
				fmt.Fprintln(w, "  "+bold.Fmt(pathName))
			}
		}
	}

	fmt.Fprintf(w, "\r\nID: %s | Last: %s | Shared: %d files, %s",
		userLabel, stats.LastLogin, stats.UploadCount, formatBytes(stats.UploadBytes))
	if stats.DownloadCount > 0 {
		fmt.Fprintf(w, " | Downloaded: %d files, %s", stats.DownloadCount, formatBytes(stats.DownloadBytes))
	}
	fmt.Fprintf(w, "\r\n")
	w.Flush()
}

func printGrid(w io.Writer, files []string, limit int) (dirs int, shown int) {
	sort.Strings(files)
	maxLen := 0
	var filtered []string
	for _, f := range files {
		if len(f) > maxLen {
			maxLen = len(f)
		}
		if strings.HasSuffix(f, "/") {
			dirs++
		}
		if !strings.Contains(f, ".git/") || strings.HasSuffix(f, ".git/") {
			filtered = append(filtered, f)
		}
	}

	toShow := filtered
	if limit > 0 && len(filtered) > limit {
		toShow = filtered[:limit]
	}
	shown = len(toShow)

	cellWidth := maxLen + 2
	if cellWidth < 20 {
		cellWidth = 20
	}

	cols := 90 / cellWidth
	if cols < 1 {
		cols = 1
	}
	rows := (len(toShow) + cols - 1) / cols

	for r := 0; r < rows; r++ {
		fmt.Fprint(w, "  ")
		for c := 0; c < cols; c++ {
			idx := c*rows + r
			if idx < len(toShow) {
				f := toShow[idx]
				style := lightGray
				if strings.HasSuffix(f, "/") {
					style = blue
				}
				fmt.Fprint(w, style.Bold(fmt.Sprintf("%-*s", cellWidth, f)))
			}
		}
		fmt.Fprint(w, "\r\n")
	}
	return dirs, shown
}

func (s *Server) ensureHostKey() error {
	if _, err := os.Stat(s.cfg.HostKeyFile); err == nil {
		return nil
	}
	_, priv, _ := ed25519.GenerateKey(cryptorand.Reader)

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	keyFile, err := os.OpenFile(s.cfg.HostKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permHostKey)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, pemBlock); err != nil {
		keyFile.Close()
		return err
	}
	keyFile.Close()

	sshPub, _ := ssh.NewPublicKey(priv.Public())
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	return os.WriteFile(s.cfg.HostKeyFile+".pub", pubBytes, permFile)
}

func (s *Server) reconcileOrphans() {
	var sysFiles []string
	for p := range s.cfg.unrestrictedMap {
		if strings.HasSuffix(p, "/") {
			cleanPath := path.Clean(strings.TrimSuffix(p, "/"))
			full := filepath.Join(s.absUploadDir, filepath.FromSlash(cleanPath))

			os.MkdirAll(full, permDir)
			s.store.EnsureDirectory(systemOwner, cleanPath)
		} else {
			sysFiles = append(sysFiles, p)
		}
	}
	s.store.RegisterSystemFiles(s.absUploadDir, sysFiles)

	filepath.WalkDir(s.absUploadDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == s.absUploadDir {
			return nil
		}
		rel, _ := filepath.Rel(s.absUploadDir, p)
		rel = filepath.ToSlash(rel)
		if !s.store.FileExistsInDB(rel) {
			fi, _ := d.Info()
			s.store.RegisterFile(rel, systemOwner, fi.Size(), d.IsDir())
			s.logger.Info("reconciled orphan file", "path", rel)
		}
		return nil
	})
}

// ============================================================================
// SFTP Handlers
// ============================================================================

type fsHandler struct {
	srv         *Server
	pubHash     string
	stderr      io.Writer
	logger      slog.Logger
	remoteAddr  net.Addr
	sessionID   string
	readLimiter *rate.Limiter // nil if not banned
	isBanned    bool
}

type pathMeta struct {
	rel            string
	full           string
	owner          string
	exists         bool
	isDir          bool
	isUnrestricted bool
	fi             os.FileInfo
}

func (h *fsHandler) isShadowBanned() bool {
	return h.srv.store.IsBanned(h.pubHash)
}

// shadowDelay sleeps for a random duration (2–8s) then returns a generic error.
// Used to make shadow-banned users think operations are just slow/broken.
func (h *fsHandler) shadowDelay() error {
	delay := time.Duration(2000+rand.Intn(6000)) * time.Millisecond
	time.Sleep(delay)
	return sftp.ErrSSHFxFailure
}

func (h *fsHandler) examine(p string) (*pathMeta, error) {
	virt := path.Clean("/" + p)
	rel := strings.TrimPrefix(virt, "/")
	if rel == "" {
		rel = "."
	}

	full := filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, h.srv.absUploadDir) {
		return nil, h.deny(errMsgPathTraversal, p)
	}

	owner, _ := h.srv.store.GetFileOwner(rel)
	meta := &pathMeta{
		rel: rel, full: full, owner: owner,
		isUnrestricted: h.checkUnrestricted(rel),
	}

	if fi, err := os.Lstat(full); err == nil {
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return nil, h.deny(errMsgSymlinksProhibited, "path", rel)
		}
		meta.exists, meta.isDir, meta.fi = true, fi.IsDir(), fi
	}
	return meta, nil
}

func (h *fsHandler) checkUnrestricted(rel string) bool {
	if h.srv.cfg.unrestrictedMap[rel] || h.srv.cfg.unrestrictedMap[rel+"/"] {
		return true
	}
	// Walk up the directory tree
	for d := rel; d != "." && d != "/"; d = path.Dir(d) {
		if h.srv.cfg.unrestrictedMap[d+"/"] {
			return true
		}
	}
	return false
}

func (h *fsHandler) isExplicitUnrestrictedDir(rel string) bool {
	if !h.srv.cfg.unrestrictedMap[rel] {
		return false
	}
	meta, err := h.examine(rel)
	return err == nil && meta.exists && meta.isDir
}

func (h *fsHandler) prepareDirectory(rel string) error {
	if rel == "." || rel == "" {
		return nil
	}

	// 1. Ownership Check (Can I create things inside the parent?)
	if h.srv.cfg.LockDirectoriesToOwners {
		parentRel := path.Dir(rel)
		if parentRel != "." {
			owner, _ := h.srv.store.GetFileOwner(parentRel)
			// Deny if the parent folder belongs to another specific user
			if owner != "" && owner != systemOwner && owner != h.pubHash {
				return h.deny(errMsgCannotWriteToDir, "path", rel, "parent", parentRel)
			}
		}
	}
	if !h.srv.store.FileExistsInDB(rel) {
		if !h.srv.mkdirLimiter.Allow() {
			return h.deny(errMsgMkdirRateLimit, "path", rel)
		}

		count, _ := h.srv.store.GetDirectoryCount()
		if count >= h.srv.cfg.MaxDirs {
			return h.deny(errMsgMaxDirsReached, "path", rel)
		}
	}

	full := filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(full, permDir); err != nil {
		h.logger.Error("mkdir error", "path", rel, "err", err)
		return err
	}

	return h.srv.store.EnsureDirectory(h.pubHash, rel)
}

func (h *fsHandler) deny(err UserPermissionError, args ...any) error {
	h.logger.Info("permission denied", append([]any{"reason", err.LogString()}, args...)...)

	h.srv.store.LogEvent(err.Kind, h.pubHash, h.sessionID, h.remoteAddr, args...)
	fmt.Fprintln(h.stderr, err.Error())
	return sftp.ErrSSHFxPermissionDenied
}

func (h *fsHandler) logLogin(stats userStats) {
	var loginType = "pubkey-hash"
	if strings.HasPrefix(h.pubHash, "anon-auth:") {
		loginType = "anon-auth"
	}
	if strings.HasPrefix(h.pubHash, "pwd-auth:") {
		loginType = "pwd-auth"
	}

	h.srv.store.LogEvent(EventLogin, h.pubHash, h.sessionID, h.remoteAddr,
		"first_timer", stats.FirstTimer,
		"upload_bytes", stats.UploadBytes,
		"login_type", loginType,
	)
}

func (h *fsHandler) logDownload(meta *pathMeta) {
	h.logger.Info("download", "path", meta.rel, "size", meta.fi.Size())
	h.srv.store.LogEvent(EventDownload, h.pubHash, h.sessionID, h.remoteAddr,
		"path", meta.rel,
		"size", meta.fi.Size(),
	)
}

func (h *fsHandler) logUpload(rel string, size, delta int64) {
	h.logger.Info("upload", "path", rel, "size", size, "delta", delta)
	h.srv.store.LogEvent(EventUpload, h.pubHash, h.sessionID, h.remoteAddr,
		"path", rel,
		"size", size,
		"delta", delta,
	)
}

func (h *fsHandler) logDelete(meta *pathMeta) {
	h.logger.Info("delete", "path", meta.rel, "is_dir", meta.isDir)
	h.srv.store.LogEvent(EventDelete, h.pubHash, h.sessionID, h.remoteAddr,
		"path", meta.rel,
		"is_dir", meta.isDir,
	)
}

func (h *fsHandler) logRename(src, dst *pathMeta) {
	h.logger.Info("rename", "from", src.rel, "to", dst.rel)
	h.srv.store.LogEvent(EventRename, h.pubHash, h.sessionID, h.remoteAddr,
		"path", src.rel,
		"target", dst.rel,
	)
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	defer h.Trace("fileread", "method", r.Method, "path", r.Filepath)()

	meta, err := h.examine(r.Filepath)
	if err != nil {
		return nil, err
	}

	if err := h.canRead(meta); err != nil {
		return nil, err
	}

	fi, err := os.Stat(meta.full)
	if err != nil {
		return nil, os.ErrNotExist
	}
	if fi.IsDir() {
		return nil, sftp.ErrSSHFxNoSuchFile
	}

	h.logDownload(meta)
	h.srv.store.RecordDownload(h.pubHash, meta.fi.Size())
	f, err := os.Open(meta.full)
	if err != nil {
		return nil, err
	}

	// SHADOW BAN: throttle reads
	if h.isBanned && h.readLimiter != nil {
		return &throttledReaderAt{r: f, lim: h.readLimiter}, nil
	}
	return f, nil
}

func (h *fsHandler) canRead(meta *pathMeta) error {
	if meta.isUnrestricted {
		return nil
	}

	status, err := h.srv.UserStatus(h.pubHash)
	if err != nil {
		return err
	}

	if !status.IsContributor {
		return h.deny(errMsgContributorsLocked.Args(meta.rel, formatBytes(h.srv.cfg.ContributorThreshold), status.BytesNeeded),
			"path", meta.rel, "uploaded", status.Stats.UploadBytes)
	}

	return nil
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	defer h.Trace("Filewrite", "method", r.Method, "path", r.Filepath)()

	meta, err := h.examine(r.Filepath)
	if err != nil {
		return nil, h.deny(errMsgPathTraversal, "path", r.Filepath)
	}

	if h.isBanned {
		return nil, h.shadowDelay()
	}

	if err := h.canModify(meta); err != nil {
		return nil, err
	}

	if err := h.prepareDirectory(path.Dir(meta.rel)); err != nil {
		return nil, err
	}

	if err := h.srv.store.ClaimFile(h.pubHash, meta.rel); err != nil {
		return nil, h.deny(errMsgFilenameClaimed, "path", meta.rel)
	}

	flags := os.O_RDWR | os.O_CREATE
	if !r.Pflags().Append {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(meta.full, flags, permFile)
	if err != nil {
		return nil, err
	}

	oldSize := int64(0)
	if fi, err := f.Stat(); err == nil {
		oldSize = fi.Size()
	}

	return &statWriter{File: f, h: h, rel: meta.rel, oldSize: oldSize}, nil
}

func (h *fsHandler) canModify(meta *pathMeta) error {
	if !meta.exists || meta.owner == "" {
		return nil
	}

	if meta.owner == systemOwner {
		return h.deny(errMsgFileProtected.Args(meta.rel))
	}

	if meta.owner != h.pubHash {
		return h.deny(errMsgFilenameClaimed, "path", meta.rel)
	}

	return nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	defer h.Trace("Filelist", "method", r.Method, "path", r.Filepath)()

	if h.isBanned && r.Method == "List" {
		delay := time.Duration(500+rand.Intn(1500)) * time.Millisecond // 0.5–2s
		time.Sleep(delay)
	}

	meta, err := h.examine(r.Filepath)
	if err != nil {
		return nil, err
	}
	if !meta.exists {
		return nil, os.ErrNotExist
	}

	switch r.Method {
	case "List":
		if !meta.isDir {
			return nil, sftp.ErrSSHFxFailure
		}

		entries, err := os.ReadDir(meta.full)
		if err != nil {
			return nil, err
		}

		var files []os.FileInfo
		for _, e := range entries {
			fi, err := e.Info()
			if err != nil {
				continue
			}

			if !fi.Mode().IsRegular() && !fi.IsDir() {
				continue
			}

			relPath := path.Join(meta.rel, e.Name())
			files = append(files, h.newSftpFile(fi, relPath))
		}
		return listerAt(files), nil
	case "Stat", "Lstat", "Fstat":
		return listerAt{h.newSftpFile(meta.fi, meta.rel)}, nil
	}

	return listerAt{h.newSftpFile(meta.fi, meta.rel)}, nil
}

func (h *fsHandler) newSftpFile(fi os.FileInfo, relPath string) *sftpFile {
	owner, _ := h.srv.store.GetFileOwner(relPath)
	return &sftpFile{
		FileInfo:       fi,
		owner:          owner,
		isUnrestricted: h.checkUnrestricted(relPath),
	}
}

func (h *fsHandler) Trace(msg string, args ...any) func() {
	start := time.Now()
	return func() {
		durationArgs := make([]any, 0, 2+len(args))
		durationArgs = append(durationArgs, "duration", time.Since(start))
		durationArgs = append(durationArgs, args...)

		h.logger.Debug(msg, durationArgs...)
	}
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	defer h.Trace("Filecmd", "method", r.Method, "path", r.Filepath)()
	meta, err := h.examine(r.Filepath)
	if err != nil {
		return h.deny(errMsgPathTraversal, r.Filepath)
	}

	if h.isBanned {
		switch r.Method {
		case "Remove", "Rmdir", "Rename", "Mkdir", "Setstat":
			return h.shadowDelay()
		}
	}

	switch r.Method {
	case "Setstat":
		return nil
	case "Mkdir":
		return h.prepareDirectory(meta.rel)

	case "Remove", "Rmdir":
		if err := h.canModify(meta); err != nil {
			return err
		}
		if err := os.RemoveAll(meta.full); err != nil {
			h.logger.Error("could not remove path", "method", r.Method, "path", meta.full, "err", err)
			return err
		}
		h.logDelete(meta)
		return h.srv.store.DeletePath(meta.rel)

	case "Rename":
		targetMeta, err := h.examine(r.Target)
		if err != nil {
			return h.deny(errMsgPathTraversal, r.Target)
		}
		if err := h.canModify(meta); err != nil {
			return err
		}
		if err := h.canModify(targetMeta); err != nil {
			return err
		}

		if err := os.Rename(meta.full, targetMeta.full); err != nil {
			h.logger.Error("could not rename file", "from", meta.rel, "to", targetMeta.rel, "err", err)
			return h.deny(errMsgRenameFailed)
		}
		h.logRename(meta, targetMeta)
		return h.srv.store.RenamePath(meta.rel, targetMeta.rel)
	}
	return sftp.ErrSshFxOpUnsupported
}

// ============================================================================
// SHADOW BAN THROTTLING
// ============================================================================

const shadowBanBytesPerSec = 2 * 1024 // 2 KB/s

type throttledConn struct {
	net.Conn
	r *rate.Limiter
	w *rate.Limiter
}

func newThrottledConn(c net.Conn, bytesPerSec float64) *throttledConn {
	burst := int(bytesPerSec) // 1-second burst
	if burst < 1 {
		burst = 1
	}
	return &throttledConn{
		Conn: c,
		r:    rate.NewLimiter(rate.Limit(bytesPerSec), burst),
		w:    rate.NewLimiter(rate.Limit(bytesPerSec), burst),
	}
}

func throttle(ctx context.Context, lim *rate.Limiter, n int) {
	// consume tokens in 4 KB chunks to avoid asking for huge reservations
	const chunk = 4096
	for remaining := n; remaining > 0; {
		take := remaining
		if take > chunk {
			take = chunk
		}
		lim.WaitN(ctx, take) //nolint:errcheck — context is background, never cancelled here
		remaining -= take
	}
}

func (c *throttledConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		throttle(context.Background(), c.r, n)
	}
	return n, err
}

func (c *throttledConn) Write(b []byte) (int, error) {
	throttle(context.Background(), c.w, len(b))
	return c.Conn.Write(b)
}

type throttledReaderAt struct {
	r   io.ReaderAt
	lim *rate.Limiter
}

func (t *throttledReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := t.r.ReadAt(p, off)
	if n > 0 {
		// Wait for n tokens; if the limiter can't immediately satisfy the
		// request we block here, which back-pressures the SFTP layer.
		ctx := context.Background()
		// Consume in chunks so we don't ask for huge token bursts at once.
		for remaining := n; remaining > 0; {
			take := remaining
			if take > shadowBanBytesPerSec {
				take = shadowBanBytesPerSec
			}
			t.lim.WaitN(ctx, take) //nolint:errcheck
			remaining -= take
		}
	}
	return n, err
}

// ============================================================================
// Helpers & Types
// ============================================================================

type statWriter struct {
	*os.File
	h       *fsHandler
	rel     string
	oldSize int64
}

func (sw *statWriter) WriteAt(p []byte, off int64) (int, error) {
	if sw.h.srv.cfg.MaxFileSize > 0 && off+int64(len(p)) > sw.h.srv.cfg.MaxFileSize {
		return 0, sw.h.deny(errMsgFileSizeExceeded.Args(sw.h.srv.cfg.MaxFileSize),
			"path", sw.rel, "offset", off, "size", len(p))
	}
	return sw.File.WriteAt(p, off)
}

func (sw *statWriter) reportUserStatus(pubHash string) {
	userStats, err := sw.h.srv.store.GetUserStats(pubHash)
	if err != nil {
		return
	}
	isContributor, remaining := userStats.IsContributor(sw.h.srv.cfg.ContributorThreshold)
	if !isContributor {
		fmt.Fprintf(sw.h.stderr, "Upload %s more bytes to unlock downloads.\r\n", formatBytes(remaining))
	}
}

func (sw *statWriter) Close() error {
	fi, _ := sw.File.Stat()
	size := fi.Size()
	delta := size - sw.oldSize
	sw.h.srv.store.UpdateFileWrite(sw.h.pubHash, sw.rel, size, delta)
	sw.h.logUpload(sw.rel, size, delta)
	sw.reportUserStatus(sw.h.pubHash)
	return sw.File.Close()
}

type sftpFile struct {
	os.FileInfo
	owner          string
	isUnrestricted bool
}

func (s *sftpFile) Sys() interface{} {
	uid := hashToUid(s.owner)
	gid := uid

	if s.isUnrestricted {
		uid = unrestrictedUID
		gid = unrestrictedGID
	}
	return &sftp.FileStat{UID: uid, GID: gid}
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if off+int64(n) == int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// ============================================================================
// Terminal Colors
// ============================================================================

type asciiStyle string

const (
	asciiReset              = "\033[0m"
	bold         asciiStyle = "1"
	underline    asciiStyle = "4"
	red          asciiStyle = "31"
	green        asciiStyle = "32"
	yellow       asciiStyle = "33"
	blue         asciiStyle = "34"
	magenta      asciiStyle = "35"
	cyan         asciiStyle = "36"
	lightGray    asciiStyle = "37"
	darkGray     asciiStyle = "90"
	lightRed     asciiStyle = "91"
	lightGreen   asciiStyle = "92"
	lightYellow  asciiStyle = "93"
	lightBlue    asciiStyle = "94"
	lightMagenta asciiStyle = "95"
	lightCyan    asciiStyle = "96"
	white        asciiStyle = "97"
)

func (s asciiStyle) apply(str, mode string) string {
	return fmt.Sprintf("\033[%s;%sm%s%s", mode, s, str, asciiReset)
}
func (s asciiStyle) Fmt(str string) string       { return s.apply(str, "0") }
func (s asciiStyle) Bold(str string) string      { return s.apply(str, "1") }
func (s asciiStyle) Italic(str string) string    { return s.apply(str, "3") }
func (s asciiStyle) Underline(str string) string { return s.apply(str, "4") }

// ============================================================================
// Utilities
// ============================================================================

func hashToUid(hash string) uint32 {
	if hash == "" || hash == systemOwner {
		return defaultUID
	}
	h := fnv.New32a()
	h.Write([]byte(hash))
	return h.Sum32() & 0x7FFFFFFF
}

// turns 1024 into "1.00 KB", etc.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d bytes", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
func getEnv(key string) (string, bool) {
	if val, ok := os.LookupEnv(envPrefix + key); ok {
		return val, true
	}
	return os.LookupEnv(key)
}

func EnvFlag[T any](ptr *T, name string, env string, def T, usage string) {
	val, ok := getEnv(env)

	switch p := any(ptr).(type) {
	case *string:
		*p = any(def).(string)
		if ok {
			*p = val
		}
		flag.StringVar(p, name, *p, usage)
	case *int:
		*p = any(def).(int)
		if ok {
			*p, _ = strconv.Atoi(val)
		}
		flag.IntVar(p, name, *p, usage)
	case *bool:
		*p = any(def).(bool)
		if ok {
			*p, _ = strconv.ParseBool(val)
		}
		flag.BoolVar(p, name, *p, usage)
	case *float64:
		*p = any(def).(float64)
		if ok {
			*p, _ = strconv.ParseFloat(val, 64)
		}
		flag.Float64Var(p, name, *p, usage)
	}
}

func EnvSizeFlag(ptr *int64, name string, env string, def string, usage string) {
	val, ok := getEnv(env)
	if !ok {
		val = def
	}
	intVal, _ := parseSize(val)
	flag.Int64Var(ptr, name, intVal, usage)
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}

	var mult int64 = 1
	switch {
	case strings.HasSuffix(s, "gb") || strings.HasSuffix(s, "g"):
		mult = 1 << 30 // 1024^3
		s = strings.TrimSuffix(strings.TrimSuffix(s, "gb"), "g")
	case strings.HasSuffix(s, "mb") || strings.HasSuffix(s, "m"):
		mult = 1 << 20 // 1024^2
		s = strings.TrimSuffix(strings.TrimSuffix(s, "mb"), "m")
	case strings.HasSuffix(s, "kb") || strings.HasSuffix(s, "k"):
		mult = 1 << 10 // 1024^1
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kb"), "k")
	case strings.HasSuffix(s, "b"):
		s = strings.TrimSuffix(s, "b")
	}

	// TrimSpace again in case of "100 MB" format
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %w", err)
	}
	return v * mult, nil
}

func shortID(id string) string {
	if len(id) <= 20 {
		return id
	}
	return id[:20]
}

type MultiLogHandler struct {
	handlers []slog.Handler
}

func (m *MultiLogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m *MultiLogHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (m *MultiLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithAttrs(attrs)
	}
	return &MultiLogHandler{handlers: newHandlers}
}

func (m *MultiLogHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithGroup(name)
	}
	return &MultiLogHandler{handlers: newHandlers}
}

type PrettyHandler struct {
	h slog.Handler
	b *bytes.Buffer
	m *sync.Mutex
}

func (h *PrettyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.h.Enabled(ctx, level)
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &PrettyHandler{h: h.h.WithAttrs(attrs), b: h.b, m: h.m}
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	return &PrettyHandler{h: h.h.WithGroup(name), b: h.b, m: h.m}
}

const (
	// timeFormat = "[2006-01-02 15:04:05.000]"
	timeFormat = "[15:04:05.000]"
)

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
	level := r.Level.String() + ":"

	switch r.Level {
	case slog.LevelDebug:
		level = lightGray.Fmt(level)
	case slog.LevelInfo:
		level = cyan.Fmt(level)
	case slog.LevelWarn:
		level = lightYellow.Fmt(level)
	case slog.LevelError:
		level = lightRed.Fmt(level)
	}

	attrs, err := h.computeAttrs(ctx, r)
	if err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(attrs, "", "  ")
	if err != nil {
		return fmt.Errorf("error when marshaling attrs: %w", err)
	}

	fmt.Println(
		lightGray.Fmt(r.Time.Format(timeFormat)),
		level,
		white.Fmt(r.Message),
		darkGray.Fmt(string(bytes)),
	)

	return nil
}

func (h *PrettyHandler) computeAttrs(
	ctx context.Context,
	r slog.Record,
) (map[string]any, error) {
	h.m.Lock()
	defer func() {
		h.b.Reset()
		h.m.Unlock()
	}()
	if err := h.h.Handle(ctx, r); err != nil {
		return nil, fmt.Errorf("error when calling inner handler's Handle: %w", err)
	}

	var attrs map[string]any
	err := json.Unmarshal(h.b.Bytes(), &attrs)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshaling inner handler's Handle result: %w", err)
	}
	return attrs, nil
}

func suppressDefaults(
	next func([]string, slog.Attr) slog.Attr,
) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey ||
			a.Key == slog.LevelKey ||
			a.Key == slog.MessageKey {
			return slog.Attr{}
		}
		if next == nil {
			return a
		}
		return next(groups, a)
	}
}

func newConsoleHandler(opts *slog.HandlerOptions) *PrettyHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	b := &bytes.Buffer{}
	return &PrettyHandler{
		b: b,
		h: slog.NewJSONHandler(b, &slog.HandlerOptions{
			Level:       opts.Level,
			AddSource:   opts.AddSource,
			ReplaceAttr: suppressDefaults(opts.ReplaceAttr),
		}),
		m: &sync.Mutex{},
	}
}

func setupLogger(cfg Config) (*slog.Logger, *os.File, error) {
	lvl := slog.LevelInfo
	if cfg.Debug {
		lvl = slog.LevelDebug
	}

	var consoleHandler slog.Handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	if cfg.Verbose {
		consoleHandler = newConsoleHandler(&slog.HandlerOptions{Level: lvl})
	}

	f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, permLogFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open log file: %w", err)
	}
	fileHandler := slog.NewTextHandler(f, &slog.HandlerOptions{Level: lvl})
	// consoleHandler := newConsoleHandler(&slog.HandlerOptions{Level: lvl})
	// logger := slog.New(slog.NewTextHandler(mw, &slog.HandlerOptions{Level: lvl}))
	logger := slog.New(&MultiLogHandler{
		handlers: []slog.Handler{fileHandler, consoleHandler},
	})
	logger.Info("configuration",
		"name", cfg.Name,
		"version", AppVersion,
		"port", cfg.Port,
		"admin.ssh", cfg.AdminEnabled,
		"noauth", cfg.SshNoAuth,
		"key", cfg.HostKeyFile,
		"upload_path", cfg.UploadDir,
		"lock_dirs_to_owners", cfg.LockDirectoriesToOwners,
		"max_dirs", cfg.MaxDirs,
		"max_file_size", cfg.MaxFileSize,
		"contributor_threshold", cfg.ContributorThreshold,
		"unrestricted", cfg.Unrestricted,
	)

	return logger, f, nil
}

func runVersionGenerator() {
	// const versionFile = "VERSION"
	h := sha256.New()

	err := fs.WalkDir(embeddedSource, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path == versionFile {
			return nil
		}

		f, err := embeddedSource.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking embed: %v\n", err)
		os.Exit(1)
	}

	newHash := fmt.Sprintf("%x", h.Sum(nil))

	// read existing VERSION from disk (not from embed, so we get the text)
	content, _ := os.ReadFile(versionFile)
	currentFull := strings.TrimSpace(string(content))
	parts := strings.Split(currentFull, "-")

	currentVer := parts[0]
	oldHash := ""
	if len(parts) > 1 {
		oldHash = parts[1]
	}

	if newHash == oldHash {
		fmt.Println("No changes. VERSION is current.")
		return
	}

	newVer, err := incrementPatch(currentVer)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	newContent := fmt.Sprintf("%s-%s", newVer, newHash)
	if err := os.WriteFile(versionFile, []byte(newContent), 0644); err != nil {
		fmt.Printf("Failed to write: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated %s: %s -> %s\n", versionFile, currentFull, newContent)
}

func incrementPatch(v string) (string, error) {
	re := regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)
	m := re.FindStringSubmatch(v)
	if len(m) != 4 {
		// Fallback for empty or malformed file
		return "v0.0.1", nil
	}
	patch, _ := strconv.Atoi(m[3])
	return fmt.Sprintf("v%s.%s.%d", m[1], m[2], patch+1), nil
}

func appShort() string {
	return strings.Split(AppVersion, "-")[0]
}

const startupBanner = `
┏━┓┏━╸╺┳╸┏━┓┏━╸╻ ╻╻ ╻
┗━┓┣╸  ┃ ┣━┛┃╺┓┃ ┃┗┳┛
┗━┛╹   ╹ ╹  ┗━┛┗━┛ ╹  %s`

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, yellow.Bold(fmt.Sprintf(startupBanner, appShort())))

	start := time.Now()

	logger, logFile, err := setupLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logger setup error: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		logger.Info("execution complete", "uptime", time.Since(start))
		logFile.Close()
	}()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		logger.Error("failed to start server", "err", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go srv.reconcileOrphans()
	go srv.Listen()

	sig := <-sigChan
	logger.Info("Shutdown signal received", "signal", sig.String())

	go func() {
		<-sigChan
		logger.Error("Forced exit: Terminating immediately")
		os.Exit(1)
	}()

	fmt.Fprintln(os.Stderr, yellow.Bold("==========  HALT   =========="))
	fmt.Fprintln(os.Stderr, yellow.Fmt("Graceful shutdown started. (Press Ctrl-C again to force)"))
	srv.Shutdown()

	fmt.Fprintln(os.Stderr, magenta.Bold("==========  DONE   =========="))
}
