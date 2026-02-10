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
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"embed"
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

//go:embed sftpguy.go fortunes.txt
var embeddedSource embed.FS

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
	AppVersion = "1.8.5"
	envPrefix  = "SFTP_"

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
	);`
)

// ============================================================================
// User Permission Errors
// ============================================================================

var errorPrefix = struct {
	EN string
	ZH string
}{
	EN: red.Fmt("DENIED:      "),
	ZH: red.Fmt("访问被拒绝:  "),
}

type UserPermissionError struct {
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

var (
	errMsgSymlinksProhibited = UserPermissionError{EN: "Symlinks are prohibited.", ZH: "禁止使用符号链接。"}
	errMsgContributorsLocked = UserPermissionError{
		EN: "%s is only available to contributors who have uploaded at least %s: upload %d more bytes.",
		ZH: "文件 %s 仅对已上传至少 %s 字节的贡献者可用：再上传 %d 字节。"}
	errMsgFileProtected    = UserPermissionError{EN: "%s is a protected system file.", ZH: "%s 是受保护的系统文件。"}
	errMsgCannotWriteToDir = UserPermissionError{EN: "Cannot write to another user's directory.", ZH: "无法写入其他用户的目录。"}
	errMsgFilenameClaimed  = UserPermissionError{EN: "This filename is already claimed.", ZH: "此文件名已被占用。"}
	errMsgNoPermissionDel  = UserPermissionError{
		EN: "You do not have permission to delete this. (%s UID [owner] %d != [you] %d)",
		ZH: "您没有删除此项的权限。(%s UID [所有者] %d != [你] %d)"}
	errMsgNotOwner = UserPermissionError{
		EN: "You do not own the source file or directory. (UID [owner] %d != [you] %d)",
		ZH: "您不是源文件或目录的所有者。(UID [所有者] %d != [你] %d)"}
	errMsgRenameFailed     = UserPermissionError{EN: "Rename failed.", ZH: "重命名失败。"}
	errMsgMkdirRateLimit   = UserPermissionError{EN: "Mkdir rate limit reached.", ZH: "已达到创建目录的频率限制。"}
	errMsgMaxDirsReached   = UserPermissionError{EN: "Maximum directory limit reached for this archive.", ZH: "已达到此归档的最大目录限制。"}
	errMsgFileSizeExceeded = UserPermissionError{EN: "File size limit exceeded. Maximum allowed: %d bytes", ZH: "超过文件大小限制。最大允许：%d 字节"}
	errMsgPathTraversal    = UserPermissionError{EN: "Path traversal detected.", ZH: "检测到路径遍历。"}
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
	db.Exec("PRAGMA journal_mode=WAL;")
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
	s.db.QueryRow(`
		SELECT 
			COUNT(*) FILTER (WHERE upload_count > 0),
			COUNT(*) FILTER (WHERE upload_bytes > ?)
		FROM users
	`, threshold).Scan(&u, &c)
	s.db.QueryRow("SELECT count(*), sum(size) FROM files WHERE is_dir = 0").Scan(&f, &b)
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

	return paths, nil
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
	MaxFileSize             int64
	ContributorThreshold    int64
	unrestrictedMap         map[string]bool
	BootstrapSrc            bool
}

func LoadConfig() (Config, error) {
	cfg := Config{}

	EnvFlag(&cfg.Name, "name", "ARCHIVE_NAME", "sftpguy", "Archive name")
	EnvFlag(&cfg.Port, "port", "PORT", 2222, "SSH port")
	EnvFlag(&cfg.HostKeyFile, "hostkey", "HOST_KEY", "id_ed25519", "SSH host key")
	EnvFlag(&cfg.DBPath, "db.path", "DB_PATH", "sftp.db", "SQLite path")
	EnvFlag(&cfg.LogFile, "logfile", "LOG_FILE", "sftp.log", "Log file path")
	EnvFlag(&cfg.UploadDir, "dir", "UPLOAD_DIR", "./uploads", "Upload directory")
	EnvFlag(&cfg.BannerFile, "banner", "BANNER_FILE", "BANNER.txt", "Banner file")
	EnvFlag(&cfg.BannerStats, "banner.stats", "BANNER_STATS", false, "Show file statistics in the banner")
	EnvFlag(&cfg.MkdirRate, "dir.rate", "MKDIR_RATE", 10.0, "Global mkdir rate limit (dirs/sec)")
	EnvFlag(&cfg.MaxDirs, "dir.max", "MAX_DIRECTORIES", 1000, "Maximum total directories allowed in archive")
	EnvFlag(&cfg.Unrestricted, "unrestricted", "UNRESTRICTED_PATHS", strings.Join(defaultUnrestrictedPaths, ","), "Comma-separated list of paths always available for download")
	EnvFlag(&cfg.LockDirectoriesToOwners, "dir.owners_only", "LOCK_DIRS_TO_OWNERS", false, "Users can only upload to directories they own")
	EnvFlag(&cfg.Verbose, "verbose", "VERBOSE", false, "Enable debug logging")

	EnvSizeFlag(&cfg.MaxFileSize, "maxsize", "MAX_FILE_SIZE", "8gb", "Max file size (e.g. 500mb, 2gb, 0=unlimited)")
	EnvSizeFlag(&cfg.ContributorThreshold, "contrib", "CONTRIBUTOR_THRESHOLD", "1mb", "Bytes a user must upload to unlock downloads")

	flag.BoolVar(&cfg.BootstrapSrc, "src", false, "Copy source code and fortunes to upload directory on boot")
	v := flag.Bool("version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *v {
		fmt.Printf("%s v%s\n", cfg.Name, AppVersion)
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

	var sysFiles []string
	for f := range cfg.unrestrictedMap {
		sysFiles = append(sysFiles, f)
	}
	store.RegisterSystemFiles(absDir, sysFiles)

	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		store:            store,
		logger:           logger,
		mkdirLimiter:     rate.NewLimiter(rate.Limit(cfg.MkdirRate), 1),
		fortuneGenerator: &FortuneGenerator{},
		cfg:              cfg,
		absUploadDir:     absDir,
		shutdown:         make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	if cfg.BootstrapSrc {
		if err := srv.bootstrapSource(); err != nil {
			logger.Error("failed to bootstrap source", "err", err)
		}
	}

	return srv, nil
}

func (s *Server) bootstrapSource() error {
	s.logger.Info("bootstrapping source files to upload directory")
	// Copy sftpguy.go
	srcData, err := embeddedSource.ReadFile(sourceFile)
	if err != nil {
		return err
	}
	destPath := filepath.Join(s.absUploadDir, s.sourceFileName())
	if err := os.WriteFile(destPath, srcData, permFile); err != nil {
		return err
	}

	s.store.RegisterFile(s.sourceFileName(), systemOwner, int64(len(srcData)), false)
	s.cfg.unrestrictedMap[s.sourceFileName()] = true

	// Copy fortunes.txt
	fData, err := embeddedSource.ReadFile("fortunes.txt")
	if err != nil {
		return err
	}
	fPath := filepath.Join(s.absUploadDir, "fortunes.txt")
	if err := os.WriteFile(fPath, fData, permFile); err != nil {
		return err
	}
	s.store.RegisterFile("fortunes.txt", systemOwner, int64(len(fData)), false)
	return nil
}

func (s *Server) sourceFileName() string {
	return fmt.Sprintf("%s-v%s.go", s.cfg.Name, AppVersion)
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
		BannerCallback:    s.bannerCallback,
		PublicKeyCallback: s.publicKeyCallback,
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
	return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
}

func (s *Server) bannerCallback(conn ssh.ConnMetadata) string {
	banner := ""
	if data, err := os.ReadFile(s.cfg.BannerFile); err == nil {
		banner = string(data)
	} else {
		banner = fmt.Sprintf("=== %s v%s ===", s.cfg.Name, AppVersion)
	}

	if s.cfg.BannerStats {
		u, c, f, b := s.store.GetBannerStats(s.cfg.ContributorThreshold)
		banner += fmt.Sprintf("\r\nUsers: %d | Contributors: %d | Files: %d | Size: %s\r\n", u, c, f, formatBytes(int64(b)))
	}
	return banner
}

func (s *Server) handleSSH(nConn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	stats, _ := s.store.UpsertUserSession(pubHash)
	sessionID := fmt.Sprintf("%x", sConn.SessionID())

	logger := s.logger.With(slog.Group("user",
		"id", shortID(pubHash),
		"uid", hashToUid(pubHash),
		"session", sessionID[:16],
		"remote_address", sConn.RemoteAddr(),
	))

	logger.Info("login")
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go s.handleChannel(ch, reqs, pubHash, sessionID, stats, sConn, logger)
	}
}

func (s *Server) handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, pubHash, sessionID string, stats userStats, sConn *ssh.ServerConn, logger *slog.Logger) {
	defer ch.Close()
	for req := range reqs {
		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			req.Reply(true, nil)
			s.Welcome(ch.Stderr(), pubHash, stats)

			handler := &fsHandler{
				srv:     s,
				pubHash: pubHash,
				stderr:  ch.Stderr(),
				logger:  *logger,
			}
			server := sftp.NewRequestServer(ch, sftp.Handlers{
				FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler,
			})
			server.Serve()
			return
		}
	}
}

func (s *Server) getRandomFortune() string {
	return s.fortuneGenerator.Random()
}

const firstTimeBanner = `
╻ ╻┏━╸╻  ┏━╸┏━┓┏┳┓┏━╸
┃╻┃┣╸ ┃  ┃  ┃ ┃┃┃┃┣╸
┗┻┛┗━╸┗━╸┗━╸┗━┛╹ ╹┗━╸`

func (s *Server) Welcome(w io.Writer, hash string, stats userStats) {
	uid := hashToUid(hash)
	userLabel := fmt.Sprintf("anonymous-%d", uid)
	isContributor, needed := stats.IsContributor(s.cfg.ContributorThreshold)
	color := blue
	if stats.FirstTimer {
		color = magenta
	} else if isContributor {
		color = yellow
	}

	if stats.FirstTimer {
		fmt.Fprintln(w, color.Bold(firstTimeBanner))
		fmt.Fprintln(w, "This is your first time visiting.")
		fmt.Fprintf(w, "This is a share-first archive. Upload at least %s to unlock all downloads.\r\n", yellow.Bold(formatBytes(s.cfg.ContributorThreshold)))
	} else {
		fmt.Fprintf(w, "\r\nWelcome, %s\r\n", color.Bold(userLabel))
	}

	fmt.Fprintf(w, "* You have been identified by your public key as %s.\r\n", color.Bold(userLabel))
	fmt.Fprintf(w, "* Files and directories you create will have %s\r\n", color.Bold(fmt.Sprintf("UID=%d", uid)))
	fmt.Fprintln(w, "* You may always modify or delete files or directories you have created.")

	files, err := s.store.FilesByOwner(hash)
	if err == nil && len(files) > 0 {
		fmt.Fprintln(w, "Your files:")
		numDirs := 0
		for _, f := range files {
			if strings.HasSuffix(f, "/") {
				numDirs += 1
				fmt.Fprintln(w, "  "+bold.Fmt(f))
			} else {
				fmt.Fprintf(w, "  %-20s\r\n", f)
			}
		}
		fmt.Fprintf(w, "%d files, %d directories\n", len(files)-numDirs, numDirs)
	}

	if isContributor {
		fmt.Fprintln(w, color.Bold("* Thank you for contributing."))
		fmt.Fprintln(w, color.Italic(s.getRandomFortune()))
		fmt.Fprint(w, green.Bold("* Downloads are unrestricted.\r\n"))
	} else {
		fmt.Fprint(w, red.Bold("* Downloads are restricted.\r\n"))
		fmt.Fprintf(w, "Share %s more to unlock all downloads.\r\n", color.Bold(formatBytes(needed)))
		fmt.Fprintln(w, "You may always download from unrestricted files or directories:")
		for pathName := range s.cfg.unrestrictedMap {
			fmt.Fprintln(w, "  "+bold.Fmt(pathName))
		}
	}

	fmt.Fprintf(w, "\r\nID: %s | Last: %s | Shared: %d files, %s",
		userLabel, stats.LastLogin, stats.UploadCount, formatBytes(stats.UploadBytes))
	if stats.DownloadCount > 0 {
		fmt.Fprintf(w, " | Downloaded: %d files, %s", stats.DownloadCount, formatBytes(stats.DownloadBytes))
	}
	fmt.Fprintf(w, "\r\n")
}

func (s *Server) ensureHostKey() error {
	if _, err := os.Stat(s.cfg.HostKeyFile); err == nil {
		return nil
	}
	_, priv, _ := ed25519.GenerateKey(cryptorand.Reader)
	bytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
	keyFile, _ := os.OpenFile(s.cfg.HostKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyFile.Close()
	return pem.Encode(keyFile, pemBlock)
}

func (s *Server) reconcileOrphans() {
	for p := range s.cfg.unrestrictedMap {
		if strings.HasSuffix(p, "/") {
			cleanPath := path.Clean(strings.TrimSuffix(p, "/"))
			full := filepath.Join(s.absUploadDir, filepath.FromSlash(cleanPath))

			os.MkdirAll(full, permDir)
			s.store.EnsureDirectory(systemOwner, cleanPath)
		}
	}

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
	srv     *Server
	pubHash string
	stderr  io.Writer
	logger  slog.Logger
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
	logArgs := make([]any, 0, 2+len(args))
	logArgs = append(logArgs, "reason", err.LogString())
	logArgs = append(logArgs, args...)

	h.logger.Info("permission denied", logArgs...)
	fmt.Fprintln(h.stderr, err.Error())
	return sftp.ErrSSHFxPermissionDenied
}

// func (h *fsHandler) resolve(p string) (rel string, full string, err error) {
// 	virt := path.Clean("/" + p)
// 	rel = strings.TrimPrefix(virt, "/")
// 	if rel == "" {
// 		rel = "."
// 	}
// 	abs := filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))

// 	if !strings.HasPrefix(abs, h.srv.absUploadDir) {
// 		return "", "", h.deny(errMsgPathTraversal, p)
// 	}
// 	return rel, abs, nil
// }

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

	h.logger.Info("file download", "path", meta.rel, "size", fi.Size())
	h.srv.store.RecordDownload(h.pubHash, fi.Size())

	return os.Open(meta.full)
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

	meta, err := h.examine(r.Filepath)
	if err != nil {
		return nil, err
	}
	if !meta.exists {
		return nil, os.ErrNotExist
	}

	if r.Method == "List" {
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

	switch r.Method {
	case "Mkdir":
		return h.prepareDirectory(meta.rel)

	case "Remove", "Rmdir":
		if err := h.canModify(meta); err != nil {
			return err
		}
		os.RemoveAll(meta.full)
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
			h.logger.Error("rename rename error", "from", meta.rel, "to", targetMeta.rel, "err", err)
			return h.deny(errMsgRenameFailed)
		}
		return h.srv.store.RenamePath(meta.rel, targetMeta.rel)
	}
	return sftp.ErrSshFxOpUnsupported
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

func (sw *statWriter) Close() error {
	fi, _ := sw.File.Stat()
	size := fi.Size()
	delta := size - sw.oldSize
	sw.h.logger.Info("file write closed", "path", sw.rel, "final_size", size, "delta", delta)
	sw.h.srv.store.UpdateFileWrite(sw.h.pubHash, sw.rel, size, delta)
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
	asciiReset            = "\033[0m"
	bold       asciiStyle = "1"
	red        asciiStyle = "31"
	green      asciiStyle = "32"
	yellow     asciiStyle = "33"
	blue       asciiStyle = "34"
	magenta    asciiStyle = "35"
)

func (s asciiStyle) apply(str, mode string) string {
	return fmt.Sprintf("\033[%s;%sm%s%s", mode, s, str, asciiReset)
}
func (s asciiStyle) Fmt(str string) string    { return s.apply(str, "0") }
func (s asciiStyle) Bold(str string) string   { return s.apply(str, "1") }
func (s asciiStyle) Italic(str string) string { return s.apply(str, "3") }

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

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func setupLogger(cfg Config) (*slog.Logger, *os.File, error) {
	lvl := slog.LevelInfo
	if cfg.Verbose {
		lvl = slog.LevelDebug
	}

	f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, permLogFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open log file: %w", err)
	}

	mw := io.MultiWriter(os.Stdout, f)
	logger := slog.New(slog.NewTextHandler(mw, &slog.HandlerOptions{Level: lvl}))

	logger.Info("configuration",
		"name", cfg.Name,
		"version", AppVersion,
		"port", cfg.Port,
		"upload_path", cfg.UploadDir,
		"max_dirs", cfg.MaxDirs,
		"contributor_threshold", cfg.ContributorThreshold,
		"unrestricted", cfg.Unrestricted,
	)

	return logger, f, nil
}

const startupBanner = `
┏━┓┏━╸╺┳╸┏━┓┏━╸╻ ╻╻ ╻
┗━┓┣╸  ┃ ┣━┛┃╺┓┃ ┃┗┳┛
┗━┛╹   ╹ ╹  ┗━┛┗━┛ ╹   ` + "v" + AppVersion

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, yellow.Bold(startupBanner))

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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go srv.reconcileOrphans()
	go srv.Listen()

	<-sigChan
	logger.Info("Shutting down...")
	srv.Shutdown()
	fmt.Fprintln(os.Stderr, magenta.Bold("==========  DONE   =========="))
}
