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
}

// ============================================================================
// Constants
// ============================================================================

const (
	AppVersion = "1.8.2"
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
	Schema = `CREATE TABLE IF NOT EXISTS users ( 
		pubkey_hash TEXT PRIMARY KEY, 
		last_login DATETIME, 
		upload_count INTEGER DEFAULT 0, 
		upload_bytes INTEGER DEFAULT 0,
		download_count INTEGER DEFAULT 0,
		download_bytes INTEGER DEFAULT 0 
	);
	
	CREATE TABLE IF NOT EXISTS files ( 
		path TEXT PRIMARY KEY,
		owner_hash TEXT,
		size INTEGER DEFAULT 0,
		is_dir INTEGER DEFAULT 0
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

func (e UserPermissionError) LogString() string {
	if len(e.args) > 0 {
		return fmt.Sprintf(e.EN, e.args...)
	}
	return e.EN
}

func (e UserPermissionError) Args(args ...any) UserPermissionError {
	e.args = args
	return e
}

func (e UserPermissionError) Error() string {
	en := e.EN
	zh := e.ZH

	if len(e.args) > 0 {
		en = fmt.Sprintf(e.EN, e.args...)
		zh = fmt.Sprintf(e.ZH, e.args...)
	}

	return fmt.Sprintf("%s%s\n%s%s",
		errorPrefix.EN, en,
		errorPrefix.ZH, zh)
}

var (
	errMsgSymlinksProhibited = UserPermissionError{EN: "Symlinks are prohibited.", ZH: "禁止使用符号链接。"}
	// errMsgAccessLocked       = UserPermissionError{EN: "Archive access locked. You must share files to reach contributor status.", ZH: "归档访问已锁定。您必须通过分享文件来获得贡献者身份。"}
	errMsgContributorsLocked = UserPermissionError{
		EN: "%s is only available to contributors who have uploaded at least %d bytes: upload %d more bytes.",
		ZH: "文件 %s 仅对已上传至少 %d 字节的贡献者可用：再上传 %d 字节。"}
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
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA journal_mode=WAL;")
	if _, err := db.Exec(Schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) transact(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
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
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(`
		INSERT INTO users (pubkey_hash, last_login) VALUES (?, ?)
		ON CONFLICT(pubkey_hash) DO UPDATE SET last_login = excluded.last_login
	`, hash, now)
	if err != nil {
		return userStats{}, err
	}
	return s.GetUserStats(hash)
}

func (s *Store) GetFileOwner(relPath string) (string, error) {
	var owner string
	err := s.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return owner, err
}

func (s *Store) RegisterSystemFiles(filenames []string) error {
	for _, f := range filenames {
		if _, err := s.db.Exec("INSERT OR REPLACE INTO files(path, owner_hash, is_dir) VALUES (?, ?, 0)", f, systemOwner); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ClaimFile(hash, relPath string) error {
	return s.transact(func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)

		if err == sql.ErrNoRows {
			if _, err := tx.Exec("INSERT INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, 0, 0)", relPath, hash); err != nil {
				return err
			}
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
	_, err := s.db.Exec("UPDATE users SET download_count = download_count + 1, download_bytes = download_bytes + ? WHERE pubkey_hash = ?", bytes, hash)
	return err
}

func (s *Store) RenamePath(oldRel, newRel string) error {
	prefixLen := len(oldRel) + 1 // "oldRel" + "/"

	_, err := s.db.Exec(`
		UPDATE files 
		SET path = ? || substr(path, ?)
		WHERE path = ? OR substr(path, 1, ?) = ?`,
		newRel, prefixLen+1,
		oldRel, prefixLen, oldRel+"/")
	return err
}

func (s *Store) DeletePath(relPath string) error {
	_, err := s.db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", relPath, relPath+"/%")
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

	var maxSizeRaw string
	EnvFlag(&maxSizeRaw, "maxsize", "MAX_FILE_SIZE", "8gb", "Max file size (e.g. 500mb, 2gb, 0=unlimited)")

	var contributorThresholdRaw string
	EnvFlag(&contributorThresholdRaw, "contrib", "CONTRIBUTOR_THRESHOLD", "1mb", "Bytes a user must upload to unlock contributor status")

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

	maxSize, err := parseSize(maxSizeRaw)
	if err != nil {
		return cfg, fmt.Errorf("invalid maxsize: %w", err)
	}
	cfg.MaxFileSize = maxSize

	contrib, err := parseSize(contributorThresholdRaw)
	if err != nil {
		return cfg, fmt.Errorf("invalid contributor threshold: %w", err)
	}
	cfg.ContributorThreshold = contrib

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
	userStatus.Stats = stats
	userStatus.IsContributor = isContributor
	userStatus.BytesNeeded = remaining
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
	store, err := NewStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}

	var sysFiles []string
	for f := range cfg.unrestrictedMap {
		sysFiles = append(sysFiles, f)
	}
	if err := store.RegisterSystemFiles(sysFiles); err != nil {
		return nil, err
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
	s.store.db.Exec("INSERT OR REPLACE INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, ?, 0)", s.sourceFileName(), systemOwner, len(srcData))
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
	s.store.db.Exec("INSERT OR REPLACE INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, ?, 0)", "fortunes.txt", systemOwner, len(fData))

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
		banner += fmt.Sprintf("\r\nUsers: %d | Contributors: %d | Files: %d | Size: %d bytes\r\n", u, c, f, b)
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

	s.logger.Info("login", "user", shortID(pubHash), "addr", sConn.RemoteAddr())
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go s.handleChannel(ch, reqs, pubHash, sessionID, stats, sConn)
	}
}

func (s *Server) handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, pubHash, sessionID string, stats userStats, sConn *ssh.ServerConn) {
	defer ch.Close()
	for req := range reqs {
		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			req.Reply(true, nil)
			s.Welcome(ch.Stderr(), pubHash, stats)

			handler := &fsHandler{
				srv:       s,
				pubHash:   pubHash,
				stderr:    ch.Stderr(),
				sessionID: sessionID,
				logger: *s.logger.With(
					slog.Group("user",
						"id", shortID(pubHash),
						"uid", hashToUid(pubHash),
						"session", sessionID[:16],
						"remote_address", sConn.RemoteAddr(),
					),
				),
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

func (s *Server) Welcome(w io.Writer, hash string, stats userStats) {
	userLabel := fmt.Sprintf("anonymous-%d", hashToUid(hash))
	isContributor, needed := stats.IsContributor(s.cfg.ContributorThreshold)
	color := bold
	if stats.FirstTimer {
		color = blue
	} else if isContributor {
		color = yellow
	}
	fmt.Fprintf(w, "\r\nWelcome, %s\r\n", color.Fmt(userLabel))

	if stats.FirstTimer {
		fmt.Fprintln(w, "This is a share-first archive. Reach contributor status to unlock all downloads.")
		fmt.Fprintln(w, "Upload at least %d bytes to unlock contributor status.", s.cfg.ContributorThreshold)
		fmt.Fprintln(w, "You may always download unrestricted files:")
		for pathName := range s.cfg.unrestrictedMap {
			fmt.Fprintln(w, "  "+bold.Fmt(pathName))
		}
	}

	if isContributor {
		fmt.Fprintln(w, yellow.Bold("* Contributor status unlocked!"))
		fmt.Fprintln(w, yellow.Italic(s.getRandomFortune()))
	} else if stats.UploadCount > 0 {
		fmt.Fprintf(w, green.Fmt("Share %d more bytes to unlock downloads.\r\n"), needed)
	} else {
		fmt.Fprint(w, red.Bold("Downloads are restricted to system files.\r\n"))
	}
	fmt.Fprintf(w, "\r\nID: %s | Last: %s | Shared: %d files, %d bytes",
		userLabel, stats.LastLogin, stats.UploadCount, stats.UploadBytes)
	if stats.DownloadCount > 0 {
		fmt.Fprintf(w, " |  Downloaded: %d files, %d bytes", stats.DownloadCount, stats.DownloadBytes)
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
	filepath.WalkDir(s.absUploadDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == s.absUploadDir {
			return nil
		}
		rel, _ := filepath.Rel(s.absUploadDir, p)
		rel = filepath.ToSlash(rel)
		if !s.store.FileExistsInDB(rel) {
			fi, _ := d.Info()
			isDir := 0
			if d.IsDir() {
				isDir = 1
			}
			s.store.db.Exec("INSERT INTO files (path, owner_hash, size, is_dir) VALUES (?, ?, ?, ?)", rel, systemOwner, fi.Size(), isDir)
		}
		return nil
	})
}

// ============================================================================
// SFTP Handlers
// ============================================================================

type fsHandler struct {
	srv       *Server
	pubHash   string
	sessionID string
	stderr    io.Writer
	logger    slog.Logger
}

type pathMeta struct {
	rel            string
	full           string
	owner          string
	exists         bool
	isDir          bool
	isUnrestricted bool
}

func (h *fsHandler) examine(p string) (*pathMeta, error) {
	rel, full, err := h.resolve(p)
	if err != nil {
		return nil, err
	}

	meta := &pathMeta{
		rel:            rel,
		full:           full,
		isUnrestricted: h.srv.cfg.unrestrictedMap[rel],
	}

	// Single DB hit for ownership and existence
	err = h.srv.store.db.QueryRow("SELECT owner_hash, is_dir FROM files WHERE path = ?", rel).
		Scan(&meta.owner, &meta.isDir)

	if err == nil {
		meta.exists = true
	} else if err == sql.ErrNoRows {
		// Check filesystem if not in DB (orphans or new files)
		if fi, err := os.Stat(full); err == nil {
			meta.exists = true
			meta.isDir = fi.IsDir()
		}
	}
	return meta, nil
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

func (h *fsHandler) resolve(p string) (rel string, full string, err error) {
	virt := path.Clean("/" + p)
	rel = strings.TrimPrefix(virt, "/")
	if rel == "" {
		rel = "."
	}
	abs := filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))

	// Combine the check here
	if !strings.HasPrefix(abs, h.srv.absUploadDir) {
		return "", "", h.deny(errMsgPathTraversal, p)
	}
	return rel, abs, nil
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	h.logger.Debug("fileread", "method", r.Method, "path", r.Filepath)

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
		return h.deny(errMsgContributorsLocked.Args(meta.rel, h.srv.cfg.ContributorThreshold, status.BytesNeeded),
			"path", meta.rel, "uploaded", status.Stats.UploadBytes)
	}

	return nil
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	h.logger.Debug("Filewrite", "method", r.Method, "path", r.Filepath)

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
	if meta.isUnrestricted {
		return h.deny(errMsgFileProtected.Args(meta.rel))
	}

	// If the file/dir doesn't exist yet, there are no ownership
	// restrictions on the target itself (directory rules still apply later).
	if !meta.exists {
		return nil
	}

	// Orphaned files on disk (exists=true, owner="") are treated as system files.
	effectiveOwner := meta.owner
	if effectiveOwner == "" {
		effectiveOwner = systemOwner
	}

	if effectiveOwner != h.pubHash {
		if effectiveOwner == systemOwner {
			return h.deny(errMsgFileProtected.Args(meta.rel))
		}
		return h.deny(errMsgFilenameClaimed, "path", meta.rel)
	}

	return nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	h.logger.Debug("Filelist", "method", r.Method, "path", r.Filepath)
	rel, full, err := h.resolve(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxPermissionDenied
	}

	if r.Method == "List" {
		entries, _ := os.ReadDir(full)
		var files []os.FileInfo

		for _, e := range entries {
			fi, _ := e.Info()
			name := e.Name()
			files = append(files, h.newSftpFile(fi, path.Join(rel, name)))
		}

		return listerAt(files), nil
	}

	fi, err := os.Lstat(full)
	if err != nil {
		return nil, os.ErrNotExist
	}

	return listerAt{h.newSftpFile(fi, rel)}, nil
}

func (h *fsHandler) newSftpFile(fi os.FileInfo, relPath string) *sftpFile {
	owner, _ := h.srv.store.GetFileOwner(relPath)
	return &sftpFile{
		FileInfo:       fi,
		owner:          owner,
		isUnrestricted: h.srv.cfg.unrestrictedMap[relPath],
	}
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	h.logger.Debug("Filecmd", "method", r.Method, "path", r.Filepath)
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
		if targetMeta.isUnrestricted {
			return h.deny(errMsgFileProtected, targetMeta.rel)
		}

		if err := os.Rename(meta.full, targetMeta.full); err != nil {
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
)

func (s asciiStyle) Fmt(str string) string {
	return fmt.Sprintf("\033[%sm%s%s", s, str, asciiReset)
}

func (s asciiStyle) Bold(str string) string {
	return fmt.Sprintf("\033[1;%sm%s%s", s, str, asciiReset)
}

func (s asciiStyle) Italic(str string) string {
	return fmt.Sprintf("\033[3;%sm%s%s", s, str, asciiReset)
}

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

func EnvFlag[T any](ptr *T, name string, env string, def T, usage string) {
	val, ok := os.LookupEnv(envPrefix + env)
	if !ok {
		val, ok = os.LookupEnv(env)
	}

	switch p := any(ptr).(type) {
	case *string:
		if ok {
			*p = val
		} else {
			*p = any(def).(string)
		}
		flag.StringVar(p, name, *p, usage)
	case *int:
		if ok {
			iv, _ := strconv.Atoi(val)
			*p = iv
		} else {
			*p = any(def).(int)
		}
		flag.IntVar(p, name, *p, usage)
	case *bool:
		if ok {
			bv, _ := strconv.ParseBool(val)
			*p = bv
		} else {
			*p = any(def).(bool)
		}
		flag.BoolVar(p, name, *p, usage)
	case *float64:
		if ok {
			fv, _ := strconv.ParseFloat(val, 64)
			*p = fv
		} else {
			*p = any(def).(float64)
		}
		flag.Float64Var(p, name, *p, usage)
	}
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
		"version", AppVersion,
		"port", cfg.Port,
		"max_dirs", cfg.MaxDirs,
		"contributor_threshold", cfg.ContributorThreshold,
		"unrestricted", cfg.Unrestricted,
	)

	return logger, f, nil
}

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		os.Exit(1)
	}

	logger, logFile, err := setupLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logger setup error: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

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
}
