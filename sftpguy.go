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


----------------------------------------------------------------------------

# What is this?
	This is an anonymous sftp archive that encourages user contributions.

	Upload something that you find thought-provoking or beautiful to gain
	download access to the archive.

# How this works:
    * you log in with your ssh key.  Any ssh key is accepted.
	* you cannot download a file until you upload a file
	* anyone can download README.txt (this file)
	* anyone can upload a file or make a directory
	* you can delete, rename, or resume uploading files you created

# How to use this server:
	TODO

# How to run this server:
	TODO
*/

import (
	"bytes"
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
	"golang.org/x/text/width"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

//go:embed sftpguy.go fortunes.txt
var embeddedSource embed.FS

// path to number of uploaded bytes needed for permission to download
var restrictedFiles = map[string]int64{
	readmeFile:       0,
	fortunesFileName: contributorThreshold,
	sourceFile:       0,
}

// ============================================================================
// Constants
// ============================================================================

const (
	AppVersion = "1.8.1"
	envPrefix  = "SFTP_"

	// System identifiers
	systemOwner      = "system"
	readmeFile       = "README.txt"
	fortunesFileName = "fortunes.txt"
	sourceFile       = "sftpguy.go"

	// File permissions
	permDir      = 0755
	permFile     = 0644
	permHostKey  = 0600
	permLogFile  = 0644
	permReadOnly = 0444

	// User thresholds
	contributorThreshold = 1024 * 1024 // 1MB uploaded = contributor

	// System defaults
	defaultUID = 1000
	defaultGID = 1000

	// Port limits
	minPort = 1
	maxPort = 65535

	// Database
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
		size INTEGER DEFAULT 0
	);`
)

// Error messages
const (
	errMsgSymlinksProhibited     = "Symlinks are prohibited. | 禁止使用符号链接。"
	errMsgAccessLocked           = "Archive access locked. You must share a file first. | 归档访问已锁定。您必须先分享一个文件。"
	errMsgContributorsLocked     = "%s is only available to contributors who have uploaded at least %d bytes. | %s 仅对上传量至少为 %d 字节的贡献者开放。"
	errMsgFileProtected          = "%s is a protected system file. | %s 是受保护的系统文件。"
	errMsgCannotWriteToDir       = "Cannot write to another user's directory. | 无法写入其他用户的目录。"
	errMsgFilenameClaimed        = "This filename is already claimed. | 此文件名已被占用。"
	errMsgNoPermissionDelete     = "You do not have permission to delete this. | 您没有删除此项的权限。"
	errMsgNotOwner               = "You do not own the source file or directory. | 您不是源文件或目录的所有者。"
	errMsgCannotMoveToDir        = "Cannot move files into a directory owned by another user. | 无法将文件移动到属于其他用户的目录。"
	errMsgDestinationClaimed     = "The destination filename is already claimed by someone else. | 目标文件名已被其他人占用。"
	errMsgRenameFailed           = "rename failed | 重命名失败"
	errMsgSymlinksNotPermitted   = "Symbolic links are not permitted on this server. | 此服务器上不允许使用符号链接。"
	errMsgAccessToSymlinksForbid = "Access to symlinks is forbidden. | 禁止访问符号链接。"
	errMsgMkdirRateLimit         = "Mkdir rate limit reached. | 已达到创建目录的频率限制。"
	errMsgFileSizeExceeded       = "File size limit exceeded. Maximum allowed: %d bytes | 超过文件大小限制。最大允许：%d 字节"
	errMsgPathTraversal          = "Path traversal detected - access denied. | 检测到路径遍历 - 访问被拒绝。"
)

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
	LockDirectoriesToOwners bool
	Verbose                 bool
	MaxFileSize             int64
}

func LoadConfig() (Config, error) {
	cfg := Config{}

	// Define all flags using EnvFlag helper
	EnvFlag(&cfg.Name, "name", "ARCHIVE_NAME", "sftpguy", "Archive name")
	EnvFlag(&cfg.Port, "port", "PORT", 2222, "SSH port")
	EnvFlag(&cfg.HostKeyFile, "hostkey", "HOST_KEY", "id_ed25519", "SSH host key")
	EnvFlag(&cfg.DBPath, "db.path", "DB_PATH", "sftp.db", "SQLite path")
	EnvFlag(&cfg.LogFile, "logfile", "LOG_FILE", "sftp.log", "Log file path")
	EnvFlag(&cfg.UploadDir, "dir", "UPLOAD_DIR", "./uploads", "Upload directory")
	EnvFlag(&cfg.BannerFile, "banner", "BANNER_FILE", "BANNER.txt", "Banner file")
	EnvFlag(&cfg.BannerStats, "banner.stats", "BANNER_STATS", false, "Show file statistics in the banner")
	EnvFlag(&cfg.MkdirRate, "dir.rate", "MKDIR_RATE", 10.0, "Global mkdir rate limit in directories per second")
	EnvFlag(&cfg.LockDirectoriesToOwners, "dir.owners_only", "LOCK_DIRS_TO_OWNERS", false, "Users can only upload to directories they own")
	EnvFlag(&cfg.Verbose, "verbose", "VERBOSE", false, "Enable debug logging")

	var maxSizeRaw string
	EnvFlag(&maxSizeRaw, "maxsize", "MAX_FILE_SIZE", "8gb", "Max file size (e.g. 500mb, 2gb, 0=unlimited)")

	src := flag.Bool("src", false, "Show source code")
	v := flag.Bool("version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNote: environment variables may be optionally prefixed with %s. ", bold.Fmt(envPrefix))
		fmt.Fprint(os.Stderr, "For example: "+bold.Fmt(envPrefix+"PORT")+" is checked before "+bold.Fmt("PORT\n"))
	}
	flag.Parse()

	if *v {
		fmt.Printf("%s v%s\n", cfg.Name, AppVersion)
		os.Exit(0)
	}

	if *src {
		srcCode, _ := embeddedSource.ReadFile(sourceFile)
		fmt.Printf("%s", srcCode)
		os.Exit(0)
	}

	maxSize, err := parseSize(maxSizeRaw)
	if err != nil {
		return cfg, fmt.Errorf("invalid maxsize: %w", err)
	}
	cfg.MaxFileSize = maxSize

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.Port < minPort || c.Port > maxPort {
		return fmt.Errorf("port must be between %d and %d, got %d", minPort, maxPort, c.Port)
	}

	if c.MkdirRate < 0 {
		return fmt.Errorf("mkdir rate cannot be negative, got %f", c.MkdirRate)
	}

	if c.MaxFileSize < 0 {
		return fmt.Errorf("max file size cannot be negative, got %d", c.MaxFileSize)
	}

	if c.Name == "" {
		return errors.New("archive name cannot be empty")
	}

	if c.HostKeyFile == "" {
		return errors.New("host key file path cannot be empty")
	}

	if c.DBPath == "" {
		return errors.New("database path cannot be empty")
	}

	if c.UploadDir == "" {
		return errors.New("upload directory cannot be empty")
	}

	return nil
}

// ============================================================================
// Server
// ============================================================================

type Server struct {
	db           *sql.DB
	logger       *slog.Logger
	mkdirLimiter *rate.Limiter
	cfg          Config
	absUploadDir string
	listener     net.Listener
	wg           sync.WaitGroup
	shutdown     chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("DB connection failed: %w", err)
	}

	db.Exec("PRAGMA journal_mode=WAL;")

	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init failed: %w", err)
	}
	for filename := range restrictedFiles {
		_, err := db.Exec("INSERT OR REPLACE INTO files(path, owner_hash) VALUES (?, ?)", filename, systemOwner)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize system file %s: %w", filename, err)
		}
	}

	absDir, err := filepath.Abs(cfg.UploadDir)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to resolve upload directory: %w", err)
	}

	if err := os.MkdirAll(absDir, permDir); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create upload directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	srv := &Server{
		db:           db,
		logger:       logger,
		mkdirLimiter: rate.NewLimiter(rate.Limit(cfg.MkdirRate), 1),
		cfg:          cfg,
		absUploadDir: absDir,
		shutdown:     make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}

	return srv, nil
}

func (s *Server) Shutdown() error {
	s.logger.Info("initiating graceful shutdown")

	// Signal shutdown
	close(s.shutdown)
	s.cancel()

	// Stop accepting new connections
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Error("error closing listener", "err", err)
		}
	}

	// Wait for active connections with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("all connections closed")
	case <-time.After(30 * time.Second):
		s.logger.Warn("shutdown timeout reached, forcing close")
	}

	// Close database
	if err := s.db.Close(); err != nil {
		s.logger.Error("error closing database", "err", err)
		return err
	}

	s.logger.Info("shutdown complete")
	return nil
}

func (s *Server) Listen() error {
	if err := s.ensureHostKey(); err != nil {
		return fmt.Errorf("host key error: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		BannerCallback:    s.bannerCallback,
		PublicKeyCallback: s.publicKeyCallback,
	}

	if err := s.addHostKey(sshConfig); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = listener

	s.logger.Info("SFTP archive online", "port", s.cfg.Port, "dir", s.absUploadDir)

	// Accept connections until shutdown
	for {
		select {
		case <-s.shutdown:
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return nil
			default:
				s.logger.Debug("accept error", "err", err)
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

func (s *Server) addHostKey(config *ssh.ServerConfig) error {
	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return fmt.Errorf("host key missing. Generate: ssh-keygen -t ed25519 -f id_ed25519 -N ''")
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse host key: %w", err)
	}

	config.AddHostKey(key)
	return nil
}

func (s *Server) bannerCallback(conn ssh.ConnMetadata) string {
	b, err := embeddedSource.ReadFile(s.cfg.BannerFile)
	banner := string(b)
	if err != nil {
		banner = fmt.Sprintf("=== %s v%s ===", s.cfg.Name, AppVersion)
	}

	if s.cfg.BannerStats {
		var u, c, f, b uint64
		s.db.QueryRow("SELECT count(*) FROM users WHERE upload_count > 0", contributorThreshold).Scan(&u)
		s.db.QueryRow("SELECT count(*) FROM users WHERE upload_bytes > ?", contributorThreshold).Scan(&c)
		s.db.QueryRow("SELECT count(*), sum(size) FROM files").Scan(&f, &b)
		banner += fmt.Sprintf("\r\nUsers: %d | Contributors: %d | Files: %d | Size: %d bytes\r\n", u, c, f, b)
	}
	return banner
}

func (s *Server) ensureHostKey() error {
	if _, err := os.Stat(s.cfg.HostKeyFile); err == nil {
		return nil // Key already exists
	}

	s.logger.Info("generating new Ed25519 host key", "path", s.cfg.HostKeyFile)

	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}

	keyFile, err := os.OpenFile(s.cfg.HostKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permHostKey)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		return fmt.Errorf("failed to encode pem: %w", err)
	}

	return nil
}

func (s *Server) handleSSH(nConn net.Conn, config *ssh.ServerConfig) {
	// Check if we're shutting down
	select {
	case <-s.shutdown:
		nConn.Close()
		return
	default:
	}

	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		s.logger.Debug("ssh handshake failed", "err", err)
		return
	}
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	stats := s.updateUserSession(pubHash)
	sessionID := fmt.Sprintf("%x", sConn.SessionID())

	s.logConnection(pubHash, sessionID, stats, sConn)
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		select {
		case <-s.shutdown:
			return
		default:
		}

		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go s.handleChannel(ch, reqs, pubHash, sessionID, stats, sConn)
	}
}

func (s *Server) logConnection(pubHash, sessionID string, stats userStats, sConn *ssh.ServerConn) {
	s.logger.Info("handling login",
		slog.Group("user",
			"id", pubHash[:12],
			"uid", hashToUid(pubHash),
			"last_login", stats.LastLogin,
			"upload_count", stats.UploadCount,
			"upload_bytes", stats.UploadBytes,
			"download_count", stats.DownloadCount,
			"download_bytes", stats.DownloadBytes,
			"first_timer", stats.FirstTimer,
		),
		slog.Group("conn",
			"user", sConn.User(),
			"session", sessionID[:16],
			"client_version", sConn.ClientVersion(),
			"remote_address", sConn.RemoteAddr(),
			"local_address", sConn.LocalAddr(),
		),
	)
}

func (s *Server) getVirtualFile(name string) ([]byte, bool) {
	if _, ok := restrictedFiles[name]; !ok {
		return nil, false
	}

	embedPath := name
	if name == readmeFile {
		embedPath = sourceFile
	}

	data, err := embeddedSource.ReadFile(embedPath)
	if err != nil {
		return nil, false
	}
	return data, true
}

func (s *Server) handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, pubHash, sessionID string, stats userStats, sConn *ssh.ServerConn) {
	defer ch.Close()

	for req := range reqs {
		select {
		case <-s.shutdown:
			return
		default:
		}

		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			req.Reply(true, nil)
			s.Welcome(ch.Stderr(), pubHash, stats)

			handler := s.newFSHandler(pubHash, sessionID, ch.Stderr(), sConn.RemoteAddr())
			server := sftp.NewRequestServer(ch, sftp.Handlers{
				FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler,
			})

			if err := server.Serve(); err != nil && err != io.EOF {
				s.logger.Error("sftp session ended", "err", err)
			}
			return
		}
	}
}

func (s *Server) newFSHandler(pubHash, sessionID string, stderr io.Writer, remoteAddr net.Addr) *fsHandler {
	return &fsHandler{
		srv:       s,
		pubHash:   pubHash,
		stderr:    stderr,
		sessionID: sessionID,
		logger: *s.logger.With(
			slog.Group("user",
				"id", pubHash[:12],
				"uid", hashToUid(pubHash),
				"session", sessionID[:16],
				"remote_address", remoteAddr,
			),
		),
	}
}

func (s *Server) Welcome(w io.Writer, hash string, stats userStats) {
	userLabel := fmt.Sprintf("anonymous-%d", hashToUid(hash))

	readme := func() {
		fmt.Fprint(w, bold.Fmt("Reminder: ")+"upload a file to download a file.\r\n")
		fmt.Fprint(w, "  See "+bold.Fmt(readmeFile)+" for more information.\r\n")
		fmt.Fprint(w, "  You may always download "+bold.Fmt(readmeFile)+"\r\n")
		fmt.Fprint(w, "  Upload 1MB+ to unlock "+yellow.Bold(fortunesFileName)+"\r\n")
	}

	if stats.FirstTimer {
		fmt.Fprint(w, bold.Fmt("\r\nWelcome, "+userLabel)+". This is a share-first archive.\r\n")
		readme()
	} else {
		isContributor := stats.UploadBytes >= contributorThreshold
		color := blue
		if isContributor {
			color = yellow
		}

		fmt.Fprintf(w, "\r\nWelcome, %s\r\n", color.Bold(userLabel))
		if isContributor {
			fmt.Fprintf(w, "\"%s\"\r\n", color.Italic(s.getRandomFortune()))
			fmt.Fprint(w, yellow.Fmt("★ Contributor status unlocked! You can now read "+fortunesFileName+"\r\n"))
		}

		if stats.UploadCount == 0 {
			fmt.Fprint(w, red.Bold("Downloads are restricted.\r\n"))
			readme()
		} else {
			fmt.Fprint(w, green.Fmt("Downloading is unlocked.\r\n"))
			for name, threshold := range restrictedFiles {
				if stats.UploadBytes < threshold {
					fmt.Fprintf(w, "  Upload %d more bytes to unlock %s\r\n", threshold-stats.UploadBytes, bold.Fmt(name))
				}
			}
			// if !isContributor {
			// 	fmt.Fprintf(w, "  Upload %d more bytes to unlock "+bold.Fmt(fortunesFileName)+"\r\n", contributorThreshold-stats.UploadBytes)
			// }
		}
	}

	fmt.Fprintf(w, "\r\nID: %s | Last: %s | Shared: %d files, %d bytes",
		userLabel, stats.LastLogin, stats.UploadCount, stats.UploadBytes)
	if stats.DownloadCount > 0 {
		fmt.Fprintf(w, " |  Downloaded: %d files, %d bytes", stats.DownloadCount, stats.DownloadBytes)
	}
	fmt.Fprintf(w, "\r\n")
}

func (s *Server) reconcileOrphans() {
	s.logger.Info("reconciling filesystem with database")
	filepath.WalkDir(s.absUploadDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == s.absUploadDir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		rel, _ := filepath.Rel(s.absUploadDir, p)
		rel = filepath.ToSlash(rel)

		var exists bool
		s.db.QueryRow("SELECT 1 FROM files WHERE path = ?", rel).Scan(&exists)
		if !exists {
			fi, _ := d.Info()
			s.logger.Debug("found orphan file, assigning to system", "path", rel)
			s.db.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, ?)", rel, systemOwner, fi.Size())
		}
		return nil
	})
}

func (s *Server) getRandomFortune() string {
	data, _ := embeddedSource.ReadFile(fortunesFileName)
	fortunes := strings.Split(string(data), "\n%\n")
	if len(fortunes) == 0 {
		return ""
	}
	return strings.TrimSpace(fortunes[rand.Intn(len(fortunes))])
}

// ============================================================================
// Database Operations
// ============================================================================

type userStats struct {
	UploadCount   int64
	LastLogin     string
	UploadBytes   int64
	DownloadCount int64
	DownloadBytes int64
	FirstTimer    bool
}

func (s *Server) GetUser(hash string) (u userStats) {
	err := s.db.QueryRow(`SELECT last_login, upload_count, upload_bytes, download_count, download_bytes 
		FROM users WHERE pubkey_hash = ?`, hash).Scan(&u.LastLogin, &u.UploadCount, &u.UploadBytes, &u.DownloadCount, &u.DownloadBytes)
	if err == sql.ErrNoRows {
		u.FirstTimer = true
		u.LastLogin = "Never"
	}
	return u
}

func (s *Server) GetOwner(relPath string) (string, error) {
	var owner string
	err := s.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)
	return owner, err
}

func (s *Server) GetOwnerTX(tx *sql.Tx, relPath string) (string, error) {
	var owner string
	err := tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relPath).Scan(&owner)
	return owner, err
}

func (s *Server) updateUserSession(hash string) (st userStats) {
	now := time.Now().Format("2006-01-02 15:04:05")
	err := s.db.QueryRow("SELECT last_login, upload_count, upload_bytes, download_count, download_bytes FROM users WHERE pubkey_hash = ?", hash).Scan(&st.LastLogin, &st.UploadCount, &st.UploadBytes, &st.DownloadCount, &st.DownloadBytes)

	if err == sql.ErrNoRows {
		s.logger.Debug("registering new user", "user.id", hash[:12])
		st.FirstTimer = true
		st.LastLogin = "Never"
		s.db.Exec("INSERT INTO users (pubkey_hash, last_login) VALUES (?, ?)", hash, now)
	} else {
		s.db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return st
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

// resolve converts an SFTP path to relative and absolute filesystem paths
// with path traversal protection
func (h *fsHandler) resolve(p string) (rel string, full string, err error) {
	// Clean the path
	virt := path.Clean("/" + p)
	rel = strings.TrimPrefix(virt, "/")
	if rel == "" {
		rel = "."
	}

	// Build full path
	full = filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))

	// Validate path doesn't escape upload directory
	if !isPathSafe(full, h.srv.absUploadDir) {
		return "", "", fmt.Errorf(errMsgPathTraversal)
	}

	return rel, full, nil
}

func (h *fsHandler) ensureDirs(pubHash, relPath string) error {
	if relPath == "." || relPath == "" {
		return nil
	}

	if !h.srv.mkdirLimiter.Allow() {
		return h.deny(errMsgMkdirRateLimit)
	}

	_, full, err := h.resolve(relPath)
	if err != nil {
		return err
	}

	// TODO: if h.srv.cfg.LockDirectoriesToOwners,  make sure that we don't let users make dirs inside each other's dirs
	if err := os.MkdirAll(full, permDir); err != nil {
		return err
	}

	parts := strings.Split(relPath, "/")
	curr := ""
	tx, err := h.srv.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, p := range parts {
		curr = path.Join(curr, p)
		if _, err := tx.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size) VALUES (?, ?, 0)", curr, pubHash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (h *fsHandler) hasUploaded(pubHash string) bool {
	var count int
	h.srv.db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", pubHash).Scan(&count)
	return count > 0
}

func (h *fsHandler) isContributor(pubHash string) bool {
	var uploadBytes int64
	h.srv.db.QueryRow("SELECT upload_bytes FROM users WHERE pubkey_hash = ?", pubHash).Scan(&uploadBytes)
	return uploadBytes >= contributorThreshold
}

var (
	enPadded = red.Fmt(padRightVisual("DENIED:", 12))
	zhPadded = red.Fmt(padRightVisual("访问被拒绝:", 12))
)

func (h *fsHandler) deny(msg string, args ...any) error {

	h.logger.Info(msg, args...)
	msgSplit := strings.SplitN(msg, "|", 2)
	fmt.Fprintf(h.stderr, "\r\n%-8s %s", red.Fmt(enPadded), strings.TrimSpace(msgSplit[0]))
	fmt.Fprintf(h.stderr, "\r\n%-8s %s\r\n", red.Fmt(zhPadded), strings.TrimSpace(msgSplit[1]))
	return sftp.ErrSshFxPermissionDenied
}

func visualWidth(s string) int {
	w := 0
	for _, r := range s {
		kind := width.LookupRune(r).Kind()
		switch kind {
		case width.EastAsianWide, width.EastAsianFullwidth:
			w += 2
		case width.EastAsianHalfwidth, width.EastAsianNarrow, width.Neutral:
			w += 1
		default:
			w += 1 // Fallback
		}
	}
	return w
}

func padRightVisual(s string, width int) string {
	padding := width - visualWidth(s)
	if padding < 0 {
		return s
	}
	return s + strings.Repeat(" ", padding)
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	rel, full, err := h.resolve(r.Filepath)
	if err != nil {
		return nil, h.deny(err.Error(), "path", r.Filepath)
	}

	h.logger.Debug("fileread request", "path", rel, "req", r)

	if threshold, isRestricted := restrictedFiles[rel]; isRestricted {
		stats := h.srv.GetUser(h.pubHash)
		if stats.UploadBytes < threshold {
			return nil, h.deny(fmt.Sprintf(errMsgContributorsLocked, rel, threshold, rel, threshold))
		}

		if data, ok := h.srv.getVirtualFile(rel); ok {
			return bytes.NewReader(data), nil
		}
		// // Map virtual path to embedded source path
		// embedPath := rel
		// if rel == readmeFile {
		// 	embedPath = sourceFile
		// }

		// data, err := embeddedSource.ReadFile(embedPath)
		// if err != nil {
		// 	return nil, err
		// }
		// return bytes.NewReader(data), nil
	}

	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, h.deny(errMsgSymlinksProhibited, "path", rel)
	}

	if !h.hasUploaded(h.pubHash) {
		return nil, h.deny(errMsgAccessLocked)
	}

	fi, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	fileSize := fi.Size()

	h.logger.Debug("tracking download", "path", rel, "size", fileSize)
	h.srv.db.Exec("UPDATE users SET download_count = download_count + 1, download_bytes = download_bytes + ? WHERE pubkey_hash = ?", fileSize, h.pubHash)

	return os.Open(full)
}

// Filewrite implements sftp file writing
func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full, err := h.resolve(r.Filepath)
	if err != nil {
		return nil, h.deny(err.Error(), "path", r.Filepath)
	}

	h.logger.Debug("filewrite request", "path", rel)

	if err := h.CanWrite(h.pubHash, rel, full); err != nil {
		return nil, err
	}

	flags := os.O_RDWR | os.O_CREATE
	if !r.Pflags().Append {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(full, flags, permFile)
	if err != nil {
		return nil, err
	}

	var oldSize int64
	if fi, err := os.Stat(full); err == nil {
		oldSize = fi.Size()
	}

	return &statWriter{
		File:        f,
		h:           h,
		rel:         rel,
		oldSize:     oldSize,
		maxFileSize: h.srv.cfg.MaxFileSize,
	}, nil
}

// CanWrite checks if a user can write to a given path
func (h *fsHandler) CanWrite(pubHash, rel, full string) error {
	if _, ok := restrictedFiles[rel]; ok {
		var color AsciiDecorator = bold
		if rel == fortunesFileName {
			color = yellow
		}
		return h.deny(fmt.Sprintf(errMsgFileProtected, color.Bold(rel), color.Bold(rel)), "rel", rel)
	}

	// Forbid overwriting or interacting with symlinks
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return h.deny(errMsgSymlinksProhibited)
	}

	// Check folder ownership
	parentRel := path.Dir(rel)
	if h.srv.cfg.LockDirectoriesToOwners && parentRel != "." {
		parentOwner, _ := h.srv.GetOwner(parentRel)
		if parentOwner != "" && parentOwner != pubHash {
			return h.deny(errMsgCannotWriteToDir, "parent", parentRel, "owner", parentOwner)
		}
	}

	if err := h.ensureDirs(pubHash, parentRel); err != nil {
		return err
	}

	return h.ClaimFile(pubHash, rel)
}

// ClaimFile attempts to claim ownership of a file
func (h *fsHandler) ClaimFile(pubhash, rel string) error {
	tx, err := h.srv.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	currentOwner, err := h.srv.GetOwnerTX(tx, rel)
	if err == sql.ErrNoRows {
		h.logger.Debug("claiming new file ownership", "path", rel)
		if _, err := tx.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", h.pubHash); err != nil {
			return err
		}
	} else if currentOwner != h.pubHash {
		return h.deny(errMsgFilenameClaimed, "path", rel, "owner", currentOwner)
	}

	return tx.Commit()
}

// Filelist implements directory listing
func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full, err := h.resolve(r.Filepath)
	if err != nil {
		return nil, h.deny(err.Error(), "path", r.Filepath)
	}

	h.logger.Debug("filelist request", "method", r.Method, "path", rel)

	if r.Method == "List" {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
		var files []os.FileInfo

		if rel == "." {
			// Add README.txt (always visible)
			readmeData, _ := embeddedSource.ReadFile(sourceFile)
			files = append(files, &virtualFileInfo{name: readmeFile, size: int64(len(readmeData))})

			// Add fortunes.txt (always visible, but locked for non-contributors)
			fortunesData, _ := embeddedSource.ReadFile(fortunesFileName)
			files = append(files, &virtualFileInfo{name: fortunesFileName, size: int64(len(fortunesData))})
		}

		for _, e := range entries {
			fi, _ := e.Info()
			owner, _ := h.srv.GetOwner(path.Join(rel, e.Name()))
			files = append(files, &sftpFile{FileInfo: fi, owner: owner})
		}
		return listerAt(files), nil
	}

	if data, isVirtual := h.srv.getVirtualFile(rel); isVirtual {
		return listerAt{&virtualFileInfo{name: rel, size: int64(len(data))}}, nil
	}

	fi, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, h.deny(errMsgAccessToSymlinksForbid)
	}

	owner, _ := h.srv.GetOwner(rel)
	return listerAt{&sftpFile{FileInfo: fi, owner: owner}}, nil
}

// Filecmd implements file operations (mkdir, remove, rename, etc)
func (h *fsHandler) Filecmd(r *sftp.Request) error {
	rel, full, err := h.resolve(r.Filepath)
	if err != nil {
		return h.deny(err.Error(), "path", r.Filepath)
	}

	h.logger.Debug("filecmd request", "method", r.Method, "path", rel)

	switch r.Method {
	case "Symlink", "Link":
		return h.deny(errMsgSymlinksNotPermitted, "path", rel)

	case "Mkdir":
		return h.ensureDirs(h.pubHash, rel)

	case "Remove", "Rmdir":
		return h.handleRemove(rel, full)

	case "Rename":
		return h.handleRename(r, rel, full)
	}

	return sftp.ErrSshFxOpUnsupported
}

func (h *fsHandler) handleRemove(rel, full string) error {
	owner, _ := h.srv.GetOwner(rel)
	parentOwner, _ := h.srv.GetOwner(path.Dir(rel))
	canDelete := (owner == h.pubHash) || (parentOwner == h.pubHash)

	if !canDelete && owner != "" {
		return h.deny(errMsgNoPermissionDelete, "path", rel, "owner", owner, "parentOwner", parentOwner)
	}

	os.RemoveAll(full)
	h.srv.db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
	return nil
}

func (h *fsHandler) handleRename(r *sftp.Request, rel, full string) error {
	relTgt, fullTgt, err := h.resolve(r.Target)
	if err != nil {
		return h.deny(err.Error(), "target", r.Target)
	}

	// Check source permissions
	sourceOwner, _ := h.srv.GetOwner(rel)
	sourceParentOwner, _ := h.srv.GetOwner(path.Dir(rel))
	if sourceOwner != h.pubHash && sourceParentOwner != h.pubHash {
		return h.deny(errMsgNotOwner, "src", rel)
	}

	// Check target directory permissions
	targetDir := path.Dir(relTgt)
	if h.srv.cfg.LockDirectoriesToOwners && targetDir != "." {
		targetParentOwner, _ := h.srv.GetOwner(targetDir)
		if targetParentOwner != "" && targetParentOwner != h.pubHash {
			return h.deny(errMsgCannotMoveToDir, "targetDir", targetDir)
		}
	}

	// Check if target is already claimed
	targetOwner, err := h.srv.GetOwner(relTgt)
	if err == nil {
		if targetOwner != "" && targetOwner != h.pubHash {
			return h.deny(errMsgDestinationClaimed, "target", relTgt, "owner", targetOwner)
		}
	}

	// Perform filesystem rename
	if err := os.Rename(full, fullTgt); err != nil {
		return h.deny(errMsgRenameFailed, "err", err)
	}

	// Update database
	tx, err := h.srv.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`UPDATE files SET path = ? || substr(path, length(?) + 1) WHERE path = ? OR path LIKE ?`,
		relTgt, rel, rel, rel+"/%")
	if err != nil {
		h.logger.Error("db update failed after rename", "err", err)
		return err
	}

	return tx.Commit()
}

// ============================================================================
// SFTP File Types
// ============================================================================

type sftpFile struct {
	os.FileInfo
	owner string
}

func (s *sftpFile) Sys() interface{} {
	uid := hashToUid(s.owner)
	return &sftp.FileStat{UID: uid, GID: uid}
}

type virtualFileInfo struct {
	name string
	size int64
}

func (v *virtualFileInfo) Name() string       { return v.name }
func (v *virtualFileInfo) Size() int64        { return v.size }
func (v *virtualFileInfo) Mode() fs.FileMode  { return permReadOnly }
func (v *virtualFileInfo) ModTime() time.Time { return time.Now() }
func (v *virtualFileInfo) IsDir() bool        { return false }
func (v *virtualFileInfo) Sys() interface{}   { return &sftp.FileStat{UID: defaultUID, GID: defaultGID} }

type statWriter struct {
	*os.File
	h           *fsHandler
	rel         string
	oldSize     int64
	maxFileSize int64
}

func (sw *statWriter) WriteAt(p []byte, off int64) (int, error) {
	requestedSize := off + int64(len(p))
	if sw.maxFileSize > 0 && requestedSize > sw.maxFileSize {
		sw.h.deny(fmt.Sprintf(errMsgFileSizeExceeded, sw.maxFileSize),
			"path", sw.rel,
			"requested_size", requestedSize,
			"limit", sw.maxFileSize)
		return 0, sftp.ErrSshFxFailure
	}
	return sw.File.WriteAt(p, off)
}

func (sw *statWriter) Close() error {
	fi, _ := sw.File.Stat()
	newSize := fi.Size()
	delta := newSize - sw.oldSize

	sw.h.srv.logger.Debug("closing file write", "path", sw.rel, "newSize", newSize, "delta", delta)
	sw.h.srv.db.Exec("UPDATE files SET size = ? WHERE path = ?", newSize, sw.rel)
	sw.h.srv.db.Exec("UPDATE users SET upload_bytes = upload_bytes + ? WHERE pubkey_hash = ?", delta, sw.h.pubHash)

	return sw.File.Close()
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

type AsciiDecorator interface {
	Fmt(string) string
	Bold(string) string
	Italic(string) string
	Underline(string) string
}

type asciiColor string
type asciiStyle string

const asciiReset = "\033[0m"

const (
	off       asciiStyle = "0"
	bold      asciiStyle = "1"
	dim       asciiStyle = "2"
	italic    asciiStyle = "3"
	underline asciiStyle = "4"
)

func (style asciiStyle) Fmt(str string) string {
	return fmt.Sprintf("\033[%sm%s%s", style, str, asciiReset)
}

func (s asciiStyle) Bold(str string) string {
	// If we are already a style, we override to bold (1)
	return fmt.Sprintf("\033[1m%s%s", str, asciiReset)
}

func (s asciiStyle) Italic(str string) string {
	return fmt.Sprintf("\033[3m%s%s", str, asciiReset)
}

func (s asciiStyle) Underline(str string) string {
	return fmt.Sprintf("\033[4m%s%s", str, asciiReset)
}

const (
	red    asciiColor = "\033[%s;31m"
	green  asciiColor = "\033[%s;32m"
	yellow asciiColor = "\033[%s;33m"
	blue   asciiColor = "\033[%s;34m"

	magenta asciiColor = "\033[%s;35m"
	cyan    asciiColor = "\033[%s;36m"
	white   asciiColor = "\033[%s;37m"
	gray    asciiColor = "\033[%s;90m"
)

func (c asciiColor) Fmt(s string) string {
	return fmt.Sprintf(string(c), off) + s + asciiReset
}

func (c asciiColor) Bold(s string) string {
	return fmt.Sprintf(string(c), bold) + s + asciiReset
}

func (c asciiColor) Italic(s string) string {
	return fmt.Sprintf(string(c), italic) + s + asciiReset
}

func (c asciiColor) Underline(s string) string {
	return fmt.Sprintf(string(c), italic) + s + asciiReset
}

// ============================================================================
// Utilities
// ============================================================================

func isPathSafe(fullPath, baseDir string) bool {
	// Get absolute paths
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}

	// Check if path is within base directory
	rel, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return false
	}

	// Path should not start with ".." which would indicate escape
	return !strings.HasPrefix(rel, "..") && !strings.Contains(rel, string(filepath.Separator)+"..")
}

func EnvFlag[T any](ptr *T, name string, env string, def T, usage string) {
	val := GetEnv(env, def)
	*ptr = val
	usageWithEnv := fmt.Sprintf("%-28s  %s", bold.Fmt(env), usage)

	switch p := any(ptr).(type) {
	case *string:
		flag.StringVar(p, name, any(val).(string), usageWithEnv)
	case *int:
		flag.IntVar(p, name, any(val).(int), usageWithEnv)
	case *bool:
		flag.BoolVar(p, name, any(val).(bool), usageWithEnv)
	case *float64:
		flag.Float64Var(p, name, any(val).(float64), usageWithEnv)
	default:
		panic(fmt.Sprintf("unsupported flag type: %T", val))
	}
}

func GetEnv[T any](k string, defaultValue T) T {
	val, ok := os.LookupEnv(fmt.Sprintf("%s%s", envPrefix, k))
	if !ok {
		val, ok = os.LookupEnv(k)
	}
	if !ok {
		return defaultValue
	}

	var res any
	var err error

	switch any(defaultValue).(type) {
	case string:
		return any(val).(T)
	case int:
		res, err = strconv.Atoi(val)
	case float64:
		res, err = strconv.ParseFloat(val, 64)
	case bool:
		res, err = strconv.ParseBool(val)
	default:
		return defaultValue
	}

	if err != nil {
		return defaultValue
	}
	return res.(T)
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}

	var multiplier int64 = 1
	suffix := ""

	if strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		suffix = "gb"
	} else if strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		suffix = "mb"
	} else if strings.HasSuffix(s, "kb") {
		multiplier = 1024
		suffix = "kb"
	} else if strings.HasSuffix(s, "b") {
		multiplier = 1
		suffix = "b"
	}

	valStr := strings.TrimSuffix(s, suffix)
	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %v", err)
	}
	return val * multiplier, nil
}

func hashToUid(hash string) uint32 {
	if hash == "" || hash == systemOwner {
		return defaultUID
	}
	h := fnv.New32a()
	h.Write([]byte(hash))
	return h.Sum32() & 0x7FFFFFFF
}

func setupLogger(cfg Config) *slog.Logger {
	logWriter := io.MultiWriter(os.Stdout)
	if f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, permLogFile); err == nil {
		logWriter = io.MultiWriter(os.Stdout, f)
	}

	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	handler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(handler)

	if cfg.Verbose {
		logger = logger.With("app", cfg.Name, "version", AppVersion)
	}

	logger.Info("server configuration",
		slog.Group("config",
			"port", cfg.Port,
			"db_path", cfg.DBPath,
			"upload_dir", cfg.UploadDir,
			"lock_dirs_to_owners", cfg.LockDirectoriesToOwners,
			"host_key", cfg.HostKeyFile,
			"mkdir_rate", cfg.MkdirRate,
			"log_file", cfg.LogFile,
			"banner_file", cfg.BannerFile,
			"banner_stats", cfg.BannerStats,
			"max_file_size", cfg.MaxFileSize,
			"verbose", cfg.Verbose,
		),
	)
	return logger
}

// ============================================================================
// Main
// ============================================================================

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg)

	srv, err := NewServer(cfg, logger)
	if err != nil {
		logger.Error("server initialization failed", "err", err)
		os.Exit(1)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start orphan reconciliation in background
	go srv.reconcileOrphans()

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(); err != nil {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
		if err := srv.Shutdown(); err != nil {
			logger.Error("shutdown error", "err", err)
			os.Exit(1)
		}
	case err := <-errChan:
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
