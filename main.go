package main

/*

curioarium-sftp - anonymous share-first SFTP server
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
	ssh-keygen -f id_throwaway -t ed25519 -N ''
	sftp <host> -i id_throwaway

# How to run this server:
    echo "Believe in yourself" > fortunes.txt
	cp README.txt main.go
	go init
	go mod tidy
	go run main.go
*/

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

//go:embed main.go fortunes.txt
var embeddedSource embed.FS

const (
	AppVersion = "1.6.2"
	Schema     = `CREATE TABLE IF NOT EXISTS users ( 
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

// --- Configuration ---

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

func LoadConfig() Config {
	cfg := Config{}
	flag.StringVar(&cfg.Name, "name", getEnv("ARCHIVE_NAME", "curioarium-sftp"), "Archive name")
	flag.IntVar(&cfg.Port, "port", getEnvInt("SFTP_PORT", 2222), "SSH port")
	flag.StringVar(&cfg.HostKeyFile, "hostkey", getEnv("HOST_KEY", "id_ed25519"), "SSH host key")
	flag.StringVar(&cfg.DBPath, "db", getEnv("DB_PATH", "sftp.db"), "SQLite path")
	flag.StringVar(&cfg.LogFile, "logfile", getEnv("LOG_FILE", "sftp.log"), "Log file path")
	flag.StringVar(&cfg.UploadDir, "dir", getEnv("UPLOAD_DIR", "./uploads"), "Upload directory")
	flag.StringVar(&cfg.BannerFile, "banner", getEnv("BANNER_FILE", "BANNER.txt"), "Banner file")
	flag.BoolVar(&cfg.BannerStats, "banner.stats", getEnvBool("BANNER_STATS", false), "Show file statistics in the banner")
	flag.Float64Var(&cfg.MkdirRate, "dir.rate", getEnvFloat("MKDIR_RATE", 10.0), "Global mkdir rate limit in directories per second")
	flag.BoolVar(&cfg.LockDirectoriesToOwners, "dir.owners_only", getEnvBool("LOCK_DIRS_TO_OWNERS", false), "Users can only upload to directories they own")
	flag.BoolVar(&cfg.Verbose, "verbose", getEnvBool("VERBOSE", false), "Enable debug logging")

	var maxSizeRaw string
	flag.StringVar(&maxSizeRaw, "maxsize", getEnv("MAX_FILE_SIZE", "8gb"), "Max file size (e.g. 500mb, 2gb, 0=unlimited)")

	src := flag.Bool("src", false, "Show source code")
	v := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *v {
		fmt.Printf("%s v%s\n", cfg.Name, AppVersion)
		os.Exit(0)
	}

	if *src {
		srcCode, _ := embeddedSource.ReadFile("main.go")
		fmt.Printf("%s", srcCode)
		os.Exit(0)
	}

	maxSize, err := parseSize(maxSizeRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing maxsize: %v\n", err)
		os.Exit(1)
	}
	cfg.MaxFileSize = maxSize

	return cfg
}

func setupLogger(cfg Config) *slog.Logger {
	logWriter := io.MultiWriter(os.Stdout)
	if f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logWriter = io.MultiWriter(os.Stdout, f)
	}

	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	handler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: logLevel})

	logger := slog.New(handler)
	if cfg.Verbose {
		logger = logger.With(
			"app", cfg.Name,
			"version", AppVersion,
		)
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

// --- Server Core ---

type Server struct {
	db           *sql.DB
	logger       *slog.Logger
	mkdirLimiter *rate.Limiter
	cfg          Config
	absUploadDir string
}

func main() {
	cfg := LoadConfig()
	logger := setupLogger(cfg)

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		logger.Error("DB connection failed", "err", err)
		os.Exit(1)
	}
	db.Exec("PRAGMA journal_mode=WAL;")
	if _, err := db.Exec(Schema); err != nil {
		logger.Error("Schema init failed", "err", err)
		os.Exit(1)
	}

	absDir, _ := filepath.Abs(cfg.UploadDir)
	_ = os.MkdirAll(absDir, 0755)

	srv := &Server{
		db:           db,
		logger:       logger,
		mkdirLimiter: rate.NewLimiter(rate.Limit(cfg.MkdirRate), 1),
		cfg:          cfg,
		absUploadDir: absDir,
	}

	go srv.reconcileOrphans()
	srv.Listen()
}

func (s *Server) Listen() {
	if err := s.ensureHostKey(); err != nil {
		s.logger.Error("host key error", "err", err)
		os.Exit(1)
	}

	sshConfig := &ssh.ServerConfig{
		BannerCallback: func(conn ssh.ConnMetadata) string {
			banner := ""
			stats := ""
			b, err := embeddedSource.ReadFile(s.cfg.BannerFile)
			if err != nil {
				s.logger.Debug("Banner file not readable, using default banner", err)
				banner = fmt.Sprintf("=== %s v%s - anonymous share-first sftp server ===", s.cfg.Name, AppVersion)
			} else {
				banner = string(b)
			}

			if s.cfg.BannerStats {
				st := s.getFileStats()
				stats = fmt.Sprintf("Serving:\r\n  Contributors: %d\r\n  Files: %d\r\n  Bytes: %d\r\nMaximum upload size permitted per file: %s\r\n",
					st.Contributors, st.Count, st.Size, st.MaxAllowed())
			}

			return fmt.Sprintf("%s\r\n%s", banner, stats)
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			hash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
		},
	}

	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		s.logger.Error("Host key missing. Generate: ssh-keygen -t ed25519 -f id_ed25519 -N ''")
		os.Exit(1)
	}
	key, _ := ssh.ParsePrivateKey(keyBytes)
	sshConfig.AddHostKey(key)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		s.logger.Error("failed to listen", "err", err)
		os.Exit(1)
	}
	s.logger.Info("SFTP archive online", "port", s.cfg.Port, "dir", s.absUploadDir)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleSSH(conn, sshConfig)
	}
}

func (s *Server) ensureHostKey() error {
	_, err := os.Stat(s.cfg.HostKeyFile)
	if err == nil {
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

	keyFile, err := os.OpenFile(s.cfg.HostKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		s.logger.Debug("ssh handshake failed", "err", err)
		return
	}
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	stats := s.updateUserSession(pubHash)
	sessionID := fmt.Sprintf("%x", sConn.SessionID())
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

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go func(in <-chan *ssh.Request) {
			defer ch.Close()
			for req := range in {
				if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)
					s.Welcome(ch.Stderr(), pubHash, stats)

					handler := &fsHandler{srv: s,
						pubHash:   pubHash,
						stderr:    ch.Stderr(),
						sessionID: sessionID,
						logger: *s.logger.With(
							slog.Group("user",
								"id", pubHash[:12],
								"uid", hashToUid(pubHash),
								"session", sessionID[:16]),
						),
					}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler,
					})
					if err := server.Serve(); err != nil && err != io.EOF {
						s.logger.Error("sftp session ended", "err", err)
					}
					return
				}
			}
		}(reqs)
	}
}

// --- SFTP Handlers ---

type fsHandler struct {
	srv       *Server
	pubHash   string
	sessionID string
	stderr    io.Writer
	logger    slog.Logger
}

func (h *fsHandler) securePath(p string) (rel string, full string) {
	virt := path.Clean("/" + p)
	rel = strings.TrimPrefix(virt, "/")
	if rel == "" {
		rel = "."
	}
	full = filepath.Join(h.srv.absUploadDir, filepath.FromSlash(rel))
	h.srv.logger.Debug("path resolution", "input", p, "rel", rel, "full", full)
	return rel, full
}

func (h *fsHandler) ensureDirOwnership(relPath string) {
	parts := strings.Split(relPath, "/")
	var currentRel string
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if currentRel == "" {
			currentRel = part
		} else {
			currentRel = path.Join(currentRel, part)
		}

		_, full := h.securePath(currentRel)
		_ = os.Mkdir(full, 0755)

		h.srv.db.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size) VALUES (?, ?, 0)",
			currentRel, h.pubHash)
	}
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	rel, full := h.securePath(r.Filepath)
	h.logger.Debug("fileread request", "path", rel)

	if rel == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
		return bytes.NewReader(data), nil
	}

	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, h.deny("Symlinks are prohibited.")
	}

	if !h.hasUploaded() {
		h.logger.Debug("fileread denied: share-first policy")
		return nil, h.deny("Archive access locked. You must share a file first.")
	}

	fi, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	fileSize := fi.Size()

	h.srv.logger.Debug("tracking download", "path", rel, "size", fileSize, "user", h.pubHash[:12])
	h.srv.db.Exec("UPDATE users SET download_count = download_count + 1, download_bytes = download_bytes + ? WHERE pubkey_hash = ?", fileSize, h.pubHash)

	return os.Open(full)
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full := h.securePath(r.Filepath)
	h.logger.Debug("filewrite request", "path", rel)

	if rel == "README.txt" {
		return nil, h.deny("README.txt is a protected system file.")
	}

	// Forbid overwriting or interacting with symlinks
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, h.deny("Symlinks are prohibited.")
	}

	// Check folder ownership
	parentRel := path.Dir(rel)
	if parentRel != "." {
		var pOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", parentRel).Scan(&pOwner)
		if h.srv.cfg.LockDirectoriesToOwners && pOwner != "" && pOwner != h.pubHash {
			h.logger.Debug("filewrite denied: parent directory owned by other", "parent", parentRel, "owner", pOwner)
			return nil, h.deny("Cannot write to another user's directory.")
		}
	}

	tx, err := h.srv.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var currentOwner string
	err = tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&currentOwner)
	if err == sql.ErrNoRows {
		h.logger.Debug("claiming new file ownership", "path", rel)
		if _, err := tx.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", h.pubHash); err != nil {
			return nil, err
		}
	} else if currentOwner != h.pubHash {
		h.logger.Debug("filewrite denied: file already claimed", "path", rel, "owner", currentOwner)
		return nil, h.deny("This filename is already claimed.")
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	h.ensureDirOwnership(path.Dir(rel))
	flags := os.O_RDWR | os.O_CREATE
	if !r.Pflags().Append {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(full, flags, 0644)
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

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := h.securePath(r.Filepath)
	h.logger.Debug("filelist request", "method", r.Method, "path", rel)

	if r.Method == "List" {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
		var files []os.FileInfo

		if rel == "." {
			data, _ := embeddedSource.ReadFile("main.go")
			files = append(files, &virtualFileInfo{name: "README.txt", size: int64(len(data))})
		}

		for _, e := range entries {
			fi, _ := e.Info()
			var owner string
			h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", path.Join(rel, e.Name())).Scan(&owner)
			files = append(files, &sftpFile{FileInfo: fi, owner: owner})
		}
		return listerAt(files), nil
	}

	if rel == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
		return listerAt{&virtualFileInfo{name: "README.txt", size: int64(len(data))}}, nil
	}

	fi, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, h.deny("Access to symlinks is forbidden.")
	}

	var owner string
	h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
	return listerAt{&sftpFile{FileInfo: fi, owner: owner}}, nil
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	rel, full := h.securePath(r.Filepath)
	h.logger.Debug("filecmd request", "method", r.Method, "path", rel)

	switch r.Method {
	case "Symlink", "Link":
		h.logger.Warn("blocked symlink creation attempt", "path", rel)
		return h.deny("Symbolic links are not permitted on this server.")

	case "Mkdir":
		if !h.srv.mkdirLimiter.Allow() {
			h.logger.Debug("mkdir rate limited")
			return h.deny("Rate limit exceeded.")
		}
		h.ensureDirOwnership(rel)
		return nil

	case "Remove", "Rmdir":
		var owner string
		var parentOwner string

		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", path.Dir(rel)).Scan(&parentOwner)

		// Permission is granted if you own the file OR you own the directory it sits in
		canDelete := (owner == h.pubHash) || (parentOwner == h.pubHash)

		if !canDelete && owner != "" {
			h.logger.Debug("remove denied: not owner or parent owner", "path", rel, "owner", owner, "parentOwner", parentOwner)
			return h.deny("You do not have permission to delete this.")
		}

		os.RemoveAll(full)
		h.srv.db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
		return nil
	case "Rename":
		relTgt, fullTgt := h.securePath(r.Target)
		var sOwner, sParentOwner string

		// Check ownership of source and its parent
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&sOwner)
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", path.Dir(rel)).Scan(&sParentOwner)

		// Allow if user owns the file or the folder it is coming from
		if sOwner != h.pubHash && sParentOwner != h.pubHash {
			h.logger.Debug("rename denied: permission issue", "src", rel)
			return h.deny("Rename permission denied.")
		}

		if err := os.Rename(full, fullTgt); err != nil {
			return err
		}

		h.srv.db.Exec(`UPDATE files SET path = ? || substr(path, length(?) + 1) WHERE path = ? OR path LIKE ?`,
			relTgt, rel, rel, rel+"/%")
		return nil
	}
	return sftp.ErrSshFxOpUnsupported
}

type fileStats struct {
	Contributors uint64
	Count        uint64
	Size         uint64
	maxAllowed   int64
}

func (fs *fileStats) MaxAllowed() string {
	if fs.maxAllowed <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d bytes", fs.maxAllowed)
}

func (s Server) getFileStats() (st fileStats) {
	err := s.db.QueryRow("SELECT count(), sum(size) from files").Scan(&st.Count, &st.Size)
	if err != nil {
		s.logger.Debug("Could not get file statistics", err)
	}

	err = s.db.QueryRow("SELECT count(*) from users where upload_count > 0").Scan(&st.Contributors)
	if err != nil {
		s.logger.Debug("Could not get user statistics", err)
	}

	st.maxAllowed = s.cfg.MaxFileSize
	return st
}

// --- DB & Metadata Helpers ---

type userStats struct {
	UploadCount   int64
	LastLogin     string
	UploadBytes   int64
	DownloadCount int64
	DownloadBytes int64
	FirstTimer    bool
}

func (s *Server) updateUserSession(hash string) (st userStats) {
	now := time.Now().Format("2006-01-02 15:04:05")
	err := s.db.QueryRow("SELECT last_login, upload_count, upload_bytes, download_count, download_bytes FROM users WHERE pubkey_hash = ?", hash).Scan(&st.LastLogin, &st.UploadCount, &st.UploadBytes, &st.DownloadCount, &st.DownloadBytes)
	if err == sql.ErrNoRows {
		s.logger.Debug("registering new user", "hash", hash[:12])
		st.FirstTimer = true
		st.LastLogin = "Never"
		s.db.Exec("INSERT INTO users (pubkey_hash, last_login) VALUES (?, ?)", hash, now)
	} else {
		s.db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return st
}

func (s *Server) getRandomFortune() string {
	data, _ := embeddedSource.ReadFile("fortunes.txt")
	fortunes := strings.Split(string(data), "\n%\n")
	return strings.TrimSpace(fortunes[rand.Intn(len(fortunes))])
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
			s.db.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, 'system', ?)", rel, fi.Size())
		}
		return nil
	})
}

// --- SFTP Glue ---

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
func (v *virtualFileInfo) Mode() fs.FileMode  { return 0444 }
func (v *virtualFileInfo) ModTime() time.Time { return time.Now() }
func (v *virtualFileInfo) IsDir() bool        { return false }
func (v *virtualFileInfo) Sys() interface{}   { return &sftp.FileStat{UID: 1000, GID: 1000} }

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
		sw.h.logger.Warn("upload blocked: size limit exceeded",
			"path", sw.rel,
			"requested_size", requestedSize,
			"limit", sw.maxFileSize)
		sw.h.deny(fmt.Sprintf("File size limit exceeded. Maximum allowed: %d bytes", sw.maxFileSize))

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

func (h *fsHandler) deny(msg string) error {
	fmt.Fprintf(h.stderr, "\r\n\033[1;31mDENIED:\033[0m %s\r\n", msg)
	return sftp.ErrSshFxPermissionDenied
}

func (h *fsHandler) hasUploaded() bool {
	var count int
	h.srv.db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", h.pubHash).Scan(&count)
	return count > 0
}

const (
	bold   = "\033[1m"
	blue   = "\033[1;34m"
	yellow = "\033[1;33m"
	green  = "\033[0;32m"
)

func Blue(s string) string {
	return fmt.Sprintf("%s%s\033[0m", blue, s)
}

func Yellow(s string) string {
	return fmt.Sprintf("%s%s\033[0m", yellow, s)
}

func Green(s string) string {
	return fmt.Sprintf("%s%s\033[0m", green, s)
}

func (s *Server) Welcome(w io.Writer, hash string, stats userStats) {
	userLabel := fmt.Sprintf("anonymous-%d", hashToUid(hash))

	readme := func() {
		fmt.Fprintf(w, "\033[1mReminder:\033[0m upload a file to download a file.\r\n")
		fmt.Fprintf(w, "  See \033[1mREADME.txt\033[0m for more information.\r\n")
		fmt.Fprintf(w, "  You may always download \033[1mREADME.txt\033[0m\r\n")
	}

	if stats.FirstTimer {
		fmt.Fprintf(w, "\r\n\033[1mWelcome, %s\033[0m. This is a share-first archive.\r\n", userLabel)
		readme()
	} else {
		isContributor := stats.UploadBytes > 1024*1024
		color := Blue
		if isContributor {
			color = Yellow
		}

		fmt.Fprintf(w, "\r\nWelcome, %s\033[0m\r\n", color(userLabel))
		if isContributor {
			fmt.Fprintf(w, "\033[3;33m\"%s\"\033[0m\r\n", s.getRandomFortune())
		}

		if stats.UploadCount == 0 {
			fmt.Fprintf(w, "\033[31;1mDownloads are restricted.\033[0m\r\n")
			readme()
		} else {
			fmt.Fprintf(w, Green("Downloading is unlocked.\r\n"))
		}

	}
	fmt.Fprintf(w, "\r\nID: %s | Last: %s | Shared: %d files, %d bytes", userLabel, stats.LastLogin, stats.UploadCount, stats.UploadBytes)
	if stats.DownloadCount > 0 {
		fmt.Fprintf(w, " |  Downloaded: %d files, %d bytes", stats.DownloadCount, stats.DownloadBytes)
	}
	fmt.Fprintf(w, "\r\n")

}

// --- Utilities ---

func getEnv(k, f string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return f
}

func getEnvInt(k string, f int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return f
}

func getEnvFloat(k string, f float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return v
	}
	return f
}

func getEnvBool(k string, f bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return f
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
	if hash == "" || hash == "system" {
		return 1000
	}
	h := fnv.New32a()
	h.Write([]byte(hash))
	return h.Sum32() & 0x7FFFFFFF
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
