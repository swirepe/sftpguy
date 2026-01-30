package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"embed"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

//go:embed main.go
//go:embed fortunes.txt
var embeddedSource embed.FS

const (
	version         = "1.1.0"
	applicationName = "curioarium-sftp"
)

type Config struct {
	Port        int
	HostKeyFile string
	DBPath      string
	LogFile     string
	UploadDir   string
	BannerFile  string
	MkdirRate   float64
}

type Server struct {
	db           *sql.DB
	logger       *slog.Logger
	mkdirLimiter *rate.Limiter
	config       Config
	absUploadDir string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    pubkey_hash TEXT PRIMARY KEY,
    last_login DATETIME,
    upload_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    owner_hash TEXT,
    size INTEGER DEFAULT 0
);`

func main() {
	cfg := Config{}
	flag.IntVar(&cfg.Port, "port", 2222, "SSH port")
	flag.StringVar(&cfg.HostKeyFile, "hostkey", "id_rsa", "SSH private host key")
	flag.StringVar(&cfg.DBPath, "db", "sftp.db", "Path to SQLite database")
	flag.StringVar(&cfg.LogFile, "logfile", "sftp.log", "Path to log file")
	flag.StringVar(&cfg.UploadDir, "dir", "./uploads", "Directory to store uploads")
	flag.StringVar(&cfg.BannerFile, "banner", "BANNER.txt", "Path to banner file")
	flag.Float64Var(&cfg.MkdirRate, "rate", 10.0, "Global mkdir rate limit (folders/sec)")
	v := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *v {
		fmt.Printf("%s v%s\n", applicationName, version)
		return
	}

	// Logging
	f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, f), nil))

	// Database
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		logger.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		logger.Error("schema init failed", "err", err)
		os.Exit(1)
	}

	absDir, _ := filepath.Abs(cfg.UploadDir)
	os.MkdirAll(absDir, 0755)

	srv := &Server{
		db:           db,
		logger:       logger,
		mkdirLimiter: rate.NewLimiter(rate.Limit(cfg.MkdirRate), 1),
		config:       cfg,
		absUploadDir: absDir,
	}

	go srv.reconcileOrphans()
	srv.start()
}

func (s *Server) start() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			hash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
		},
	}

	keyBytes, err := os.ReadFile(s.config.HostKeyFile)
	if err != nil {
		s.logger.Error("host key missing", "cmd", "ssh-keygen -f id_rsa -t rsa -N ''")
		os.Exit(1)
	}
	key, _ := ssh.ParsePrivateKey(keyBytes)
	sshConfig.AddHostKey(key)

	listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	s.logger.Info("server started", "port", s.config.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(conn, sshConfig)
	}
}

func (s *Server) handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	stats := s.updateLoginStats(pubHash)
	s.logger.Info("login", "user", pubHash[:12], "addr", nConn.RemoteAddr().String())

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
					s.sendBanner(ch.Stderr(), pubHash, stats)

					handler := &fsHandler{srv: s, pubHash: pubHash, stderr: ch.Stderr()}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler,
					})
					server.Serve()
					return
				}
			}
		}(reqs)
	}
}

type fsHandler struct {
	srv     *Server
	pubHash string
	stderr  io.Writer
}

// securePath prevents traversal and returns relative (DB) and absolute (FS) paths
func (h *fsHandler) securePath(p string) (rel string, full string) {
	// Clean and convert to OS-specific path
	clean := filepath.FromSlash(p)
	full = filepath.Join(h.srv.absUploadDir, clean)

	// Evaluate symlinks and re-verify prefix
	evalFull, err := filepath.Abs(full)
	if err != nil || !strings.HasPrefix(evalFull, h.srv.absUploadDir) {
		return ".", h.srv.absUploadDir
	}

	rel, _ = filepath.Rel(h.srv.absUploadDir, evalFull)
	return filepath.ToSlash(rel), evalFull
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	rel, full := h.securePath(r.Filepath)
	if rel == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
		return bytes.NewReader(data), nil
	}

	if !h.hasUploaded() {
		return nil, h.deny("You must upload at least one file to download others.")
	}

	return os.Open(full)
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full := h.securePath(r.Filepath)

	// 1. Check Parent Ownership
	parentRel := filepath.ToSlash(filepath.Dir(rel))
	if parentRel != "." {
		var pOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", parentRel).Scan(&pOwner)
		if pOwner != "" && pOwner != h.pubHash {
			return nil, h.deny("Parent directory is owned by another user.")
		}
	}

	// 2. Atomic Ownership Claim
	tx, _ := h.srv.db.Begin()
	var owner string
	err := tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)

	if err == sql.ErrNoRows {
		tx.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash)
		tx.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", h.pubHash)
	} else if owner != h.pubHash {
		tx.Rollback()
		return nil, h.deny("File owned by another user.")
	}
	tx.Commit()

	// 3. File Handling (Support Resume vs Truncate)
	os.MkdirAll(filepath.Dir(full), 0755)

	flags := os.O_RDWR | os.O_CREATE
	// If it's a fresh write (offset 0) and not an append, truncate
	if r.Pflags().Write && !r.Pflags().Append {
		// We handle truncation manually or via OpenFile flags if offset is 0
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

	return &statWriter{File: f, h: h, rel: rel, oldSize: oldSize}, nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := h.securePath(r.Filepath)
	if r.Method == "List" {
		entries, _ := os.ReadDir(full)
		var files []os.FileInfo
		if rel == "." {
			data, _ := embeddedSource.ReadFile("main.go")
			files = append(files, &sftpFile{name: "README.txt", size: int64(len(data)), mode: 0444, modTime: time.Now()})
		}
		for _, e := range entries {
			fi, _ := e.Info()
			var owner string
			h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", filepath.ToSlash(filepath.Join(rel, e.Name()))).Scan(&owner)
			files = append(files, newSftpFile(fi, owner))
		}
		return listerAt(files), nil
	}
	// Stat/Lstat
	fi, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	var owner string
	h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
	return listerAt{newSftpFile(fi, owner)}, nil
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	rel, full := h.securePath(r.Filepath)
	switch r.Method {
	case "Mkdir":
		if !h.srv.mkdirLimiter.Allow() {
			return h.deny("Rate limit exceeded.")
		}
		// Check parent ownership for mkdir
		pRel := filepath.ToSlash(filepath.Dir(rel))
		var pOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", pRel).Scan(&pOwner)
		if pOwner != "" && pOwner != h.pubHash {
			return h.deny("Cannot create directory in restricted parent.")
		}

		os.MkdirAll(full, 0755)
		h.srv.db.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash)
		return nil

	case "Remove", "Rmdir":
		var owner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if owner != "" && owner != h.pubHash {
			return h.deny("Ownership required for removal.")
		}
		os.RemoveAll(full)
		h.srv.db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
		return nil

	case "Rename":
		relTgt, fullTgt := h.securePath(r.Target)
		var sOwner, tOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&sOwner)
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relTgt).Scan(&tOwner)

		if sOwner != h.pubHash || (tOwner != "" && tOwner != h.pubHash) {
			return h.deny("Rename permission denied.")
		}

		if err := os.Rename(full, fullTgt); err != nil {
			return err
		}

		// Atomic path update for directory and all its children
		_, err := h.srv.db.Exec(`
			UPDATE files 
			SET path = ? || substr(path, length(?) + 1)
			WHERE path = ? OR path LIKE ?`,
			relTgt, rel, rel, rel+"/%")
		return err
	}
	return sftp.ErrSshFxOpUnsupported
}

// --- Internal Helpers ---

func (h *fsHandler) deny(msg string) error {
	fmt.Fprintf(h.stderr, "\r\n\033[1;31mERROR:\033[0m %s\r\n", msg)
	return sftp.ErrSshFxPermissionDenied
}

func (h *fsHandler) hasUploaded() bool {
	var count int
	h.srv.db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", h.pubHash).Scan(&count)
	return count > 0
}

func (s *Server) updateLoginStats(hash string) (st userStats) {
	now := time.Now().Format(time.DateTime)
	err := s.db.QueryRow("SELECT last_login, total_bytes, upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&st.LastLogin, &st.TotalBytes, &st.FilesUploadedCount)
	if err == sql.ErrNoRows {
		s.db.Exec("INSERT INTO users (pubkey_hash, last_login, total_bytes, upload_count) VALUES (?, ?, 0, 0)", hash, now)
		st.IsFirstLogin = true
	} else {
		s.db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return st
}

func (s *Server) reconcileOrphans() {
	s.logger.Info("starting orphan reconciliation")
	dummies := []string{"archivist", "collector", "legacy"}
	var dummyHashes []string
	for _, d := range dummies {
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(d)))
		s.db.Exec("INSERT OR IGNORE INTO users (pubkey_hash, last_login) VALUES (?, ?)", h, time.Now().Format(time.DateTime))
		dummyHashes = append(dummyHashes, h)
	}

	filepath.WalkDir(s.absUploadDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == s.absUploadDir {
			return nil
		}
		rel, _ := filepath.Rel(s.absUploadDir, path)
		rel = filepath.ToSlash(rel)

		var owner string
		if err := s.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner); err == sql.ErrNoRows {
			h := dummyHashes[rand.Intn(len(dummyHashes))]
			info, _ := d.Info()
			s.db.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, ?)", rel, h, info.Size())
		}
		return nil
	})
	s.logger.Info("orphan reconciliation complete")
}

func (s *Server) sendBanner(w io.Writer, hash string, stats userStats) {
	banner, _ := os.ReadFile(s.config.BannerFile)
	if len(banner) > 0 {
		fmt.Fprintf(w, "\r\n%s\r\n", string(banner))
	}
	uid := ownerHashToUid(hash)
	fmt.Fprintf(w, "Welcome anonymous-%d\r\n", uid)
	if stats.IsFirstLogin {
		fmt.Fprint(w, "Upload a file to unlock the full archive.\r\n")
	} else {
		fmt.Fprintf(w, "Total Shared: %d bytes across %d files\r\n", stats.TotalBytes, stats.FilesUploadedCount)
	}
}

type statWriter struct {
	*os.File
	h       *fsHandler
	rel     string
	oldSize int64
}

func (sw *statWriter) Close() error {
	fi, _ := sw.File.Stat()
	newSize := fi.Size()
	delta := newSize - sw.oldSize
	sw.h.srv.db.Exec("UPDATE files SET size = ? WHERE path = ?", newSize, sw.rel)
	sw.h.srv.db.Exec("UPDATE users SET total_bytes = total_bytes + ? WHERE pubkey_hash = ?", delta, sw.h.pubHash)
	return sw.File.Close()
}

type userStats struct {
	FilesUploadedCount int64
	LastLogin          string
	TotalBytes         int64
	IsFirstLogin       bool
}

type sftpFile struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	owner   string
}

func (s *sftpFile) Name() string       { return s.name }
func (s *sftpFile) Size() int64        { return s.size }
func (s *sftpFile) Mode() fs.FileMode  { return s.mode }
func (s *sftpFile) ModTime() time.Time { return s.modTime }
func (s *sftpFile) IsDir() bool        { return s.mode.IsDir() }
func (s *sftpFile) Sys() interface{} {
	uid := uint32(1000)
	if s.owner != "" {
		uid = ownerHashToUid(s.owner)
	}
	return &sftp.FileStat{UID: uid, GID: uid}
}

func newSftpFile(fi os.FileInfo, owner string) *sftpFile {
	return &sftpFile{name: fi.Name(), size: fi.Size(), mode: fi.Mode(), modTime: fi.ModTime(), owner: owner}
}

func ownerHashToUid(hash string) uint32 {
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
