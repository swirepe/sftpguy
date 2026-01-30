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
	version         = "1.1.1"
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
	flag.Float64Var(&cfg.MkdirRate, "rate", 10.0, "Global mkdir rate limit")
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
	db.Exec("PRAGMA journal_mode=WAL;")
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

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		s.logger.Error("failed to listen", "err", err)
		os.Exit(1)
	}
	s.logger.Info("server listening", "port", s.config.Port)

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
	s.logger.Info("user logged in", "hash", pubHash[:12], "addr", nConn.RemoteAddr().String())

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
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
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

func (h *fsHandler) securePath(p string) (rel string, full string) {
	clean := filepath.FromSlash(p)
	full = filepath.Join(h.srv.absUploadDir, clean)

	// Final verification that path is contained in upload dir
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
		return nil, h.deny("You must share at least one file to participate in the archive.")
	}

	return os.Open(full)
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full := h.securePath(r.Filepath)

	// Check Parent ownership (can't upload into someone else's folder)
	parentRel := filepath.ToSlash(filepath.Dir(rel))
	if parentRel != "." {
		var pOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", parentRel).Scan(&pOwner)
		if pOwner != "" && pOwner != h.pubHash {
			return nil, h.deny("You do not have permission to write to this folder.")
		}
	}

	tx, _ := h.srv.db.Begin()
	var owner string
	err := tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)

	if err == sql.ErrNoRows {
		tx.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash)
		tx.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", h.pubHash)
	} else if owner != h.pubHash {
		tx.Rollback()
		return nil, h.deny("This file name is already claimed by another archivist.")
	}
	tx.Commit()

	os.MkdirAll(filepath.Dir(full), 0755)

	// Handle Truncate vs Resume
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

	return &statWriter{File: f, h: h, rel: rel, oldSize: oldSize}, nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := h.securePath(r.Filepath)

	if r.Method == "List" {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
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
			return h.deny("Global mkdir rate limit reached.")
		}
		pRel := filepath.ToSlash(filepath.Dir(rel))
		var pOwner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", pRel).Scan(&pOwner)
		if pOwner != "" && pOwner != h.pubHash {
			return h.deny("Cannot create directory inside another user's folder.")
		}

		os.MkdirAll(full, 0755)
		h.srv.db.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, h.pubHash)
		return nil

	case "Remove", "Rmdir":
		var owner string
		h.srv.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if owner != "" && owner != h.pubHash {
			return h.deny("You can only remove your own creations.")
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
			return h.deny("Rename permission denied (ownership mismatch).")
		}

		if err := os.Rename(full, fullTgt); err != nil {
			return err
		}

		h.srv.db.Exec(`
			UPDATE files 
			SET path = ? || substr(path, length(?) + 1)
			WHERE path = ? OR path LIKE ?`,
			relTgt, rel, rel, rel+"/%")
		return nil
	}
	return sftp.ErrSshFxOpUnsupported
}

// --- Helpers ---

func (h *fsHandler) deny(msg string) error {
	fmt.Fprintf(h.stderr, "\r\n\033[1;31mPERMISSION DENIED:\033[0m %s\r\n", msg)
	return sftp.ErrSshFxPermissionDenied
}

func (h *fsHandler) hasUploaded() bool {
	var count int
	h.srv.db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", h.pubHash).Scan(&count)
	return count > 0
}

func (s *Server) updateLoginStats(hash string) (st userStats) {
	now := time.Now().Format("2006-01-02 15:04:05")
	err := s.db.QueryRow("SELECT last_login, total_bytes, upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&st.LastLogin, &st.TotalBytes, &st.FilesUploadedCount)
	if err == sql.ErrNoRows {
		s.db.Exec("INSERT INTO users (pubkey_hash, last_login, total_bytes, upload_count) VALUES (?, ?, 0, 0)", hash, now)
		st.IsFirstLogin = true
		st.LastLogin = "Never"
	} else {
		s.db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return st
}

func (s *Server) sendBanner(w io.Writer, hash string, stats userStats) {
	banner, err := os.ReadFile(s.config.BannerFile)
	if err == nil {
		fmt.Fprintf(w, "\r\n%s\r\n", string(banner))
	} else {
		fmt.Fprintf(w, "\r\n\033[1;34m=== %s - Anonymous SFTP Storage ===\033[0m\r\n", applicationName)
	}

	displayName := fmt.Sprintf("anonymous-%d", ownerHashToUid(hash))

	if stats.IsFirstLogin {
		fmt.Fprintf(w, boldAscii("Welcome, "+displayName, "This is a 'share-first' archive.\r\n"))
		fmt.Fprintf(w, "Upload something meaningful to unlock access to the collections of others.\r\n")
		fmt.Fprintf(w, "Download README.txt to view the server source code.\r\n")
	} else {
		fmt.Fprintf(w, "Username: %s\r\n", displayName)
		fmt.Fprintf(w, "Last Seen: %s\r\n", stats.LastLogin)
		fmt.Fprintf(w, "Contribution: %d bytes / %d files\r\n\r\n", stats.TotalBytes, stats.FilesUploadedCount)
	}

	if stats.FilesUploadedCount == 0 {
		fmt.Fprint(w, boldAscii("Reminder:", "You must upload a file before you can download."))
	} else if stats.TotalBytes > 1024 {
		fmt.Fprint(w, boldAscii("Thank you for contributing, "+displayName, "\r\nYour fortune:\r\n"))
		fortune := s.getRandomFortune()
		fmt.Fprintf(w, "\033[3;33m\"%s\"\033[0m\r\n\r\n", fortune)
	}
}

func (s *Server) getRandomFortune() string {
	data, err := embeddedSource.ReadFile("fortunes.txt")
	if err != nil {
		return "A path begins with a single upload."
	}
	content := string(data)
	var fortunes []string
	if strings.Contains(content, "\n%\n") {
		fortunes = strings.Split(content, "\n%\n")
	} else {
		fortunes = strings.Split(content, "\n")
	}

	var valid []string
	for _, f := range fortunes {
		f = strings.TrimSpace(f)
		if f != "" {
			valid = append(valid, f)
		}
	}
	if len(valid) == 0 {
		return "Fortune favors the bold archivist."
	}
	return valid[rand.Intn(len(valid))]
}

func boldAscii(header string, body string) string {
	return fmt.Sprintf("\r\n\033[1m%s\033[0m %s\r\n", header, body)
}

func (s *Server) reconcileOrphans() {
	s.logger.Info("scanning for orphans")
	dummies := []string{"archivist", "pioneer", "collector", "jennifer", "trodgor", "oxide"}
	var hashes []string
	for _, d := range dummies {
		h := fmt.Sprintf("%x", sha256.Sum256([]byte("dummy-"+d)))
		s.db.Exec("INSERT OR IGNORE INTO users (pubkey_hash, last_login) VALUES (?, '2020-01-01')", h)
		hashes = append(hashes, h)
	}

	filepath.WalkDir(s.absUploadDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == s.absUploadDir {
			return nil
		}
		rel, _ := filepath.Rel(s.absUploadDir, path)
		rel = filepath.ToSlash(rel)
		var owner string
		if err := s.db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner); err == sql.ErrNoRows {
			h := hashes[rand.Intn(len(hashes))]
			fi, _ := d.Info()
			s.db.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, ?)", rel, h, fi.Size())
		}
		return nil
	})
	s.logger.Info("orphan reconciliation finished")
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
	uid := ownerHashToUid(s.owner)
	return &sftp.FileStat{UID: uid, GID: uid}
}

func newSftpFile(fi os.FileInfo, owner string) *sftpFile {
	return &sftpFile{name: fi.Name(), size: fi.Size(), mode: fi.Mode(), modTime: fi.ModTime(), owner: owner}
}

func ownerHashToUid(hash string) uint32 {
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
