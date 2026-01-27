package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

//go:embed main.go
var embeddedSource embed.FS

// Configuration
var (
	port        = flag.Int("port", 2222, "SSH port")
	hostKeyFile = flag.String("hostkey", "id_rsa", "SSH private host key")
	dbPath      = flag.String("db", "sftp.db", "Path to SQLite database")
	logFile     = flag.String("logfile", "sftp.log", "Path to log file")
	uploadDir   = flag.String("dir", "./uploads", "Directory to store uploads")
	bannerFile  = flag.String("banner", "BANNER.txt", "Path to banner file")
	mkdirLimit  = flag.Float64("rate", 10.0, "Global mkdir rate limit (folders/sec)")
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    pubkey_hash TEXT PRIMARY KEY,
    last_login DATETIME,
    upload_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    owner_hash TEXT
);`

var (
	db           *sql.DB
	mkdirLimiter *rate.Limiter
	logger       *log.Logger
)

func main() {
	flag.Parse()

	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(io.MultiWriter(os.Stdout, f), "[SFTP] ", log.LstdFlags)

	var dbErr error
	db, dbErr = sql.Open("sqlite", *dbPath)
	if dbErr != nil {
		logger.Fatal(dbErr)
	}
	db.Exec(schema)

	mkdirLimiter = rate.NewLimiter(rate.Limit(*mkdirLimit), 1)
	os.MkdirAll(*uploadDir, 0755)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			hash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": hash}}, nil
		},
	}

	keyBytes, err := os.ReadFile(*hostKeyFile)
	if err != nil {
		logger.Fatal("Host key not found. Generate one: ssh-keygen -f id_rsa -t rsa -N ''")
	}
	key, _ := ssh.ParsePrivateKey(keyBytes)
	config.AddHostKey(key)

	listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	logger.Printf("Server listening on port %d", *port)

	for {
		conn, _ := listener.Accept()
		go handleConn(conn, config)
	}
}

func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sConn.Close()

	pubHash := sConn.Permissions.Extensions["pubkey-hash"]
	stats := updateLoginStats(pubHash)
	logger.Printf("User anonymous-%s (%s) logged in from %s", pubHash[:12], sConn.User(), nConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, _ := newCh.Accept()
		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)

					// RULE 8: Send banner/stats to Stderr to avoid corrupting the SFTP stream
					sendBanner(ch.Stderr(), pubHash, stats)

					handler := &fsHandler{pubHash: pubHash}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet:  handler,
						FilePut:  handler,
						FileCmd:  handler,
						FileList: handler,
					})
					server.Serve()
				}
			}
		}(reqs)
	}
}

type fsHandler struct{ pubHash string }

func (f *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	// 1. Normalize path: remove leading slashes and dot-references
	cleanPath := filepath.Base(filepath.Clean(r.Filepath))

	// Rule 6: README.txt access (Check base name only)
	if cleanPath == "README.txt" {
		data, err := embeddedSource.ReadFile("main.go")
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(data), nil
	}

	// Rule 5: Download permissions
	if !hasUploaded(f.pubHash) {
		// Log the attempt
		logger.Printf("User %s blocked from downloading %s (no uploads yet)", f.pubHash[:12], cleanPath)
		// We return a specific error message that the client will display
		return nil, fmt.Errorf("PERMISSION DENIED: You must upload at least one file before you can download. Total bytes uploaded: 0")
	}

	// Join with the actual upload directory
	fullPath := filepath.Join(*uploadDir, cleanPath)
	return os.Open(fullPath)
}

func (f *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	cleanPath := filepath.Base(filepath.Clean(r.Filepath))
	fullPath := filepath.Join(*uploadDir, cleanPath)

	// Rule 7 & 13: Ownership/Resume logic
	var owner string
	err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", cleanPath).Scan(&owner)

	// If file exists and you aren't the owner
	if err == nil && owner != f.pubHash {
		return nil, fmt.Errorf("DENIED: File '%s' was uploaded by another user", cleanPath)
	}

	// Open file for writing (O_RDWR allows resuming/WriteAt)
	file, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// If this is a new file, register ownership
	if err != nil || owner == "" {
		db.Exec("INSERT OR IGNORE INTO files (path, owner_hash) VALUES (?, ?)", cleanPath, f.pubHash)
		db.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", f.pubHash)
	}

	logger.Printf("User %s writing to %s", f.pubHash[:12], cleanPath)
	return &statWriter{File: file, pubHash: f.pubHash}, nil
}

func (f *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	// Ensure we are reading the correct directory
	targetDir := *uploadDir

	files, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}

	res := make([]os.FileInfo, 0)

	// Always show README.txt in the root listing
	if r.Filepath == "/" || r.Filepath == "." || r.Filepath == "" {
		data, _ := embeddedSource.ReadFile("main.go")
		res = append(res, &virtualFileInfo{name: "README.txt", size: int64(len(data))})
	}

	for _, fl := range files {
		if info, err := fl.Info(); err == nil {
			// Don't show the physical README if it exists in the folder to avoid confusion
			if info.Name() != "README.txt" {
				res = append(res, info)
			}
		}
	}
	return listerAt(res), nil
}

func (f *fsHandler) Filecmd(r *sftp.Request) error {
	cleanPath := filepath.Clean(r.Filepath)
	fullPath := filepath.Join(*uploadDir, cleanPath)

	switch r.Method {
	case "Mkdir":
		if !mkdirLimiter.Allow() {
			return errors.New("rate limit exceeded")
		}
		logger.Printf("User %s mkdir %s", f.pubHash[:12], cleanPath)
		return os.MkdirAll(fullPath, 0755)
	case "Remove", "Rename":
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", cleanPath).Scan(&owner)
		if owner != f.pubHash {
			return errors.New("PERMISSION DENIED: You can only modify files you uploaded.")
		}
		if r.Method == "Remove" {
			db.Exec("DELETE FROM files WHERE path = ?", cleanPath)
			return os.Remove(fullPath)
		}
		target := filepath.Clean(r.Target)
		db.Exec("UPDATE files SET path = ? WHERE path = ?", target, cleanPath)
		return os.Rename(fullPath, filepath.Join(*uploadDir, target))
	case "Setstat":
		return errors.New("PERMISSION DENIED: Manual permission changes are disabled.")
	}
	return nil
}

// --- Helpers ---

type userStats struct {
	LastLogin  string
	TotalBytes int64
}

func updateLoginStats(hash string) userStats {
	now := time.Now().Format("2006-01-02 15:04:05")
	var stats userStats
	err := db.QueryRow("SELECT last_login, total_bytes FROM users WHERE pubkey_hash = ?", hash).Scan(&stats.LastLogin, &stats.TotalBytes)
	if err != nil {
		db.Exec("INSERT INTO users (pubkey_hash, last_login, total_bytes) VALUES (?, ?, 0)", hash, now)
		stats.LastLogin = "First Login"
	} else {
		db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return stats
}

func hasUploaded(hash string) bool {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM files WHERE owner_hash = ?", hash).Scan(&count)
	return count > 0
}

func sendBanner(w io.Writer, hash string, stats userStats) {
	banner, _ := os.ReadFile(*bannerFile)
	fmt.Fprintf(w, "\r\n%s\r\n", string(banner))
	fmt.Fprintf(w, "ID: anonymous-%s\r\n", hash[:12])
	fmt.Fprintf(w, "Last Login: %s\r\n", stats.LastLogin)
	fmt.Fprintf(w, "Total Uploaded: %d bytes\r\n\r\n", stats.TotalBytes)
}

type statWriter struct {
	*os.File
	pubHash string
}

func (sw *statWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := sw.File.WriteAt(p, off)
	if n > 0 {
		db.Exec("UPDATE users SET total_bytes = total_bytes + ? WHERE pubkey_hash = ?", n, sw.pubHash)
	}
	return n, err
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

type virtualFileInfo struct {
	name string
	size int64
}

func (v *virtualFileInfo) Name() string       { return v.name }
func (v *virtualFileInfo) Size() int64        { return v.size }
func (v *virtualFileInfo) Mode() fs.FileMode  { return 0444 }
func (v *virtualFileInfo) ModTime() time.Time { return time.Now() }
func (v *virtualFileInfo) IsDir() bool        { return false }
func (v *virtualFileInfo) Sys() interface{}   { return nil }
