package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

const Schema = `
CREATE TABLE IF NOT EXISTS users (hash TEXT PRIMARY KEY, uploaded INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, owner TEXT, size INTEGER, is_dir INT);
INSERT OR IGNORE INTO users (hash) VALUES ('system');`

// maxFileSize caps individual uploads at 10 GiB to prevent disk exhaustion.
const maxFileSize = 10 << 30

type Config struct {
	Port         int
	Dir          string
	DB           string
	Key          string
	Threshold    int64
	Unrestricted string
}

func main() {
	c := Config{}
	flag.IntVar(&c.Port, "p", 2222, "Port")
	flag.StringVar(&c.Dir, "d", "./uploads", "Upload Dir")
	flag.StringVar(&c.DB, "db", "sftp.db", "DB Path")
	flag.StringVar(&c.Key, "k", "id_ed25519", "Host Key")
	flag.Int64Var(&c.Threshold, "t", 1024*1024, "Threshold (bytes)")
	flag.StringVar(&c.Unrestricted, "u", "README.txt,public/", "Unrestricted paths")
	flag.Parse()

	// WAL mode + busy timeout for concurrent writers.
	db, err := sql.Open("sqlite", c.DB+"?_journal=WAL&_timeout=5000")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(Schema); err != nil {
		log.Fatalf("init schema: %v", err)
	}
	if err := os.MkdirAll(c.Dir, 0755); err != nil {
		log.Fatalf("create upload dir: %v", err)
	}
	signer, err := getSigner(c.Key)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			h := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			if _, err := db.Exec("INSERT OR IGNORE INTO users (hash) VALUES (?)", h); err != nil {
				log.Printf("insert user %s: %v", h[:8], err)
			}
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": h}}, nil
		},
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "\r\n" +
				"░█▀▀░█░█░█▀█░█▀▄░█▀▀░░░█▀▀░▀█▀░█▀▄░█▀▀░▀█▀░░░█▀▀░█▀▀░▀█▀░█▀█\r\n" +
				"░▀▀█░█▀█░█▀█░█▀▄░█▀▀░░░█▀▀░░█░░█▀▄░▀▀█░░█░░░░▀▀█░█▀▀░░█░░█▀▀\r\n" +
				"░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░░░▀░░░▀▀▀░▀░▀░▀▀▀░░▀░░░░▀▀▀░▀░░░░▀░░▀░░\r\n" +
				"Welcome. This is a share-first SFTP archive.\r\n\r\n"
		},
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", c.Port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("SFTP Server online on :%d", c.Port)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, cfg, db, c)
	}
}

func handleConn(conn net.Conn, cfg *ssh.ServerConfig, db *sql.DB, c Config) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		log.Printf("ssh handshake from %s: %v", conn.RemoteAddr(), err)
		return
	}
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			log.Printf("accept channel: %v", err)
			continue
		}
		go handleSession(channel, requests, sConn, db, c)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, sConn *ssh.ServerConn, db *sql.DB, c Config) {
	defer channel.Close()

	h := &fsHandler{
		db:         db,
		hash:       sConn.Permissions.Extensions["pubkey-hash"],
		remoteAddr: sConn.RemoteAddr().String(),
		cfg:        c,
		stderr:     channel.Stderr(),
	}
	h.printStatus()

	for req := range requests {
		switch req.Type {
		case "subsystem":
			if len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				sftp.NewRequestServer(channel, sftp.Handlers{
					FileGet: h, FilePut: h, FileCmd: h, FileList: h,
				}).Serve()
				return
			}
			req.Reply(false, nil)
		case "env", "pty-req":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			fmt.Fprintln(channel, "This server is SFTP-only. Shell access is not permitted.")
			return
		default:
			req.Reply(false, nil)
		}
	}
}

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

// --- fsHandler ---

type fsHandler struct {
	db         *sql.DB
	hash       string
	remoteAddr string
	cfg        Config
	stderr     io.Writer
}

func (h *fsHandler) printStatus() {
	var uploaded int64
	h.db.QueryRow("SELECT uploaded FROM users WHERE hash = ?", h.hash).Scan(&uploaded)
	if uploaded >= h.cfg.Threshold {
		fmt.Fprintf(h.stderr, "\u2713 Downloads unlocked. You have uploaded %s.\r\n", formatBytes(uploaded))
	} else {
		fmt.Fprintf(h.stderr, "\u2191 Upload progress: %s / %s \u2014 upload %s more to unlock downloads.\r\n",
			formatBytes(uploaded), formatBytes(h.cfg.Threshold), formatBytes(h.cfg.Threshold-uploaded))
	}
}

func (h *fsHandler) deny(format string, args ...any) error {
	fmt.Fprintf(h.stderr, "Denied: "+format+"\n", args...)
	return sftp.ErrSSHFxPermissionDenied
}

func (h *fsHandler) dbExec(query string, args ...any) {
	if _, err := h.db.Exec(query, args...); err != nil {
		log.Printf("dbExec %q: %v", query, err)
	}
}

func (h *fsHandler) withTx(fn func(*sql.Tx) error) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ownerCheck returns a permission error if rel is owned by a different user.
// Accepts either *sql.DB or *sql.Tx via the shared QueryRow interface.
func (h *fsHandler) ownerCheck(q interface{ QueryRow(string, ...any) *sql.Row }, rel string) error {
	var owner string
	q.QueryRow("SELECT owner FROM files WHERE path = ?", rel).Scan(&owner)
	if owner != "" && owner != h.hash && owner != "system" {
		return h.deny("File owned by another user.")
	}
	return nil
}

func (h *fsHandler) clean(p string) string {
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

func (h *fsHandler) safePath(rel string) (string, error) {
	base, err := filepath.Abs(h.cfg.Dir)
	if err != nil {
		return "", err
	}
	full := filepath.Join(base, rel)
	if !strings.HasPrefix(full, base+string(filepath.Separator)) && full != base {
		return "", fmt.Errorf("path traversal: %q escapes root", rel)
	}
	return full, nil
}

func (h *fsHandler) isUnrestricted(rel string) bool {
	for _, p := range strings.Split(h.cfg.Unrestricted, ",") {
		p = strings.TrimSpace(p)
		if rel == p || strings.HasPrefix(rel, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// --- SFTP handlers ---

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	rel := h.clean(r.Filepath)
	if !h.isUnrestricted(rel) {
		var up int64
		if err := h.db.QueryRow("SELECT uploaded FROM users WHERE hash = ?", h.hash).Scan(&up); err != nil {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		if up < h.cfg.Threshold {
			return nil, h.deny("Upload %d more bytes to unlock.", h.cfg.Threshold-up)
		}
	}
	full, err := h.safePath(rel)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	return os.Open(full)
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel := h.clean(r.Filepath)
	full, err := h.safePath(rel)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	// Atomically check ownership and claim the file record.
	if err := h.withTx(func(tx *sql.Tx) error {
		if err := h.ownerCheck(tx, rel); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT OR REPLACE INTO files (path, owner, size, is_dir) VALUES (?, ?, 0, 0)", rel, h.hash)
		return err
	}); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path.Dir(full), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return &statWriter{File: f, h: h, rel: rel}, nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel := h.clean(r.Filepath)
	full, err := h.safePath(rel)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	if r.Method == "List" {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
		var files []os.FileInfo
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			files = append(files, h.wrap(info, path.Join(rel, e.Name())))
		}
		return listerAt(files), nil
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return listerAt{h.wrap(fi, rel)}, nil
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	rel := h.clean(r.Filepath)
	full, err := h.safePath(rel)
	if err != nil {
		return sftp.ErrSSHFxPermissionDenied
	}
	if r.Method == "Mkdir" {
		if parent := path.Dir(rel); parent != "." && parent != "" {
			if err := h.ownerCheck(h.db, parent); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(full, 0755); err != nil {
			return err
		}
		h.dbExec("INSERT OR REPLACE INTO files (path, owner, is_dir) VALUES (?, ?, 1)", rel, h.hash)
		return nil
	}
	if _, err := os.Lstat(full); err != nil {
		return os.ErrNotExist
	}
	if err := h.ownerCheck(h.db, rel); err != nil {
		return err
	}
	switch r.Method {
	case "Remove", "Rmdir":
		if err := os.RemoveAll(full); err != nil {
			return err
		}
		h.dbExec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
	case "Rename":
		tRel := h.clean(r.Target)
		tFull, err := h.safePath(tRel)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
		if err := os.Rename(full, tFull); err != nil {
			return err
		}
		h.dbExec("UPDATE files SET path = ? WHERE path = ?", tRel, rel)
	}
	return nil
}

// --- statWriter ---

type statWriter struct {
	*os.File
	h   *fsHandler
	rel string
}

func (w *statWriter) WriteAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > maxFileSize {
		return 0, w.h.deny("File would exceed maximum size of %s.", formatBytes(maxFileSize))
	}
	return w.File.WriteAt(p, off)
}

func (w *statWriter) Close() error {
	defer w.File.Close()
	fi, err := w.Stat()
	if err != nil {
		return err
	}
	newSize := fi.Size()
	return w.h.withTx(func(tx *sql.Tx) error {
		var oldSize int64
		tx.QueryRow("SELECT size FROM files WHERE path = ?", w.rel).Scan(&oldSize)
		delta := max(newSize-oldSize, 0)
		if _, err := tx.Exec("UPDATE files SET size = ? WHERE path = ?", newSize, w.rel); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE users SET uploaded = uploaded + ? WHERE hash = ?", delta, w.h.hash); err != nil {
			return err
		}
		log.Printf("[UPLOAD] Path: %q, Size: %d, Delta: %d, UserHash: %s, Address: %s",
			w.rel, newSize, delta, w.h.hash, w.h.remoteAddr)
		w.h.printStatus()
		return nil
	})
}

// --- misc helpers ---

func (h *fsHandler) wrap(fi os.FileInfo, rel string) os.FileInfo {
	if fi == nil {
		return nil
	}
	var owner string
	h.db.QueryRow("SELECT owner FROM files WHERE path = ?", rel).Scan(&owner)
	return &wrappedFI{fi, hashToUid(owner)}
}

type wrappedFI struct {
	os.FileInfo
	uid uint32
}

func (w *wrappedFI) Sys() interface{} { return &sftp.FileStat{UID: w.uid, GID: w.uid} }

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

func hashToUid(h string) uint32 {
	if h == "" || h == "system" {
		return 1000
	}
	f := fnv.New32a()
	f.Write([]byte(h))
	return f.Sum32() & 0x7FFFFFFF
}

func getSigner(keyPath string) (ssh.Signer, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		s, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key: %w", err)
		}
		return s, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
		return nil, fmt.Errorf("encode key: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return s, nil
}
