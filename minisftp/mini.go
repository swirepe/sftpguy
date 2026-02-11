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

	db, _ := sql.Open("sqlite", c.DB)
	db.Exec(Schema)
	os.MkdirAll(c.Dir, 0755)

	signer := getSigner(c.Key)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			h := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			db.Exec("INSERT OR IGNORE INTO users (hash) VALUES (?)", h)
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-hash": h}}, nil
		},
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "\r\n" +
				"░█▀▀░█░█░█▀█░█▀▄░█▀▀░░░█▀▀░▀█▀░█▀▄░█▀▀░▀█▀░░░█▀▀░█▀▀░▀█▀░█▀█\r\n" +
				"░▀▀█░█▀█░█▀█░█▀▄░█▀▀░░░█▀▀░░█░░█▀▄░▀▀█░░█░░░░▀▀█░█▀▀░░█░░█▀▀\r\n" +
				"░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░░░▀░░░▀▀▀░▀░▀░▀▀▀░░▀░░░░▀▀▀░▀░░░░▀░░▀░░\r\n" +
				"Welcome.\r\n" +
				"This is a share first sftp archive.\r\n" +
				"Please upload 1MB to unlock full downloads.\r\n\r\n"

		},
	}
	cfg.AddHostKey(signer)

	l, _ := net.Listen("tcp", fmt.Sprintf(":%d", c.Port))
	log.Printf("SFTP Server online on :%d", c.Port)

	for {
		conn, _ := l.Accept()
		go func() {
			sConn, chans, reqs, _ := ssh.NewServerConn(conn, cfg)
			go ssh.DiscardRequests(reqs)
			for ch := range chans {
				if ch.ChannelType() != "session" {
					continue
				}
				channel, requests, _ := ch.Accept()
				go func(sChan ssh.Channel, in <-chan *ssh.Request) {
					defer sChan.Close()
					for req := range in {
						switch req.Type {
						case "subsystem":
							if string(req.Payload[4:]) == "sftp" {
								req.Reply(true, nil)
								addr := sConn.RemoteAddr().String()
								h := sConn.Permissions.Extensions["pubkey-hash"]
								handler := &fsHandler{db: db, hash: h, remoteAddr: addr, cfg: c, stderr: channel.Stderr()}
								server := sftp.NewRequestServer(channel, sftp.Handlers{FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler})
								server.Serve()
								return
							}
						case "env":
							// Accept environment variables but ignore them
							req.Reply(true, nil)
						case "shell":
							req.Reply(true, nil)
							fmt.Fprintln(sChan, "This server is SFTP-only. Shell access is not permitted.")
							return
						case "pty-req":
							// Some clients request a terminal before a shell
							req.Reply(true, nil)
						default:
							// Reject everything else (exec, x11, etc)
							req.Reply(false, nil)
						}

					}
				}(channel, requests)
			}
		}()
	}
}

type fsHandler struct {
	db         *sql.DB
	hash       string
	remoteAddr string
	cfg        Config
	stderr     io.Writer
}

func (h *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	rel := h.clean(r.Filepath)
	if !h.isUnrestricted(rel) {
		var up int64
		h.db.QueryRow("SELECT uploaded FROM users WHERE hash = ?", h.hash).Scan(&up)
		if up < h.cfg.Threshold {
			fmt.Fprintf(h.stderr, "Denied: Upload %d more bytes to unlock.\n", h.cfg.Threshold-up)
			return nil, sftp.ErrSSHFxPermissionDenied
		}
	}
	return os.Open(filepath.Join(h.cfg.Dir, rel))
}

func (h *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel := h.clean(r.Filepath)
	if err := h.canModify(rel); err != nil {
		return nil, err
	}

	full := filepath.Join(h.cfg.Dir, rel)
	os.MkdirAll(path.Dir(full), 0755)

	f, _ := os.OpenFile(full, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	h.db.Exec("INSERT OR REPLACE INTO files (path, owner, size, is_dir) VALUES (?, ?, 0, 0)", rel, h.hash)
	return &statWriter{File: f, h: h, rel: rel}, nil
}

func (h *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel := h.clean(r.Filepath)
	full := filepath.Join(h.cfg.Dir, rel)

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
			} // Skip files we can't stat
			files = append(files, h.wrap(info, path.Join(rel, e.Name())))
		}
		return listerAt(files), nil
	}

	// Stat, Lstat, Fstat
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return listerAt{h.wrap(fi, rel)}, nil
}

func (h *fsHandler) Filecmd(r *sftp.Request) error {
	rel := h.clean(r.Filepath)
	full := filepath.Join(h.cfg.Dir, rel)
	if r.Method == "Mkdir" {
		os.MkdirAll(full, 0755)
		h.db.Exec("INSERT OR REPLACE INTO files (path, owner, is_dir) VALUES (?, ?, 1)", rel, h.hash)
		return nil
	}
	if _, err := os.Lstat(full); err != nil {
		return os.ErrNotExist
	}
	if err := h.canModify(rel); err != nil {
		return err
	}

	switch r.Method {
	case "Remove", "Rmdir":
		os.RemoveAll(full)
		h.db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
	case "Rename":
		tRel := h.clean(r.Target)
		os.Rename(full, filepath.Join(h.cfg.Dir, tRel))
		h.db.Exec("UPDATE files SET path = ? WHERE path = ?", tRel, rel)
	}
	return nil
}

func (h *fsHandler) clean(p string) string {
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

func (h *fsHandler) canModify(rel string) error {
	var owner string
	h.db.QueryRow("SELECT owner FROM files WHERE path = ?", rel).Scan(&owner)
	if owner != "" && owner != h.hash && owner != "system" {
		fmt.Fprintln(h.stderr, "Denied: File owned by another user.")
		return sftp.ErrSSHFxPermissionDenied
	}
	return nil
}

func (h *fsHandler) isUnrestricted(rel string) bool {
	for _, p := range strings.Split(h.cfg.Unrestricted, ",") {
		p = strings.TrimSpace(p)
		if rel == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p)) {
			return true
		}
	}
	return false
}

type statWriter struct {
	*os.File
	h   *fsHandler
	rel string
}

func (w *statWriter) Close() error {
	fi, err := w.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	w.h.db.Exec("UPDATE files SET size = ? WHERE path = ?", size, w.rel)
	w.h.db.Exec("UPDATE users SET uploaded = uploaded + ? WHERE hash = ?", size, w.h.hash)

	log.Printf("[UPLOAD] Path: %q, Size: %d, UserHash: %s, Address: %s",
		w.rel, size, w.h.hash, w.h.remoteAddr)

	return w.File.Close()
}

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

func getSigner(path string) ssh.Signer {
	if data, err := os.ReadFile(path); err == nil {
		s, _ := ssh.ParsePrivateKey(data)
		return s
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := x509.MarshalPKCS8PrivateKey(priv)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: b})
	f.Close()
	s, _ := ssh.NewSignerFromKey(priv)
	return s
}
