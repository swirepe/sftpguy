package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var db *sql.DB

// Requirement 2: Hash public key to create the username
func getUsername(pubKey ssh.PublicKey) string {
	hash := sha256.Sum256(pubKey.Marshal())
	return fmt.Sprintf("anonymous%x", hash[:8])
}

// lister implements the sftp.ListerAt interface
type lister []os.FileInfo

func (l lister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func main() {
	// Initialize Database
	var err error
	db, err = sql.Open("sqlite3", "./sftp_meta.db")
	if err != nil {
		log.Fatal(err)
	}
	setupDB()

	// SSH Server Configuration
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			user := getUsername(pubKey)

			// Requirement 6: Get stats before updating login time
			var lastLogin string
			var totalBytes int64
			err := db.QueryRow("SELECT last_login, bytes_uploaded FROM users WHERE username = ?", user).Scan(&lastLogin, &totalBytes)

			if err == sql.ErrNoRows {
				lastLogin = "Never (First login)"
				_, _ = db.Exec("INSERT INTO users (username, last_login, bytes_uploaded) VALUES (?, ?, 0)", user, time.Now().Format(time.RFC3339))
			} else {
				_, _ = db.Exec("UPDATE users SET last_login = ? WHERE username = ?", time.Now().Format(time.RFC3339), user)
			}

			// Return stats in extensions to pass to the SFTP handler
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-username": user,
					"msg":             fmt.Sprintf("\nWelcome %s\nLast Login: %s\nTotal Uploaded: %d bytes\n", user, lastLogin, totalBytes),
				},
			}, nil
		},
	}

	// Load host key (generate with: ssh-keygen -t rsa -f host_key -N "")
	privateBytes, err := os.ReadFile("host_key")
	if err != nil {
		log.Fatal("Failed to load private key (host_key)")
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	config.AddHostKey(private)

	// Start Listener
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal("failed to listen on port 2222")
	}
	fmt.Println("SFTP Server running on port 2222...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, config)
	}
}

func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}

	// Requirement 6: Display banner
	fmt.Print(sshConn.Permissions.Extensions["msg"])

	go ssh.DiscardRequests(reqs)

	for newChann := range chans {
		if newChann.ChannelType() != "session" {
			newChann.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, _ := newChann.Accept()
		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)

					// Start SFTP handler
					user := sshConn.Permissions.Extensions["pubkey-username"]
					handler := &customHandler{username: user, root: "./sftp_data"}
					server := sftp.NewRequestServer(channel, sftp.Handlers{
						FileGet:  handler,
						FilePut:  handler,
						FileCmd:  handler,
						FileList: handler,
					})
					if err := server.Serve(); err == io.EOF {
						server.Close()
					}
				}
			}
		}(requests)
	}
}

// --- SFTP Logic Implementation ---

type customHandler struct {
	username string
	root     string
}

func (h *customHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	// Requirement 4: Only users that have uploaded can download
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM files WHERE owner = ?", h.username).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("permission denied: you must upload a file before you can download")
	}
	return os.Open(filepath.Join(h.root, r.Filepath))
}

func (h *customHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	// Requirement 3: Any user can upload
	path := filepath.Join(h.root, r.Filepath)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	// Requirement 5: Track ownership for modifications/deletions
	_, _ = db.Exec("INSERT OR REPLACE INTO files (filename, owner) VALUES (?, ?)", r.Filepath, h.username)

	return &wrappedWriter{File: f, username: h.username}, nil
}

func (h *customHandler) Filecmd(r *sftp.Request) error {
	// Requirement 5: Only owners can delete or rename
	if r.Method == "Remove" || r.Method == "Rename" {
		var owner string
		err := db.QueryRow("SELECT owner FROM files WHERE filename = ?", r.Filepath).Scan(&owner)
		if err != nil || owner != h.username {
			return fmt.Errorf("permission denied: you do not own this file")
		}
	}

	// Standard OS operations
	path := filepath.Join(h.root, r.Filepath)
	switch r.Method {
	case "Remove":
		return os.Remove(path)
	case "Rename":
		return os.Rename(path, filepath.Join(h.root, r.Target))
	case "Mkdir":
		return os.Mkdir(path, 0755)
	}
	return nil
}

func (h *customHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	// Requirement 3: Any user can list
	path := filepath.Join(h.root, r.Filepath)

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var infos []os.FileInfo
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		infos = append(infos, info)
	}

	return lister(infos), nil
}

// Helper to track bytes uploaded
type wrappedWriter struct {
	*os.File
	username string
}

func (w *wrappedWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := w.File.WriteAt(p, off)
	if n > 0 {
		_, _ = db.Exec("UPDATE users SET bytes_uploaded = bytes_uploaded + ? WHERE username = ?", n, w.username)
	}
	return n, err
}

func setupDB() {
	db.Exec(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, last_login TEXT, bytes_uploaded INTEGER)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS files (filename TEXT PRIMARY KEY, owner TEXT)`)
}
