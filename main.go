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
	"log"
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

/*
  SPECIFICATION IMPLEMENTATION:
  1. Users identified by Public Key Hash (SHA256).
  2. Logging to console and file via multi-writer.
  3. UID/GIDs generated via FNV-1a hash of public key.
  4. Any user can upload/mkdir/list.
  5. Download requires at least one previous upload (except README.txt).
  6. README.txt is the source code, embedded via go:embed.
  7. Ownership checks on Rename, Remove, and Write.
  8. Login displays Banner, Last Login, and Total Bytes.
  9. Global rate limiting on Mkdir.
  10. Custom error messages sent to stderr for permission denials.
  11. Ownership enforced on directories and files.
  12. Fully configurable via flags.
  13. Resumable uploads supported via O_RDWR in Filewrite.

  Fortunes from:
  	 https://github.com/JKirchartz/fortunes/tree/master
	 https://github.com/ruanyf/fortunes
*/

//go:embed main.go
//go:embed fortunes.txt
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
    owner_hash TEXT,
    size INTEGER DEFAULT 0
);`

var (
	db           *sql.DB
	mkdirLimiter *rate.Limiter
	logger       *log.Logger
)

func main() {
	flag.Parse()

	// Initialize Logger
	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(io.MultiWriter(os.Stdout, f), "[SFTP] ", log.LstdFlags)

	// Initialize Database
	var dbErr error
	db, dbErr = sql.Open("sqlite", *dbPath)
	if dbErr != nil {
		logger.Fatalf("Failed to open database: %v", dbErr)
	}
	db.SetMaxOpenConns(1) // SQLite consistency
	db.Exec("PRAGMA journal_mode=WAL;")
	if _, err := db.Exec(schema); err != nil {
		logger.Fatalf("Failed to initialize schema: %v", err)
	}

	// Ensure upload directory exists
	if err := os.MkdirAll(*uploadDir, 0755); err != nil {
		logger.Fatalf("Failed to create upload directory: %v", err)
	}

	reconcileOrphans()

	// Initialize Rate Limiter
	mkdirLimiter = rate.NewLimiter(rate.Limit(*mkdirLimit), 1)

	// SSH Server Configuration
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
	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		logger.Fatalf("Failed to parse host key: %v", err)
	}
	config.AddHostKey(key)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		logger.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	logger.Printf("Server listening on port %d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}

func reconcileOrphans() {
	dummyNames := []string{"archivist", "pioneer", "collector", "jessica", "legacy", "trogdor", "orphaneer", "hoarder"}
	var dummies []string
	for _, name := range dummyNames {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte("dummy-key-"+name)))
		dummies = append(dummies, hash)

		db.Exec("INSERT OR IGNORE INTO users (pubkey_hash, last_login, upload_count, total_bytes) VALUES (?, '2020-01-01 00:00:00', 0, 0)", hash)
	}

	logger.Println("Scanning for orphaned files in upload directory...")

	err := filepath.WalkDir(*uploadDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Printf("Error walking path %s: %v", path, err)
			return err
		}

		if path == *uploadDir {
			return nil
		}

		// Get the relative path (the format used in the DB)
		rel, err := filepath.Rel(*uploadDir, path)
		if err != nil {
			logger.Printf("Error getting relative path for %s: %v", path, err)
			return nil
		}
		rel = filepath.ToSlash(rel) // Normalize separators for DB consistency

		var owner string
		err = db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if err == sql.ErrNoRows {
			chosenDummy := dummies[rand.Intn(len(dummies))]

			info, err := d.Info()
			if err != nil {
				logger.Printf("Error getting file info for %s: %v", rel, err)
				return nil
			}
			size := info.Size()

			_, err = db.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, ?)", rel, chosenDummy, size)
			if err == nil {
				db.Exec("UPDATE users SET upload_count = upload_count + 1, total_bytes = total_bytes + ? WHERE pubkey_hash = ?", size, chosenDummy)
				logger.Printf("Reconciled orphan: %s -> assigned to %s", rel, dummyNames[dummiesToIdx(chosenDummy, dummies)])
			} else {
				logger.Printf("Error inserting orphan %s: %v", rel, err)
			}
		} else if err != nil {
			logger.Printf("Error querying owner for %s: %v", rel, err)
		}
		return nil
	})

	if err != nil {
		logger.Printf("Error during orphan reconciliation: %v", err)
	}
}

// Helper for logging which name was used
func dummiesToIdx(hash string, list []string) int {
	for i, v := range list {
		if v == hash {
			return i
		}
	}
	return 0
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

		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}

		go func(in <-chan *ssh.Request, channel ssh.Channel) {
			defer channel.Close()
			for req := range in {
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)
					sendBanner(ch.Stderr(), pubHash, stats)

					handler := &fsHandler{
						pubHash: pubHash,
						stderr:  ch.Stderr(),
					}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet:  handler,
						FilePut:  handler,
						FileCmd:  handler,
						FileList: handler,
					})
					if err := server.Serve(); err != nil && err != io.EOF {
						logger.Printf("SFTP session ended with error: %v", err)
					}
					return
				}
			}
		}(reqs, ch)
	}
}

type fsHandler struct {
	pubHash string
	stderr  io.Writer
}

// secure ensures the path is relative to the upload directory and clean
func (f *fsHandler) secure(p string) (rel string, full string) {
	cleanPath := filepath.Clean(p)
	if cleanPath == "/" || cleanPath == "." || cleanPath == ".." {
		return ".", *uploadDir
	}
	// Remove leading slashes to make it relative for joining
	rel = strings.TrimPrefix(cleanPath, "/")
	// Re-verify that joining doesn't escape the uploadDir
	full = filepath.Join(*uploadDir, rel)
	// Normalize to forward slashes for database consistency
	rel = filepath.ToSlash(rel)
	return rel, full
}

func (f *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	relPath, fullPath := f.secure(r.Filepath)

	if relPath == "README.txt" {
		data, err := embeddedSource.ReadFile("main.go")
		if err != nil {
			logger.Printf("Error reading embedded source: %v", err)
			return nil, err
		}
		return bytes.NewReader(data), nil
	}

	if !hasUploaded(f.pubHash) {
		logger.Printf("User %s blocked from downloading %s (No previous uploads)", f.pubHash[:12], relPath)
		return nil, f.permissionDenied("You must successfully upload at least one file before you can download other files.")
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *fsHandler) permissionDenied(msg string) error {
	errString := fmt.Sprintf("\r\n\033[1;31mPERMISSION DENIED:\033[0m %s\r\n", msg)
	fmt.Fprint(f.stderr, errString)
	return sftp.ErrSshFxPermissionDenied
}

func (f *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full := f.secure(r.Filepath)

	// Ensure parent directory exists
	parentDir := filepath.Dir(full)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		logger.Printf("Error creating parent directory %s: %v", parentDir, err)
		return nil, err
	}

	// Use a transaction to atomically check and claim ownership
	tx, err := db.Begin()
	if err != nil {
		logger.Printf("Error beginning transaction: %v", err)
		return nil, err
	}

	var owner string
	err = tx.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)

	if err == sql.ErrNoRows {
		// File doesn't exist - claim ownership
		_, err = tx.Exec("INSERT INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, f.pubHash)
		if err != nil {
			tx.Rollback()
			logger.Printf("Error inserting file ownership for %s: %v", rel, err)
			return nil, err
		}
		_, err = tx.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", f.pubHash)
		if err != nil {
			tx.Rollback()
			logger.Printf("Error updating upload count: %v", err)
			return nil, err
		}
	} else if err != nil {
		tx.Rollback()
		logger.Printf("Error checking ownership for %s: %v", rel, err)
		return nil, err
	} else if owner != f.pubHash {
		// File exists and owned by someone else
		tx.Rollback()
		return nil, f.permissionDenied("This file is owned by another user.")
	}

	if err := tx.Commit(); err != nil {
		logger.Printf("Error committing transaction: %v", err)
		return nil, err
	}

	// Get current file size before opening for writing
	var oldSize int64
	fileInfo, err := os.Stat(full)
	if err == nil {
		oldSize = fileInfo.Size()
	}

	// Prepare file for writing (supports resume)
	file, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		logger.Printf("Error opening file %s for writing: %v", full, err)
		return nil, err
	}

	return &statWriter{file, f.pubHash, rel, oldSize}, nil
}

func (f *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := f.secure(r.Filepath)

	switch r.Method {
	case "List":
		items, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}

		res := make([]os.FileInfo, 0)
		// Virtual README in root
		if rel == "." {
			data, err := embeddedSource.ReadFile("main.go")
			if err != nil {
				logger.Printf("Error reading embedded source for README: %v", err)
			} else {
				res = append(res, &sftpFile{"README.txt", int64(len(data)), 0444, time.Now(), false, "system"})
			}
		}

		for _, item := range items {
			info, err := item.Info()
			if err != nil {
				logger.Printf("Error getting file info for %s: %v", item.Name(), err)
				continue
			}
			var owner string
			childPath := filepath.ToSlash(filepath.Join(rel, info.Name()))
			err = db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", childPath).Scan(&owner)
			if err != nil && err != sql.ErrNoRows {
				logger.Printf("Error querying owner for %s: %v", childPath, err)
			}
			res = append(res, newSftpFile(info.Name(), info, owner))
		}
		return listerAt(res), nil

	case "Stat", "Lstat":
		if rel == "README.txt" {
			data, err := embeddedSource.ReadFile("main.go")
			if err != nil {
				logger.Printf("Error reading embedded source for README stat: %v", err)
				return nil, err
			}
			return listerAt{&sftpFile{"README.txt", int64(len(data)), 0444, time.Now(), false, "system"}}, nil
		}

		info, err := os.Stat(full)
		if err != nil {
			return nil, err
		}
		var owner string
		err = db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if err != nil && err != sql.ErrNoRows {
			logger.Printf("Error querying owner for %s: %v", rel, err)
		}
		return listerAt{newSftpFile(info.Name(), info, owner)}, nil
	}
	return nil, sftp.ErrSshFxOpUnsupported
}

func (f *fsHandler) Filecmd(r *sftp.Request) error {
	rel, full := f.secure(r.Filepath)

	switch r.Method {
	case "Mkdir":
		if !mkdirLimiter.Allow() {
			return f.permissionDenied("Global directory creation limit reached. Please try again later.")
		}
		if err := os.MkdirAll(full, 0755); err != nil {
			return err
		}
		_, err := db.Exec("INSERT OR IGNORE INTO files (path, owner_hash, size) VALUES (?, ?, 0)", rel, f.pubHash)
		if err != nil {
			logger.Printf("Error recording directory ownership for %s: %v", rel, err)
		}
		logger.Printf("User %s created directory: %s", f.pubHash[:12], rel)
		return nil

	case "Remove":
		var owner string
		err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if err != nil && err != sql.ErrNoRows {
			logger.Printf("Error checking ownership for removal of %s: %v", rel, err)
			return err
		}
		if owner != "" && owner != f.pubHash {
			return f.permissionDenied("You can only delete files or directories you created.")
		}

		// Check if it's a directory and get all nested paths
		info, err := os.Stat(full)
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Delete all nested files from database
			_, err = db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
			if err != nil {
				logger.Printf("Error deleting nested files from database for %s: %v", rel, err)
			}
		} else {
			// Just delete the single file entry
			_, err = db.Exec("DELETE FROM files WHERE path = ?", rel)
			if err != nil {
				logger.Printf("Error deleting file from database %s: %v", rel, err)
			}
		}

		if err := os.RemoveAll(full); err != nil {
			return err
		}
		logger.Printf("User %s removed: %s", f.pubHash[:12], rel)
		return nil

	case "Rename":
		relTarget, fullTarget := f.secure(r.Target)

		// Check source ownership
		var sourceOwner string
		err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&sourceOwner)
		if err == sql.ErrNoRows {
			return f.permissionDenied("Source file does not exist.")
		}
		if err != nil {
			logger.Printf("Error checking source ownership for rename: %v", err)
			return err
		}
		if sourceOwner != f.pubHash {
			return f.permissionDenied("You do not own the source file.")
		}

		// Check target ownership if it exists
		var targetOwner string
		err = db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relTarget).Scan(&targetOwner)
		if err == nil && targetOwner != "" && targetOwner != f.pubHash {
			return f.permissionDenied("The destination already exists and is owned by another user.")
		}

		// Check if source is a directory
		info, err := os.Stat(full)
		if err != nil {
			return err
		}

		// Perform filesystem rename first
		if err := os.Rename(full, fullTarget); err != nil {
			return err
		}

		// Transactional database update
		tx, err := db.Begin()
		if err != nil {
			// Try to rollback filesystem change
			os.Rename(fullTarget, full)
			logger.Printf("Error beginning transaction for rename: %v", err)
			return err
		}

		// Delete target if it exists
		_, err = tx.Exec("DELETE FROM files WHERE path = ?", relTarget)
		if err != nil {
			tx.Rollback()
			os.Rename(fullTarget, full)
			logger.Printf("Error deleting target in rename: %v", err)
			return err
		}

		if info.IsDir() {
			// Update all nested paths for directories
			// First, get all paths that start with the old directory path
			rows, err := tx.Query("SELECT path FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
			if err != nil {
				tx.Rollback()
				os.Rename(fullTarget, full)
				logger.Printf("Error querying nested paths for rename: %v", err)
				return err
			}

			var pathsToUpdate []string
			for rows.Next() {
				var oldPath string
				if err := rows.Scan(&oldPath); err != nil {
					rows.Close()
					tx.Rollback()
					os.Rename(fullTarget, full)
					logger.Printf("Error scanning path for rename: %v", err)
					return err
				}
				pathsToUpdate = append(pathsToUpdate, oldPath)
			}
			rows.Close()

			// Update each path
			for _, oldPath := range pathsToUpdate {
				var newPath string
				if oldPath == rel {
					newPath = relTarget
				} else {
					// Replace the prefix
					newPath = relTarget + strings.TrimPrefix(oldPath, rel)
				}
				_, err = tx.Exec("UPDATE files SET path = ? WHERE path = ?", newPath, oldPath)
				if err != nil {
					tx.Rollback()
					os.Rename(fullTarget, full)
					logger.Printf("Error updating path %s to %s: %v", oldPath, newPath, err)
					return err
				}
			}
		} else {
			// Just update the single file
			_, err = tx.Exec("UPDATE files SET path = ? WHERE path = ?", relTarget, rel)
			if err != nil {
				tx.Rollback()
				os.Rename(fullTarget, full)
				logger.Printf("Error updating file path in rename: %v", err)
				return err
			}
		}

		if err := tx.Commit(); err != nil {
			os.Rename(fullTarget, full)
			logger.Printf("Error committing rename transaction: %v", err)
			return err
		}

		logger.Printf("User %s renamed %s to %s", f.pubHash[:12], rel, relTarget)
		return nil

	case "Rmdir":
		var owner string
		err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if err != nil && err != sql.ErrNoRows {
			logger.Printf("Error checking ownership for rmdir of %s: %v", rel, err)
			return err
		}
		if owner != "" && owner != f.pubHash {
			return f.permissionDenied("You do not own this directory.")
		}

		// Delete from database including nested files
		_, err = db.Exec("DELETE FROM files WHERE path = ? OR path LIKE ?", rel, rel+"/%")
		if err != nil {
			logger.Printf("Error deleting directory from database %s: %v", rel, err)
		}

		return os.Remove(full)
	}
	return sftp.ErrSshFxOpUnsupported
}

// --- Helpers ---

type userStats struct {
	FilesUploadedCount int64
	LastLogin          string
	TotalBytes         int64
	IsFirstLogin       bool
}

func updateLoginStats(hash string) userStats {
	now := time.Now().Format("2006-01-02 15:04:05")
	var stats userStats
	err := db.QueryRow("SELECT last_login, total_bytes, upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&stats.LastLogin, &stats.TotalBytes, &stats.FilesUploadedCount)

	if err == sql.ErrNoRows {
		_, err = db.Exec("INSERT INTO users (pubkey_hash, last_login, total_bytes, upload_count) VALUES (?, ?, 0, 0)", hash, now)
		if err != nil {
			logger.Printf("Error inserting new user: %v", err)
		}
		stats.LastLogin = "First Login"
		stats.IsFirstLogin = true
	} else if err != nil {
		logger.Printf("Error querying user stats: %v", err)
	} else {
		_, err = db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
		if err != nil {
			logger.Printf("Error updating last login: %v", err)
		}
	}
	return stats
}

func hasUploaded(hash string) bool {
	var count int
	err := db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&count)
	if err != nil {
		logger.Printf("Error checking upload count for %s: %v", hash[:12], err)
		return false
	}
	return count > 0
}

func sendBanner(w io.Writer, hash string, stats userStats) {
	banner, err := os.ReadFile(*bannerFile)
	if err == nil {
		fmt.Fprintf(w, "\r\n%s\r\n", string(banner))
	} else {
		if !os.IsNotExist(err) {
			logger.Printf("Error reading banner file: %v", err)
		}
		fmt.Fprint(w, "\r\n\033[1;34m=== Anonymous SFTP Storage ===\033[0m\r\n")
	}

	displayName := fmt.Sprintf("anonymous-%d", ownerHashToUid(hash))

	if stats.IsFirstLogin {
		fmt.Fprintf(w, boldAscii("Welcome, "+displayName, "This appears to be your first time here, and we are happy to have you.\r\n"))

		fmt.Fprintf(w, "This server uses a \033[1;34m'share first'\033[0m system.  To participate, upload something you find thought-provoking, beautiful, or novel. Once you've shared something, the full archive will open up for you to explore.\r\n")
		fmt.Fprintf(w, "\r\nYou can always download \033[1mREADME.txt\033[0m for more information.\r\n")

	} else {
		fmt.Fprintf(w, "Username: %s\r\n", displayName)
		fmt.Fprintf(w, "Previous Session: %s\r\n", stats.LastLogin)
		fmt.Fprintf(w, "Bytes Uploaded: %d bytes\r\n", stats.TotalBytes)
		fmt.Fprintf(w, "Files uploaded: %d files\r\n\r\n", stats.FilesUploadedCount)
	}

	if !hasUploaded(hash) {
		fmt.Fprint(w, boldAscii("Reminder:", "You must upload a file before you can download a file."))
	} else if stats.TotalBytes > 1024 {
		fmt.Fprint(w, boldAscii("Thank you for contributing, "+displayName, "\r\nHere is your fortune:\r\n"))
		fortune := getRandomFortune()
		fmt.Fprintf(w, "\033[3;33m\"%s\"\033[0m\r\n", fortune) // Italicized yellow text
	} else {
		fmt.Fprint(w, boldAscii("Welcome back, "+displayName, "You may now download any file."))
	}
}

func boldAscii(header string, body string) string {
	return fmt.Sprintf("\r\n\033[1m%s\033[0m %s\r\n", header, body)
}

func getRandomFortune() string {
	data, err := embeddedSource.ReadFile("fortunes.txt")
	if err != nil {
		logger.Printf("Error reading fortunes file: %v", err)
		return "Your future is yet to be written."
	}

	// Split by traditional fortune delimiter (%) or by newline
	var fortunes []string
	content := string(data)
	if strings.Contains(content, "\n%\n") {
		fortunes = strings.Split(content, "\n%\n")
	} else {
		fortunes = strings.Split(content, "\n")
	}

	// Filter out empty entries
	var valid []string
	for _, f := range fortunes {
		f = strings.TrimSpace(f)
		if f != "" {
			valid = append(valid, f)
		}
	}

	if len(valid) == 0 {
		return "A path of a thousand miles begins with a single upload."
	}

	// Use the global rand (already used in your planet generator)
	return valid[rand.Intn(len(valid))]
}

type statWriter struct {
	*os.File
	pubHash string
	relPath string
	oldSize int64
}

func (sw *statWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := sw.File.WriteAt(p, off)
	return n, err
}

func (sw *statWriter) Close() error {
	// On close, recalculate the actual file size and update database
	fileInfo, err := sw.File.Stat()
	if err != nil {
		logger.Printf("Error getting file info on close: %v", err)
		return sw.File.Close()
	}

	newSize := fileInfo.Size()
	sizeDelta := newSize - sw.oldSize

	// Update the file size in the files table
	_, err = db.Exec("UPDATE files SET size = ? WHERE path = ?", newSize, sw.relPath)
	if err != nil {
		logger.Printf("Error updating file size for %s: %v", sw.relPath, err)
	}

	// Update user's total bytes (only add the delta, not the full size)
	if sizeDelta != 0 {
		_, err = db.Exec("UPDATE users SET total_bytes = total_bytes + ? WHERE pubkey_hash = ?", sizeDelta, sw.pubHash)
		if err != nil {
			logger.Printf("Error updating bytes for %s: %v", sw.pubHash[:12], err)
		}
	}

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

type sftpFile struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	owner   string
}

func (s *sftpFile) Name() string       { return s.name }
func (s *sftpFile) Size() int64        { return s.size }
func (s *sftpFile) Mode() fs.FileMode  { return s.mode }
func (s *sftpFile) ModTime() time.Time { return s.modTime }
func (s *sftpFile) IsDir() bool        { return s.isDir }
func (s *sftpFile) Sys() interface{} {
	uid := uint32(1000)
	gid := uint32(1000)

	if s.owner != "" && s.owner != "system" {
		uid = ownerHashToUid(s.owner)
		gid = uid
	}

	return &sftp.FileStat{
		UID: uid,
		GID: gid,
	}
}

func ownerHashToUid(hash string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(hash))
	// Mask to 31 bits to ensure compatibility with all SFTP clients (signed/unsigned issues)
	return h.Sum32() & 0x7FFFFFFF
}

func newSftpFile(name string, info os.FileInfo, ownerHash string) *sftpFile {
	owner := "system"
	if ownerHash != "" {
		owner = ownerHash
	}
	return &sftpFile{
		name:    name,
		size:    info.Size(),
		mode:    info.Mode(),
		modTime: info.ModTime(),
		isDir:   info.IsDir(),
		owner:   owner,
	}
}
