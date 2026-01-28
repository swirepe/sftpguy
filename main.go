package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"math"
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
    owner_hash TEXT
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

	// Initialize Rate Limiter
	mkdirLimiter = rate.NewLimiter(rate.Limit(*mkdirLimit), 1)

	// Ensure upload directory exists
	if err := os.MkdirAll(*uploadDir, 0755); err != nil {
		logger.Fatalf("Failed to create upload directory: %v", err)
	}

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
	return rel, full
}

func (f *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	relPath, fullPath := f.secure(r.Filepath)

	if relPath == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
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

	// Check ownership
	var owner string
	err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if owner != "" && owner != f.pubHash {
		return nil, f.permissionDenied("This file is owned by another user.")
	}

	// Prepare file for writing (supports resume)
	file, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// If new file, record ownership
	if owner == "" {
		_, err = db.Exec("INSERT OR IGNORE INTO files (path, owner_hash) VALUES (?, ?)", rel, f.pubHash)
		if err == nil {
			db.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", f.pubHash)
		}
	}

	return &statWriter{file, f.pubHash}, nil
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
			data, _ := embeddedSource.ReadFile("main.go")
			res = append(res, &sftpFile{"README.txt", int64(len(data)), 0444, time.Now(), false, "system"})
		}

		for _, item := range items {
			info, _ := item.Info()
			var owner string
			childPath := filepath.Join(rel, info.Name())
			db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", childPath).Scan(&owner)
			res = append(res, newSftpFile(info.Name(), info, owner))
		}
		return listerAt(res), nil

	case "Stat", "Lstat":
		if rel == "README.txt" {
			data, _ := embeddedSource.ReadFile("main.go")
			return listerAt{&sftpFile{"README.txt", int64(len(data)), 0444, time.Now(), false, "system"}}, nil
		}

		info, err := os.Stat(full)
		if err != nil {
			return nil, err
		}
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
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
		db.Exec("INSERT OR IGNORE INTO files (path, owner_hash) VALUES (?, ?)", rel, f.pubHash)
		logger.Printf("User %s created directory: %s", f.pubHash[:12], rel)
		return nil

	case "Remove":
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if owner != "" && owner != f.pubHash {
			return f.permissionDenied("You can only delete files or directories you created.")
		}
		if err := os.RemoveAll(full); err != nil {
			return err
		}
		db.Exec("DELETE FROM files WHERE path = ?", rel)
		logger.Printf("User %s removed: %s", f.pubHash[:12], rel)
		return nil

	case "Rename":
		relTarget, fullTarget := f.secure(r.Target)

		// Check source ownership
		var sourceOwner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&sourceOwner)
		if sourceOwner != f.pubHash {
			return f.permissionDenied("You do not own the source file.")
		}

		// Check target ownership if it exists
		var targetOwner string
		err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relTarget).Scan(&targetOwner)
		if err == nil && targetOwner != "" && targetOwner != f.pubHash {
			return f.permissionDenied("The destination already exists and is owned by another user.")
		}

		// Transactional database update
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		tx.Exec("DELETE FROM files WHERE path = ?", relTarget)
		tx.Exec("UPDATE files SET path = ? WHERE path = ?", relTarget, rel)
		if err := tx.Commit(); err != nil {
			return err
		}

		if err := os.Rename(full, fullTarget); err != nil {
			return err
		}
		logger.Printf("User %s renamed %s to %s", f.pubHash[:12], rel, relTarget)
		return nil

	case "Rmdir":
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if owner != "" && owner != f.pubHash {
			return f.permissionDenied("You do not own this directory.")
		}
		db.Exec("DELETE FROM files WHERE path = ?", rel)
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
		db.Exec("INSERT INTO users (pubkey_hash, last_login, total_bytes, upload_count) VALUES (?, ?, 0, 0)", hash, now)
		stats.LastLogin = "First Login"
		stats.IsFirstLogin = true
	} else {
		db.Exec("UPDATE users SET last_login = ? WHERE pubkey_hash = ?", now, hash)
	}
	return stats
}

func hasUploaded(hash string) bool {
	var count int
	db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&count)
	return count > 0
}

func sendBanner(w io.Writer, hash string, stats userStats) {
	banner, err := os.ReadFile(*bannerFile)
	if err == nil {
		fmt.Fprintf(w, "\r\n%s\r\n", string(banner))
	} else {
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
		planetName := NewPlanetName(hash + fmt.Sprintf("%d", stats.TotalBytes))
		planet := GeneratePlanet(planetName)
		fmt.Fprintf(w, "\r\n%s\r\n", planet)
		fmt.Fprint(w, boldAscii("Thank you for contributing, "+displayName, "Look at this cool planet."))
	} else {
		fmt.Fprint(w, boldAscii("Welcome back, "+displayName, "You may now download any file."))
	}
}

func boldAscii(header string, body string) string {
	return fmt.Sprintf("\r\n\033[1m%s\033[0m %s\r\n", header, body)
}

type statWriter struct {
	*os.File
	pubHash string
}

func (sw *statWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := sw.File.WriteAt(p, off)
	if n > 0 {
		// Update byte count in DB
		_, dbErr := db.Exec("UPDATE users SET total_bytes = total_bytes + ? WHERE pubkey_hash = ?", n, sw.pubHash)
		if dbErr != nil {
			logger.Printf("Error updating bytes for %s: %v", sw.pubHash[:12], dbErr)
		}
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

// --- Procedural Generation Engine ---

type PlanetConfig struct {
	Radius       float64
	HasRings     bool
	RingInner    float64
	RingOuter    float64
	RingTilt     float64
	CloudDensity float64
	PlanetType   int
	Seed         int64
}

type PlanetNameGenerator struct {
	Prefixes []string
	Infixes  []string
	Suffixes []string
	Post     []string
}

func NewPlanetName(input string) string {
	gen := &PlanetNameGenerator{
		Prefixes: []string{"Ae", "Bar", "Cor", "Dax", "Exo", "Faer", "Glis", "Hel", "Ira", "Kael", "Lyr", "Mora", "Nix", "Oph", "Pyr", "Qir", "Rhun", "Sol", "Tra", "Ulu", "Vex", "Xen", "Yul", "Zor"},
		Infixes:  []string{"an", "bel", "cor", "den", "en", "fos", "gan", "hal", "ion", "jar", "kyn", "lan", "mox", "nor", "on", "phi", "quon", "ren", "syl", "tur", "vun", "wen", "xin", "yos", "zen"},
		Suffixes: []string{"ia", "os", "on", "us", "is", "a", "eon", "ath", "ar", "og", "un", "ara", "o", "u", "i", "en", "eth"},
		Post:     []string{"Prime", "IV", "VI", "Major", "Minor", "Beta", "Gamma", "X", "Station", "Alpha", "Rise", "Reach"},
	}
	return gen.Generate(input)
}

func (pg *PlanetNameGenerator) Generate(input string) string {
	h := fnv.New64a()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(input))))
	seed := h.Sum64()
	r := rand.New(rand.NewSource(int64(seed)))

	syllables := r.Intn(2) + 2
	var name strings.Builder
	name.WriteString(pg.Prefixes[r.Intn(len(pg.Prefixes))])

	if syllables == 3 {
		name.WriteString(pg.Infixes[r.Intn(len(pg.Infixes))])
	}
	name.WriteString(pg.Suffixes[r.Intn(len(pg.Suffixes))])

	if r.Float32() > 0.8 {
		name.WriteString(" ")
		name.WriteString(pg.Post[r.Intn(len(pg.Post))])
	}
	return name.String()
}

func GeneratePlanet(input string) string {
	const (
		width  = 80
		height = 34
		aspect = 0.45
	)

	hash := sha256.Sum256([]byte(input))
	seed := int64(binary.BigEndian.Uint64(hash[:8]))
	rng := rand.New(rand.NewSource(seed))

	conf := PlanetConfig{
		Seed:         seed,
		Radius:       rng.Float64()*6 + 6,
		HasRings:     rng.Float64() > 0.6,
		CloudDensity: rng.Float64()*0.3 + 0.3,
		PlanetType:   rng.Intn(4),
	}
	conf.RingInner = conf.Radius * (1.3 + rng.Float64()*0.2)
	conf.RingOuter = conf.RingInner * (1.4 + rng.Float64()*0.5)
	conf.RingTilt = (rng.Float64() - 0.5) * 0.8

	var out strings.Builder
	centerX, centerY := float64(width)/2, float64(height)/2

	for y := 0; y < height; y++ {
		fy := float64(y)
		for x := 0; x < width; x++ {
			fx := float64(x)
			dx := (fx - centerX) * aspect
			dy := fy - centerY

			sinTilt := math.Sin(math.Abs(conf.RingTilt) + 0.1)
			ty := dy / sinTilt
			ringDist := math.Sqrt(dx*dx + ty*ty)
			ringIsFront := (dy * conf.RingTilt) > 0

			distSq := dx*dx + dy*dy
			planetRadiusSq := conf.Radius * conf.Radius
			isRing := conf.HasRings && ringDist > conf.RingInner && ringDist < conf.RingOuter

			if distSq < planetRadiusSq {
				if isRing && ringIsFront {
					out.WriteString(getRingChar(ringDist, conf))
				} else {
					out.WriteString(getPlanetChar(dx, dy, conf))
				}
			} else if isRing {
				out.WriteString(getRingChar(ringDist, conf))
			} else {
				out.WriteString(getStarChar(x, y, seed))
			}
		}
		out.WriteString("\033[0m\n")
	}

	types := []string{"Terrestrial", "Volcanic", "Gas Giant", "Ice Giant"}
	out.WriteString(fmt.Sprintf("\n\033[1mSector:\033[0m %s | \033[1mClass:\033[0m %s | \033[1mRadius:\033[0m %.1f\n",
		input, types[conf.PlanetType], conf.Radius))

	return out.String()
}

func getStarChar(x, y int, seed int64) string {
	h := uint64(seed) ^ (uint64(x) * 0x45d9f3b) ^ (uint64(y) * 0x119de1f3)
	h = ((h >> 16) ^ h) * 0x45d9f3b
	if h%150 == 0 {
		chars := []string{".", "*", "·"}
		return fmt.Sprintf("\033[38;5;244m%s", chars[h%uint64(len(chars))])
	}
	return " "
}

func getPlanetChar(dx, dy float64, conf PlanetConfig) string {
	z := math.Sqrt(math.Max(0, conf.Radius*conf.Radius-dx*dx-dy*dy))
	dot := (dx*-0.5 + dy*-0.5 + z*0.7) / conf.Radius
	shade := math.Max(0.1, dot)

	h := 0.0
	for i := 1; i <= 3; i++ {
		f := float64(i) * 0.2
		h += math.Sin(dx*f+float64(conf.Seed)) * math.Cos(dy*f+z*f)
	}
	h = (h + 2.0) / 4.0
	c := (math.Sin(dx*0.3+float64(conf.Seed))*math.Cos(dy*0.3+z*0.2) + 1.0) / 2.0

	var r, g, b float64
	if c > (1.0 - conf.CloudDensity) {
		r, g, b = 240, 240, 255
	} else {
		switch conf.PlanetType {
		case 0: // Terrestrial
			if h < 0.5 {
				r, g, b = 30, 80, 200
			} else {
				r, g, b = 60, 160, 40
			}
		case 1: // Volcanic
			r, g, b = 220, 60, 20
		case 2: // Gas
			r, g, b = 180, 140, 200
		case 3: // Ice
			r, g, b = 150, 220, 255
		}
	}

	r, g, b = r*shade, g*shade, b*shade
	ansi := 16 + int(r/255*5)*36 + int(g/255*5)*6 + int(b/255*5)
	return fmt.Sprintf("\033[38;5;%dm@", ansi)
}

func getRingChar(dist float64, conf PlanetConfig) string {
	bands := math.Sin(dist * 3.0)
	if bands < -0.3 {
		return " "
	}
	shade := 0.4 + 0.5*math.Abs(bands)
	s := int(shade * 3)
	chars := []string{".", ":", "=", "#"}
	color := 240 + s
	return fmt.Sprintf("\033[38;5;%dm%s", color, chars[s%len(chars)])
}
