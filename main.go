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

	"encoding/binary"

	"hash/fnv"
	"math"
	"math/rand"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

/*
  1. users are identified internally by their public key.
  2. Usernames, keys, addresses, uploads, directory creations, etc. are logged to the console and to a configurable file.
  3. all users are displayed as "anonymous-<hash of public key>" with UID 1000 and GID 1000.
  4. any user can upload files, create directories, or list directories
  5. Only users that have uploaded a file can download files.  A user that has uploaded at least one file has permission to download any file.
  6. Any user can download README.txt, even if they have not uploaded a file.  Use go:embed to save the source code of this application as README.txt.
  7. Users can only modify or delete files that they have uploaded.  Users CANNOT modify permissions.
  8. When a user logs in, display the contents of BANNER.txt (if configured), the last time that user logged in, and the total number of bytes they have uploaded
  9. directory creation is rate-limited globally to 10 folders per second.  This is configurable.
  10. When a user tries to download a file without uploading a file first, display a message explaining why they cannot.
  11. When a user tries to delete, rename, or modify a file or directory they did not create, display a message explaining why they cannot.
  12. The application is fully configurable
  13. Users can resume uploads for files they have created.
*/

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
	db.Exec("PRAGMA journal_mode=WAL;")
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

		go func(in <-chan *ssh.Request, channel ssh.Channel) {
			defer channel.Close()
			for req := range in {
				if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)
					sendBanner(ch.Stderr(), pubHash, stats)

					handler := &fsHandler{pubHash: pubHash}
					server := sftp.NewRequestServer(ch, sftp.Handlers{
						FileGet:  handler,
						FilePut:  handler,
						FileCmd:  handler,
						FileList: handler,
					})
					server.Serve()
					return
				}
			}
		}(reqs, ch)
	}
}

type fsHandler struct{ pubHash string }

func (f *fsHandler) secure(p string) (string, string) {
	rel := strings.TrimPrefix(filepath.Clean(filepath.Join("/", p)), string(filepath.Separator))
	if rel == "" {
		rel = "."
	}
	return rel, filepath.Join(*uploadDir, rel)
}

// Lstat implements sftp.NameLookupFileLister
func (f *fsHandler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return f.Stat(r) // In this app, we treat Lstat and Stat the same
}

// Stat implements sftp.NameLookupFileLister
func (f *fsHandler) Stat(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := f.secure(r.Filepath)

	if rel == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
		return listerAt{&sftpFile{
			name:      "README.txt",
			size:      int64(len(data)),
			mode:      0444,
			modTime:   time.Now(),
			isDir:     false,
			ownerName: "anonymous",
			ownerHash: "system",
		}}, nil
	}

	// Handle real files/directories
	info, err := os.Stat(full)
	if err != nil {
		return nil, err
	}

	var owner string
	db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
	return listerAt{newSftpFile(info.Name(), info, owner)}, nil
}

// Readlink implements sftp.NameLookupFileLister
func (f *fsHandler) Readlink(r *sftp.Request) (sftp.ListerAt, error) {
	return nil, sftp.ErrSSHFxOpUnsupported
}

func (f *fsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	relPath, fullPath := f.secure(r.Filepath)

	if relPath == "README.txt" {
		data, _ := embeddedSource.ReadFile("main.go")
		return bytes.NewReader(data), nil
	}

	// Rule 5: Download permissions
	if !hasUploaded(f.pubHash) {
		logger.Printf("User %s blocked from downloading %s", f.pubHash[:12], relPath)
		return nil, fmt.Errorf("PERMISSION DENIED: You must upload at least one file first.")
	}

	return os.Open(fullPath)
}

func (f *fsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	rel, full := f.secure(r.Filepath)
	var owner string
	db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
	if owner != "" && owner != f.pubHash {
		return nil, errors.New("PERMISSION DENIED: File owned by another")
	}
	file, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	if owner == "" {
		db.Exec("INSERT OR IGNORE INTO files (path, owner_hash) VALUES (?, ?)", rel, f.pubHash)
		db.Exec("UPDATE users SET upload_count = upload_count + 1 WHERE pubkey_hash = ?", f.pubHash)
	}
	return &statWriter{file, f.pubHash}, nil
}

func (f *fsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	rel, full := f.secure(r.Filepath)

	if r.Method != "List" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	items, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}

	res := make([]os.FileInfo, 0)

	// Virtual file for the root directory
	if rel == "." {
		data, _ := embeddedSource.ReadFile("main.go")
		res = append(res, &sftpFile{"README.txt", int64(len(data)), 0444, time.Now(), false, "anonymous", "system"})
	}

	for _, item := range items {
		info, _ := item.Info()
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", filepath.Join(rel, info.Name())).Scan(&owner)
		res = append(res, newSftpFile(info.Name(), info, owner))
	}
	return listerAt(res), nil
}

func (f *fsHandler) Filecmd(r *sftp.Request) error {
	rel, full := f.secure(r.Filepath)
	switch r.Method {
	case "Mkdir":
		if !mkdirLimiter.Allow() {
			return errors.New("rate limited")
		}
		db.Exec("INSERT OR IGNORE INTO files (path, owner_hash) VALUES (?, ?)", rel, f.pubHash)
		return os.MkdirAll(full, 0755)
	case "Remove":
		var owner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&owner)
		if owner != f.pubHash {
			return errors.New("PERMISSION DENIED")
		}
		db.Exec("DELETE FROM files WHERE path = ?", rel)
		return os.RemoveAll(full)
	case "Rename":
		relT, fullT := f.secure(r.Target)

		var sourceOwner string
		db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", rel).Scan(&sourceOwner)
		if sourceOwner != f.pubHash {
			return errors.New("PERMISSION DENIED: You do not own the source file")
		}

		var targetOwner string
		err := db.QueryRow("SELECT owner_hash FROM files WHERE path = ?", relT).Scan(&targetOwner)
		if err == nil && targetOwner != "" { // File exists in DB
			if targetOwner != f.pubHash {
				return errors.New("PERMISSION DENIED: Destination is occupied and owned by another user")
			}
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}
		tx.Exec("DELETE FROM files WHERE path = ?", relT)
		tx.Exec("UPDATE files SET path = ? WHERE path = ?", relT, rel)
		if err := tx.Commit(); err != nil {
			return err
		}

		return os.Rename(full, fullT)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
	return nil

}

// --- Helpers ---

type userStats struct {
	FilesUploadedCount int64
	LastLogin          string
	TotalBytes         int64
}

func updateLoginStats(hash string) userStats {
	now := time.Now().Format("2006-01-02 15:04:05")
	var stats userStats
	err := db.QueryRow("SELECT last_login, total_bytes, upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&stats.LastLogin, &stats.TotalBytes, &stats.FilesUploadedCount)
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
	db.QueryRow("SELECT upload_count FROM users WHERE pubkey_hash = ?", hash).Scan(&count)
	return count > 0
}

func sendBanner(w io.Writer, hash string, stats userStats) {
	banner, _ := os.ReadFile(*bannerFile)
	fmt.Fprintf(w, "\r\n%s\r\n", string(banner))

	if !hasUploaded(hash) {
		fmt.Fprint(w, boldAscii("Reminder:", "You must upload a file to download files."))
	} else if stats.TotalBytes > 1024 {
		fmt.Fprint(w, boldAscii("Thank you for uploading.", "Here is a cool planet to look at."))
		planetName := NewPlanetName(hash + fmt.Sprintf("%d", stats.TotalBytes))
		planet := GeneratePlanet(planetName)
		fmt.Fprintf(w, "\r\n%s\r\n", planet)
	} else {
		fmt.Fprint(w, boldAscii("Thank you for uploading.", "You may now download files."))
	}

	fmt.Fprintf(w, "ID: anonymous-%s\r\n", hash[:12])
	fmt.Fprintf(w, "UID: %d\r\n", ownerHashToUid(hash))
	fmt.Fprintf(w, "Last Login: %s\r\n", stats.LastLogin)
	fmt.Fprintf(w, "Total Uploaded: %d bytes\r\n\r\n", stats.TotalBytes)

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

type sftpFile struct {
	name      string
	size      int64
	mode      fs.FileMode
	modTime   time.Time
	isDir     bool
	ownerName string
	ownerHash string // Full hash for extension data
}

func (s *sftpFile) Name() string       { return s.name }
func (s *sftpFile) Size() int64        { return s.size }
func (s *sftpFile) Mode() fs.FileMode  { return s.mode }
func (s *sftpFile) ModTime() time.Time { return s.modTime }
func (s *sftpFile) IsDir() bool        { return s.isDir }
func (s *sftpFile) Sys() interface{} {
	// Convert the owner hash to a numeric UID/GID for display
	// This makes the hash visible in ls -l output
	uid := uint32(1000) // Default for system files
	gid := uint32(1000)

	if s.ownerHash != "" && s.ownerHash != "system" {
		// Use FNV hash of the first 12 chars to generate a unique numeric ID

		uid = ownerHashToUid(s.ownerHash)
		gid = uid
	}

	return &sftp.FileStat{
		UID: uid,
		GID: gid,
		Extended: []sftp.StatExtended{
			{
				ExtType: "owner-name",
				ExtData: s.ownerName,
			},
			{
				ExtType: "owner-hash",
				ExtData: s.ownerHash,
			},
		},
	}
}

func ownerHashToUid(hash string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(hash[:12]))
	return h.Sum32()
}

func (s *sftpFile) LongName() string {
	mode := s.mode.String()
	modTime := s.modTime.Format("Jan _2 15:04")
	// Standard Unix-style listing: mode, links, owner, group, size, date, name
	return fmt.Sprintf("%s    1 %-16s %-16s %8d %s %s",
		mode, s.ownerName, s.ownerName, s.size, modTime, s.name)
}

func newSftpFile(name string, info os.FileInfo, ownerHash string) *sftpFile {
	displayName := "anonymous-system"
	if ownerHash != "" && ownerHash != "system" {
		displayName = "anonymous-" + ownerHash[:12]
	}
	return &sftpFile{
		name:      name,
		size:      info.Size(),
		mode:      info.Mode(),
		modTime:   info.ModTime(),
		isDir:     info.IsDir(),
		ownerName: displayName,
		ownerHash: ownerHash,
	}
}

// PlanetConfig holds the deterministic parameters
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
	nameGenerator := NewPlanetNameGenerator()
	return nameGenerator.Generate(input)
}

func NewPlanetNameGenerator() *PlanetNameGenerator {
	return &PlanetNameGenerator{
		Prefixes: []string{"Ae", "Bar", "Cor", "Dax", "Exo", "Faer", "Glis", "Hel", "Ira", "Kael", "Lyr", "Mora", "Nix", "Oph", "Pyr", "Qir", "Rhun", "Sol", "Tra", "Ulu", "Vex", "Xen", "Yul", "Zor"},
		Infixes:  []string{"an", "bel", "cor", "den", "en", "fos", "gan", "hal", "ion", "jar", "kyn", "lan", "mox", "nor", "on", "phi", "quon", "ren", "syl", "tur", "vun", "wen", "xin", "yos", "zen"},
		Suffixes: []string{"ia", "os", "on", "us", "is", "a", "eon", "ath", "ar", "og", "un", "ara", "o", "u", "i", "en", "eth"},
		Post:     []string{"Prime", "IV", "VI", "Major", "Minor", "Beta", "Gamma", "X", "Station", "Alpha", "Rise", "Reach"},
	}
}

// Generate takes a seed string and returns a deterministic planet name
func (pg *PlanetNameGenerator) Generate(input string) string {
	// 1. Create a deterministic seed from the input string using FNV hash
	h := fnv.New64a()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(input))))
	seed := h.Sum64()

	// 2. Initialize a local random source with that seed
	// This ensures the same input always produces the same output
	r := rand.New(rand.NewSource(int64(seed)))

	// 3. Determine name structure
	// Length can be 2 or 3 syllables
	syllables := r.Intn(2) + 2

	var name strings.Builder

	// Add Prefix
	name.WriteString(pg.Prefixes[r.Intn(len(pg.Prefixes))])

	// Add Infix (if 3 syllables)
	if syllables == 3 {
		name.WriteString(pg.Infixes[r.Intn(len(pg.Infixes))])
	}

	// Add Suffix
	name.WriteString(pg.Suffixes[r.Intn(len(pg.Suffixes))])

	// 4. Optional Post-fix (20% chance)
	if r.Float32() > 0.8 {
		name.WriteString(" ")
		name.WriteString(pg.Post[r.Intn(len(pg.Post))])
	}

	return name.String()
}

// GeneratePlanet takes a string and returns a colorful ASCII planet as a single string.
func GeneratePlanet(input string) string {
	const (
		width  = 100
		height = 44
		aspect = 0.45 // Adjust based on your terminal font
	)

	// 1. Deterministic Seeding via SHA-256
	hash := sha256.Sum256([]byte(input))
	seed := int64(binary.BigEndian.Uint64(hash[:8]))
	rng := rand.New(rand.NewSource(seed))

	// 2. Setup Configuration
	conf := PlanetConfig{
		Seed:         seed,
		Radius:       rng.Float64()*8 + 7,     // Radius between 7 and 15
		HasRings:     rng.Float64() > 0.6,     // 40% chance
		CloudDensity: rng.Float64()*0.3 + 0.3, // 30% to 60% cover
		PlanetType:   rng.Intn(4),             // 4 Biomes
	}
	conf.RingInner = conf.Radius * (1.3 + rng.Float64()*0.2)
	conf.RingOuter = conf.RingInner * (1.4 + rng.Float64()*0.5)
	conf.RingTilt = (rng.Float64() - 0.5) * 1.0

	var out strings.Builder
	centerX, centerY := float64(width)/2, float64(height)/2

	// 3. Render Loop
	for y := 0; y < height; y++ {
		fy := float64(y)
		for x := 0; x < width; x++ {
			fx := float64(x)
			dx := (fx - centerX) * aspect
			dy := fy - centerY

			// Ring Projection Math
			// We calculate the Z-depth of the ring plane to handle occlusion (behind vs front)
			sinTilt := math.Sin(math.Abs(conf.RingTilt) + 0.2) // Avoid division by zero
			ty := dy / sinTilt
			ringDist := math.Sqrt(dx*dx + ty*ty)

			// Depth logic: positive dy with positive tilt puts ring in front
			ringIsFront := (dy * conf.RingTilt) > 0

			distSq := dx*dx + dy*dy
			planetRadiusSq := conf.Radius * conf.Radius

			isRing := conf.HasRings && ringDist > conf.RingInner && ringDist < conf.RingOuter

			if distSq < planetRadiusSq {
				// We are on the planet surface.
				// Draw ring only if it's in front of the planet.
				if isRing && ringIsFront {
					out.WriteString(getRingChar(ringDist, conf))
				} else {
					out.WriteString(getPlanetChar(dx, dy, conf))
				}
			} else if isRing {
				// Space where only the ring exists
				out.WriteString(getRingChar(ringDist, conf))
			} else {
				// Background: Use coordinate hash to prevent "line patterns"
				out.WriteString(getStarChar(x, y, seed))
			}
		}
		out.WriteString("\033[0m\n") // Reset color at end of line
	}

	// Footer
	types := []string{"Terrestrial", "Volcanic", "Gas Giant", "Ice Giant"}
	out.WriteString(fmt.Sprintf("\n\033[1mPlanet:\033[0m %s | \033[1mClass:\033[0m %s | \033[1mSize:\033[0m %.1f\n",
		input, types[conf.PlanetType], conf.Radius))

	return out.String()
}

// getStarChar uses a bit-mixing hash for deterministic, non-linear star placement
func getStarChar(x, y int, seed int64) string {
	// Simple coordinate hash (SplitMix64-style mix)
	h := uint64(seed) ^ (uint64(x) * 0x45d9f3b) ^ (uint64(y) * 0x119de1f3)
	h = ((h >> 16) ^ h) * 0x45d9f3b
	h = ((h >> 16) ^ h) * 0x45d9f3b
	h = (h >> 16) ^ h

	// Chance of a star (0.8% density)
	if h%125 == 0 {
		brightness := 235 + int(h%20) // Varying shades of white/grey
		chars := []string{".", "*", "·", "°"}
		return fmt.Sprintf("\033[38;5;%dm%s", brightness, chars[h%uint64(len(chars))])
	}
	return " "
}

func getPlanetChar(dx, dy float64, conf PlanetConfig) string {
	z := math.Sqrt(conf.Radius*conf.Radius - dx*dx - dy*dy)

	// Light direction (from top-left)
	dot := (dx*-0.5 + dy*-0.5 + z*0.7) / conf.Radius
	shade := math.Max(0.05, dot)

	// Procedural Terrain (Harmonic sine waves)
	h := 0.0
	for i := 1; i <= 3; i++ {
		f := float64(i) * 0.18
		h += math.Sin(dx*f+float64(conf.Seed)) * math.Cos(dy*f+z*f)
	}
	h = (h + 2.0) / 4.0

	// Procedural Clouds
	c := (math.Sin(dx*0.25+float64(conf.Seed))*math.Cos(dy*0.25+z*0.15) + 1.0) / 2.0

	var r, g, b float64
	if c > (1.0 - conf.CloudDensity) {
		r, g, b = 230, 230, 255 // Clouds
		shade += 0.1
	} else {
		switch conf.PlanetType {
		case 0: // Terrestrial
			if h < 0.48 {
				b = 220
				g = 50
			} else {
				g = 180
				r = 60
			}
		case 1: // Volcanic
			r = 255
			g = h * 120
			b = 20
		case 2: // Gas
			r = 170 + h*80
			g = 110
			b = 190
		case 3: // Ice
			r = 140
			g = 210
			b = 255
		}
	}

	r, g, b = r*shade, g*shade, b*shade
	ansi := 16 + int(r/255*5)*36 + int(g/255*5)*6 + int(b/255*5)
	return fmt.Sprintf("\033[38;5;%dm@", ansi)
}

func getRingChar(dist float64, conf PlanetConfig) string {
	// Add some gaps/banding to the rings
	bands := math.Sin(dist * 2.5)
	if bands < -0.2 {
		return " "
	}

	shade := 0.4 + 0.6*math.Abs(bands)
	s := int(shade * 3)
	chars := []string{".", ":", "=", "#"}
	if s > 3 {
		s = 3
	}

	// Use brown/grey tones for rings
	color := 242 + s
	return fmt.Sprintf("\033[38;5;%dm%s", color, chars[s])
}
