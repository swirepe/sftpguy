package adminexplorer

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── constants ────────────────────────────────────────────────────────────────

const (
	cookieUnlock  = "explorer_unlocked"
	cookieTheme   = "explorer_theme"
	cookieView    = "explorer_view"
	cookieHue     = "explorer_hue"
	cookieCSRF    = "explorer_csrf"
	cookiePreview = "explorer_preview"

	viewTable   = "table"
	viewTiles   = "tiles"
	viewTree    = "tree"
	viewClassic = "classic"

	defaultHue = "212"

	DefaultBasePath        = "/admin/explorer"
	defaultMaxUploadBytes  = 1_000 << 20
	defaultWarmCacheMax    = 20_000
	defaultDeleteAPIPath   = "/admin/api/explorer/delete"
	defaultBanOwnerAPIPath = "/admin/api/explorer/ban-owner"
	defaultMarkBadAPIPath  = "/admin/api/maintenance/mark-bad"

	thumbCacheCapacity   = 5_000
	dirSizeCacheCapacity = 10_000
	previewCacheCapacity = 20_000

	thumbBrowserTTL = 24 * time.Hour
)

// ── extension / category maps ─────────────────────────────────────────────────

var (
	imageExts = map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true,
		".gif": true, ".webp": true, ".bmp": true,
	}
	dangerExts = map[string]bool{
		".exe": true, ".scr": true, ".lnk": true,
	}
	cadExts = map[string]bool{
		".stl": true,
	}
	videoExts = map[string]bool{
		".mp4": true, ".webm": true, ".ogg": true,
		".mov": true, ".mkv": true, ".flv": true,
		".avi": true,
	}
	// nativeVideoExts are formats browsers play without Video.js
	nativeVideoExts = map[string]bool{
		".mp4": true, ".webm": true, ".ogg": true,
	}
	archiveExts = map[string]bool{
		".zip": true, ".tar": true, ".gz": true, ".tgz": true,
		".rar": true, ".7z": true, ".bz2": true, ".xz": true,
	}
	textExts = map[string]bool{
		".txt": true, ".md": true, ".markdown": true,
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".html": true, ".htm": true, ".css": true, ".scss": true,
		".json": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".env": true,
		".sh": true, ".bash": true, ".zsh": true, ".fish": true,
		".c": true, ".cpp": true, ".h": true, ".rs": true, ".java": true, ".rb": true,
		".xml": true, ".svg": true, ".csv": true, ".tsv": true, ".log": true,
		".dockerfile": true, ".makefile": true, ".gitignore": true, ".editorconfig": true,
	}
)

// ── globals ───────────────────────────────────────────────────────────────────

var (
	rootDir           string
	maxFileSize       int64
	basePath          string
	embedAssets       bool
	tmpl              *template.Template
	fileDetailsLookup func(relPath string) (FileDetails, error)
	ownerLookup       func(relPath string) (string, error)
	ownerFilesURLFunc func(owner string) string
	ownerDetailsURLFn func(owner string) string
)

//go:embed three.min.js video.js video-js.css flv.js videojs-flvjs.min.js
var staticAssets embed.FS

// ── generic LRU cache ─────────────────────────────────────────────────────────

type lruEntry[V any] struct {
	key        string
	val        V
	prev, next *lruEntry[V]
}

type lruCache[V any] struct {
	mu    sync.Mutex
	cap   int
	items map[string]*lruEntry[V]
	head  *lruEntry[V]
	tail  *lruEntry[V]
}

func newLRU[V any](capacity int) *lruCache[V] {
	return &lruCache[V]{cap: capacity, items: make(map[string]*lruEntry[V], capacity)}
}

func (c *lruCache[V]) get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		c.moveToFront(e)
		return e.val, true
	}
	var zero V
	return zero, false
}

func (c *lruCache[V]) set(key string, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		e.val = val
		c.moveToFront(e)
		return
	}
	e := &lruEntry[V]{key: key, val: val}
	c.items[key] = e
	c.pushFront(e)
	if len(c.items) > c.cap {
		c.evict()
	}
}

func (c *lruCache[V]) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		c.unlink(e)
		delete(c.items, key)
	}
}

func (c *lruCache[V]) pushFront(e *lruEntry[V]) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

func (c *lruCache[V]) unlink(e *lruEntry[V]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (c *lruCache[V]) moveToFront(e *lruEntry[V]) {
	if c.head == e {
		return
	}
	c.unlink(e)
	c.pushFront(e)
}

func (c *lruCache[V]) evict() {
	if c.tail == nil {
		return
	}
	delete(c.items, c.tail.key)
	c.unlink(c.tail)
}

// ── dirSize cache ─────────────────────────────────────────────────────────────

var dirSizeCache = newLRU[int64](dirSizeCacheCapacity)

func cachedDirSize(absPath string) int64 {
	if v, ok := dirSizeCache.get(absPath); ok {
		return v
	}
	size := computeDirSize(absPath)
	dirSizeCache.set(absPath, size)
	return size
}

func invalidateDirSizeCache(absPath string) {
	p := absPath
	for {
		dirSizeCache.delete(p)
		if p == rootDir {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
}

func computeDirSize(path string) int64 {
	var total int64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ── versioned byte cache ──────────────────────────────────────────────────────
// Used by both the thumbnail cache and the preview-JSON cache.

type bytesCacheEntry struct {
	data    []byte
	modTime time.Time
}

// bytesCache wraps an LRU with a modTime-based freshness check.
type bytesCache struct {
	lru *lruCache[bytesCacheEntry]
}

func newBytesCache(capacity int) *bytesCache {
	return &bytesCache{lru: newLRU[bytesCacheEntry](capacity)}
}

func (c *bytesCache) get(key string, modTime time.Time) ([]byte, bool) {
	if entry, ok := c.lru.get(key); ok && entry.modTime.Equal(modTime) {
		return entry.data, true
	}
	return nil, false
}

func (c *bytesCache) set(key string, modTime time.Time, data []byte) {
	c.lru.set(key, bytesCacheEntry{data: data, modTime: modTime})
}

// ── thumbnail cache ───────────────────────────────────────────────────────────

var thumbCache = newBytesCache(thumbCacheCapacity)

func getThumb(absPath string, modTime time.Time) ([]byte, bool) {
	return thumbCache.get(absPath, modTime)
}

func storeThumb(absPath string, modTime time.Time, data []byte) {
	thumbCache.set(absPath, modTime, data)
}

// ── preview cache ─────────────────────────────────────────────────────────────

var previewCache = newBytesCache(previewCacheCapacity)

func getPreview(key string, modTime time.Time) ([]byte, bool) {
	return previewCache.get(key, modTime)
}

func storePreview(key string, modTime time.Time, data []byte) {
	previewCache.set(key, modTime, data)
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

func generateCSRFToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && c.Value != "" {
		return c.Value
	}
	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func validateCSRF(r *http.Request) bool {
	cookieVal := ""
	if c, err := r.Cookie(cookieCSRF); err == nil {
		cookieVal = c.Value
	}
	formVal := r.FormValue("csrf_token")
	return cookieVal != "" && cookieVal == formVal
}

// ── data types ────────────────────────────────────────────────────────────────

func getCategory(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case imageExts[ext]:
		return "image"
	case videoExts[ext]:
		return "video"
	case archiveExts[ext] || strings.HasSuffix(strings.ToLower(name), ".tar.gz"):
		return "archive"
	case textExts[ext]:
		return "text"
	case ext == ".pdf":
		return "pdf"
	case cadExts[ext]:
		return "stl"
	default:
		return "other"
	}
}

// isNativeVideo reports whether the browser can play the video without Video.js.
func isNativeVideo(name string) bool {
	return nativeVideoExts[strings.ToLower(filepath.Ext(name))]
}

// FileEntry represents one file or directory for any view.
type FileEntry struct {
	Name              string
	Owner             string
	OwnerShort        string
	OwnerFilesURL     template.URL
	Downloads         int64
	Size              int64
	SizeReadable      string
	Category          string
	IsDir             bool
	IsEmpty           bool
	IsNew             bool
	IsDanger          bool
	URL               template.URL
	ThumbURL          template.URL
	ModTimeRaw        int64
	ModTime           string
	Children          []FileEntry
	ChildDirs         int
	ChildFiles        int
	TotalSize         int64
	TotalSizeReadable string
}

// PageData is the top-level template context.
type PageData struct {
	CurrentPath     string
	ParentPath      string
	CurrentURL      template.URL
	ParentURL       template.URL
	BasePath        template.URL
	DeleteAPIURL    template.URL
	BanOwnerAPIURL  template.URL
	MarkBadAPIURL   template.URL
	Breadcrumbs     []Breadcrumb
	Files           []FileEntry
	Tree            []FileEntry
	IsUnlocked      bool
	Theme           string
	Hue             string
	View            string
	SortBy          string
	Order           string
	SortSuffix      template.URL
	UploadDirLabel  string
	WantedFile      string
	CSRFToken       string
	PreviewOpen     bool
	DirName         string
	DirChildDirs    int
	DirChildFiles   int
	DirTotalSize    string
	DirModTime      string
	ThreeCDN        string
	VideoJsCssCDN   string // Video.js CSS URL
	VideoJsJsCDN    string // Video.js JS URL
	FlvjsCDN        string
	VideoJsFlvJsCDN string
}

// Breadcrumb is one path segment in navigation.
type Breadcrumb struct {
	Name      string
	URL       template.URL
	IsCurrent bool
}

// ── template init ─────────────────────────────────────────────────────────────

func init() {
	tmpl = template.Must(
		template.New("ui").Funcs(template.FuncMap{
			"dict": templateDict,
			"huePresets": func() []int {
				return []int{0, 25, 45, 90, 150, 180, 212, 240, 270, 300, 330}
			},
		}).Parse(htmlTmpl),
	)
}

func templateDict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict requires an even number of arguments")
	}
	m := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		m[key] = values[i+1]
	}
	return m, nil
}

type Config struct {
	RootDir           string
	BasePath          string
	EmbedAssets       bool
	MaxUploadBytes    int64
	WarmCacheMax      int
	LookupFileDetails func(relPath string) (FileDetails, error)
	LookupOwner       func(relPath string) (string, error)
	OwnerFilesURL     func(owner string) string
	OwnerDetailsURL   func(owner string) string
}

type FileDetails struct {
	Owner     string
	Downloads int64
}

type Explorer struct {
	basePath string
}

func New(cfg Config) (*Explorer, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, fmt.Errorf("root directory is required")
	}
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = defaultMaxUploadBytes
	}
	if cfg.WarmCacheMax <= 0 {
		cfg.WarmCacheMax = defaultWarmCacheMax
	}

	abs, err := filepath.Abs(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("resolve root directory %q: %w", cfg.RootDir, err)
	}
	if err := os.MkdirAll(abs, os.ModePerm); err != nil {
		return nil, fmt.Errorf("create root directory %q: %w", abs, err)
	}

	rootDir = abs
	embedAssets = cfg.EmbedAssets
	maxFileSize = cfg.MaxUploadBytes
	basePath = normalizeBasePath(cfg.BasePath)
	fileDetailsLookup = cfg.LookupFileDetails
	ownerLookup = cfg.LookupOwner
	ownerFilesURLFunc = cfg.OwnerFilesURL
	ownerDetailsURLFn = cfg.OwnerDetailsURL

	go warmCaches(rootDir, cfg.WarmCacheMax)
	return &Explorer{basePath: basePath}, nil
}

func (e *Explorer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == e.basePath {
		http.Redirect(w, r, e.basePath+"/", http.StatusMovedPermanently)
		return
	}
	if !strings.HasPrefix(r.URL.Path, e.basePath+"/") {
		http.NotFound(w, r)
		return
	}

	innerPath := strings.TrimPrefix(r.URL.Path, e.basePath)
	if innerPath == "" {
		innerPath = "/"
	}

	u := *r.URL
	u.Path = innerPath
	r2 := r.Clone(r.Context())
	r2.URL = &u
	handle(w, r2)
}

func normalizeBasePath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		p = DefaultBasePath
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(filepath.ToSlash(filepath.Clean(p)), "/")
	if p == "." || p == "" {
		return DefaultBasePath
	}
	return p
}

func explorerURL(relPath string) string {
	rel := strings.TrimSpace(filepath.ToSlash(relPath))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." || rel == "" {
		return basePath + "/"
	}
	u := url.URL{Path: "/" + rel}
	return basePath + u.EscapedPath()
}

// ── cache warmup ──────────────────────────────────────────────────────────────

func warmCaches(root string, maxFiles int) {
	start := time.Now()
	log.Printf("CACHE WARMUP: starting (limit %d files)", maxFiles)

	var (
		mu    sync.Mutex
		count int
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 8)
	)

	var walk func(dir string)
	walk = func(dir string) {
		cachedDirSize(dir)

		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			mu.Lock()
			if count >= maxFiles {
				mu.Unlock()
				return
			}
			count++
			mu.Unlock()

			fullPath := filepath.Join(dir, e.Name())
			if e.IsDir() {
				walk(fullPath)
				continue
			}

			info, err := e.Info()
			if err != nil {
				continue
			}
			fPath := fullPath
			fInfo := info
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				warmFilePreview(fPath, fInfo)
			}()
		}
	}

	walk(root)
	wg.Wait()

	elapsed := time.Since(start)
	log.Printf("CACHE WARMUP: done — %d files processed in %v", count, elapsed.Round(time.Millisecond))
}

// buildFilePreviewPayload constructs the previewPayload for a single file.
// It is shared by warmFilePreview and servePreviewJSON to avoid duplication.
// unlocked controls whether download/media URLs are included.
func buildFilePreviewPayload(fullPath string, info os.FileInfo, escapedPath string, unlocked bool) previewPayload {
	p := previewPayload{
		Name:    info.Name(),
		IsDir:   false,
		Size:    formatBytes(info.Size()),
		ModTime: info.ModTime().Format("2006-01-02 15:04"),
		Ext:     strings.ToLower(filepath.Ext(info.Name())),
	}
	if unlocked {
		p.DownloadURL = escapedPath
	}

	// Detect MIME type from the first 512 bytes.
	if f, err := os.Open(fullPath); err == nil {
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		p.MimeType = http.DetectContentType(buf[:n])
		f.Close()
	}

	cat := getCategory(info.Name())
	likelyText := cat == "text" || strings.HasPrefix(p.MimeType, "text/")
	if !likelyText && p.Ext == "" {
		likelyText = isLikelyTextFile(fullPath)
	}

	switch {
	case unlocked && cat == "image":
		p.IsImage = true
		p.ThumbURL = escapedPath + "?thumb=1"
		if iw, ih, mode := imageStats(fullPath); iw > 0 {
			p.ImageWidth = iw
			p.ImageHeight = ih
			p.ImageMode = mode
		}
		// Warm the thumbnail while we're here.
		if _, ok := getThumb(fullPath, info.ModTime()); !ok {
			generateAndStoreThumb(fullPath, info.ModTime())
		}

	case likelyText:
		p.IsText = true
		p.TextLines = readFirstLines(fullPath, 25)
		lc, wc, cc, ending := textStats(fullPath)
		p.TextLineCount = lc
		p.TextWordCount = wc
		p.TextCharCount = cc
		p.TextLineEnding = ending

	case unlocked && (cat == "video" || strings.HasPrefix(p.MimeType, "video/")):
		p.IsVideo = true
		p.VideoURL = escapedPath
		p.VideoNative = isNativeVideo(info.Name())

	case cat == "archive":
		p.IsArchive = true
		p.ArchiveEntries = listArchive(fullPath)

	case cat == "pdf":
		p.IsPdf = true
		p.PdfPageCount = countPdfPages(fullPath)

	case cat == "stl":
		p.IsStl = true
		p.StlTriangles, p.StlTitle = readStlMeta(fullPath)
	}

	return p
}

// generateAndStoreThumb decodes the image at fullPath, scales it to 150×150,
// and stores the JPEG bytes in the thumbnail cache.
func generateAndStoreThumb(fullPath string, modTime time.Time) {
	f, err := os.Open(fullPath)
	if err != nil {
		return
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		log.Printf("thumb decode error for %q: %v", fullPath, err)
		return
	}
	dst := image.NewRGBA(image.Rect(0, 0, 150, 150))
	src := img.Bounds()
	srcW, srcH := src.Dx(), src.Dy()
	if srcW == 0 || srcH == 0 {
		return
	}
	for y := 0; y < 150; y++ {
		sy := src.Min.Y + (y*srcH)/150
		for x := 0; x < 150; x++ {
			sx := src.Min.X + (x*srcW)/150
			dst.Set(x, y, img.At(sx, sy))
		}
	}
	var bb byteBuffer
	if jpeg.Encode(&bb, dst, &jpeg.Options{Quality: 70}) == nil {
		storeThumb(fullPath, modTime, bb.b)
	}
}

// warmFilePreview pre-computes and caches the preview JSON (locked variant)
// and thumbnail for a single file.
func warmFilePreview(fullPath string, info os.FileInfo) {
	relPath := strings.TrimPrefix(filepath.ToSlash(fullPath), filepath.ToSlash(rootDir)+"/")
	escapedPath := explorerURL(relPath)

	// Build the locked (unlocked=false) variant; the unlocked variant is built
	// on first real request.
	p := buildFilePreviewPayload(fullPath, info, escapedPath, false)

	var buf byteBuffer
	json.NewEncoder(&buf).Encode(p)
	storePreview(fullPath, info.ModTime(), buf.b)
}

// ── middleware ────────────────────────────────────────────────────────────────

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		log.Printf("[%s] %s %s %s", ip, r.Method, r.URL.Path, r.URL.RawQuery)
		next.ServeHTTP(w, r)
	})
}

func getIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ── request routing ───────────────────────────────────────────────────────────

func handle(w http.ResponseWriter, r *http.Request) {
	fetchSite := r.Header.Get("Sec-Fetch-Site")
	referer := r.Header.Get("Referer")
	if (fetchSite != "" && fetchSite != "same-origin" && fetchSite != "none") ||
		(referer != "" && !strings.Contains(referer, r.Host)) {
		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		if ext != "" && ext != ".html" {
			http.Error(w, "Direct access only", http.StatusForbidden)
			return
		}
	}

	relPath := normaliseRelPath(r.URL.Path)
	fullPath := filepath.Join(rootDir, relPath)

	if !strings.HasPrefix(fullPath+string(filepath.Separator), rootDir+string(filepath.Separator)) &&
		fullPath != rootDir {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	q := r.URL.Query()

	if q.Has("toggle-preview") {
		prev := cookieValue(r, cookiePreview, "open")
		next := "closed"
		if prev == "closed" {
			next = "open"
		}
		http.SetCookie(w, &http.Cookie{Name: cookiePreview, Value: next, Path: "/", MaxAge: 86400 * 365})
		http.Redirect(w, r, stripQuery("toggle-preview", r), http.StatusSeeOther)
		return
	}

	if q.Has("toggle-theme") {
		theme := "dark"
		if cookieValue(r, cookieTheme, "light") == "dark" {
			theme = "light"
		}
		http.SetCookie(w, &http.Cookie{Name: cookieTheme, Value: theme, Path: "/", MaxAge: 86400 * 365})
		http.Redirect(w, r, stripQuery("toggle-theme", r), http.StatusSeeOther)
		return
	}

	if hue := q.Get("set-hue"); hue != "" {
		if isValidHue(hue) {
			http.SetCookie(w, &http.Cookie{Name: cookieHue, Value: hue, Path: "/", MaxAge: 86400 * 365})
		}
		http.Redirect(w, r, stripQuery("set-hue", r), http.StatusSeeOther)
		return
	}

	if v := q.Get("set-view"); v != "" {
		if v == viewTable || v == viewTiles || v == viewTree || v == viewClassic {
			http.SetCookie(w, &http.Cookie{Name: cookieView, Value: v, Path: "/", MaxAge: 86400 * 365})
		}
		http.Redirect(w, r, stripQuery("set-view", r), http.StatusSeeOther)
		return
	}

	switch {
	case q.Get("static") != "":
		serveStaticAsset(w, r, q.Get("static"))
	case q.Get("thumb") == "1":
		serveThumb(w, r, fullPath)
	case q.Get("preview") == "true":
		servePreviewJSON(w, r, fullPath, relPath)
	case r.Method == http.MethodPost:
		handleUpload(w, r, fullPath, relPath)
	default:
		handleGet(w, r, fullPath, relPath)
	}
}

func normaliseRelPath(urlPath string) string {
	p := filepath.Clean(strings.TrimPrefix(urlPath, "/"))
	if p == "." {
		return ""
	}
	return p
}

func stripQuery(param string, r *http.Request) string {
	q := r.URL.Query()
	q.Del(param)
	target := r.URL.Path
	if target == "" {
		target = "/"
	}
	target = basePath + target
	if encoded := q.Encode(); encoded != "" {
		target += "?" + encoded
	}
	return target
}

func isValidHue(s string) bool {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return false
	}
	return n >= 0 && n <= 360
}

func setCacheHeaders(w http.ResponseWriter, ttl time.Duration) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
	w.Header().Set("Expires", time.Now().Add(ttl).UTC().Format(http.TimeFormat))
}

// ── thumbnail handler ─────────────────────────────────────────────────────────

func serveThumb(w http.ResponseWriter, r *http.Request, fullPath string) {
	if !isUnlocked(r) {
		http.Error(w, "Locked", http.StatusForbidden)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	modTime := info.ModTime()

	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !modTime.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	// Check in-memory cache first.
	if cached, ok := getThumb(fullPath, modTime); ok {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
		setCacheHeaders(w, thumbBrowserTTL)
		w.Write(cached)
		return
	}

	// Generate and cache the thumbnail; on decode failure return 404.
	generateAndStoreThumb(fullPath, modTime)
	cached, ok := getThumb(fullPath, modTime)
	if !ok {
		// Decode failed (unsupported or corrupt image).
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	setCacheHeaders(w, thumbBrowserTTL)
	w.Write(cached)
}

// byteBuffer is a minimal io.Writer that accumulates bytes.
type byteBuffer struct{ b []byte }

func (bb *byteBuffer) Write(p []byte) (int, error) {
	bb.b = append(bb.b, p...)
	return len(p), nil
}

// ── GET handler ───────────────────────────────────────────────────────────────

func handleGet(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	if !info.IsDir() {
		w.Header().Set("Content-Disposition", "attachment; filename="+info.Name())
		w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
		http.ServeFile(w, r, fullPath)
		return
	}

	unlocked := true

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	csrf := csrfToken(w, r)

	view := cookieValue(r, cookieView, viewTable)
	theme := cookieValue(r, cookieTheme, "light")
	hue := cookieValue(r, cookieHue, defaultHue)
	if urlHue := r.URL.Query().Get("hue"); urlHue != "" && isValidHue(urlHue) {
		hue = urlHue
	}

	newNames := parseNewNames(r.URL.Query().Get("new"))

	var files []FileEntry
	var tree []FileEntry
	switch view {
	case viewTree:
		tree = buildTree(fullPath, relPath, unlocked, newNames)
	default:
		files = listDirectory(fullPath, relPath, r, unlocked)
	}

	uploadLabel := "root"
	if relPath != "" {
		uploadLabel = relPath
	}
	wantedFile := strings.TrimSpace(r.URL.Query().Get("wanted"))
	if wantedFile != "" {
		wantedFile = filepath.Base(filepath.ToSlash(wantedFile))
		if wantedFile == "." || wantedFile == "/" {
			wantedFile = ""
		}
	}

	parent := filepath.ToSlash(filepath.Dir(relPath))
	if parent == "." || parent == "/" {
		parent = ""
	}

	var sortSuffix template.URL
	if sortBy := r.URL.Query().Get("sort"); sortBy != "" {
		order := r.URL.Query().Get("order")
		if order == "" {
			order = "asc"
		}
		sortSuffix = template.URL("?sort=" + sortBy + "&order=" + order)
	}

	dirChildDirs, dirChildFiles := 0, 0
	if files != nil {
		for _, f := range files {
			if f.IsDir {
				dirChildDirs++
			} else {
				dirChildFiles++
			}
		}
	} else if entries, err := os.ReadDir(fullPath); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				dirChildDirs++
			} else {
				dirChildFiles++
			}
		}
	}
	dirName := filepath.Base(fullPath)
	if relPath == "" {
		dirName = "root"
	}

	threeCDN := "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"
	videoJsCssCDN := "https://vjs.zencdn.net/8.23.4/video-js.css"
	videoJsJsCDN := "https://vjs.zencdn.net/8.23.4/video.min.js"
	flvjsCDN := "https://cdnjs.cloudflare.com/ajax/libs/flv.js/1.6.2/flv.min.js"
	videoJsFlvJsCDN := "https://cdn.jsdelivr.net/npm/videojs-flvjs@0.3.1/dist/videojs-flvjs.min.js"
	if embedAssets {
		threeCDN = basePath + "/?static=three.min.js"
		videoJsCssCDN = basePath + "/?static=video-js.css"
		videoJsJsCDN = basePath + "/?static=video.js"
		flvjsCDN = basePath + "/?static=flv.js"
		videoJsFlvJsCDN = basePath + "/?static=videojs-flvjs.min.js"
	}

	data := PageData{
		CurrentPath:     relPath,
		ParentPath:      parent,
		CurrentURL:      template.URL(explorerURL(relPath)),
		ParentURL:       template.URL(explorerURL(parent)),
		BasePath:        template.URL(basePath),
		DeleteAPIURL:    template.URL(defaultDeleteAPIPath),
		BanOwnerAPIURL:  template.URL(defaultBanOwnerAPIPath),
		MarkBadAPIURL:   template.URL(defaultMarkBadAPIPath),
		Breadcrumbs:     buildBreadcrumbs(relPath),
		Files:           files,
		Tree:            tree,
		IsUnlocked:      unlocked,
		Theme:           theme,
		Hue:             hue,
		View:            view,
		SortBy:          r.URL.Query().Get("sort"),
		Order:           r.URL.Query().Get("order"),
		SortSuffix:      sortSuffix,
		UploadDirLabel:  uploadLabel,
		WantedFile:      wantedFile,
		CSRFToken:       csrf,
		PreviewOpen:     cookieValue(r, cookiePreview, "open") == "open",
		DirName:         dirName,
		DirChildDirs:    dirChildDirs,
		DirChildFiles:   dirChildFiles,
		DirTotalSize:    formatBytes(cachedDirSize(fullPath)),
		DirModTime:      info.ModTime().Format("2006-01-02 15:04"),
		ThreeCDN:        threeCDN,
		VideoJsCssCDN:   videoJsCssCDN,
		VideoJsJsCDN:    videoJsJsCDN,
		FlvjsCDN:        flvjsCDN,
		VideoJsFlvJsCDN: videoJsFlvJsCDN,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template execute error: %v", err)
	}
}

// ── directory listing ─────────────────────────────────────────────────────────

func listDirectory(fullPath, relPath string, r *http.Request, unlocked bool) []FileEntry {
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		log.Printf("readdir %q: %v", fullPath, err)
		return nil
	}
	newNames := parseNewNames(r.URL.Query().Get("new"))
	files := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		finfo, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, createFileEntry(e.Name(), relPath, finfo, e.IsDir(), newNames[e.Name()], unlocked))
	}
	sortFiles(files, r.URL.Query().Get("sort"), r.URL.Query().Get("order"))
	return files
}

func parseNewNames(raw string) map[string]bool {
	m := make(map[string]bool)
	for _, name := range strings.Split(raw, ",") {
		if name != "" {
			m[name] = true
		}
	}
	return m
}

func sortFiles(files []FileEntry, by, order string) {
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		var less bool
		switch by {
		case "downloads":
			less = files[i].Downloads < files[j].Downloads
		case "size":
			si, sj := files[i].Size, files[j].Size
			if files[i].IsDir {
				si = files[i].TotalSize
			}
			if files[j].IsDir {
				sj = files[j].TotalSize
			}
			less = si < sj
		case "modified":
			less = files[i].ModTimeRaw < files[j].ModTimeRaw
		default:
			less = strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
		}
		if order == "desc" {
			return !less
		}
		return less
	})
}

// ── tree builder ──────────────────────────────────────────────────────────────

func buildTree(fullPath, relPath string, unlocked bool, newNames map[string]bool) []FileEntry {
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		log.Printf("buildTree readdir %q: %v", fullPath, err)
		return nil
	}
	nodes := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		finfo, err := e.Info()
		if err != nil {
			continue
		}
		node := createFileEntry(e.Name(), relPath, finfo, e.IsDir(), newNames[e.Name()], unlocked)
		if e.IsDir() {
			node.Children = buildTree(
				filepath.Join(fullPath, e.Name()),
				filepath.Join(relPath, e.Name()),
				unlocked,
				newNames,
			)
			node.ChildDirs, node.ChildFiles, _ = treeStats(node.Children)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func treeStats(children []FileEntry) (dirs, files int, _ int64) {
	for _, c := range children {
		if c.IsDir {
			dirs++
		} else {
			files++
		}
	}
	return
}

// ── file entry factory ────────────────────────────────────────────────────────

func createFileEntry(name, relPath string, info os.FileInfo, isDir, isNew, unlocked bool) FileEntry {
	entryRelPath := filepath.ToSlash(filepath.Join(relPath, name))
	urlStr := explorerURL(entryRelPath)
	details, ownerShort, ownerFilesURL, _ := fileDetailsForPath(entryRelPath)

	var thumbURL string
	if unlocked && imageExts[strings.ToLower(filepath.Ext(name))] {
		thumbURL = urlStr + "?thumb=1"
	}

	absPath := filepath.Join(rootDir, relPath, name)
	entry := FileEntry{
		Name:          name,
		Owner:         details.Owner,
		OwnerShort:    ownerShort,
		OwnerFilesURL: ownerFilesURL,
		Downloads:     details.Downloads,
		Size:          info.Size(),
		SizeReadable:  formatBytes(info.Size()),
		IsDir:         isDir,
		IsEmpty:       checkIsEmpty(absPath, info),
		URL:           template.URL(urlStr),
		ThumbURL:      template.URL(thumbURL),
		ModTimeRaw:    info.ModTime().Unix(),
		ModTime:       info.ModTime().Format("2006-01-02 15:04"),
		IsNew:         isNew,
		IsDanger:      !isDir && dangerExts[strings.ToLower(filepath.Ext(name))],
		Category:      getCategory(name),
	}
	if isDir {
		entry.TotalSize = cachedDirSize(absPath)
		entry.TotalSizeReadable = formatBytes(entry.TotalSize)
	}
	return entry
}

// ── multipart helpers ─────────────────────────────────────────────────────────

func getFullFilename(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, _ := mime.ParseMediaType(v)
	return dispositionParams["filename"]
}

func streamMultipartParts(mr *multipart.Reader, w http.ResponseWriter, r *http.Request, fullPath string, ip string) (map[string]bool, error) {
	topLevelRemap := make(map[string]string)
	uploadedTopLevel := make(map[string]bool)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "reading multipart: "+err.Error(), 500)
			return nil, err
		}

		filename := getFullFilename(part)
		if filename == "" {
			io.Copy(io.Discard, part)
			part.Close()
			continue
		}

		cleanRel := filepath.FromSlash(filepath.Clean("/" + filepath.ToSlash(filename)))
		cleanRel = strings.TrimPrefix(cleanRel, string(filepath.Separator))

		segments := strings.SplitN(cleanRel, string(filepath.Separator), 2)
		topLevel := segments[0]
		isNested := len(segments) == 2

		var destRel string
		if isNested {
			if _, seen := topLevelRemap[topLevel]; !seen {
				wanted := filepath.Join(fullPath, topLevel)
				unique := getUniqueDirPath(wanted)
				topLevelRemap[topLevel] = filepath.Base(unique)
				if err := os.MkdirAll(unique, os.ModePerm); err != nil {
					log.Printf("[%s] UPLOAD ERROR: mkdir %q: %v", ip, unique, err)
					io.Copy(io.Discard, part)
					part.Close()
					continue
				}
				invalidateDirSizeCache(unique)
				uploadedTopLevel[filepath.Base(unique)] = true
			}
			uniqueTop := topLevelRemap[topLevel]
			destRel = filepath.Join(uniqueTop, segments[1])
		} else {
			destRel = topLevel
		}

		destPath := filepath.Join(fullPath, destRel)

		if !strings.HasPrefix(filepath.Clean(destPath)+string(filepath.Separator),
			filepath.Clean(fullPath)+string(filepath.Separator)) {
			log.Printf("[%s] UPLOAD SKIP (traversal): %q", ip, filename)
			io.Copy(io.Discard, part)
			part.Close()
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), os.ModePerm); err != nil {
			log.Printf("[%s] UPLOAD ERROR: mkdir %q: %v", ip, filepath.Dir(destPath), err)
			io.Copy(io.Discard, part)
			part.Close()
			continue
		}

		if !isNested {
			destPath = getUniquePath(destPath)
			uploadedTopLevel[filepath.Base(destPath)] = true
		}

		log.Printf("[%s] UPLOAD %q → %q", ip, filename, destPath)
		if err := saveFile(part, destPath); err != nil {
			log.Printf("[%s] UPLOAD ERROR: save %q: %v", ip, destPath, err)
		}
		part.Close()
	}

	invalidateDirSizeCache(fullPath)
	return uploadedTopLevel, nil
}

// ── upload handler ────────────────────────────────────────────────────────────

func handleUpload(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
	ip := getIP(r)
	log.Printf("[%s] UPLOAD START: target=%q, size=%d bytes", ip, relPath, r.ContentLength)

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	csrfPart, err := mr.NextPart()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if csrfPart.FormName() != "csrf_token" {
		log.Printf("[%s] UPLOAD REJECTED: first part is %q, expected csrf_token", ip, csrfPart.FormName())
		http.Error(w, "Invalid request", http.StatusForbidden)
		return
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(csrfPart, 64))
	csrfPart.Close()
	if err != nil || !validateCSRFValue(r, string(tokenBytes)) {
		log.Printf("[%s] UPLOAD REJECTED: invalid CSRF token", ip)
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	uploadedTopLevel, err := streamMultipartParts(mr, w, r, fullPath, ip)
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieUnlock,
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})

	u := url.URL{Path: explorerURL(relPath)}
	q := u.Query()
	if len(uploadedTopLevel) > 0 {
		var names []string
		for k := range uploadedTopLevel {
			names = append(names, k)
		}
		q.Set("new", strings.Join(names, ","))
	}
	if s := r.URL.Query().Get("sort"); s != "" {
		q.Set("sort", s)
		q.Set("order", r.URL.Query().Get("order"))
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func validateCSRFValue(r *http.Request, token string) bool {
	c, err := r.Cookie(cookieCSRF)
	if err != nil || c.Value == "" {
		return false
	}
	return token != "" && c.Value == token
}

// ── static asset handler ──────────────────────────────────────────────────────

// staticMIME maps embedded asset filenames to their correct Content-Type.
// http.ServeContent can misidentify types — e.g. "video.js" would be served as
// video/*, not application/javascript — causing browsers to ignore the asset.
var staticMIME = map[string]string{
	"three.min.js":         "application/javascript",
	"video.js":             "application/javascript",
	"video-js.css":         "text/css; charset=utf-8",
	"flv.js":               "application/javascript",
	"videojs-flvjs.min.js": "application/javascript",
}

func serveStaticAsset(w http.ResponseWriter, r *http.Request, name string) {
	data, err := staticAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	ct, ok := staticMIME[name]
	if !ok {
		ct = mime.TypeByExtension(filepath.Ext(name))
		if ct == "" {
			ct = http.DetectContentType(data)
		}
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

// ── preview JSON handler ──────────────────────────────────────────────────────

type archiveEntry struct {
	Name     string `json:"name"`
	Size     string `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Category string `json:"category"`
}

type previewPayload struct {
	Name            string `json:"name"`
	IsDir           bool   `json:"is_dir"`
	RelPath         string `json:"rel_path,omitempty"`
	Owner           string `json:"owner,omitempty"`
	OwnerFilesURL   string `json:"owner_files_url,omitempty"`
	OwnerDetailsURL string `json:"owner_details_url,omitempty"`
	Downloads       int64  `json:"downloads"`
	Size            string `json:"size"`
	ModTime         string `json:"mod_time"`
	Ext             string `json:"ext,omitempty"`

	ChildDirs  int    `json:"child_dirs"`
	ChildFiles int    `json:"child_files"`
	TotalSize  string `json:"total_size,omitempty"`

	MimeType    string `json:"mime_type"`
	DownloadURL string `json:"download_url,omitempty"`

	IsImage     bool   `json:"is_image"`
	ThumbURL    string `json:"thumb_url,omitempty"`
	ImageWidth  int    `json:"image_width,omitempty"`
	ImageHeight int    `json:"image_height,omitempty"`
	ImageMode   string `json:"image_mode,omitempty"`

	IsVideo     bool   `json:"is_video"`
	VideoURL    string `json:"video_url,omitempty"`
	VideoNative bool   `json:"video_native"` // true = browser plays natively; false = needs Video.js

	IsText         bool     `json:"is_text"`
	TextLines      []string `json:"text_lines,omitempty"`
	TextLineCount  int      `json:"text_line_count,omitempty"`
	TextWordCount  int      `json:"text_word_count,omitempty"`
	TextCharCount  int      `json:"text_char_count,omitempty"`
	TextLineEnding string   `json:"text_line_ending,omitempty"`

	IsArchive      bool           `json:"is_archive"`
	ArchiveEntries []archiveEntry `json:"archive_entries,omitempty"`

	IsPdf        bool `json:"is_pdf"`
	PdfPageCount int  `json:"pdf_page_count,omitempty"`

	IsStl        bool   `json:"is_stl"`
	StlTriangles int    `json:"stl_triangles,omitempty"`
	StlTitle     string `json:"stl_title,omitempty"`
}

func servePreviewJSON(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
	info, err := os.Stat(fullPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	unlocked := isUnlocked(r)
	details, _, ownerFilesURL, ownerDetailsURL := fileDetailsForPath(relPath)

	cacheKey := fullPath
	if unlocked {
		cacheKey += ":unlocked"
	}
	cacheKey += fmt.Sprintf(":owner=%s:downloads=%d", details.Owner, details.Downloads)
	if cached, ok := getPreview(cacheKey, info.ModTime()); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached)
		return
	}

	escapedPath := explorerURL(filepath.ToSlash(relPath))

	var p previewPayload
	if info.IsDir() {
		p = previewPayload{
			Name:    info.Name(),
			IsDir:   true,
			Size:    formatBytes(info.Size()),
			ModTime: info.ModTime().Format("2006-01-02 15:04"),
		}
		entries, _ := os.ReadDir(fullPath)
		for _, e := range entries {
			if e.IsDir() {
				p.ChildDirs++
			} else {
				p.ChildFiles++
			}
		}
		p.TotalSize = formatBytes(cachedDirSize(fullPath))
	} else {
		p = buildFilePreviewPayload(fullPath, info, escapedPath, unlocked)
	}
	p.RelPath = filepath.ToSlash(relPath)
	p.Owner = details.Owner
	p.Downloads = details.Downloads
	if ownerFilesURL != "" {
		p.OwnerFilesURL = string(ownerFilesURL)
	}
	if ownerDetailsURL != "" {
		p.OwnerDetailsURL = string(ownerDetailsURL)
	}

	var jsonBuf byteBuffer
	json.NewEncoder(&jsonBuf).Encode(p)
	storePreview(cacheKey, info.ModTime(), jsonBuf.b)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBuf.b)
}

// ── text / image helpers ──────────────────────────────────────────────────────

const textProbeBytes = 8 << 10

func isLikelyTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, textProbeBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	return isLikelyText(buf[:n])
}

func isLikelyText(sample []byte) bool {
	if len(sample) == 0 {
		return true
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}

	controls := 0
	for _, b := range sample {
		switch b {
		case '\n', '\r', '\t', '\f':
			continue
		}
		if b < 0x20 {
			controls++
		}
	}

	// Treat payloads with many control bytes as binary.
	return controls*100 <= len(sample)*5
}

func readFirstLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(lines) < n {
		lines = append(lines, sc.Text())
	}
	return lines
}

func imageStats(path string) (width, height int, mode string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return
	}
	width, height = cfg.Width, cfg.Height

	switch cfg.ColorModel {
	case color.RGBAModel, color.RGBA64Model:
		mode = "RGBA"
	case color.NRGBAModel, color.NRGBA64Model:
		mode = "NRGBA"
	case color.YCbCrModel:
		mode = "YCbCr (JPEG)"
	case color.GrayModel, color.Gray16Model:
		mode = "Grayscale"
	case color.CMYKModel:
		mode = "CMYK"
	case color.AlphaModel, color.Alpha16Model:
		mode = "Alpha"
	default:
		type stringer interface{ String() string }
		if cfg.ColorModel == nil {
			mode = "Unknown"
		} else if s, ok := cfg.ColorModel.(stringer); ok {
			mode = s.String()
		} else {
			t := fmt.Sprintf("%T", cfg.ColorModel)
			if i := strings.LastIndex(t, "."); i >= 0 {
				t = t[i+1:]
			}
			t = strings.ReplaceAll(t, "modelFunc", "Standard")
			t = strings.TrimSuffix(t, "Model")
			mode = t
		}
	}
	return
}

func textStats(path string) (lines, words, chars int, lineEnding string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var hasCRLF, hasLF, inWord bool
	br := bufio.NewReader(f)
	for {
		ch, _, err := br.ReadRune()
		if err != nil {
			if inWord {
				words++
			}
			break
		}
		chars++
		switch ch {
		case '\r':
			if next, _ := br.ReadByte(); next == '\n' {
				hasCRLF = true
				chars++
			} else {
				_ = br.UnreadByte()
			}
			lines++
			if inWord {
				words++
				inWord = false
			}
		case '\n':
			hasLF = true
			lines++
			if inWord {
				words++
				inWord = false
			}
		case ' ', '\t':
			if inWord {
				words++
				inWord = false
			}
		default:
			inWord = true
		}
	}
	if chars > 0 {
		lines++
	}

	switch {
	case hasCRLF && hasLF:
		lineEnding = "mixed"
	case hasCRLF:
		lineEnding = "CRLF"
	case hasLF:
		lineEnding = "LF"
	default:
		lineEnding = "n/a"
	}
	return
}

// ── archive listing ───────────────────────────────────────────────────────────

const maxArchiveEntries = 200

func listArchive(path string) []archiveEntry {
	ext := strings.ToLower(filepath.Ext(path))
	if strings.HasSuffix(strings.ToLower(path), ".tar.gz") {
		ext = ".tar.gz"
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	switch ext {
	case ".zip":
		return listZip(path)
	case ".tar", ".tar.gz", ".tgz":
		return listTar(f, ext == ".tar.gz")
	}
	return nil
}

func listZip(path string) []archiveEntry {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	entries := make([]archiveEntry, 0, min(len(r.File), maxArchiveEntries))
	for i, file := range r.File {
		if i >= maxArchiveEntries {
			break
		}
		isDir := file.FileInfo().IsDir()
		cat := ""
		if !isDir {
			cat = getCategory(file.Name)
		}
		entries = append(entries, archiveEntry{
			Name:     file.Name,
			Size:     formatBytes(int64(file.UncompressedSize64)),
			IsDir:    isDir,
			Category: cat,
		})
	}
	return entries
}

func listTar(f *os.File, isGzip bool) []archiveEntry {
	var tr *tar.Reader
	if isGzip {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	} else {
		tr = tar.NewReader(f)
	}

	var entries []archiveEntry
	for i := 0; i < maxArchiveEntries; i++ {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		isDir := header.Typeflag == tar.TypeDir
		cat := ""
		if !isDir {
			cat = getCategory(header.Name)
		}
		entries = append(entries, archiveEntry{
			Name:     header.Name,
			Size:     formatBytes(header.Size),
			IsDir:    isDir,
			Category: cat,
		})
	}
	return entries
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── PDF helpers ───────────────────────────────────────────────────────────────

func countPdfPages(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	buf := make([]byte, 2<<20)
	n, _ := f.Read(buf)
	data := buf[:n]

	needle := []byte("/Count ")
	idx := bytes.Index(data, needle)
	if idx == -1 {
		return 0
	}
	rest := data[idx+len(needle):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	count := 0
	for _, ch := range rest[:end] {
		count = count*10 + int(ch-'0')
	}
	return count
}

// ── STL helpers ───────────────────────────────────────────────────────────────

func readStlMeta(path string) (triangles int, title string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	header := make([]byte, 84)
	n, err := f.Read(header)
	if err != nil || n < 84 {
		return
	}

	if bytes.HasPrefix(bytes.TrimSpace(header[:80]), []byte("solid")) {
		line := strings.TrimSpace(string(header[:80]))
		if strings.HasPrefix(line, "solid") {
			title = strings.TrimSpace(strings.TrimPrefix(line, "solid"))
		}
		return
	}

	rawHeader := header[:80]
	end := 0
	for end < len(rawHeader) {
		b := rawHeader[end]
		if b == 0 || b < 0x20 || b > 0x7e {
			break
		}
		end++
	}
	rawTitle := strings.TrimSpace(string(rawHeader[:end]))
	if rawTitle != "" {
		title = rawTitle
	}
	triangles = int(uint32(header[80]) | uint32(header[81])<<8 | uint32(header[82])<<16 | uint32(header[83])<<24)
	return
}

// ── misc helpers ──────────────────────────────────────────────────────────────

func cookieValue(r *http.Request, name, def string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return def
	}
	return c.Value
}

func fileDetailsForPath(relPath string) (details FileDetails, ownerShort string, filesURL template.URL, detailsURL template.URL) {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relPath)), "/")
	if clean == "." {
		clean = ""
	}
	if clean == "" {
		return FileDetails{}, "", "", ""
	}

	if fileDetailsLookup != nil {
		found, err := fileDetailsLookup(clean)
		if err != nil {
			return FileDetails{}, "", "", ""
		}
		details = found
	} else if ownerLookup != nil {
		found, err := ownerLookup(clean)
		if err != nil {
			return FileDetails{}, "", "", ""
		}
		details.Owner = found
	}
	details.Owner = strings.TrimSpace(details.Owner)
	if details.Owner == "" {
		return details, "", "", ""
	}

	ownerShort = details.Owner
	if len(ownerShort) > 12 {
		ownerShort = ownerShort[:12]
	}
	if ownerFilesURLFunc != nil {
		if u := strings.TrimSpace(ownerFilesURLFunc(details.Owner)); u != "" {
			filesURL = template.URL(u)
		}
	}
	if ownerDetailsURLFn != nil {
		if u := strings.TrimSpace(ownerDetailsURLFn(details.Owner)); u != "" {
			detailsURL = template.URL(u)
		}
	}
	return details, ownerShort, filesURL, detailsURL
}

func isUnlocked(r *http.Request) bool {
	return true
}

func checkIsEmpty(path string, fi os.FileInfo) bool {
	if !fi.IsDir() {
		return fi.Size() == 0
	}
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == io.EOF
}

// uniquePathHelper returns the first non-existing path of the form
// "dir/stem (N)suffix" starting at N=1.
func uniquePathHelper(dir, stem, suffix string) string {
	for i := 1; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, suffix))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

func getUniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	dir, file := filepath.Split(path)
	ext := filepath.Ext(file)
	return uniquePathHelper(filepath.Clean(dir), strings.TrimSuffix(file, ext), ext)
}

func getUniqueDirPath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	return uniquePathHelper(filepath.Dir(path), filepath.Base(path), "")
}

func buildBreadcrumbs(relPath string) []Breadcrumb {
	crumbs := []Breadcrumb{{Name: "root", URL: template.URL(explorerURL(""))}}
	if relPath == "" || relPath == "." {
		crumbs[0].IsCurrent = true
		return crumbs
	}
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	accumulated := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		accumulated += "/" + p
		crumbs = append(crumbs, Breadcrumb{Name: p, URL: template.URL(explorerURL(accumulated))})
	}
	crumbs[len(crumbs)-1].IsCurrent = true
	return crumbs
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func saveFile(src io.Reader, destPath string) error {
	dst, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// ── template ──────────────────────────────────────────────────────────────────

var htmlTmpl = `
<!DOCTYPE html>
<html lang="en" data-theme="{{.Theme}}" style="--hue:{{.Hue}}">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>neurokyme explorer{{if .CurrentPath}} — {{.CurrentPath}}{{end}}</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M2 16h4l3-9 5 18 4-13 3 4h9' fill='none' stroke='%230969da' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
    <link rel="stylesheet" href="{{.VideoJsCssCDN}}">
    <style>
        /* ── hue-driven design tokens ── */
        :root {
            --hue: 212;
            --bg:            hsl(var(--hue), 0%,   100%);
            --surface:       hsl(var(--hue), 14%,  97%);
            --surface2:      hsl(var(--hue), 14%,  92%);
            --text:          hsl(var(--hue), 18%,  13%);
            --text-muted:    hsl(var(--hue), 8%,   40%);
            --accent:        hsl(var(--hue), 87%,  42%);
            --accent-fg:     #ffffff;
            --success:       hsl(134, 61%, 30%);
            --border:        hsl(var(--hue), 14%,  84%);
            --shadow:        0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
            --radius:        8px;
            --upload-bg:     hsl(var(--hue), 80%,  96%);
            --upload-border: hsl(var(--hue), 60%,  72%);
            --warn-bg:       hsl(38, 92%, 95%);
            --warn-border:   hsl(38, 80%, 70%);
            --warn-text:     hsl(38, 60%, 28%);
            --warn-icon:     hsl(38, 90%, 45%);
            --icon-image:    hsl(var(--hue), 75%, 50%);
            --icon-video:    hsl(280, 70%, 52%);
            --icon-text:     hsl(160, 55%, 38%);
            --icon-archive:  hsl(38,  80%, 42%);
            --icon-other:    var(--text-muted);
            --icon-dir:      hsl(var(--hue), 75%, 50%);
            --icon-pdf:      hsl(0, 75%, 48%);
            --icon-stl:      hsl(180, 55%, 38%);
        }
        [data-theme="dark"] {
            --bg:            hsl(var(--hue), 14%,  7%);
            --surface:       hsl(var(--hue), 14%,  11%);
            --surface2:      hsl(var(--hue), 12%,  16%);
            --text:          hsl(var(--hue), 14%,  90%);
            --text-muted:    hsl(var(--hue), 8%,   57%);
            --accent:        hsl(var(--hue), 90%,  68%);
            --accent-fg:     hsl(var(--hue), 14%,  7%);
            --success:       hsl(134, 55%, 48%);
            --border:        hsl(var(--hue), 12%,  22%);
            --shadow:        0 1px 3px rgba(0,0,0,.4);
            --upload-bg:     hsl(var(--hue), 40%,  10%);
            --upload-border: hsl(var(--hue), 50%,  30%);
            --warn-bg:       hsl(38, 30%, 10%);
            --warn-border:   hsl(38, 50%, 28%);
            --warn-text:     hsl(38, 70%, 65%);
            --warn-icon:     hsl(38, 80%, 55%);
            --icon-image:    hsl(var(--hue), 85%, 65%);
            --icon-video:    hsl(280, 75%, 70%);
            --icon-text:     hsl(160, 60%, 55%);
            --icon-archive:  hsl(38,  85%, 60%);
            --icon-pdf:      hsl(0, 80%, 65%);
            --icon-stl:      hsl(180, 60%, 55%);
        }

        *, *::before, *::after { box-sizing: border-box; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            margin: 0;
            padding: 0;
        }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        a:focus-visible, button:focus-visible, summary:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 2px;
            border-radius: 2px;
        }
        .sr-only {
            position: absolute; width: 1px; height: 1px;
            padding: 0; margin: -1px; overflow: hidden;
            clip: rect(0,0,0,0); white-space: nowrap; border: 0;
        }

        .shell { max-width: 1080px; margin: 0 auto; padding: 24px 20px 48px; }

        /* ── header ── */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }
        .header h1 { margin: 0; font-size: 1.25rem; font-weight: 600; letter-spacing: -.02em; }
        .header ruby { font-size: 1.1rem; }
        .header rt  { font-size: .6rem; font-weight: 400; color: var(--text-muted); }
        .header-controls { display: flex; align-items: center; gap: 6px; }

        .unlock-hint {
            display: inline-block;
            background-image: linear-gradient(90deg,
                #ff0000, #ff7f00, #ffff00, #00ff00, #0000ff, #4b0082, #8b00ff,
                #ff0000, #ff7f00, #ffff00, #00ff00, #0000ff, #4b0082, #8b00ff
            );
            background-size: 400% auto;
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: flashy-settle 3.5s cubic-bezier(.77,0,.18,1) forwards;
        }
        @keyframes flashy-settle {
            0%   { background-position: 0% center; }
            70%  { -webkit-text-fill-color: transparent; }
            100% { background-position: 300% center; -webkit-text-fill-color: var(--text-muted); }
        }

        /* ── locked-file banner ── */
        .locked-banner {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            background: var(--warn-bg);
            border: 1px solid var(--warn-border);
            border-radius: var(--radius);
            padding: 14px 16px;
            margin-bottom: 16px;
            animation: banner-in 0.25s ease;
        }
        @keyframes banner-in {
            from { opacity: 0; transform: translateY(-6px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .locked-banner-icon {
            flex-shrink: 0; width: 20px; height: 20px;
            stroke: var(--warn-icon); fill: none; stroke-width: 1.75;
            stroke-linecap: round; stroke-linejoin: round; margin-top: 1px;
        }
        .locked-banner-body    { flex: 1; min-width: 0; }
        .locked-banner-title   { font-weight: 600; color: var(--warn-text); margin-bottom: 2px; }
        .locked-banner-filename {
            font-family: ui-monospace, "SFMono-Regular", monospace;
            font-size: 13px;
            background: color-mix(in srgb, var(--warn-border) 30%, transparent);
            border-radius: 4px; padding: 0 5px; color: var(--warn-text);
        }
        .locked-banner-sub  { font-size: 13px; color: var(--warn-text); opacity: .85; margin-top: 2px; }
        .locked-banner-dismiss {
            flex-shrink: 0; background: none; border: none; cursor: pointer;
            padding: 2px; color: var(--warn-text); opacity: .6; border-radius: 4px;
            display: flex; align-items: center; justify-content: center; transition: opacity .15s;
        }
        .locked-banner-dismiss:hover { opacity: 1; }

        /* ── icons ── */
        .icon {
            width: 16px; height: 16px;
            vertical-align: middle; flex-shrink: 0;
            fill: none; stroke: currentColor;
            stroke-width: 1.75; stroke-linecap: round; stroke-linejoin: round;
        }
        .icon-lg { width: 40px; height: 40px; stroke-width: 1.5; }
        .icon-cat-image   { stroke: var(--icon-image); }
        .icon-cat-video   { stroke: var(--icon-video); }
        .icon-cat-text    { stroke: var(--icon-text); }
        .icon-cat-archive { stroke: var(--icon-archive); }
        .icon-cat-pdf     { stroke: var(--icon-pdf); fill: color-mix(in srgb, var(--icon-pdf) 10%, transparent); }
        .icon-cat-stl     { stroke: var(--icon-stl); fill: color-mix(in srgb, var(--icon-stl) 10%, transparent); }
        .icon-cat-other   { stroke: var(--icon-other); }
        .icon-cat-dir     { stroke: var(--icon-dir); fill: color-mix(in srgb, var(--icon-dir) 12%, transparent); }
        .icon-cat-dir.empty { fill: none; stroke: var(--text-muted); }
        .icon.muted   { stroke: var(--text-muted) !important; fill: none !important; opacity: .45; }
        .icon.success { stroke: var(--success); }

        /* ── copy-link button ── */
        .copy-link-btn {
            display: inline-flex; align-items: center; justify-content: center;
            width: 22px; height: 22px; border-radius: 4px;
            border: none; background: transparent; cursor: pointer;
            color: var(--text-muted); opacity: 0; transition: opacity .15s, color .15s;
            padding: 0; flex-shrink: 0;
        }
        tr:hover .copy-link-btn,
        .tile:hover .copy-link-btn,
        .tree-file:hover .copy-link-btn,
        details > summary:hover .copy-link-btn { opacity: 1; }
        .copy-link-btn:hover { color: var(--accent); }
        .copy-link-btn.copied { color: var(--success); opacity: 1; }
        .copy-link-btn svg { width: 13px; height: 13px; pointer-events: none; }

        /* ── buttons ── */
        .btn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 5px 14px; border: none; border-radius: 6px;
            font-size: 13px; font-weight: 600; cursor: pointer;
            transition: filter .15s, opacity .15s; white-space: nowrap;
        }
        .btn:hover  { filter: brightness(1.08); }
        .btn:active { filter: brightness(.95); }
        .btn-primary { background: var(--success); color: #fff; }
        .btn-ghost {
            background: var(--surface); border: 1px solid var(--border);
            color: var(--text); font-weight: 400;
        }
        .btn-ghost:hover { background: var(--surface2); }
        .btn-icon {
            padding: 5px; border-radius: 6px;
            background: var(--surface); border: 1px solid var(--border);
            color: var(--text); cursor: pointer;
            display: inline-flex; align-items: center; justify-content: center;
            transition: background .1s;
        }
        .btn-icon:hover { background: var(--surface2); }

        /* ── upload card ── */
        .upload-card {
            background: var(--upload-bg);
            border: 1px dashed var(--upload-border);
            border-radius: var(--radius);
            padding: 14px 16px; margin-bottom: 20px;
            transition: background .15s, border-color .15s, box-shadow .2s;
        }
        .upload-card:focus-within { border-style: solid; }
        .upload-card.upload-highlight {
            border-style: solid; border-color: var(--accent);
            box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent), var(--shadow);
        }
        .upload-header {
            display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
            font-size: 12px; color: var(--text-muted); font-weight: 500;
            text-transform: uppercase; letter-spacing: .04em;
        }
        .upload-dest {
            font-family: ui-monospace, "SFMono-Regular", monospace;
            font-size: 12px; font-weight: 600; color: var(--accent);
            text-transform: none; letter-spacing: 0;
        }
        .upload-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .upload-label {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 5px 12px; border: 1px solid var(--border); border-radius: 6px;
            background: var(--bg); color: var(--text); font-size: 13px;
            cursor: pointer; transition: background .1s, border-color .1s;
        }
        .upload-label:hover { background: var(--surface2); border-color: var(--accent); }
        .upload-label input[type="file"] { position: absolute; width: 1px; height: 1px; opacity: 0; }
        .upload-filename {
            font-size: 13px; color: var(--text-muted); font-family: ui-monospace, monospace;
            flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }

        /* ── hue picker ── */
        .hue-picker-wrap { position: relative; }
        .hue-picker-btn {
            width: 28px; height: 28px; border-radius: 6px;
            border: 1px solid var(--border); background: var(--surface);
            cursor: pointer; display: flex; align-items: center; justify-content: center;
            transition: background .1s; padding: 0;
        }
        .hue-picker-btn:hover { background: var(--surface2); }
        .hue-picker-btn .hue-dot {
            width: 14px; height: 14px; border-radius: 50%;
            background: hsl(var(--hue), 80%, 50%);
            border: 1px solid rgba(0,0,0,.15); pointer-events: none;
        }
        .hue-picker-panel {
            display: none; position: absolute; top: calc(100% + 6px); right: 0;
            background: var(--surface); border: 1px solid var(--border);
            border-radius: var(--radius); box-shadow: 0 8px 24px rgba(0,0,0,.18);
            padding: 12px; width: 220px; z-index: 200;
        }
        .hue-picker-panel.open { display: block; }
        .hue-picker-label {
            font-size: 11px; font-weight: 600; text-transform: uppercase;
            letter-spacing: .05em; color: var(--text-muted); margin-bottom: 10px;
        }
        .hue-slider {
            width: 100%; height: 14px; border-radius: 7px; cursor: pointer;
            -webkit-appearance: none; appearance: none;
            background: linear-gradient(to right,
                hsl(0,80%,55%), hsl(30,80%,55%), hsl(60,80%,55%),
                hsl(90,80%,55%), hsl(120,80%,55%), hsl(150,80%,55%),
                hsl(180,80%,55%), hsl(210,80%,55%), hsl(240,80%,55%),
                hsl(270,80%,55%), hsl(300,80%,55%), hsl(330,80%,55%),
                hsl(360,80%,55%));
            outline: none; margin-bottom: 12px;
        }
        .hue-slider::-webkit-slider-thumb {
            -webkit-appearance: none; width: 18px; height: 18px; border-radius: 50%;
            background: #fff; border: 2px solid rgba(0,0,0,.3);
            box-shadow: 0 1px 4px rgba(0,0,0,.25); cursor: pointer;
        }
        .hue-slider::-moz-range-thumb {
            width: 18px; height: 18px; border-radius: 50%;
            background: #fff; border: 2px solid rgba(0,0,0,.3);
            box-shadow: 0 1px 4px rgba(0,0,0,.25); cursor: pointer;
        }
        .hue-presets { display: flex; gap: 6px; flex-wrap: wrap; }
        .hue-preset {
            width: 22px; height: 22px; border-radius: 50%;
            border: 2px solid transparent; cursor: pointer;
            transition: transform .1s, border-color .1s;
        }
        .hue-preset:hover  { transform: scale(1.15); }
        .hue-preset.active { border-color: var(--text); }

        /* ── view toggle ── */
        .view-group {
            display: inline-flex; border: 1px solid var(--border);
            border-radius: 6px; overflow: hidden;
        }
        .view-group a {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 5px 11px; font-size: 13px; color: var(--text);
            background: var(--surface); border-right: 1px solid var(--border);
            transition: background .1s;
        }
        .view-group a:last-child { border-right: none; }
        .view-group a:hover  { background: var(--surface2); text-decoration: none; }
        .view-group a.active { background: var(--accent); color: var(--accent-fg); }

        /* ── toolbar ── */
        .toolbar {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 16px; flex-wrap: wrap;
        }
        .toolbar-spacer { flex: 1; }
        .filter-container {
            position: relative; display: flex; align-items: center;
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 0 10px; width: 220px;
            transition: border-color .1s, box-shadow .1s;
        }
        .filter-container:focus-within {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 15%, transparent);
        }
        .filter-container input {
            background: transparent; border: none; color: var(--text);
            font-size: 13px; padding: 6px 0; width: 100%; outline: none; margin-left: 8px;
        }
        .filter-count-badge { font-size: 11px; color: var(--text-muted); white-space: nowrap; margin-left: 8px; }
        @media (max-width: 768px) { .filter-container { width: 100%; order: 10; } }

        /* ── breadcrumbs ── */
        .breadcrumb {
            display: flex; align-items: center; gap: 4px;
            font-size: 13px; color: var(--text-muted); flex-wrap: wrap;
        }
        .breadcrumb a { color: var(--text-muted); }
        .breadcrumb a:hover { color: var(--accent); }
        .breadcrumb .sep     { opacity: .4; }
        .breadcrumb .current { color: var(--text); font-weight: 500; }

        /* ── table view ── */
        .file-table {
            width: 100%; border-collapse: collapse;
            border: 1px solid var(--border); border-radius: var(--radius);
            overflow: hidden; box-shadow: var(--shadow);
        }
        .file-table thead tr { background: var(--surface); }
        .file-table th {
            text-align: left; padding: 10px 14px;
            font-size: 12px; font-weight: 600; text-transform: uppercase;
            letter-spacing: .04em; color: var(--text-muted);
            border-bottom: 1px solid var(--border); white-space: nowrap;
        }
        .file-table th:nth-child(2) { width: 190px; }
        .file-table th:nth-child(3) { width: 100px; }
        .file-table th:nth-child(4) { width: 160px; }
        @media (max-width: 700px) {
            .file-table th:nth-child(2), .file-table td:nth-child(2) { display: none; }
        }
        @media (max-width: 500px) {
            .file-table th:nth-child(3), .file-table td:nth-child(3) { display: none; }
            .file-table th:nth-child(4) { width: 120px; }
        }
        .file-table th a { color: var(--text-muted); display: block; }
        .file-table th a:hover { color: var(--accent); }
        .file-table td {
            padding: 9px 14px; border-bottom: 1px solid var(--border);
            vertical-align: middle; overflow: hidden;
        }
        .file-table tbody tr:last-child td { border-bottom: none; }
        .file-table tbody tr { transition: background .1s; }
        .file-table tbody tr:hover { background: var(--surface); }
        .file-table tbody tr.is-dir { cursor: pointer; }
        .file-table tbody tr.wanted-file td { background: color-mix(in srgb, var(--warn-bg) 60%, transparent); }
        .file-table tbody tr.selected td { background: color-mix(in srgb, var(--accent) 10%, transparent); }
        .file-table tbody tr.selected td:first-child { box-shadow: inset 3px 0 0 var(--accent); }
        .file-table tbody tr.parent-row.kb-selected td { background: color-mix(in srgb, var(--accent) 7%, var(--surface2)); }
        .file-table tbody tr.parent-row.kb-selected td:first-child { box-shadow: inset 3px 0 0 var(--text-muted); }
        .icon-danger { color: #e53935; flex-shrink: 0; stroke: #e53935 !important; fill: none !important; opacity: 1 !important; }
        .cell-name {
            display: flex; align-items: center; gap: 8px; min-width: 0;
        }
        .cell-name a, .cell-name span.locked-text {
            overflow-wrap: anywhere; word-break: break-word; min-width: 0;
        }
        .cell-meta   { color: var(--text-muted); font-size: 13px; }
        .cell-size   { white-space: nowrap; text-align: right; }
        .owner-chip {
            display: inline-flex; align-items: center;
            gap: 4px; max-width: 100%;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: var(--surface2);
            padding: 2px 8px;
            color: var(--text-muted);
            text-decoration: none;
        }
        .owner-chip:hover { color: var(--accent); border-color: var(--accent); text-decoration: none; }
        .owner-chip code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
            font-size: 11px;
            white-space: nowrap;
        }
        .sort-arrow  { font-size: 10px; margin-left: 2px; }
        .locked-text { color: var(--text-muted); }

        /* ── tile grid ── */
        .tile-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 12px;
        }
        .tile {
            border: 1px solid var(--border); border-radius: var(--radius);
            overflow: hidden; background: var(--surface);
            transition: box-shadow .15s, transform .1s;
            cursor: pointer;
        }
        .tile:hover        { box-shadow: var(--shadow); transform: translateY(-1px); }
        .tile.selected     { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent); outline: none; }
        .tile.selected .tile-thumb { background: color-mix(in srgb, var(--accent) 12%, var(--surface2)); }
        .tile.selected .tile-info  { background: color-mix(in srgb, var(--accent) 8%, transparent); }
        .tile.wanted-tile  { border-color: var(--warn-border); box-shadow: 0 0 0 2px color-mix(in srgb, var(--warn-border) 35%, transparent); }
        .tile a { display: block; color: inherit; text-decoration: none; }
        .tile-thumb {
            width: 100%; height: 110px;
            background: var(--surface2);
            display: flex; align-items: center; justify-content: center;
            overflow: hidden; position: relative;
        }
        .tile-thumb img   { width: 100%; height: 100%; object-fit: cover; }
        .tile-badge-new   { position: absolute; top: 6px; right: 6px; }
        .tile-info {
            padding: 8px 10px; font-size: 12px;
            display: flex; flex-direction: column; align-items: stretch; gap: 4px;
            border-top: 1px solid var(--border);
        }
        .tile-info-top {
            display: flex; align-items: center; gap: 4px; min-width: 0;
        }
        .tile-info-name {
            flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .tile-owner-line {
            min-width: 0;
            font-size: 11px;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .tile-owner-link {
            color: var(--text-muted);
            text-decoration: none;
        }
        .tile-owner-link:hover { color: var(--accent); text-decoration: none; }
        .tile-dir-hint, .tile-file-hint {
            position: absolute; bottom: 6px; right: 6px;
            opacity: 0; transition: opacity .15s; pointer-events: none;
        }
        .tile:hover .tile-dir-hint,
        .tile:hover .tile-file-hint { opacity: .55; }

        /* ── tiles layout + preview ── */
        .tiles-toolbar {
            display: flex; align-items: center; gap: 8px;
            margin-bottom: 12px; min-height: 32px;
        }
        .tiles-toolbar-spacer { flex: 1; }

        /* ── content+preview layout (shared by table, tree, tiles) ── */
        .content-layout { display: flex; gap: 16px; align-items: flex-start; }
        .content-main   { flex: 1; min-width: 0; }

        /* ── preview toggle button ── */
        .preview-toggle-btn {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 5px 10px; border: 1px solid var(--border); border-radius: 6px;
            background: var(--surface); color: var(--text-muted); font-size: 12px;
            cursor: pointer; text-decoration: none; transition: background .1s, color .1s, border-color .1s;
            white-space: nowrap; flex-shrink: 0;
        }
        .preview-toggle-btn:hover { background: var(--surface2); color: var(--text); border-color: var(--accent); text-decoration: none; }
        .preview-toggle-btn.active { background: var(--surface2); color: var(--text); }

        /* ── sort controls ── */
        .sort-select {
            appearance: none; -webkit-appearance: none;
            padding: 4px 24px 4px 9px; border: 1px solid var(--border); border-radius: 6px;
            background: var(--surface) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%238b949e' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat right 8px center;
            color: var(--text); font-size: 13px; cursor: pointer;
            height: 30px; line-height: 1; outline: none;
        }
        .sort-select:hover        { background-color: var(--surface2); }
        .sort-select:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
        .sort-order-btn {
            display: inline-flex; align-items: center; justify-content: center;
            width: 30px; height: 30px; border: 1px solid var(--border); border-radius: 6px;
            background: var(--surface); color: var(--text-muted); cursor: pointer;
            font-size: 13px; transition: background .1s, color .1s, border-color .1s;
            text-decoration: none; flex-shrink: 0;
        }
        .sort-order-btn:hover  { background: var(--surface2); color: var(--text); border-color: var(--accent); text-decoration: none; }
        .sort-order-btn.active { background: var(--surface2); color: var(--text); }

        /* ── preview pane ── */
        .preview-pane {
            width: 260px; flex-shrink: 0;
            border: 1px solid var(--border); border-radius: var(--radius);
            background: var(--surface); box-shadow: var(--shadow); overflow: hidden;
            position: sticky; top: 16px; align-self: flex-start;
            max-height: calc(100vh - 40px); overflow-y: auto;
        }
        .preview-backdrop { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 999; }
        .preview-header {
            display: flex; align-items: center; gap: 8px;
            padding: 10px 12px; border-bottom: 1px solid var(--border);
            background: var(--surface2); position: sticky; top: 0; z-index: 1;
        }
        .preview-header-name {
            flex: 1; font-size: 13px; font-weight: 600;
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .preview-thumb {
            width: 100%; height: 140px; object-fit: cover;
            display: block; border-bottom: 1px solid var(--border);
        }
        .preview-icon-hero {
            width: 100%; height: 100px;
            display: flex; align-items: center; justify-content: center;
            background: var(--surface2); border-bottom: 1px solid var(--border);
        }
        .preview-actions {
            padding: 10px 12px; border-bottom: 1px solid var(--border);
            display: flex; flex-direction: column; gap: 8px;
        }
        .preview-actions .btn { flex: 1; justify-content: center; }
        .preview-meta { padding: 10px 12px; }
        .preview-meta-row {
            display: flex; justify-content: space-between; align-items: baseline;
            padding: 3px 0; font-size: 12px; border-bottom: 1px solid var(--border);
        }
        .preview-meta-row:last-child { border-bottom: none; }
        .preview-meta-label { color: var(--text-muted); }
        .preview-meta-value { font-weight: 500; text-align: right; }
        .owner-details-block {
            border-top: 1px solid var(--border);
            padding: 10px 12px;
        }
        .owner-details-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            margin-bottom: 8px;
        }
        .owner-details-heading {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 0;
        }
        .owner-details-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: var(--text-muted);
        }
        .owner-details-hash {
            display: inline-flex;
            align-items: center;
            max-width: 100%;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: var(--surface2);
            padding: 2px 8px;
            color: var(--text);
        }
        .owner-details-hash code {
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 11px;
        }
        .owner-status {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 58px;
            border-radius: 999px;
            padding: 3px 8px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: .04em;
            text-transform: uppercase;
        }
        .owner-status.active {
            color: #0e6245;
            background: color-mix(in srgb, #4ade80 18%, transparent);
            border: 1px solid color-mix(in srgb, #22c55e 28%, var(--border));
        }
        .owner-status.banned {
            color: #b42318;
            background: color-mix(in srgb, #fda4af 18%, transparent);
            border: 1px solid color-mix(in srgb, #ef4444 30%, var(--border));
        }
        .owner-details-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 8px;
            margin-bottom: 10px;
        }
        .owner-stat-card {
            border: 1px solid var(--border);
            border-radius: 10px;
            background: var(--surface2);
            padding: 8px;
        }
        .owner-stat-label {
            display: block;
            margin-bottom: 4px;
            color: var(--text-muted);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .owner-stat-value {
            display: block;
            font-size: 12px;
            font-weight: 600;
            overflow-wrap: anywhere;
            word-break: break-word;
        }
        .owner-files-wrap,
        .owner-events-wrap {
            border: 1px solid var(--border);
            border-radius: 10px;
            background: var(--surface2);
            overflow: hidden;
        }
        .owner-files-head,
        .owner-events-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            padding: 8px 10px;
            border-bottom: 1px solid var(--border);
        }
        .owner-files-title,
        .owner-events-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: var(--text-muted);
        }
        .owner-files-count,
        .owner-events-count {
            font-size: 11px;
            color: var(--text-muted);
            white-space: nowrap;
        }
        .owner-files-list,
        .owner-events-list {
            max-height: 220px;
            overflow-y: auto;
        }
        .owner-file-row,
        .owner-event-row {
            padding: 8px 10px;
            border-bottom: 1px solid var(--border);
        }
        .owner-file-row:last-child,
        .owner-event-row:last-child {
            border-bottom: none;
        }
        .owner-file-actions {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 6px;
            flex-wrap: wrap;
        }
        .owner-file-path {
            display: block;
            font-family: ui-monospace, "SFMono-Regular", monospace;
            font-size: 11px;
            line-height: 1.5;
            overflow-wrap: anywhere;
            word-break: break-word;
        }
        .owner-file-link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 4px 8px;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: var(--surface);
            color: var(--text);
            font-size: 11px;
            text-decoration: none;
            cursor: pointer;
        }
        .owner-file-link:hover {
            border-color: var(--accent);
            color: var(--accent);
            text-decoration: none;
        }
        .owner-file-kind {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 4px 8px;
            border-radius: 999px;
            background: color-mix(in srgb, var(--accent) 10%, transparent);
            color: var(--text-muted);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .owner-event-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            margin-bottom: 4px;
        }
        .owner-event-kind {
            font-family: ui-monospace, "SFMono-Regular", monospace;
            font-size: 11px;
            font-weight: 600;
        }
        .owner-event-time {
            color: var(--text-muted);
            font-size: 11px;
            white-space: nowrap;
        }
        .owner-event-meta {
            display: flex;
            flex-direction: column;
            gap: 2px;
            color: var(--text-muted);
            font-size: 11px;
        }
        .owner-details-note {
            color: var(--text-muted);
            font-size: 11px;
        }
        .owner-details-empty {
            padding: 12px 10px;
            color: var(--text-muted);
            font-size: 11px;
        }

        .preview-archive-block { border-top: 1px solid var(--border); padding: 10px 12px; }
        .preview-archive-label {
            font-size: 11px; font-weight: 600; text-transform: uppercase;
            letter-spacing: .05em; color: var(--text-muted); margin-bottom: 6px;
        }
        .preview-archive-list {
            list-style: none; margin: 0; padding: 0;
            max-height: 260px; overflow-y: auto;
        }
        .preview-archive-item {
            display: flex; align-items: center; gap: 6px;
            padding: 3px 0; font-size: 12px;
            border-bottom: 1px solid var(--border);
        }
        .preview-archive-item:last-child { border-bottom: none; }
        .preview-archive-name {
            flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
            font-family: ui-monospace, "SFMono-Regular", monospace; font-size: 11px;
        }
        .preview-archive-size { color: var(--text-muted); font-size: 11px; white-space: nowrap; }
        .preview-archive-more {
            font-size: 11px; color: var(--text-muted);
            font-style: italic; padding: 6px 0 2px; text-align: center;
        }

        .preview-text-block  { border-top: 1px solid var(--border); padding: 10px 12px; }
        .preview-text-label  {
            font-size: 11px; font-weight: 600; text-transform: uppercase;
            letter-spacing: .05em; color: var(--text-muted); margin-bottom: 6px;
        }
        .preview-truncated   { font-weight: 400; text-transform: none; letter-spacing: 0; font-style: italic; opacity: .75; }
        .preview-text-content {
            font-family: ui-monospace, "SFMono-Regular", monospace;
            font-size: 11px; line-height: 1.6; white-space: pre-wrap;
            word-break: break-all; color: var(--text);
            max-height: 240px; overflow-y: auto;
        }
        .preview-empty   { padding: 36px 16px; text-align: center; color: var(--text-muted); font-size: 13px; }
        .preview-loading { padding: 32px 12px; text-align: center; color: var(--text-muted); font-size: 13px; }
        .preview-close   { display: none; }
        .preview-pdf-embed {
            width: 100%; height: 320px;
            border-bottom: 1px solid var(--border);
            background: var(--surface2);
        }
        .preview-pdf-embed object { display: block; width: 100%; height: 100%; border: none; }
        .preview-stl-wrap {
            width: 100%; height: 260px; position: relative;
            border-bottom: 1px solid var(--border);
            background: var(--surface2); overflow: hidden;
        }
        .preview-stl-wrap canvas { display: block; width: 100% !important; height: 100% !important; cursor: grab; }
        .preview-stl-wrap canvas:active { cursor: grabbing; }
        .preview-stl-status {
            position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
            font-size: 12px; color: var(--text-muted); pointer-events: none;
        }
        /* Video.js overrides to match the UI */
        .preview-video-wrap { border-bottom: 1px solid var(--border); background: #000; }
        .preview-video-wrap .video-js { width: 100%; height: 180px; }

        /* ── mobile preview sheet ── */
        @media (max-width: 600px) {
            .content-layout { flex-direction: column; }
            .preview-pane {
                display: none; position: fixed;
                bottom: 0; left: 0; right: 0; width: 100%; max-height: 75vh;
                z-index: 1000; transform: translateY(calc(200% + 40px));
                transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                border-radius: 16px 16px 0 0;
                box-shadow: 0 -4px 20px rgba(0,0,0,.2);
                flex-direction: column; background: var(--bg);
            }
            .preview-backdrop.active { display: block; }
            .preview-empty           { display: none; }
            .preview-pane.active     { transform: translateY(0); }
            .preview-header          { padding: 15px; border-radius: 16px 16px 0 0; }
            .preview-close           { display: block !important; background: var(--surface2); border: none; padding: 8px; border-radius: 50%; cursor: pointer; color: var(--text); }
            .upload-header           { flex-wrap: wrap; row-gap: 4px; }
            .unlock-hint             { width: 100%; margin-top: 2px; }
            .sort-select             { flex: 1; }
            .sort-order-btn          { width: 36px; height: 36px; }
            .owner-details-grid      { grid-template-columns: 1fr; }
        }

        /* ── tree view ── */
        .tree-wrap {
            border: 1px solid var(--border); border-radius: var(--radius);
            background: var(--surface); padding: 12px; box-shadow: var(--shadow);
        }
        .tree-parent-link {
            display: flex; align-items: center; gap: 6px;
            padding: 5px 8px; border-radius: 5px;
            font-size: 13px; color: var(--text-muted); margin-bottom: 2px;
        }
        .tree-parent-link:hover { background: var(--surface2); text-decoration: none; color: var(--text); }
        .tree-toolbar {
            display: flex; align-items: center; gap: 6px;
            padding: 8px 8px 10px; margin-bottom: 2px;
            border-bottom: 1px solid var(--border); flex-wrap: wrap;
        }
        .tree-toolbar-row     { display: contents; }
        .tree-toolbar-label   { font-size: 11px; color: var(--text-muted); font-weight: 500; text-transform: uppercase; letter-spacing: .05em; margin-right: 2px; }
        .tree-toolbar-divider { width: 1px; height: 18px; background: var(--border); margin: 0 2px; flex-shrink: 0; }
        @media (max-width: 600px) {
            .tree-toolbar            { flex-direction: column; align-items: stretch; gap: 8px; }
            .tree-toolbar-row        { display: flex; align-items: center; gap: 6px; }
            .tree-toolbar-divider    { display: none; }
            .tree-toolbar-sort .sort-select { flex: 1; }
            .tree-toolbar-view .tree-ctrl   { flex: 1; justify-content: center; }
        }
        .tree-ctrl {
            display: inline-flex; align-items: center; gap: 4px;
            padding: 3px 9px; border: 1px solid var(--border); border-radius: 5px;
            background: var(--bg); color: var(--text-muted); font-size: 12px;
            cursor: pointer; transition: background .1s, color .1s, border-color .1s; white-space: nowrap;
        }
        .tree-ctrl:hover  { background: var(--surface2); color: var(--text); border-color: var(--accent); }
        .tree-ctrl.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
        .tree-ctrl .icon  { width: 12px; height: 12px; display: inline; vertical-align: middle; }
        @media (max-width: 600px) {
            .tree-ctrl span.tree-ctrl-label { display: none; }
            .tree-ctrl { padding: 8px 10px; }
        }

        /* ── tree nodes ── */
        details { margin: 0; }
        details > summary {
            list-style: none; display: grid;
            grid-template-columns: 18px 18px 1fr auto auto auto;
            align-items: center; column-gap: 6px;
            padding: 3px 8px 3px 6px; border-radius: 5px;
            cursor: pointer; font-size: 13px; transition: background .1s; outline: none;
        }
        details > summary::-webkit-details-marker { display: none; }
        details > summary:hover        { background: var(--surface2); }
        details > summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
        .tree-chevron {
            flex-shrink: 0; width: 14px; height: 14px;
            stroke: var(--text-muted); stroke-width: 2; fill: none;
            transition: transform .15s; justify-self: center;
        }
        details[open] > summary .tree-chevron { transform: rotate(90deg); }
        .tree-children {
            padding-left: 30px; border-left: 1px solid var(--border); margin-left: 15px;
        }
        .tree-file {
            display: grid; grid-template-columns: 18px 18px 1fr auto auto auto;
            align-items: center; column-gap: 6px;
            padding: 3px 8px 3px 6px; border-radius: 5px;
            font-size: 13px; transition: background .1s;
        }
        .tree-file:hover    { background: var(--surface2); }
        .tree-file.selected { background: color-mix(in srgb, var(--accent) 12%, transparent); box-shadow: inset 3px 0 0 var(--accent); }
        .tree-file.wanted-tree { background: color-mix(in srgb, var(--warn-bg) 60%, transparent); }
        details > summary.selected { background: color-mix(in srgb, var(--accent) 12%, transparent); box-shadow: inset 3px 0 0 var(--accent); }
        .tree-dir-link { font-weight: 500; color: var(--text); }
        .tree-dir-link:hover { text-decoration: none; color: var(--accent); }
        .tree-meta {
            font-size: 11px; color: var(--text-muted); white-space: nowrap;
            background: var(--surface2); border: 1px solid var(--border);
            border-radius: 10px; padding: 1px 7px; line-height: 18px; letter-spacing: .01em;
        }
        .tree-size { font-size: 11px; color: var(--text-muted); white-space: nowrap; font-variant-numeric: tabular-nums; }

        /* ── empty state ── */
        .empty-state { text-align: center; padding: 48px 20px; color: var(--text-muted); }

        /* ── badge ── */
        .badge-new {
            font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 10px;
            background: var(--success); color: #fff; letter-spacing: .04em;
            text-transform: uppercase; flex-shrink: 0;
        }

        /* ── footer ── */
        footer {
            margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
            display: flex; align-items: center; justify-content: center; gap: 8px;
            color: var(--text-muted); font-size: 12px;
        }

        #file-label-text { pointer-events: none; }

        /* ── upload loading state ── */
        .btn-loading {
            opacity: 0.7; cursor: not-allowed; pointer-events: none;
        }
        .upload-spinner {
            display: inline-block; width: 14px; height: 14px;
            border: 2px solid rgba(255,255,255,0.4);
            border-top-color: #fff; border-radius: 50%;
            animation: spin 0.7s linear infinite; flex-shrink: 0;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* ── classic view ── */
        .classic-wrap {
            max-width: 900px; margin: 0 auto; padding: 20px 16px;
            font-family: monospace; font-size: 14px; color: var(--text);
        }
        .classic-title { font-size: 18px; font-weight: bold; margin: 0 0 4px; font-family: monospace; }
        .classic-hr { border: none; border-top: 1px solid var(--border); margin: 8px 0; }
        .classic-table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 13px; }
        .classic-table th { text-align: left; padding: 2px 16px 4px 4px; border-bottom: 1px solid var(--border); }
        .classic-table th a { color: var(--accent); }
        .classic-table td { padding: 2px 16px 2px 4px; vertical-align: top; }
        .classic-table tr:hover td { background: var(--surface2); }
        .classic-meta { white-space: nowrap; color: var(--text-muted); }
        .classic-size { text-align: right; font-variant-numeric: tabular-nums; }
        .classic-desc { color: var(--text-muted); font-size: 12px; }
        .classic-upload { padding: 10px 4px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .classic-upload form { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .classic-upload-btn {
            padding: 3px 12px; background: var(--accent); color: var(--accent-fg);
            border: none; border-radius: 4px; cursor: pointer; font-size: 13px;
        }
        .classic-upload-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .classic-upload-status { font-size: 12px; color: var(--text-muted); }
        .classic-footer { color: var(--text-muted); font-family: monospace; }
    </style>
</head>
<body>
<div class="shell">

    <!-- ── header ── -->
    <header class="header" role="banner">
        <h1>
            <a href="{{.BasePath}}/" style="color:inherit">
                <ruby>neu·ro·kyme<rt>\ˈn(y)u̇r-ə-ˌkīm\</rt></ruby>
            </a>
        </h1>
        <div class="header-controls">
            <a href="/admin"
               class="btn-icon"
               aria-label="Back to admin console"
               title="Back to admin console">
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <path d="M3 3h18v18H3z"/>
                    <path d="M9 3v18"/>
                </svg>
            </a>
            <div class="hue-picker-wrap" id="hue-picker-wrap">
                <button class="hue-picker-btn btn-icon"
                        id="hue-picker-btn"
                        aria-label="Choose accent colour"
                        title="Choose accent colour"
                        onclick="toggleHuePicker(event)">
                    <span class="hue-dot"></span>
                </button>
                <div class="hue-picker-panel" id="hue-picker-panel" role="dialog" aria-label="Accent colour picker">
                    <div class="hue-picker-label">Accent colour</div>
                    <input type="range" class="hue-slider" id="hue-slider"
                           min="0" max="360" value="{{.Hue}}"
                           aria-label="Hue"
                           oninput="previewHue(this.value)"
                           onchange="applyHue(this.value)">
                    <div class="hue-presets" aria-label="Preset colours">
                        {{$currentHue := .Hue}}
                        {{range $h := huePresets}}
                        <button class="hue-preset{{if eq (printf "%d" $h) $currentHue}} active{{end}}"
                                style="background:hsl({{$h}},75%,50%)"
                                aria-label="Hue {{$h}}"
                                title="Hue {{$h}}"
                                onclick="applyHue({{$h}})"></button>
                        {{end}}
                    </div>
                </div>
            </div>

            <a href="?toggle-theme=1{{if .SortBy}}&sort={{.SortBy}}&order={{.Order}}{{end}}"
               class="btn-icon"
               aria-label="Toggle colour theme"
               title="Toggle colour theme">
                {{if eq .Theme "light"}}
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/>
                </svg>
                {{else}}
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <circle cx="12" cy="12" r="5"/>
                    <line x1="12" y1="1"  x2="12" y2="3"/>
                    <line x1="12" y1="21" x2="12" y2="23"/>
                    <line x1="4.22" y1="4.22"  x2="5.64" y2="5.64"/>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                    <line x1="1"  y1="12" x2="3"  y2="12"/>
                    <line x1="21" y1="12" x2="23" y2="12"/>
                    <line x1="4.22"  y1="19.78" x2="5.64"  y2="18.36"/>
                    <line x1="18.36" y1="5.64"  x2="19.78" y2="4.22"/>
                </svg>
                {{end}}
            </a>
        </div>
    </header>

    <!-- ── locked-file banner ── -->
    {{if .WantedFile}}
    <div class="locked-banner" id="locked-banner" role="alert" aria-live="assertive">
        <svg class="locked-banner-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <div class="locked-banner-body">
            <div class="locked-banner-title">Downloads are locked</div>
            <div class="locked-banner-sub">
                To download <span class="locked-banner-filename">{{.WantedFile}}</span>,
                upload any file using the form below to unlock access.
            </div>
        </div>
        <button class="locked-banner-dismiss" aria-label="Dismiss" onclick="dismissBanner()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2.5"
                 stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"/>
                <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
        </button>
    </div>
    {{end}}

    <!-- ── upload card ── -->
    <section aria-label="Upload files">
        <form action="{{.CurrentURL}}" method="post" enctype="multipart/form-data" class="upload-card" id="upload-form" onsubmit="uploadStart(this)">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            <div class="upload-header">
                <svg class="icon" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
                Upload to <span class="upload-dest">/{{.UploadDirLabel}}</span>
                {{if not .IsUnlocked}}&nbsp;·&nbsp;<span class="unlock-hint">uploading unlocks downloads</span>{{end}}
            </div>
            <div class="upload-row">
                <label class="upload-label" title="Select one or more files">
                    <svg class="icon" viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                    <input type="file" name="uploadFiles" id="input-files" multiple onchange="syncInputs(this)">
                    Files
                </label>
                <label class="upload-label" title="Select a folder to upload it and its contents">
                    <svg class="icon" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    <input type="file" name="uploadFiles" id="input-folder" webkitdirectory directory onchange="syncInputs(this)">
                    Folder
                </label>
                <span class="upload-filename" id="file-label-text">No selection</span>
                <button type="submit" class="btn btn-primary" id="upload-submit-btn">
                    <svg class="icon" id="upload-btn-icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                    <span id="upload-btn-label">Upload</span>
                </button>
            </div>
        </form>
    </section>

    <!-- ── toolbar ── -->
    <div class="toolbar" role="toolbar" aria-label="View controls">
        <nav aria-label="Breadcrumb navigation" class="breadcrumb">
            {{range $i, $bc := .Breadcrumbs}}
                {{if $i}}<span class="sep" aria-hidden="true">/</span>{{end}}
                <a href="{{$bc.URL}}{{$.SortSuffix}}"{{if $bc.IsCurrent}} aria-current="page" class="current"{{end}}>{{$bc.Name}}</a>
            {{end}}
        </nav>

        <div class="toolbar-spacer"></div>

        <div class="filter-container">
            <svg class="icon muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input type="text"
                   id="global-filter"
                   placeholder="Filter current view..."
                   aria-label="Filter files and folders"
                   oninput="applyFilter(this.value)">
            <span id="filter-count" class="filter-count-badge"></span>
        </div>

        <nav class="view-group" aria-label="View mode">
            <a href="{{if .SortSuffix}}{{.SortSuffix}}&{{else}}?{{end}}set-view=table"
               class="{{if eq .View "table"}}active{{end}}"
               aria-label="Table view"{{if eq .View "table"}} aria-current="true"{{end}}>
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <line x1="8" y1="6"  x2="21" y2="6"/>
                    <line x1="8" y1="12" x2="21" y2="12"/>
                    <line x1="8" y1="18" x2="21" y2="18"/>
                    <line x1="3" y1="6"  x2="3.01" y2="6"/>
                    <line x1="3" y1="12" x2="3.01" y2="12"/>
                    <line x1="3" y1="18" x2="3.01" y2="18"/>
                </svg>
                Table
            </a>
            <a href="{{if .SortSuffix}}{{.SortSuffix}}&{{else}}?{{end}}set-view=tiles"
               class="{{if eq .View "tiles"}}active{{end}}"
               aria-label="Tiles view"{{if eq .View "tiles"}} aria-current="true"{{end}}>
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <rect x="3" y="3" width="7" height="7"/>
                    <rect x="14" y="3" width="7" height="7"/>
                    <rect x="3" y="14" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/>
                </svg>
                Tiles
            </a>
            <a href="{{if .SortSuffix}}{{.SortSuffix}}&{{else}}?{{end}}set-view=tree"
               class="{{if eq .View "tree"}}active{{end}}"
               aria-label="Tree view"{{if eq .View "tree"}} aria-current="true"{{end}}>
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <line x1="6" y1="3" x2="6" y2="15"/>
                    <circle cx="18" cy="6" r="3"/>
                    <circle cx="6" cy="18" r="3"/>
                    <path d="M18 9a9 9 0 0 1-9 9"/>
                </svg>
                Tree
            </a>
            <a href="{{if .SortSuffix}}{{.SortSuffix}}&{{else}}?{{end}}set-view=classic"
               class="{{if eq .View "classic"}}active{{end}}"
               aria-label="Classic view"{{if eq .View "classic"}} aria-current="true"{{end}}>
                <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <rect x="2" y="3" width="20" height="18" rx="1"/>
                    <line x1="2" y1="8" x2="22" y2="8"/>
                    <line x1="7" y1="3" x2="7" y2="8"/>
                </svg>
                Classic
            </a>
        </nav>

        <a href="?toggle-preview=1{{if .SortBy}}&sort={{.SortBy}}&order={{.Order}}{{end}}"
           class="preview-toggle-btn{{if .PreviewOpen}} active{{end}}"
           aria-label="Toggle preview pane"
           title="Toggle preview pane">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <rect x="3" y="3" width="18" height="18" rx="2"/>
                <line x1="15" y1="3" x2="15" y2="21"/>
            </svg>
            Preview
        </a>
    </div>

    <!-- ── main content ── -->
    <main id="main-content">

    {{if eq .View "tiles"}}
    <!-- ── tiles view ── -->
    <div class="content-layout">
        <div class="content-main">
            <div class="tiles-toolbar">
                {{if ne .CurrentPath ""}}
                <a href="{{.ParentURL}}{{$.SortSuffix}}" class="btn btn-ghost" aria-label="Go to parent directory">
                    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                        <line x1="19" y1="12" x2="5" y2="12"/>
                        <polyline points="12 19 5 12 12 5"/>
                    </svg>
                    Up
                </a>
                {{end}}
                <div class="tiles-toolbar-spacer"></div>
                {{template "sort-controls" .}}
            </div>

            {{if .Files}}
            <div class="tile-grid" role="list" aria-label="Directory contents" id="tile-grid">
                {{$wanted := .WantedFile}}
                {{$unlocked := .IsUnlocked}}
                {{range .Files}}
                <div class="tile{{if and (not .IsDir) (eq .Name $wanted)}} wanted-tile{{end}}"
                     role="listitem" tabindex="0" data-name="{{.Name}}"
                     data-preview-url="{{.URL}}?preview=true"
                     {{if .IsDir}}data-dir-url="{{.URL}}{{$.SortSuffix}}" data-nav-url="{{.URL}}{{$.SortSuffix}}"{{else}}{{if $.IsUnlocked}}data-download-url="{{.URL}}"{{end}}{{end}}
                     onclick="tileClick(this, event)"
                     ondblclick="tileDblClick(this, event)">
                    <div class="tile-thumb" aria-hidden="true">
                        {{if .IsDir}}
                            {{template "icon-dir-lg" .}}
                            <svg class="tile-dir-hint" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" width="16" height="16">
                                <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                            </svg>
                        {{else if not $.IsUnlocked}}
                            {{template "icon-lock-lg" .}}
                        {{else if .ThumbURL}}
                            <img src="{{.ThumbURL}}" alt="" loading="lazy">
                            <svg class="tile-file-hint" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" width="16" height="16">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                            </svg>
                        {{else if eq .Category "video"}}
                            <svg class="icon icon-lg icon-cat-video video-thumb-canvas" data-src="{{.URL}}"
                                 viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <rect x="2" y="3" width="20" height="18" rx="2" ry="2"/>
                                <path d="m10 8 5 4-5 4V8z"/>
                            </svg>
                            <svg class="tile-file-hint" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" width="16" height="16">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                            </svg>
                        {{else}}
                            {{if .IsDanger}}
                                {{template "icon-danger-lg" .}}
                            {{else}}
                                {{template "icon-file-lg" .}}
                            {{end}}
                        {{end}}
                        {{if .IsNew}}<span class="tile-badge-new badge-new" aria-hidden="true">new</span>{{end}}
                    </div>
                    <div class="tile-info" title="{{.Name}}">
                        <div class="tile-info-top">
                            <span class="tile-info-name">{{.Name}}</span>
                            {{if or .IsDir $unlocked}}
                            <button class="copy-link-btn" onclick="copyLink(event, '{{.URL}}')" aria-label="Copy link to {{.Name}}" title="Copy link">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                </svg>
                            </button>
                            {{end}}
                        </div>
                        {{if .Owner}}
                        <div class="tile-owner-line">
                            Uploaded by
                            {{if .OwnerFilesURL}}
                            <a class="tile-owner-link" href="{{.OwnerFilesURL}}" title="{{.Owner}}" onclick="event.stopPropagation()"><code>{{.OwnerShort}}</code></a>
                            {{else}}
                            <code title="{{.Owner}}">{{.OwnerShort}}</code>
                            {{end}}
                        </div>
                        {{end}}
                        {{if not .IsDir}}
                        <div class="tile-owner-line">{{.Downloads}} downloads</div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>
            {{else}}
            {{template "empty-state" .}}
            {{end}}
        </div>
        {{template "preview-pane" .}}
    </div>

    {{else if eq .View "tree"}}
    <!-- ── tree view ── -->
    <div class="content-layout">
        <div class="content-main">
    <div class="tree-wrap" role="region" aria-label="Directory tree" id="tree-root">
        <div class="tree-toolbar" role="toolbar" aria-label="Tree controls">
            <div class="tree-toolbar-row tree-toolbar-view">
                <span class="tree-toolbar-label">View</span>
                <button class="tree-ctrl active" id="ctrl-one"
                        onclick="treeOneLevel()" aria-pressed="true"
                        title="Show only the first level of folders">
                    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" stroke-width="2" fill="none">
                        <line x1="3" y1="6"  x2="21" y2="6"/>
                        <line x1="3" y1="12" x2="14" y2="12"/>
                        <line x1="3" y1="18" x2="8"  y2="18"/>
                    </svg>
                    <span class="tree-ctrl-label">One level</span>
                </button>
                <button class="tree-ctrl" id="ctrl-all"
                        onclick="treeExpandAll()" aria-pressed="false"
                        title="Expand all folders">
                    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" stroke-width="2" fill="none">
                        <polyline points="7 13 12 18 17 13"/>
                        <polyline points="7 6  12 11 17 6"/>
                    </svg>
                    <span class="tree-ctrl-label">Expand all</span>
                </button>
                <button class="tree-ctrl" id="ctrl-none"
                        onclick="treeCollapseAll()" aria-pressed="false"
                        title="Collapse all folders">
                    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" stroke-width="2" fill="none">
                        <polyline points="7 11 12 6  17 11"/>
                        <polyline points="7 18 12 13 17 18"/>
                    </svg>
                    <span class="tree-ctrl-label">Collapse all</span>
                </button>
            </div>
            <div class="tree-toolbar-divider" aria-hidden="true"></div>
            <div class="tree-toolbar-row tree-toolbar-sort">
                <span class="tree-toolbar-label">Sort</span>
                {{template "sort-controls" .}}
            </div>
        </div>

        {{if ne .CurrentPath ""}}
        <a href="{{.ParentURL}}{{$.SortSuffix}}" class="tree-parent-link" aria-label="Go to parent directory">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <line x1="19" y1="12" x2="5" y2="12"/>
                <polyline points="12 19 5 12 12 5"/>
            </svg>
            Parent directory
        </a>
        {{end}}
        {{if .Tree}}
        {{template "tree-node" (dict "Children" .Tree "IsUnlocked" .IsUnlocked "SortSuffix" .SortSuffix "WantedFile" .WantedFile)}}
        {{else}}
        {{template "empty-state" .}}
        {{end}}
    </div>
        </div>
        {{template "preview-pane" .}}
    </div>

    {{else if eq .View "classic"}}
    <!-- ── classic view ── -->
    <div class="classic-wrap">
        <h2 class="classic-title">Index of /{{.CurrentPath}}</h2>
        <hr class="classic-hr">
        <table class="classic-table">
            <thead>
                <tr>
                    <th><a href="?sort=name&order={{if eq .SortBy "name"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}">Name</a></th>
                    <th>Uploader</th>
                    <th><a href="?sort=modified&order={{if eq .SortBy "modified"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}desc{{end}}">Last Modified</a></th>
                    <th><a href="?sort=size&order={{if eq .SortBy "size"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}">Size</a></th>
                    <th><a href="?sort=downloads&order={{if eq .SortBy "downloads"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}desc{{end}}">Downloads</a></th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {{if ne .CurrentPath ""}}
                <tr>
                    <td><a href="{{.ParentURL}}">Parent Directory</a></td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                </tr>
                {{end}}
                {{$unlocked := .IsUnlocked}}
                {{range .Files}}
                <tr>
                    <td>
                        {{if .IsDir}}
                            <a href="{{.URL}}/">{{.Name}}/</a>
                        {{else if $unlocked}}
                            <a href="{{.URL}}" download>{{.Name}}</a>
                        {{else}}
                            {{.Name}}
                        {{end}}
                        {{if .IsNew}}&nbsp;<span class="badge-new">new</span>{{end}}
                    </td>
                    <td class="classic-meta">
                        {{if .Owner}}
                            {{if .OwnerFilesURL}}
                            <a class="owner-chip" href="{{.OwnerFilesURL}}" title="{{.Owner}}"><code>{{.OwnerShort}}</code></a>
                            {{else}}
                            <span class="owner-chip" title="{{.Owner}}"><code>{{.OwnerShort}}</code></span>
                            {{end}}
                        {{else}}-{{end}}
                    </td>
                    <td class="classic-meta">{{.ModTime}}</td>
                    <td class="classic-meta classic-size">{{if .IsDir}}{{.TotalSizeReadable}}{{else}}{{.SizeReadable}}{{end}}</td>
                    <td class="classic-meta">{{if .IsDir}}-{{else}}{{.Downloads}}{{end}}</td>
                    <td class="classic-meta classic-desc">{{.Category}}</td>
                </tr>
                {{end}}
                {{if not .Files}}
                <tr><td colspan="6"><em>Empty directory</em></td></tr>
                {{end}}
            </tbody>
        </table>
        <hr class="classic-hr">
        <!-- inline upload form -->
        <div class="classic-upload">
            <form action="{{.CurrentURL}}" method="post" enctype="multipart/form-data" onsubmit="uploadStart(this)" id="classic-upload-form">
                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                <strong>Upload to /{{.UploadDirLabel}}:</strong>
                <input type="file" name="uploadFiles" id="classic-input-files" multiple onchange="classicSyncInput(this)">
                <button type="submit" class="classic-upload-btn" id="classic-submit-btn">
                    <span id="classic-btn-label">Upload</span>
                </button>
                <span id="classic-upload-status" class="classic-upload-status"></span>
            </form>
        </div>
        <hr class="classic-hr">
        <small class="classic-footer">neurokyme explorer — classic view</small>
    </div>

    {{else}}
    <!-- ── table view ── -->
    <div class="content-layout">
        <div class="content-main">
    {{if or .Files (ne .CurrentPath "")}}
    <table class="file-table" aria-label="Directory contents" id="file-table">
        <thead>
            <tr>
                <th scope="col">
                    <a href="?sort=name&order={{if eq .SortBy "name"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}">
                        Name{{if eq .SortBy "name"}}<span class="sort-arrow" aria-hidden="true">{{if eq .Order "asc"}}▲{{else}}▼{{end}}</span>{{end}}
                    </a>
                </th>
                <th scope="col">
                    Uploader
                </th>
                <th scope="col">
                    <a href="?sort=size&order={{if eq .SortBy "size"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}">
                        Size{{if eq .SortBy "size"}}<span class="sort-arrow" aria-hidden="true">{{if eq .Order "asc"}}▲{{else}}▼{{end}}</span>{{end}}
                    </a>
                </th>
                <th scope="col">
                    <a href="?sort=downloads&order={{if eq .SortBy "downloads"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}desc{{end}}">
                        Downloads{{if eq .SortBy "downloads"}}<span class="sort-arrow" aria-hidden="true">{{if eq .Order "asc"}}▲{{else}}▼{{end}}</span>{{end}}
                    </a>
                </th>
                <th scope="col">
                    <a href="?sort=modified&order={{if eq .SortBy "modified"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}desc{{end}}">
                        Modified{{if eq .SortBy "modified"}}<span class="sort-arrow" aria-hidden="true">{{if eq .Order "asc"}}▲{{else}}▼{{end}}</span>{{end}}
                    </a>
                </th>
            </tr>
        </thead>
        <tbody>
            {{if ne .CurrentPath ""}}
            <tr class="is-dir parent-row" data-is-parent="true" onclick="window.location='{{.ParentURL}}{{if .SortSuffix}}?{{.SortSuffix}}{{end}}'">
                <td colspan="5">
                    <div class="cell-name">
                        <svg class="icon muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <polyline points="9 14 4 9 9 4"/>
                            <path d="M20 20v-7a4 4 0 0 0-4-4H4"/>
                        </svg>
                        <a href="{{.ParentURL}}{{.SortSuffix}}" aria-label="Go to parent directory">..</a>
                    </div>
                </td>
            </tr>
            {{end}}
            {{$wanted := .WantedFile}}
            {{$unlocked := .IsUnlocked}}
            {{range .Files}}
            <tr{{if .IsDir}} class="is-dir" data-name="{{.Name}}" data-dir-url="{{.URL}}{{$.SortSuffix}}" onclick="handleDirClick(this,'{{.URL}}{{$.SortSuffix}}','{{.URL}}',event)"{{else if and (not .IsDir) (eq .Name $wanted)}} class="wanted-file" onclick="handleFileClick(this,'{{.URL}}?preview=true','{{if $.IsUnlocked}}{{.URL}}{{end}}',event)"{{else}} onclick="handleFileClick(this,'{{.URL}}?preview=true','{{if $.IsUnlocked}}{{.URL}}{{end}}',event)"{{end}} data-name="{{.Name}}" style="cursor:pointer">
                <td>
                    <div class="cell-name">
                        {{if .IsDir}}
                            {{template "icon-dir" .}}
                            <a href="{{.URL}}{{$.SortSuffix}}" class="tree-dir-link">{{.Name}}</a>
                        {{else if $.IsUnlocked}}
                            {{if .IsDanger}}{{template "icon-danger" .}}{{else}}{{template "icon-file" .}}{{end}}
                            <a href="{{.URL}}" download>{{.Name}}</a>
                        {{else}}
                            <svg class="icon muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                            </svg>
                            <span class="locked-text" title="Upload a file to unlock downloads">{{.Name}}</span>
                        {{end}}
                        {{if .IsNew}}<span class="badge-new">new</span>{{end}}
                        {{if or .IsDir $unlocked}}
                        <button class="copy-link-btn" onclick="copyLink(event, '{{.URL}}')" aria-label="Copy link to {{.Name}}" title="Copy link">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                        </button>
                        {{end}}
                    </div>
                </td>
                <td class="cell-meta">
                    {{if .Owner}}
                        {{if .OwnerFilesURL}}
                        <a class="owner-chip" href="{{.OwnerFilesURL}}" title="{{.Owner}}" onclick="event.stopPropagation()"><code>{{.OwnerShort}}</code></a>
                        {{else}}
                        <span class="owner-chip" title="{{.Owner}}"><code>{{.OwnerShort}}</code></span>
                        {{end}}
                    {{else}}
                    <span class="locked-text">-</span>
                    {{end}}
                </td>
                <td class="cell-meta cell-size">{{if .IsDir}}{{.TotalSizeReadable}}{{else}}{{.SizeReadable}}{{end}}</td>
                <td class="cell-meta">{{if .IsDir}}-{{else}}{{.Downloads}}{{end}}</td>
                <td class="cell-meta">{{.ModTime}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
    {{else}}
    {{template "empty-state" .}}
    {{end}}
        </div>
        {{template "preview-pane" .}}
    </div>
    {{end}}

    </main>

    <!-- ── footer ── -->
    <footer>
        <svg class="icon success" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
        </svg>
        Admin explorer access enabled.
    </footer>

    <div class="preview-backdrop" id="preview-backdrop" onclick="closePreview()"></div>
</div><!-- /.shell -->

<script>
// ── Video.js / FLV plugin: load on demand for non-native formats ─────────────
var _vjsLoaded = false;
var _flvPluginLoaded = false;
var _vjsCallbacks = [];
var _flvCallbacks = [];

var VJS_JS_CDN  = {{.VideoJsJsCDN    | js}};
var FLV_JS_CDN  = {{.FlvjsCDN        | js}};
var VJS_FLV_CDN = {{.VideoJsFlvJsCDN | js}};
var EXPLORER_BASE = {{.BasePath | js}};
var EXPLORER_DELETE_API = {{.DeleteAPIURL | js}};
var EXPLORER_BAN_API = {{.BanOwnerAPIURL | js}};
var EXPLORER_MARK_BAD_API = {{.MarkBadAPIURL | js}};
var _previewData = null;

function ensureVideoJs(cb) {
    if (_vjsLoaded) { cb(); return; }
    _vjsCallbacks.push(cb);
    if (_vjsCallbacks.length > 1) return; // already loading
    loadScript(VJS_JS_CDN, function() {
        _vjsLoaded = true;
        var cbs = _vjsCallbacks.slice(); _vjsCallbacks = [];
        cbs.forEach(function(fn) { fn(); });
    });
}

// ensureFlvPlugin loads Video.js → flv.js → videojs-flvjs in order.
function ensureFlvPlugin(cb) {
    if (_flvPluginLoaded) { cb(); return; }
    _flvCallbacks.push(cb);
    if (_flvCallbacks.length > 1) return; // already loading
    ensureVideoJs(function() {
        loadScript(FLV_JS_CDN, function() {
            loadScript(VJS_FLV_CDN, function() {
                _flvPluginLoaded = true;
                var cbs = _flvCallbacks.slice(); _flvCallbacks = [];
                cbs.forEach(function(fn) { fn(); });
            });
        });
    });
}

// ── on-load: locked-file banner UX ───────────────────────────────────────────
(function() {
    var wanted = {{.WantedFile | js}};
    if (!wanted) return;
    var form = document.getElementById('upload-form');
    if (form) {
        form.classList.add('upload-highlight');
        setTimeout(function() { form.classList.remove('upload-highlight'); }, 2200);
        form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
})();

function dismissBanner() {
    var banner = document.getElementById('locked-banner');
    if (!banner) return;
    banner.style.transition = 'opacity 0.2s, transform 0.2s';
    banner.style.opacity = '0';
    banner.style.transform = 'translateY(-6px)';
    setTimeout(function() { banner.remove(); }, 220);
    var url = new URL(window.location.href);
    url.searchParams.delete('error');
    url.searchParams.delete('wanted');
    url.hash = '';
    window.history.replaceState(null, '', url.toString());
}

// ── hue picker ────────────────────────────────────────────────────────────────
var currentHue = {{.Hue}};

function toggleHuePicker(e) {
    e.stopPropagation();
    document.getElementById('hue-picker-panel').classList.toggle('open');
}
document.addEventListener('click', function(e) {
    var wrap = document.getElementById('hue-picker-wrap');
    if (wrap && !wrap.contains(e.target)) {
        var panel = document.getElementById('hue-picker-panel');
        if (panel) panel.classList.remove('open');
    }
});
function previewHue(h) {
    document.documentElement.style.setProperty('--hue', h);
    var dot = document.querySelector('.hue-dot');
    if (dot) dot.style.background = 'hsl(' + h + ',80%,50%)';
    document.querySelectorAll('.hue-preset').forEach(function(btn) {
        btn.classList.toggle('active', btn.getAttribute('aria-label') === 'Hue ' + h);
    });
}
function applyHue(h) {
    h = parseInt(h, 10);
    previewHue(h);
    currentHue = h;
    var slider = document.getElementById('hue-slider');
    if (slider) slider.value = h;
    fetch('?set-hue=' + h, { redirect: 'manual' }).catch(function(){});
    document.cookie = 'explorer_hue=' + h + '; path=/; max-age=' + (86400 * 365);
    setTimeout(function() {
        var panel = document.getElementById('hue-picker-panel');
        if (panel) panel.classList.remove('open');
    }, 150);
}

// ── upload: loading indicator + double-submit prevention ─────────────────────
function uploadStart(form) {
    var btn = form.querySelector('#upload-submit-btn, #classic-submit-btn');
    var label = form.querySelector('#upload-btn-label, #classic-btn-label');
    var icon = form.querySelector('#upload-btn-icon');
    if (!btn) return;
    btn.disabled = true;
    btn.classList.add('btn-loading');
    if (label) label.textContent = 'Uploading…';
    if (icon) {
        var spinner = document.createElement('span');
        spinner.className = 'upload-spinner';
        icon.parentNode.replaceChild(spinner, icon);
    }
    var status = form.querySelector('#classic-upload-status');
    if (status) status.textContent = 'Uploading…';
}

// ── file picker label ─────────────────────────────────────────────────────────
function classicSyncInput(input) {
    var status = document.getElementById('classic-upload-status');
    if (!status) return;
    if (!input.files || input.files.length === 0) { status.textContent = ''; return; }
    status.textContent = input.files.length === 1 ? input.files[0].name : '(' + input.files.length + ' files selected)';
}

// ── file picker label ─────────────────────────────────────────────────────────
function syncInputs(input) {
    const label = document.getElementById('file-label-text');
    const otherInputId = input.id === 'input-files' ? 'input-folder' : 'input-files';
    const otherInput = document.getElementById(otherInputId);
    otherInput.value = "";
    if (!input.files || input.files.length === 0) {
        label.textContent = "No selection";
        return;
    }
    if (input.files.length === 1) {
        label.textContent = input.files[0].name;
    } else {
        let folderName = "";
        if (input.files[0] && input.files[0].webkitRelativePath) {
            folderName = input.files[0].webkitRelativePath.split('/')[0] + "/ ";
        }
        label.textContent = folderName + "(" + input.files.length + " files)";
    }
}

// ── drag-and-drop upload ──────────────────────────────────────────────────────
(function() {
    const card = document.getElementById('upload-form');
    const fileInput = document.getElementById('input-files');
    if (!card || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(name => {
        card.addEventListener(name, e => { e.preventDefault(); e.stopPropagation(); });
    });
    card.addEventListener('dragover', () => card.classList.add('upload-highlight'));
    card.addEventListener('dragleave', () => card.classList.remove('upload-highlight'));
    card.addEventListener('drop', e => {
        card.classList.remove('upload-highlight');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            syncInputs(fileInput);
            uploadStart(card);
            card.submit();
        }
    });
    document.body.addEventListener('dragenter', function(e) {
        if (e.dataTransfer && e.dataTransfer.types && Array.from(e.dataTransfer.types).includes('Files')) {
            card.classList.add('upload-highlight');
        }
    });
    document.body.addEventListener('dragleave', function(e) {
        if (e.relatedTarget === null || e.relatedTarget === document.documentElement) {
            card.classList.remove('upload-highlight');
        }
    });
    document.body.addEventListener('dragover', function(e) { e.preventDefault(); });
    document.body.addEventListener('drop', function(e) {
        if (e.target === card || card.contains(e.target)) return;
        e.preventDefault();
        card.classList.remove('upload-highlight');
        const files = e.dataTransfer.files;
        if (!files || files.length === 0) return;
        fileInput.files = files;
        syncInputs(fileInput);
        uploadStart(card);
        card.submit();
    });
})();

// ── video thumbnail extraction (lazy via IntersectionObserver) ────────────────
function initVideoThumbObserver() {
    var canvases = document.querySelectorAll('.video-thumb-canvas');
    if (!canvases.length) return;

    // On failure the element is already showing the video icon — just clear
    // data-src so we know it's settled and won't be retried.
    function fallbackToIcon(el) {
        if (!el) return;
        delete el.dataset.src;
        el.dataset.loading = '';
    }

    // Draw a video frame onto a temp canvas, convert to JPEG, then swap the
    // icon SVG for an <img>. Falls back to leaving the icon if anything fails.
    function captureVideoFrame(video, placeholder) {
        try {
            var vw = video.videoWidth, vh = video.videoHeight;
            if (!vw || !vh) { fallbackToIcon(placeholder); return; }
            var cw = 150, ch = 110;
            var offscreen = document.createElement('canvas');
            offscreen.width  = cw;
            offscreen.height = ch;
            var ctx = offscreen.getContext('2d');
            var scale = Math.max(cw / vw, ch / vh);
            var dw = vw * scale, dh = vh * scale;
            ctx.drawImage(video, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
            var img = document.createElement('img');
            img.src = offscreen.toDataURL('image/jpeg', 0.75);
            img.style.cssText = 'width:100%;height:100%;object-fit:cover;display:block';
            img.alt = '';
            if (placeholder.parentNode) placeholder.parentNode.replaceChild(img, placeholder);
        } catch(err) { fallbackToIcon(placeholder); }
    }

    function extractThumb(canvas) {
        var src = canvas.dataset.src;
        if (!src || canvas.dataset.loading) return;
        canvas.dataset.loading = '1';

        var ext = src.split('?')[0].split('.').pop().toLowerCase();
        if (ext === 'flv') {
            // FLV thumbnails via flv.js.
            //
            // flv.js only supports H.264 video (codec ID 7). VP6 (codec ID 4) and
            // other codecs cause DemuxException errors that bypass the player event
            // system and become unhandled Promise rejections. We therefore:
            //   1. Fetch just the first 512 bytes to probe the video codec ID.
            //   2. Only spin up flv.js if codec ID is 7 (H.264) or 12 (HEVC).
            //   3. Wrap everything in try/catch AND use a window unhandledrejection
            //      guard as a last-resort silencer for the specific flv.js message.
            fetch(src, { headers: { Range: 'bytes=0-511' } })
                .then(function(r) { return r.arrayBuffer(); })
                .then(function(buf) {
                    // FLV tag structure: after the 9-byte file header + 4-byte backpointer
                    // comes the first tag. Tag header: type(1) + datasize(3) + timestamp(4)
                    // + streamid(3) = 11 bytes. For a video tag (type=9) the first data byte
                    // is: high nibble = frame type, low nibble = codec ID.
                    // We scan forward looking for a video tag (0x09) within the first 512 b.
                    var bytes = new Uint8Array(buf);
                    var codecId = 0;
                    for (var i = 9; i + 15 < bytes.length; i++) {
                        if (bytes[i] === 0x09) { // video tag type
                            codecId = bytes[i + 11] & 0x0F;
                            break;
                        }
                    }
                    // Only H.264 (7) and HEVC (12) are supported by flv.js.
                    // codec 4 = VP6, codec 5 = VP6 alpha, codec 6 = Screen Video 2, etc.
                    if (codecId !== 7 && codecId !== 12) { fallbackToIcon(canvas); return; } // unsupported codec

                    loadScript(FLV_JS_CDN, function() {
                        if (typeof flvjs === 'undefined' || !flvjs.isSupported()) { fallbackToIcon(canvas); return; }
                        var video = document.createElement('video');
                        video.muted = true;
                        video.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0;pointer-events:none';
                        document.body.appendChild(video);

                        var player;
                        try {
                            player = flvjs.createPlayer(
                                { type: 'flv', url: src },
                                { enableWorker: false, lazyLoad: false, stashInitialSize: 128 }
                            );
                        } catch(e) {
                            if (video.parentNode) document.body.removeChild(video);
                            fallbackToIcon(canvas);
                            return;
                        }

                        var done = false;
                        var captured = false; // set true when a frame is successfully drawn
                        function cleanup() {
                            if (done) return;
                            done = true;
                            try { player.destroy(); } catch(e) {}
                            if (video.parentNode) document.body.removeChild(video);
                            if (!captured) fallbackToIcon(canvas);
                        }

                        // flv.js ERROR events: catches network and most demux errors.
                        player.on(flvjs.Events.ERROR, function() { cleanup(); });

                        // Last-resort: suppress the unhandled-rejection that flv.js
                        // can emit on its internal Promise chain during load().
                        // We only silence rejections whose message matches flv.js's
                        // exact "Unhandled error." pattern while our player is live.
                        function rejectionGuard(e) {
                            if (done) return;
                            var msg = (e.reason && e.reason.message) || '';
                            if (msg.indexOf('Unhandled error') !== -1) {
                                e.preventDefault();
                                cleanup();
                            }
                        }
                        window.addEventListener('unhandledrejection', rejectionGuard);

                        function onFrame() {
                            if (captured) return;
                            captured = true;
                            captureVideoFrame(video, canvas);
                            window.removeEventListener('unhandledrejection', rejectionGuard);
                            cleanup();
                        }

                        video.addEventListener('seeked',     onFrame);
                        video.addEventListener('timeupdate', function() {
                            if (video.currentTime > 0) onFrame();
                        });
                        video.addEventListener('error', function() {
                            window.removeEventListener('unhandledrejection', rejectionGuard);
                            cleanup();
                        });

                        video.addEventListener('loadedmetadata', function() {
                            var t = isFinite(video.duration) && video.duration > 0
                                ? Math.min(video.duration * 0.1, 2) : 0;
                            if (t > 0) {
                                video.currentTime = t;
                            } else {
                                video.play().catch(function() {});
                            }
                        });

                        try {
                            player.attachMediaElement(video);
                            player.load();
                        } catch(e) {
                            window.removeEventListener('unhandledrejection', rejectionGuard);
                            cleanup();
                        }
                    });
                })
                .catch(function() { fallbackToIcon(canvas); });
            return;
        }

        var video = document.createElement('video');
        video.muted = true;
        video.preload = 'metadata';
        video.crossOrigin = 'anonymous';
        video.src = src;
        video.addEventListener('loadedmetadata', function() {
            video.currentTime = Math.min(video.duration * 0.1, 2);
        });
        video.addEventListener('seeked', function() {
            captureVideoFrame(video, canvas);
            video.src = '';
        });
        video.addEventListener('error', function() { fallbackToIcon(canvas); });
        video.load();
    }

    if ('IntersectionObserver' in window) {
        var obs = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting) {
                    extractThumb(entry.target);
                    obs.unobserve(entry.target);
                }
            });
        }, { rootMargin: '200px' });
        canvases.forEach(function(c) { obs.observe(c); });
    } else {
        // Fallback for old browsers: extract all immediately.
        canvases.forEach(extractThumb);
    }
}
document.addEventListener('DOMContentLoaded', initVideoThumbObserver);

// ── copy link ─────────────────────────────────────────────────────────────────
function copyLink(event, urlPath) {
    event.preventDefault();
    event.stopPropagation();
    var full = window.location.origin + urlPath;
    var btn = event.currentTarget;
    navigator.clipboard.writeText(full).then(function() {
        btn.classList.add('copied');
        var prev = btn.innerHTML;
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
        setTimeout(function() {
            btn.innerHTML = prev;
            btn.classList.remove('copied');
        }, 1800);
    }).catch(function() {
        var ta = document.createElement('textarea');
        ta.value = full;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    });
}

// ── tree expand / collapse ────────────────────────────────────────────────────
function treeDetails() { return document.querySelectorAll('#tree-root details'); }

function setCtrlActive(id) {
    ['ctrl-one','ctrl-all','ctrl-none'].forEach(function(cid) {
        var el = document.getElementById(cid);
        if (!el) return;
        var active = cid === id;
        el.classList.toggle('active', active);
        el.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
}
function treeOneLevel() {
    treeDetails().forEach(function(d) { d.open = !d.parentElement.closest('#tree-root details'); });
    setCtrlActive('ctrl-one');
}
function treeExpandAll()  { treeDetails().forEach(function(d) { d.open = true;  }); setCtrlActive('ctrl-all'); }
function treeCollapseAll(){ treeDetails().forEach(function(d) { d.open = false; }); setCtrlActive('ctrl-none'); }

document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('tree-root')) {
        treeOneLevel();
        var params = new URLSearchParams(window.location.search);
        treeSortContainer(document.getElementById('tree-root'),
            params.get('sort') || 'name', params.get('order') || 'asc');
    }
});

// ── sort helpers ──────────────────────────────────────────────────────────────
function sortChange(sel) {
    var params = new URLSearchParams(window.location.search);
    var prev = params.get('sort') || 'name';
    params.set('sort', sel.value);
    if (sel.value !== prev) params.set('order', 'asc');
    window.location.search = params.toString();
}
function treeSortContainer(root, by, order) {
    var containers = [root];
    root.querySelectorAll('.tree-children').forEach(function(c) { containers.push(c); });
    containers.forEach(function(container) {
        var nodes = Array.from(container.children).filter(function(el) {
            return el.tagName === 'DETAILS' || el.classList.contains('tree-file');
        });
        if (nodes.length < 2) return;
        var dirs  = nodes.filter(function(n) { return n.tagName === 'DETAILS'; });
        var files = nodes.filter(function(n) { return n.classList.contains('tree-file'); });
        function key(el) {
            switch (by) {
                case 'size':     return parseInt(el.dataset.size     || '0', 10);
                case 'modified': return parseInt(el.dataset.modified || '0', 10);
                default:         return (el.dataset.name || '').toLowerCase();
            }
        }
        function cmp(a, b) {
            var ka = key(a), kb = key(b), less = (typeof ka === 'number') ? ka < kb : ka < kb;
            return order === 'desc' ? (less ? 1 : -1) : (less ? -1 : 1);
        }
        dirs.sort(cmp); files.sort(cmp);
        dirs.concat(files).forEach(function(n) { container.appendChild(n); });
    });
}

// ── filter ────────────────────────────────────────────────────────────────────
function applyFilter(query) {
    query = query.toLowerCase();
    var visibleCount = 0;
    var countEl = document.getElementById('filter-count');

    document.querySelectorAll('#file-table tbody tr').forEach(function(row) {
        if (row.classList.contains('is-dir') && row.querySelector('a[aria-label="Go to parent directory"]')) return;
        var match = (row.dataset.name || '').toLowerCase().includes(query);
        row.style.display = match ? '' : 'none';
        if (match) visibleCount++;
    });
    document.querySelectorAll('#tile-grid .tile').forEach(function(tile) {
        var match = (tile.dataset.name || '').toLowerCase().includes(query);
        tile.style.display = match ? '' : 'none';
        if (match) visibleCount++;
    });
    document.querySelectorAll('#tree-root .tree-file, #tree-root details').forEach(function(item) {
        var name = (item.dataset.name || '').toLowerCase();
        if (item.tagName === 'DETAILS') {
            var childMatch = !!item.querySelector('.tree-file[data-name*="' + query + '" i], details[data-name*="' + query + '" i]');
            var show = name.includes(query) || childMatch;
            item.style.display = show ? '' : 'none';
            if (show && query.length > 0) item.open = true;
            if (show) visibleCount++;
        } else {
            var show = name.includes(query);
            item.style.display = show ? '' : 'none';
            if (show) visibleCount++;
        }
    });

    countEl.textContent = query.length > 0 ? visibleCount + ' found' : '';
    if (!query.length && document.getElementById('tree-root')) treeOneLevel();
}

// ── tile click handlers ───────────────────────────────────────────────────────
// Single click → preview (for both files and dirs).
// Double click → navigate (for dirs) or download (for files).
function tileClick(tile, event) {
    if (event.target.closest('.copy-link-btn')) return;
    event.preventDefault();

    var previewUrl  = tile.dataset.previewUrl;
    var navUrl      = tile.dataset.navUrl      || null;
    var downloadUrl = tile.dataset.downloadUrl || null;
    var isDir       = !!navUrl;

    if (_sel && _sel.el === tile) {
        // Second single-click: same as double-click action.
        if (isDir && navUrl)      { window.location = navUrl; return; }
        if (!isDir && downloadUrl){ triggerDownload(downloadUrl); return; }
    }

    setSelection(tile, isDir ? 'dir' : 'file', previewUrl, navUrl, downloadUrl);
    if (previewUrl) loadPreview(previewUrl);
}

function tileDblClick(tile, event) {
    event.preventDefault();
    var navUrl      = tile.dataset.navUrl      || null;
    var downloadUrl = tile.dataset.downloadUrl || null;
    if (navUrl)      { window.location = navUrl; return; }
    if (downloadUrl) { triggerDownload(downloadUrl); }
}

// ── unified selection & keyboard navigation ───────────────────────────────────

var _sel = null; // { el, type, previewUrl, navUrl, downloadUrl }

function handleFileClick(el, previewUrl, downloadUrl, event) {
    if (event) event.preventDefault();
    if (_sel && _sel.el === el) {
        if (_sel.downloadUrl) triggerDownload(_sel.downloadUrl);
        return;
    }
    setSelection(el, 'file', previewUrl, null, downloadUrl || null);
    loadPreview(previewUrl);
}

function handleDirClick(el, navUrl, previewUrl, event) {
    if (event) event.preventDefault();
    if (_kbNav) {
        setSelection(el, 'dir', previewUrl + '?preview=true', navUrl, null);
        loadPreview(previewUrl + '?preview=true');
        return;
    }
    setSelection(el, 'dir', previewUrl + '?preview=true', navUrl, null);
    window.location = navUrl;
}

function setSelection(el, type, previewUrl, navUrl, downloadUrl) {
    if (_sel && _sel.el !== el) clearSelectionVisual();
    el.classList.add('selected');
    _sel = { el: el, type: type, previewUrl: previewUrl, navUrl: navUrl, downloadUrl: downloadUrl };
}

function clearSelectionVisual() {
    if (_sel) {
        _sel.el.classList.remove('selected');
        _sel.el.classList.remove('kb-selected');
    }
}

function clearSelection() {
    clearSelectionVisual();
    _sel = null;
    closePreview();
}

function previewDir(event, url) {
    var summary = event.currentTarget;
    setSelection(summary, 'dir', url + '?preview=true', summary.dataset.dirUrl || url, null);
    loadPreview(url + '?preview=true');
    if (_kbNav) event.preventDefault();
}

function triggerDownload(url) {
    var a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ── keyboard navigation ───────────────────────────────────────────────────────

var _kbNav = false;

function installKeyboardNav() {
    document.addEventListener('keydown', function(e) {
        var tag = document.activeElement && document.activeElement.tagName;

        if ((e.key === '?' || e.key === '/') && tag !== 'INPUT' && tag !== 'TEXTAREA') {
            e.preventDefault();
            var filter = document.getElementById('global-filter');
            if (filter) { filter.focus(); filter.select(); }
            return;
        }

        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

        var inTree  = !!document.getElementById('tree-root');
        var inTiles = !!document.getElementById('tile-grid');

        if (e.key === 'Escape') {
            if (_sel) { e.preventDefault(); clearSelection(); }
            return;
        }

        if (e.key === 'Home' || e.key === 'End') {
            var items = getNavigableItems();
            if (!items.length) return;
            e.preventDefault();
            activateItem(e.key === 'Home' ? items[0] : items[items.length - 1]);
            return;
        }

        if (inTiles) {
            var arrowKeys = ['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'];

            if (e.key === 'Enter' && _sel) {
                e.preventDefault();
                if (_sel.type === 'dir' && _sel.navUrl) { window.location = _sel.navUrl; }
                else if (_sel.type === 'file' && _sel.downloadUrl) { triggerDownload(_sel.downloadUrl); }
                return;
            }
            if (e.key === ' ' && _sel) {
                e.preventDefault();
                loadPreview(_sel.previewUrl);
                return;
            }
            if (arrowKeys.includes(e.key)) {
                e.preventDefault();
                var items = getNavigableItems();
                if (!items.length) return;
                var curIdx = _sel ? items.indexOf(_sel.el) : -1;
                var cols = tileColumnCount(items);
                var next;
                if (curIdx === -1) {
                    next = items[0];
                } else if (e.key === 'ArrowRight') {
                    next = curIdx + 1 < items.length ? items[curIdx + 1] : null;
                } else if (e.key === 'ArrowLeft') {
                    next = curIdx > 0 ? items[curIdx - 1] : null;
                } else if (e.key === 'ArrowDown') {
                    var downIdx = curIdx + cols;
                    next = downIdx < items.length ? items[downIdx] : null;
                } else {
                    var upIdx = curIdx - cols;
                    next = upIdx >= 0 ? items[upIdx] : null;
                }
                if (next) activateItem(next);
                return;
            }
        }

        if (inTree) {
            if (e.key === ' ' && _sel) {
                var det = _sel.el.tagName === 'SUMMARY'
                    ? _sel.el.parentElement
                    : _sel.el.closest('details');
                if (det && det.tagName === 'DETAILS') {
                    e.preventDefault();
                    det.open = !det.open;
                } else {
                    e.preventDefault();
                    loadPreview(_sel.previewUrl);
                }
                return;
            }
            if (e.key === 'ArrowLeft') {
                e.preventDefault();
                if (_sel) {
                    var pd = _sel.el.tagName === 'SUMMARY'
                        ? _sel.el.parentElement
                        : _sel.el.closest('details');
                    if (pd && pd.tagName === 'DETAILS') {
                        if (pd.open) {
                            pd.open = false;
                            activateItem(pd.querySelector(':scope > summary'));
                            return;
                        }
                        var outerDetails = pd.parentElement.closest('details');
                        if (outerDetails) {
                            activateItem(outerDetails.querySelector(':scope > summary'));
                            return;
                        }
                    }
                }
                var parentPath = {{.ParentPath | js}};
                var curPath    = {{.CurrentPath | js}};
                if (curPath !== '') window.location = EXPLORER_BASE + '/' + parentPath;
                return;
            }
            if (e.key === 'ArrowRight') {
                if (_sel) {
                    e.preventDefault();
                    var rd = _sel.el.tagName === 'SUMMARY' ? _sel.el.parentElement : null;
                    if (rd && rd.tagName === 'DETAILS' && !rd.open) { rd.open = true; return; }
                    if (_sel.type === 'dir' && _sel.navUrl) { window.location = _sel.navUrl; }
                    else if (_sel.type === 'file' && _sel.downloadUrl) { triggerDownload(_sel.downloadUrl); }
                    return;
                }
            }
            if (e.key === 'Enter' && _sel) {
                e.preventDefault();
                if (_sel.type === 'dir' && _sel.navUrl) { window.location = _sel.navUrl; }
                else if (_sel.type === 'file' && _sel.downloadUrl) { triggerDownload(_sel.downloadUrl); }
                return;
            }
        }

        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            var items = getNavigableItems();
            if (!items.length) return;
            var curIdx = _sel ? items.indexOf(_sel.el) : -1;
            var next;
            if (e.key === 'ArrowDown') {
                next = curIdx === -1 ? items[0]
                     : curIdx + 1 < items.length ? items[curIdx + 1] : items[0];
            } else {
                next = curIdx === -1 ? items[items.length - 1]
                     : curIdx - 1 >= 0 ? items[curIdx - 1] : items[items.length - 1];
            }
            activateItem(next);
        }

        if (!inTree && !inTiles && _sel) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (_sel.type === 'parent' && _sel.navUrl) { window.location = _sel.navUrl; }
                else if (_sel.type === 'dir' && _sel.navUrl) { window.location = _sel.navUrl; }
                else if (_sel.type === 'file' && _sel.downloadUrl) { triggerDownload(_sel.downloadUrl); }
            } else if (e.key === ' ') {
                e.preventDefault();
                if (_sel.type === 'parent') { showParentPreview(); }
                else { loadPreview(_sel.previewUrl); }
            }
        }
    });
}

function tileColumnCount(items) {
    if (!items || items.length < 2) return items ? items.length : 1;
    var firstTop = items[0].getBoundingClientRect().top;
    var cols = 0;
    for (var i = 0; i < items.length; i++) {
        if (Math.abs(items[i].getBoundingClientRect().top - firstTop) < 4) { cols++; }
        else { break; }
    }
    return cols || 1;
}

function activateItem(el) {
    if (!el) return;
    if (el.dataset && el.dataset.isParent) {
        if (_sel) clearSelectionVisual();
        el.classList.add('kb-selected');
        _sel = { el: el, type: 'parent', previewUrl: null, navUrl: null, downloadUrl: null };
        var link = el.querySelector('a');
        if (link) _sel.navUrl = link.href;
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        showParentPreview();
        return;
    }
    // For tiles, simulate a click (which calls tileClick).
    // For table/tree, call the existing onclick handler.
    _kbNav = true;
    el.click();
    _kbNav = false;
    el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function getNavigableItems() {
    var table = document.getElementById('file-table');
    if (table) {
        return Array.from(table.querySelectorAll('tbody tr[data-name], tbody tr[data-is-parent]'));
    }
    var treeRoot = document.getElementById('tree-root');
    if (treeRoot) {
        return Array.from(treeRoot.querySelectorAll('.tree-file, details > summary'))
            .filter(function(el) { return isVisible(el); });
    }
    var tileGrid = document.getElementById('tile-grid');
    if (tileGrid) {
        return Array.from(tileGrid.querySelectorAll('.tile'));
    }
    return [];
}

function isVisible(el) {
    var isSummary = el.tagName === 'SUMMARY';
    var node = el.parentElement;
    while (node) {
        if (node.tagName === 'DETAILS' && !node.open) {
            if (isSummary && node === el.parentElement) {
                node = node.parentElement;
                isSummary = false;
                continue;
            }
            return false;
        }
        node = node.parentElement;
    }
    return true;
}

document.addEventListener('DOMContentLoaded', installKeyboardNav);

function isMobile() { return window.innerWidth <= 600; }
function closePreview() {
    var pane     = document.getElementById('preview-pane');
    var backdrop = document.getElementById('preview-backdrop');
    if (pane) {
        pane.classList.remove('active');
        if (isMobile()) {
            pane.addEventListener('transitionend', function h() {
                pane.style.display = 'none';
                pane.removeEventListener('transitionend', h);
            });
        }
    }
    if (backdrop) backdrop.classList.remove('active');
}

function explorerApiPost(url, payload) {
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {})
    }).then(function(r) {
        return r.text().then(function(raw) {
            var data = {};
            try { data = raw ? JSON.parse(raw) : {}; } catch (_) {}
            if (!r.ok) {
                throw new Error(data.error || ('HTTP ' + r.status));
            }
            return data;
        });
    });
}

function explorerDeletePath(event) {
    if (event) { event.preventDefault(); event.stopPropagation(); }
    if (!_previewData || !_previewData.rel_path) return;
    if (!confirm('Delete "' + _previewData.rel_path + '"? This cannot be undone.')) return;
    explorerApiPost(EXPLORER_DELETE_API, { path: _previewData.rel_path })
        .then(function() { window.location.reload(); })
        .catch(function(err) { alert('Delete failed: ' + err.message); });
}

function explorerBanOwner(event) {
    if (event) { event.preventDefault(); event.stopPropagation(); }
    if (!_previewData || !_previewData.rel_path) return;
    if (!confirm('Ban owner of "' + _previewData.rel_path + '"?')) return;
    explorerApiPost(EXPLORER_BAN_API, { path: _previewData.rel_path })
        .then(function(data) {
            var owner = (data && data.owner) ? data.owner : '(unknown)';
            alert('Owner banned: ' + owner);
        })
        .catch(function(err) { alert('Ban failed: ' + err.message); });
}

function explorerMarkBad(event) {
    if (event) { event.preventDefault(); event.stopPropagation(); }
    if (!_previewData || !_previewData.rel_path) return;
    if (!confirm('Mark "' + _previewData.rel_path + '" as bad? This adds its hash to bad_files.txt.')) return;
    explorerApiPost(EXPLORER_MARK_BAD_API, { path: _previewData.rel_path })
        .then(function(data) {
            var hash = (data && data.hash) ? data.hash : '(unknown)';
            var suffix = data && data.already_present ? ' (already present)' : '';
            alert('Marked bad: ' + hash + suffix);
        })
        .catch(function(err) { alert('Mark bad failed: ' + err.message); });
}

function loadPreview(url) {
    var pane    = document.getElementById('preview-pane');
    var prompt  = document.getElementById('preview-prompt');
    var content = document.getElementById('preview-content');
    if (!content) return;
    if (prompt) prompt.style.display = 'none';
    content.innerHTML = '<div class="preview-loading">Loading\u2026</div>';
    if (pane) {
        if (isMobile()) pane.style.display = 'flex';
        pane.classList.add('active');
    }
    var backdrop = document.getElementById('preview-backdrop');
    if (backdrop && isMobile()) backdrop.classList.add('active');

    fetch(url)
        .then(function(r) {
            if (r.status === 403) throw new Error('locked');
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(renderPreview)
        .catch(function(err) {
            var msg = err.message === 'locked'
                ? '<svg style="width:24px;height:24px;display:block;margin:0 auto 8px;stroke:currentColor;fill:none;stroke-width:1.5;opacity:.5" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Preview not available.'
                : 'Could not load preview.';
            content.innerHTML = '<div class="preview-empty">' + msg + '</div>';
        });
}

// ── parent-directory preview ──────────────────────────────────────────────────
function showParentPreview() {
    var content = document.getElementById('preview-content');
    var prompt  = document.getElementById('preview-prompt');
    if (!content) return;
    if (prompt) prompt.style.display = 'none';
    var parentPath = {{.ParentPath | js}};
    var curPath    = {{.CurrentPath | js}};
    var html = '<div class="preview-header">'
        + '<span class="preview-header-name" title="Parent directory">Parent directory</span>'
        + '<button class="preview-close" onclick="closePreview()" aria-label="Close preview">'
        + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        + '</button></div>';
    html += '<div class="preview-icon-hero">'
        + '<div style="display:flex;flex-direction:column;align-items:center;gap:6px">'
        + '<svg style="width:48px;height:48px;fill:none;stroke:var(--text-muted);stroke-width:1.5;opacity:.6" viewBox="0 0 24 24">'
        + '<polyline points="9 14 4 9 9 4"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/>'
        + '</svg>'
        + '<span style="font-size:11px;color:var(--text-muted);text-align:center">Go up one level</span>'
        + '</div></div>';
    html += '<div class="preview-actions">'
        + '<a href="' + EXPLORER_BASE + '/' + esc(parentPath) + '" class="btn btn-ghost" style="flex:1;justify-content:center;">'
        + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
        + '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>'
        + '</svg> Open parent</a></div>';
    html += '<div class="preview-meta">';
    html += metaRow('Navigate', 'Enter \u2192 open');
    html += metaRow('Current', esc('/' + curPath));
    if (parentPath) html += metaRow('Parent', esc('/' + parentPath));
    else html += metaRow('Parent', 'root');
    html += '</div>';
    content.innerHTML = html;
    var pane = document.getElementById('preview-pane');
    if (pane) {
        if (isMobile()) pane.style.display = 'flex';
        pane.classList.add('active');
        pane.scrollTop = 0;
    }
    var backdrop = document.getElementById('preview-backdrop');
    if (backdrop && isMobile()) backdrop.classList.add('active');
}

(function renderDirStatsOnLoad() {
    var statsEl = document.getElementById('preview-dir-stats');
    if (!statsEl) return;
    var d = {
        name:         {{.DirName       | js}},
        child_dirs:   {{.DirChildDirs}},
        child_files:  {{.DirChildFiles}},
        total_size:   {{.DirTotalSize  | js}},
        mod_time:     {{.DirModTime    | js}},
    };
    statsEl.innerHTML = renderDirStatsHtml(d);
})();

function renderDirStatsHtml(d) {
    var html = '<div style="padding:10px 12px 6px;border-bottom:1px solid var(--border);background:var(--surface2)">'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);margin-bottom:4px">Current Directory</div>'
        + '<div style="font-size:13px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:flex;align-items:center;gap:6px" title="' + esc(d.name) + '">'
        + previewCatIcon('dir', 16) + '<span>' + esc(d.name) + '</span></div>'
        + '</div>'
        + '<div class="preview-meta">';
    html += metaRow('Folders', d.child_dirs.toLocaleString());
    html += metaRow('Files',   d.child_files.toLocaleString());
    if (d.total_size) html += metaRow('Total size', d.total_size);
    html += metaRow('Modified', d.mod_time);
    html += '</div>'
        + '<div style="padding:10px 12px;border-top:1px solid var(--border);color:var(--text-muted);font-size:12px;text-align:center">'
        + 'Click to preview \u00b7 click again to act'
        + '<br><span style="font-size:11px;opacity:.7">\u2191\u2193 navigate \u00b7 Enter act \u00b7 Space preview \u00b7 Esc close \u00b7 / filter</span>'
        + '</div>';
    return html;
}

// ── preview rendering ─────────────────────────────────────────────────────────
function esc(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function metaRow(label, value) {
    return '<div class="preview-meta-row">'
        + '<span class="preview-meta-label">' + esc(label) + '</span>'
        + '<span class="preview-meta-value">' + esc(String(value)) + '</span>'
        + '</div>';
}
function metaRowHTML(label, htmlValue) {
    return '<div class="preview-meta-row">'
        + '<span class="preview-meta-label">' + esc(label) + '</span>'
        + '<span class="preview-meta-value">' + htmlValue + '</span>'
        + '</div>';
}

function previewCatIcon(cat, size) {
    size = size || 48;
    var catClass = 'icon-cat-' + (cat || 'other');
    var style = 'width:' + size + 'px;height:' + size + 'px;display:block;stroke-width:1.5;fill:none;';
    var body;
    switch (cat) {
        case 'image':
            body = '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>'
                 + '<circle cx="8.5" cy="8.5" r="1.5"/>'
                 + '<polyline points="21 15 16 10 5 21"/>';
            break;
        case 'video':
            body = '<rect x="2" y="3" width="20" height="18" rx="2" ry="2"/>'
                 + '<path d="m10 8 5 4-5 4V8z"/>';
            break;
        case 'text':
            body = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                 + '<polyline points="14 2 14 8 20 8"/>'
                 + '<line x1="8" y1="13" x2="16" y2="13"/>'
                 + '<line x1="8" y1="17" x2="16" y2="17"/>';
            break;
        case 'archive':
            body = '<polyline points="21 8 21 21 3 21 3 8"/>'
                 + '<rect x="1" y="3" width="22" height="5"/>'
                 + '<line x1="10" y1="12" x2="14" y2="12"/>';
            break;
        case 'pdf':
            body = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                 + '<polyline points="14 2 14 8 20 8"/>'
                 + '<line x1="8" y1="13" x2="12" y2="13"/>'
                 + '<line x1="8" y1="17" x2="16" y2="17"/>';
            catClass = 'icon-cat-pdf';
            style += 'fill:color-mix(in srgb,var(--icon-pdf) 10%,transparent);';
            break;
        case 'stl':
            body = '<path d="M12 2L2 7l10 5 10-5-10-5z"/>'
                 + '<path d="M2 17l10 5 10-5"/>'
                 + '<path d="M2 12l10 5 10-5"/>';
            catClass = 'icon-cat-stl';
            style += 'fill:color-mix(in srgb,var(--icon-stl) 10%,transparent);';
            break;
        case 'danger':
            body = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
                 + '<line x1="12" y1="9" x2="12" y2="13"/>'
                 + '<line x1="12" y1="17" x2="12.01" y2="17"/>';
            catClass = 'icon-danger';
            style += 'stroke:#e53935;fill:none;';
            break;
        case 'dir':
            body = '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>';
            catClass = 'icon-cat-dir';
            break;
        default:
            body = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                 + '<polyline points="14 2 14 8 20 8"/>';
    }
    return '<svg class="' + catClass + '" style="' + style + '" viewBox="0 0 24 24" aria-hidden="true">' + body + '</svg>';
}

var MAX_PREVIEW_LINES = 25;

function archiveEntryIcon(e) {
    var S = 'width:12px;height:12px;flex-shrink:0;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;fill:none;';
    if (e.is_dir) {
        return '<svg style="' + S + 'stroke:var(--icon-dir);fill:color-mix(in srgb,var(--icon-dir) 15%,transparent)" viewBox="0 0 24 24">'
            + '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
    }
    var cat = e.category || '';
    if (!cat) {
        var ext2 = e.name.split('.').pop().toLowerCase();
        if (['jpg','jpeg','png','gif','webp','bmp'].includes(ext2))       cat = 'image';
        else if (['mp4','webm','ogg','mov','mkv'].includes(ext2))         cat = 'video';
        else if (['zip','tar','gz','tgz','rar','7z','bz2','xz'].includes(ext2)) cat = 'archive';
        else if (ext2 === 'pdf')                                           cat = 'pdf';
        else if (ext2 === 'stl')                                           cat = 'stl';
        else if (['exe','scr','lnk'].includes(ext2))                       cat = 'danger';
    }
    switch (cat) {
        case 'image':
            return '<svg style="' + S + 'stroke:var(--icon-image)" viewBox="0 0 24 24">'
                + '<rect x="3" y="3" width="18" height="18" rx="2"/>'
                + '<circle cx="8.5" cy="8.5" r="1.5"/>'
                + '<polyline points="21 15 16 10 5 21"/></svg>';
        case 'video':
            return '<svg style="' + S + 'stroke:var(--icon-video)" viewBox="0 0 24 24">'
                + '<rect x="2" y="3" width="20" height="18" rx="2"/>'
                + '<path d="m10 8 5 4-5 4V8z"/></svg>';
        case 'text':
            return '<svg style="' + S + 'stroke:var(--icon-text)" viewBox="0 0 24 24">'
                + '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                + '<polyline points="14 2 14 8 20 8"/>'
                + '<line x1="8" y1="13" x2="16" y2="13"/>'
                + '<line x1="8" y1="17" x2="16" y2="17"/></svg>';
        case 'archive':
            return '<svg style="' + S + 'stroke:var(--icon-archive)" viewBox="0 0 24 24">'
                + '<polyline points="21 8 21 21 3 21 3 8"/>'
                + '<rect x="1" y="3" width="22" height="5"/>'
                + '<line x1="10" y1="12" x2="14" y2="12"/></svg>';
        case 'pdf':
            return '<svg style="' + S + 'stroke:var(--icon-pdf);fill:color-mix(in srgb,var(--icon-pdf) 10%,transparent)" viewBox="0 0 24 24">'
                + '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                + '<polyline points="14 2 14 8 20 8"/>'
                + '<line x1="8" y1="13" x2="12" y2="13"/>'
                + '<line x1="8" y1="17" x2="16" y2="17"/></svg>';
        case 'stl':
            return '<svg style="' + S + 'stroke:var(--icon-stl);fill:color-mix(in srgb,var(--icon-stl) 10%,transparent)" viewBox="0 0 24 24">'
                + '<path d="M12 2L2 7l10 5 10-5-10-5z"/>'
                + '<path d="M2 17l10 5 10-5"/>'
                + '<path d="M2 12l10 5 10-5"/></svg>';
        case 'danger':
            return '<svg style="' + S + 'stroke:#e53935" viewBox="0 0 24 24">'
                + '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
                + '<line x1="12" y1="9" x2="12" y2="13"/>'
                + '<line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
        default:
            return '<svg style="' + S + 'stroke:var(--text-muted)" viewBox="0 0 24 24">'
                + '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                + '<polyline points="14 2 14 8 20 8"/></svg>';
    }
}

var _vjsPlayerCounter = 0;
var _ownerDetailsCache = Object.create(null);

function renderPreview(d) {
    var content = document.getElementById('preview-content');
    if (!content) return;
    _previewData = d || null;

    var html = '<div class="preview-header">'
        + '<span class="preview-header-name" title="' + esc(d.name) + '">' + esc(d.name) + '</span>'
        + '<button class="preview-close" onclick="closePreview()" aria-label="Close preview">'
        + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        + '</button></div>';

    if (!d.is_dir) {
        html += '<div class="preview-actions">';
        if (d.download_url) {
            html += '<a href="' + esc(d.download_url) + '" download class="btn btn-primary">'
                + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                + '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'
                + 'Download</a>';
        } else {
            html += '<button class="btn btn-ghost" disabled style="opacity:0.6;width:100%;cursor:not-allowed;justify-content:center">'
                + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                + '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
                + 'Download unavailable</button>';
        }
        if (d.rel_path) {
            html += '<button class="btn btn-ghost" onclick="explorerDeletePath(event)" title="Delete this file">'
                + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                + '<polyline points="3 6 5 6 21 6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>'
                + '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'
                + '<line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>'
                + 'Delete</button>';
            html += '<button class="btn btn-ghost" onclick="explorerMarkBad(event)" title="Add this file to bad_files.txt">'
                + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                + '<path d="M12 3l9 4.5v6c0 5-3.8 8.8-9 10.5C6.8 22.3 3 18.5 3 13.5v-6L12 3z"/>'
                + '<line x1="8" y1="12" x2="16" y2="12"/></svg>'
                + 'Mark bad</button>';
            html += '<button class="btn btn-ghost" onclick="explorerBanOwner(event)" title="Ban this file owner">'
                + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                + '<circle cx="12" cy="7" r="4"/><path d="M5.5 21a6.5 6.5 0 0 1 13 0"/>'
                + '<line x1="4" y1="14" x2="10" y2="20"/><line x1="10" y1="14" x2="4" y2="20"/></svg>'
                + 'Ban owner</button>';
            if (d.owner_files_url) {
                html += '<a class="btn btn-ghost" href="' + esc(d.owner_files_url) + '" title="View all files uploaded by this owner">'
                    + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
                    + '<path d="M3 7h18"/><path d="M3 12h18"/><path d="M3 17h18"/></svg>'
                    + 'View owner files</a>';
            }
        }
        html += '</div>';
    } else if (d.rel_path) {
        html += '<div class="preview-actions">';
        html += '<button class="btn btn-ghost" onclick="explorerDeletePath(event)" title="Delete this directory">'
            + '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">'
            + '<polyline points="3 6 5 6 21 6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>'
            + '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'
            + '<line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>'
            + 'Delete folder</button>';
        html += '</div>';
    }

    var vjsVideoId  = null;
    var vjsVideoExt = null; // extension for FLV source-type selection

    if (d.is_image && d.thumb_url) {
        html += '<img class="preview-thumb" src="' + esc(d.thumb_url) + '" alt="">';
    } else if (d.is_video && d.video_url) {
        if (d.video_native) {
            // Browser-native: plain <video>
            html += '<video class="preview-thumb" preload="metadata" controls muted>'
                + '<source src="' + esc(d.video_url) + '"></video>';
        } else {
            // Non-native (e.g. FLV): requires Video.js + videojs-flvjs plugin
            vjsVideoId  = 'vjs-preview-' + (++_vjsPlayerCounter);
            vjsVideoExt = d.ext ? d.ext.replace('.', '').toLowerCase() : '';
            html += '<div class="preview-video-wrap">'
                + '<video id="' + vjsVideoId + '" class="video-js vjs-default-skin vjs-fluid" controls preload="metadata" muted>'
                + '</video></div>';
        }
    } else if (d.is_pdf && d.download_url) {
        html += '<div class="preview-pdf-embed">'
            + '<object data="' + esc(d.download_url) + '#toolbar=1&navpanes=0" type="application/pdf" width="100%" height="100%">'
            + '<div class="preview-icon-hero">' + previewCatIcon('pdf', 48) + '</div>'
            + '</object></div>';
    } else if (d.is_stl && d.download_url) {
        var stlCanvasId = 'stl-canvas-' + Date.now();
        html += '<div class="preview-stl-wrap" id="stl-wrap-' + stlCanvasId + '">'
            + '<canvas id="' + stlCanvasId + '"></canvas>'
            + '<div class="preview-stl-status" id="stl-status-' + stlCanvasId + '">Loading\u2026</div>'
            + '</div>';
    } else {
        var ext = d.ext ? d.ext.replace('.', '').toLowerCase() : '';
        var isDanger = ['exe','scr','lnk'].includes(ext);
        var iconCat = d.is_dir ? 'dir'
            : (!d.download_url ? 'lock'
            : (isDanger         ? 'danger'
            : (d.is_archive     ? 'archive'
            : (d.is_pdf         ? 'pdf'
            : (d.is_stl         ? 'stl'
            : (d.is_text        ? 'text'
            : (d.is_video       ? 'video'
            : (['jpg','jpeg','png','gif','webp','bmp'].includes(ext) ? 'image' : 'other'))))))));
        html += '<div class="preview-icon-hero">';
        if (!d.download_url && !d.is_dir) {
            html += '<svg class="icon muted" style="width:48px;height:48px;opacity:.5" viewBox="0 0 24 24" fill="none">'
                + '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
        } else {
            html += previewCatIcon(iconCat, 48);
        }
        html += '</div>';
    }

    html += '<div class="preview-meta">';
    html += metaRow('Size', d.size);
    html += metaRow('Modified', d.mod_time);
    if (!d.is_dir) {
        html += metaRow('Downloads', Number(d.downloads || 0).toLocaleString());
    }
    if (d.owner) {
        if (d.owner_files_url) {
            html += metaRowHTML('Owner', '<a class="owner-chip" href="' + esc(d.owner_files_url) + '" title="' + esc(d.owner) + '"><code>' + esc(d.owner.length > 12 ? d.owner.slice(0, 12) : d.owner) + '</code></a>');
        } else {
            html += metaRow('Owner', d.owner);
        }
    }
    if (d.ext)       html += metaRow('Ext', d.ext);
    if (d.mime_type) html += metaRow('MIME', d.mime_type);
    if (d.is_dir) {
        html += metaRow('Folders', d.child_dirs);
        html += metaRow('Files',   d.child_files);
    }
    if (d.is_image && d.image_width && d.image_height) {
        html += metaRow('Dimensions', d.image_width + '\u202f\u00d7\u202f' + d.image_height + '\u202fpx');
        html += metaRow('Megapixels', (d.image_width * d.image_height / 1e6).toFixed(1) + '\u202fMP');
        var orient = d.image_width > d.image_height ? 'Landscape'
                   : d.image_width < d.image_height ? 'Portrait' : 'Square';
        html += metaRow('Orientation', orient);
        if (d.image_mode) html += metaRow('Colour', d.image_mode);
    }
    if (d.is_text && d.text_line_count) {
        html += metaRow('Lines',      d.text_line_count.toLocaleString());
        html += metaRow('Words',      d.text_word_count.toLocaleString());
        html += metaRow('Characters', d.text_char_count.toLocaleString());
        if (d.text_line_ending && d.text_line_ending !== 'n/a') {
            html += metaRow('Line endings', d.text_line_ending);
        }
    }
    if (d.is_archive && d.archive_entries) {
        html += metaRow('Entries', d.archive_entries.length + (d.archive_entries.length >= 200 ? '+' : ''));
    }
    if (d.is_pdf && d.pdf_page_count) {
        html += metaRow('Pages', d.pdf_page_count.toLocaleString());
    }
    if (d.is_stl) {
        if (d.stl_title) html += metaRow('Title', d.stl_title);
        if (d.stl_triangles) html += metaRow('Triangles', d.stl_triangles.toLocaleString());
    }
    html += '</div>';

    if (d.owner_details_url) {
        html += '<div class="owner-details-block" id="preview-owner-details">'
            + '<div class="owner-details-note">Loading owner details…</div>'
            + '</div>';
    }

    if (d.is_archive && d.archive_entries && d.archive_entries.length > 0) {
        var truncated = d.archive_entries.length >= 200;
        html += '<div class="preview-archive-block">'
            + '<div class="preview-archive-label">Contents</div>'
            + '<ul class="preview-archive-list">';
        d.archive_entries.forEach(function(e) {
            var icon = archiveEntryIcon(e);
            html += '<li class="preview-archive-item">'
                + icon
                + '<span class="preview-archive-name" title="' + esc(e.name) + '">' + esc(e.name) + '</span>'
                + (e.is_dir ? '' : '<span class="preview-archive-size">' + esc(e.size) + '</span>')
                + '</li>';
        });
        html += '</ul>';
        if (truncated) html += '<div class="preview-archive-more">Showing first 200 entries\u2026</div>';
        html += '</div>';
    }

    if (d.is_text && d.text_lines && d.text_lines.length > 0) {
        var textTrunc = d.text_lines.length >= MAX_PREVIEW_LINES;
        html += '<div class="preview-text-block">'
            + '<div class="preview-text-label">Preview'
            + (textTrunc ? ' <span class="preview-truncated">\u2026</span>' : '')
            + '</div>'
            + '<div class="preview-text-content">' + esc(d.text_lines.join('\n')) + '</div>'
            + '</div>';
    }

    content.innerHTML = html;
    var pane = document.getElementById('preview-pane');
    if (pane) pane.scrollTop = 0;
    if (d.owner_details_url) {
        loadOwnerDetails(d.owner_details_url);
    }

    // Boot Video.js for non-native video formats.
    if (vjsVideoId) {
        (function(vid, ext, videoUrl) {
            var isFlv = (ext === 'flv');
            if (!isFlv) {
                ensureVideoJs(function() {
                    var el = document.getElementById(vid);
                    if (typeof videojs === 'undefined' || !el) return;
                    videojs(vid, { fluid: true, controls: true, preload: 'metadata' });
                });
                return;
            }

            // For FLV: probe the first 512 bytes to check video codec before
            // spinning up flv.js. VP6 (codec 4) and others will cause unhandled
            // DemuxException rejections that no event handler can catch.
            fetch(videoUrl, { headers: { Range: 'bytes=0-511' } })
                .then(function(r) { return r.arrayBuffer(); })
                .then(function(buf) {
                    var bytes = new Uint8Array(buf);
                    var codecId = 0;
                    for (var i = 9; i + 15 < bytes.length; i++) {
                        if (bytes[i] === 0x09) { codecId = bytes[i + 11] & 0x0F; break; }
                    }
                    var el = document.getElementById(vid);
                    if (!el) return;

                    if (codecId !== 0 && codecId !== 7 && codecId !== 12) {
                        // Unsupported codec — replace the player element with a notice
                        // rather than letting flv.js throw unhandled rejections.
                        var wrap = el.closest('.preview-video-wrap') || el.parentNode;
                        wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;'
                            + 'height:120px;color:var(--text-muted);font-size:12px;text-align:center;padding:12px">'
                            + '<div>'
                            + '<svg style="width:28px;height:28px;display:block;margin:0 auto 6px;stroke:currentColor;fill:none;stroke-width:1.5" viewBox="0 0 24 24">'
                            + '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
                            + 'FLV codec unsupported in browser<br>'
                            + '<span style="opacity:.6">Download to play locally</span>'
                            + '</div></div>';
                        return;
                    }

                    ensureFlvPlugin(function() {
                        var el2 = document.getElementById(vid);
                        if (typeof videojs === 'undefined' || !el2) return;
                        var player = videojs(vid, { fluid: true, controls: true, preload: 'metadata' });

                        // Suppress errors from flv.js DemuxExceptions that bypass
                        // the player event system and become unhandled Promise rejections.
                        var alive = true;
                        player.on('dispose', function() { alive = false; });
                        player.on('error', function() {
                            console.warn('[explorer] FLV player error:', player.error && player.error());
                        });
                        function rejectionGuard(e) {
                            if (!alive) return;
                            var msg = (e.reason && e.reason.message) || '';
                            if (msg.indexOf('Unhandled error') !== -1) { e.preventDefault(); }
                        }
                        window.addEventListener('unhandledrejection', rejectionGuard);
                        player.on('dispose', function() {
                            window.removeEventListener('unhandledrejection', rejectionGuard);
                        });

                        player.src({ src: videoUrl, type: 'video/x-flv' });
                    });
                })
                .catch(function() {
                    // Fetch probe failed (e.g. server doesn't support Range). Fall
                    // back to attempting playback — worst case is a console warning.
                    ensureFlvPlugin(function() {
                        var el = document.getElementById(vid);
                        if (typeof videojs === 'undefined' || !el) return;
                        var player = videojs(vid, { fluid: true, controls: true, preload: 'metadata' });
                        player.on('error', function() {
                            console.warn('[explorer] FLV player error (fallback):', player.error && player.error());
                        });
                        player.src({ src: videoUrl, type: 'video/x-flv' });
                    });
                });
        })(vjsVideoId, vjsVideoExt, d.video_url);
    }

    // Boot STL viewer if needed.
    if (d.is_stl && d.download_url) {
        var canvas = content.querySelector('canvas[id^="stl-canvas-"]');
        if (canvas) initStlViewer(canvas, d.download_url);
    }
}

function ownerExplorerURL(relPath) {
    var rel = String(relPath || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
    if (!rel) return EXPLORER_BASE + '/';
    return EXPLORER_BASE + '/' + rel.split('/').filter(function(part) { return part.length > 0; }).map(encodeURIComponent).join('/');
}

function previewOwnerPath(event, relPath) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    var rel = String(relPath || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
    if (!rel) return;
    loadPreview(ownerExplorerURL(rel) + '?preview=true');
}

function ownerFolderPath(relPath) {
    var rel = String(relPath || '').trim().replace(/^\/+/, '');
    if (!rel) return '';
    rel = rel.replace(/\/+$/, '');
    var cut = rel.lastIndexOf('/');
    if (cut === -1) return '';
    return rel.slice(0, cut);
}

function ownerDetailsStat(label, value) {
    return '<div class="owner-stat-card">'
        + '<span class="owner-stat-label">' + esc(label) + '</span>'
        + '<span class="owner-stat-value">' + esc(String(value == null || value === '' ? 'Never' : value)) + '</span>'
        + '</div>';
}

function renderOwnerFiles(files) {
    if (!files || !files.length) {
        return '<div class="owner-details-empty">No tracked files for this owner.</div>';
    }
    var rows = files.map(function(path) {
        var raw = String(path || '').trim();
        if (!raw) return '';
        var isDir = /\/$/.test(raw);
        var target = raw.replace(/\/+$/, '');
        var folderTarget = isDir ? target : ownerFolderPath(raw);
        var previewEnc = encodeURIComponent(target);
        var folderURL = ownerExplorerURL(folderTarget);
        var folderLabel = isDir ? 'Open folder' : 'Open parent';
        return '<div class="owner-file-row">'
            + '<div class="owner-file-actions">'
            + '<button class="owner-file-link" onclick="previewOwnerPath(event, decodeURIComponent(\'' + previewEnc + '\'))">Preview</button>'
            + '<a class="owner-file-link" href="' + esc(folderURL) + '">' + folderLabel + '</a>'
            + '<span class="owner-file-kind">' + (isDir ? 'folder' : 'file') + '</span>'
            + '</div>'
            + '<code class="owner-file-path">' + esc(raw) + '</code>'
            + '</div>';
    }).filter(function(row) { return row !== ''; }).join('');
    return rows || '<div class="owner-details-empty">No tracked files for this owner.</div>';
}

function renderOwnerEvents(events) {
    if (!events || !events.length) {
        return '<div class="owner-details-empty">No recent events for this owner.</div>';
    }
    return events.slice(0, 12).map(function(evt) {
        var path = String(evt.path || '').trim();
        var ip = String(evt.ip || '').trim();
        return '<div class="owner-event-row">'
            + '<div class="owner-event-head">'
            + '<span class="owner-event-kind">' + esc(evt.event || '') + '</span>'
            + '<span class="owner-event-time">' + esc(evt.time || '') + '</span>'
            + '</div>'
            + '<div class="owner-event-meta">'
            + (path ? '<code class="owner-file-path">' + esc(path) + '</code>' : '')
            + (ip ? '<span>IP ' + esc(ip) + '</span>' : '')
            + '</div>'
            + '</div>';
    }).join('');
}

function renderOwnerDetails(payload) {
    var stats = payload && payload.stats ? payload.stats : {};
    var files = Array.isArray(payload && payload.files) ? payload.files : [];
    var events = Array.isArray(payload && payload.events) ? payload.events : [];
    var hash = String(payload && payload.hash || '');
    var statusClass = payload && payload.is_banned ? 'banned' : 'active';
    var statusLabel = payload && payload.is_banned ? 'Banned' : 'Active';
    return '<div class="owner-details-header">'
        + '<div class="owner-details-heading">'
        + '<span class="owner-details-title">Owner profile</span>'
        + (hash ? '<span class="owner-details-hash"><code>' + esc(hash) + '</code></span>' : '')
        + '</div>'
        + '<span class="owner-status ' + statusClass + '">' + statusLabel + '</span>'
        + '</div>'
        + '<div class="owner-details-grid">'
        + ownerDetailsStat('Last login', stats.last_login || 'Never')
        + ownerDetailsStat('Seen', String(stats.seen || 0) + ' logins')
        + ownerDetailsStat('Last address', stats.last_address || 'Never')
        + ownerDetailsStat('Uploads', String(stats.upload_count || 0) + ' files')
        + ownerDetailsStat('Uploaded', formatBytes(stats.upload_bytes || 0))
        + ownerDetailsStat('Downloads', String(stats.download_count || 0) + ' files')
        + ownerDetailsStat('Downloaded', formatBytes(stats.download_bytes || 0))
        + '</div>'
        + '<div class="owner-files-wrap">'
        + '<div class="owner-files-head"><span class="owner-files-title">Tracked files</span><span class="owner-files-count">' + esc(files.length) + '</span></div>'
        + '<div class="owner-files-list">' + renderOwnerFiles(files) + '</div>'
        + '</div>'
        + '<div class="owner-events-wrap" style="margin-top:10px">'
        + '<div class="owner-events-head"><span class="owner-events-title">Recent events</span><span class="owner-events-count">' + esc(Math.min(events.length, 12)) + '</span></div>'
        + '<div class="owner-events-list">' + renderOwnerEvents(events) + '</div>'
        + '</div>';
}

function loadOwnerDetails(url) {
    var slot = document.getElementById('preview-owner-details');
    if (!slot || !url) return;
    var requestedURL = String(url);
    if (_ownerDetailsCache[requestedURL]) {
        slot.innerHTML = renderOwnerDetails(_ownerDetailsCache[requestedURL]);
        return;
    }
    slot.innerHTML = '<div class="owner-details-note">Loading owner details...</div>';
    fetch(requestedURL, {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
    }).then(function(res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    }).then(function(payload) {
        _ownerDetailsCache[requestedURL] = payload || {};
        if (!_previewData || _previewData.owner_details_url !== requestedURL) return;
        var currentSlot = document.getElementById('preview-owner-details');
        if (currentSlot) {
            currentSlot.innerHTML = renderOwnerDetails(payload || {});
        }
    }).catch(function(err) {
        if (!_previewData || _previewData.owner_details_url !== requestedURL) return;
        var currentSlot = document.getElementById('preview-owner-details');
        if (currentSlot) {
            currentSlot.innerHTML = '<div class="owner-details-note">Owner details unavailable: ' + esc(err.message || 'request failed') + '</div>';
        }
    });
}

// ── lazy script loader ────────────────────────────────────────────────────────
var _loadedScripts = {};
function loadScript(src, cb) {
    if (_loadedScripts[src]) { cb(); return; }
    var s = document.createElement('script');
    s.src = src;
    s.onload = function() { _loadedScripts[src] = true; cb(); };
    s.onerror = function() { cb(new Error('Failed to load ' + src)); };
    document.head.appendChild(s);
}

// ── STL 3-D viewer ────────────────────────────────────────────────────────────

var THREE_CDN = '{{.ThreeCDN}}';

function initStlViewer(canvas, url) {
    var statusEl = document.getElementById('stl-status-' + canvas.id);
    function setStatus(msg) { if (statusEl) statusEl.textContent = msg; }
    function clearStatus() { if (statusEl) statusEl.style.display = 'none'; }

    loadScript(THREE_CDN, function(err) {
        if (err) { setStatus('Could not load 3-D viewer.'); return; }
        fetch(url)
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.arrayBuffer();
            })
            .then(function(buf) {
                setStatus('');
                var geo = parseStl(buf);
                if (!geo) { setStatus('Could not parse STL.'); return; }
                mountStlScene(canvas, geo);
                clearStatus();
            })
            .catch(function(e) { setStatus('Load error: ' + e.message); });
    });
}

function parseStl(buf) {
    var head = new Uint8Array(buf, 0, Math.min(256, buf.byteLength));
    var headStr = String.fromCharCode.apply(null, head).trimLeft();
    var isAscii = headStr.indexOf('solid') === 0 && headStr.indexOf('facet') !== -1;
    try {
        return isAscii ? parseAsciiStl(buf) : parseBinaryStl(buf);
    } catch(e) {
        try { return parseBinaryStl(buf); } catch(e2) { return null; }
    }
}

function parseBinaryStl(buf) {
    var view = new DataView(buf);
    var triCount = view.getUint32(80, true);
    var positions = new Float32Array(triCount * 9);
    var normals   = new Float32Array(triCount * 9);
    var offset = 84;
    for (var i = 0; i < triCount; i++) {
        var nx = view.getFloat32(offset,      true);
        var ny = view.getFloat32(offset +  4, true);
        var nz = view.getFloat32(offset +  8, true);
        offset += 12;
        for (var v = 0; v < 3; v++) {
            var base = i * 9 + v * 3;
            positions[base]     = view.getFloat32(offset,     true);
            positions[base + 1] = view.getFloat32(offset + 4, true);
            positions[base + 2] = view.getFloat32(offset + 8, true);
            normals[base]     = nx;
            normals[base + 1] = ny;
            normals[base + 2] = nz;
            offset += 12;
        }
        offset += 2;
    }
    var geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geo.setAttribute('normal',   new THREE.BufferAttribute(normals,   3));
    return geo;
}

function parseAsciiStl(buf) {
    var text = new TextDecoder().decode(buf);
    var positions = [];
    var normals   = [];
    var re = /facet\s+normal\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)[\s\S]*?vertex\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+vertex\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+vertex\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)\s+([\d.eE+\-]+)/g;
    var m;
    while ((m = re.exec(text)) !== null) {
        var nx = +m[1], ny = +m[2], nz = +m[3];
        for (var v = 0; v < 3; v++) {
            positions.push(+m[4+v*3], +m[5+v*3], +m[6+v*3]);
            normals.push(nx, ny, nz);
        }
    }
    if (!positions.length) throw new Error('No faces');
    var geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(positions), 3));
    geo.setAttribute('normal',   new THREE.BufferAttribute(new Float32Array(normals),   3));
    return geo;
}

function mountStlScene(canvas, geo) {
    var wrap = canvas.parentElement;
    var W = wrap.clientWidth  || 240;
    var H = wrap.clientHeight || 260;

    var renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(W, H);
    renderer.setClearColor(0x000000, 0);

    var scene  = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(45, W / H, 0.01, 1000);

    scene.add(new THREE.AmbientLight(0xffffff, 0.5));
    var dir1 = new THREE.DirectionalLight(0xffffff, 0.8);
    dir1.position.set(1, 2, 3);
    scene.add(dir1);
    var dir2 = new THREE.DirectionalLight(0xffffff, 0.3);
    dir2.position.set(-2, -1, -1);
    scene.add(dir2);

    geo.computeBoundingBox();
    var box    = geo.boundingBox;
    var center = new THREE.Vector3();
    box.getCenter(center);
    var size   = new THREE.Vector3();
    box.getSize(size);
    var maxDim = Math.max(size.x, size.y, size.z);

    var accentHsl = getComputedStyle(document.documentElement).getPropertyValue('--icon-stl').trim() || '#2a9d8f';
    var mat = new THREE.MeshPhongMaterial({
        color: new THREE.Color(accentHsl),
        shininess: 40,
        side: THREE.DoubleSide
    });
    var mesh = new THREE.Mesh(geo, mat);
    mesh.position.sub(center);
    scene.add(mesh);

    var dist = maxDim / (2 * Math.tan(Math.PI * 45 / 360));
    camera.position.set(0, 0, dist * 1.6);
    camera.lookAt(0, 0, 0);

    var isDragging = false, lastX = 0, lastY = 0;
    var rotX = 0.3, rotY = 0.5;

    function applyRot() { mesh.rotation.x = rotX; mesh.rotation.y = rotY; }
    applyRot();

    canvas.addEventListener('mousedown',  function(e) { isDragging = true;  lastX = e.clientX; lastY = e.clientY; });
    window.addEventListener('mouseup',    function()  { isDragging = false; });
    window.addEventListener('mousemove',  function(e) {
        if (!isDragging) return;
        rotY += (e.clientX - lastX) * 0.01;
        rotX += (e.clientY - lastY) * 0.01;
        lastX = e.clientX; lastY = e.clientY;
        applyRot(); renderer.render(scene, camera);
    });
    canvas.addEventListener('touchstart', function(e) { if (e.touches.length===1) { isDragging=true; lastX=e.touches[0].clientX; lastY=e.touches[0].clientY; } }, {passive:true});
    canvas.addEventListener('touchend',   function()  { isDragging=false; });
    canvas.addEventListener('touchmove',  function(e) {
        if (!isDragging||e.touches.length!==1) return;
        rotY += (e.touches[0].clientX - lastX) * 0.01;
        rotX += (e.touches[0].clientY - lastY) * 0.01;
        lastX = e.touches[0].clientX; lastY = e.touches[0].clientY;
        applyRot(); renderer.render(scene, camera);
    }, {passive:true});
    canvas.addEventListener('wheel', function(e) {
        e.preventDefault();
        camera.position.z *= (1 + e.deltaY * 0.001);
        renderer.render(scene, camera);
    }, {passive:false});

    var autoRotate = true;
    canvas.addEventListener('mousedown', function() { autoRotate = false; });
    canvas.addEventListener('touchstart', function() { autoRotate = false; }, {passive:true});

    var rafId;
    function animate() {
        rafId = requestAnimationFrame(animate);
        if (autoRotate) { rotY += 0.008; applyRot(); }
        renderer.render(scene, camera);
    }
    animate();

    var observer = new MutationObserver(function() {
        if (!document.body.contains(canvas)) {
            cancelAnimationFrame(rafId);
            renderer.dispose();
            observer.disconnect();
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
}
</script>
</body>
</html>

{{/* ── reusable: preview pane ── */}}
{{define "preview-pane"}}
{{if .PreviewOpen}}
<aside class="preview-pane" id="preview-pane"
       aria-label="File preview" role="complementary"
       aria-live="polite" aria-atomic="true">
    <div class="preview-empty" id="preview-prompt">
        <div id="preview-dir-stats"></div>
    </div>
    <div id="preview-content"></div>
</aside>
{{end}}
{{end}}

{{/* ── reusable: sort controls (select + order button) ── */}}
{{define "sort-controls"}}
{{$sortBy := .SortBy}}{{if eq $sortBy ""}}{{$sortBy = "name"}}{{end}}
{{$curOrder := .Order}}{{if eq $curOrder ""}}{{$curOrder = "asc"}}{{end}}
{{$nextOrder := "asc"}}{{if eq $curOrder "asc"}}{{$nextOrder = "desc"}}{{end}}
<label for="sort-select-{{.View}}" class="sr-only">Sort by</label>
<select id="sort-select-{{.View}}" class="sort-select" aria-label="Sort by" onchange="sortChange(this)">
    <option value="name"     {{if or (eq .SortBy "name") (eq .SortBy "")}}selected{{end}}>Name</option>
    <option value="modified" {{if eq .SortBy "modified"}}selected{{end}}>Modified</option>
    <option value="size"     {{if eq .SortBy "size"}}selected{{end}}>Size</option>
    <option value="downloads" {{if eq .SortBy "downloads"}}selected{{end}}>Downloads</option>
</select>
<a href="?sort={{$sortBy}}&order={{$nextOrder}}"
   class="sort-order-btn{{if eq $curOrder "asc"}} active{{end}}"
   aria-label="{{if eq $curOrder "asc"}}Ascending, click for descending{{else}}Descending, click for ascending{{end}}"
   title="Toggle sort order">{{if eq $curOrder "asc"}}↑{{else}}↓{{end}}</a>
{{end}}

{{/* ── icon sub-templates ── */}}

{{define "icon-dir"}}
<svg class="icon icon-cat-dir{{if .IsEmpty}} empty{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
</svg>
{{end}}

{{define "icon-dir-lg"}}
<svg class="icon icon-lg icon-cat-dir{{if .IsEmpty}} empty{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
</svg>
{{end}}

{{define "icon-file"}}
{{$empty := .IsEmpty}}
{{if eq .Category "image"}}
<svg class="icon icon-cat-image{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
    <circle cx="8.5" cy="8.5" r="1.5"/>
    <polyline points="21 15 16 10 5 21"/>
</svg>
{{else if eq .Category "video"}}
<svg class="icon icon-cat-video{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="2" y="3" width="20" height="18" rx="2" ry="2"/>
    <path d="m10 8 5 4-5 4V8z"/>
</svg>
{{else if eq .Category "text"}}
<svg class="icon icon-cat-text{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="8" y1="13" x2="16" y2="13"/>
    <line x1="8" y1="17" x2="16" y2="17"/>
</svg>
{{else if eq .Category "archive"}}
<svg class="icon icon-cat-archive{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <polyline points="21 8 21 21 3 21 3 8"/>
    <rect x="1" y="3" width="22" height="5"/>
    <line x1="10" y1="12" x2="14" y2="12"/>
</svg>
{{else if eq .Category "pdf"}}
<svg class="icon icon-cat-pdf{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="8" y1="13" x2="12" y2="13"/>
    <line x1="8" y1="17" x2="16" y2="17"/>
</svg>
{{else if eq .Category "stl"}}
<svg class="icon icon-cat-stl{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M12 2L2 7l10 5 10-5-10-5z"/>
    <path d="M2 17l10 5 10-5"/>
    <path d="M2 12l10 5 10-5"/>
</svg>
{{else}}
<svg class="icon icon-cat-other{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
</svg>
{{end}}
{{end}}

{{define "icon-file-lg"}}
{{$empty := .IsEmpty}}
{{if eq .Category "image"}}
<svg class="icon icon-lg icon-cat-image{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
    <circle cx="8.5" cy="8.5" r="1.5"/>
    <polyline points="21 15 16 10 5 21"/>
</svg>
{{else if eq .Category "video"}}
<svg class="icon icon-lg icon-cat-video{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="2" y="3" width="20" height="18" rx="2" ry="2"/>
    <path d="m10 8 5 4-5 4V8z"/>
</svg>
{{else if eq .Category "text"}}
<svg class="icon icon-lg icon-cat-text{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="8" y1="13" x2="16" y2="13"/>
    <line x1="8" y1="17" x2="16" y2="17"/>
</svg>
{{else if eq .Category "archive"}}
<svg class="icon icon-lg icon-cat-archive{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <polyline points="21 8 21 21 3 21 3 8"/>
    <rect x="1" y="3" width="22" height="5"/>
    <line x1="10" y1="12" x2="14" y2="12"/>
</svg>
{{else if eq .Category "pdf"}}
<svg class="icon icon-lg icon-cat-pdf{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="8" y1="13" x2="12" y2="13"/>
    <line x1="8" y1="17" x2="16" y2="17"/>
</svg>
{{else if eq .Category "stl"}}
<svg class="icon icon-lg icon-cat-stl{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M12 2L2 7l10 5 10-5-10-5z"/>
    <path d="M2 17l10 5 10-5"/>
    <path d="M2 12l10 5 10-5"/>
</svg>
{{else}}
<svg class="icon icon-lg icon-cat-other{{if $empty}} muted{{end}}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
</svg>
{{end}}
{{end}}

{{define "icon-lock"}}
<svg class="icon muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>
{{end}}

{{define "icon-danger"}}
<svg class="icon icon-danger" viewBox="0 0 24 24" aria-hidden="true" focusable="false" aria-label="Potentially dangerous file">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke-width="1.75"/>
    <line x1="12" y1="9" x2="12" y2="13" stroke-width="1.75" stroke-linecap="round"/>
    <line x1="12" y1="17" x2="12.01" y2="17" stroke-width="2.5" stroke-linecap="round"/>
</svg>
{{end}}

{{define "icon-danger-lg"}}
<svg class="icon icon-lg icon-danger" viewBox="0 0 24 24" aria-hidden="true" focusable="false" aria-label="Potentially dangerous file">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke-width="1.5"/>
    <line x1="12" y1="9" x2="12" y2="13" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="12" y1="17" x2="12.01" y2="17" stroke-width="2.25" stroke-linecap="round"/>
</svg>
{{end}}

{{define "icon-lock-lg"}}
<svg class="icon icon-lg muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>
{{end}}

{{define "tree-node"}}
{{$unlocked  := .IsUnlocked}}
{{$sortSuffix := .SortSuffix}}
{{$wanted    := .WantedFile}}
{{range .Children}}
    {{if .IsDir}}
    <details data-name="{{.Name}}" data-size="{{.TotalSize}}" data-modified="{{.ModTimeRaw}}" data-dir-url="{{.URL}}{{$sortSuffix}}">
        <summary aria-label="{{.Name}} (folder{{if .IsEmpty}}, empty{{end}})" onclick="previewDir(event, '{{.URL}}')" data-dir-url="{{.URL}}{{$sortSuffix}}" data-preview-url="{{.URL}}">
            <svg class="tree-chevron" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <polyline points="9 18 15 12 9 6"/>
            </svg>
            {{template "icon-dir" .}}
            <a href="{{.URL}}{{$sortSuffix}}" class="tree-dir-link" onclick="event.stopPropagation()">{{.Name}}</a>
            <span class="tree-meta" aria-label="{{.ChildDirs}} folders, {{.ChildFiles}} files, {{.TotalSizeReadable}}">
                {{- if .ChildDirs}}{{.ChildDirs}} {{if eq .ChildDirs 1}}folder{{else}}folders{{end}}{{end -}}
                {{- if and .ChildDirs .ChildFiles}} · {{end -}}
                {{- if .ChildFiles}}{{.ChildFiles}} {{if eq .ChildFiles 1}}file{{else}}files{{end}}{{end -}}
                {{- if or .ChildDirs .ChildFiles}} · {{end -}}
                {{- .TotalSizeReadable -}}
            </span>
            <button class="copy-link-btn" onclick="copyLink(event, '{{.URL}}')" aria-label="Copy link to {{.Name}}" title="Copy link">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
            </button>
            <div>{{if .IsNew}}<span class="badge-new">new</span>{{end}}</div>
        </summary>
        <div class="tree-children">
            {{template "tree-node" (dict "Children" .Children "IsUnlocked" $unlocked "SortSuffix" $sortSuffix "WantedFile" $wanted)}}
        </div>
    </details>
    {{else}}
    <div class="tree-file{{if eq .Name $wanted}} wanted-tree{{end}}" data-name="{{.Name}}" data-size="{{.Size}}" data-modified="{{.ModTimeRaw}}" onclick="handleFileClick(this,'{{.URL}}?preview=true','{{if $unlocked}}{{.URL}}{{end}}',event)" style="cursor:pointer">
        <span style="width:18px"></span>
        {{if $unlocked}}
            {{if .IsDanger}}{{template "icon-danger" .}}{{else}}{{template "icon-file" .}}{{end}}
            <a href="{{.URL}}" download>{{.Name}}</a>
        {{else}}
            {{template "icon-lock" .}}
            <span class="locked-text" title="Upload a file to unlock downloads">{{.Name}}</span>
        {{end}}
        <span class="tree-size">{{.SizeReadable}}</span>
        <span class="tree-size">{{.Downloads}} dl</span>
        {{if $unlocked}}
        <button class="copy-link-btn" onclick="copyLink(event, '{{.URL}}')" aria-label="Copy link to {{.Name}}" title="Copy link">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
        </button>
        {{else}}
        <span></span>
        {{end}}
        <div>{{if .IsNew}}<span class="badge-new">new</span>{{end}}</div>
    </div>
    {{end}}
{{end}}
{{end}}

{{define "empty-state"}}
<div class="empty-state" role="status">
    <svg class="icon icon-lg muted" viewBox="0 0 24 24" aria-hidden="true" focusable="false"
         style="width:48px;height:48px;margin:0 auto 12px;display:block">
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
    </svg>
    <p style="margin:0;font-size:14px">This folder is empty.</p>
</div>
{{end}}
`
