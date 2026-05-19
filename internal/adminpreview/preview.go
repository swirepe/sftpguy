package adminpreview

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	thumbCacheCapacity   = 5_000
	dirSizeCacheCapacity = 10_000
	previewCacheCapacity = 20_000
	thumbBrowserTTL      = 24 * time.Hour

	textProbeBytes    = 8 << 10
	maxPreviewLines   = 25
	maxArchiveEntries = 200
)

var (
	ErrInvalidPath = errors.New("invalid path")
	ErrNotFound    = errors.New("path not found")
)

var (
	imageExts = map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true,
		".gif": true, ".webp": true, ".bmp": true,
	}
	cadExts = map[string]bool{
		".stl": true,
	}
	videoExts = map[string]bool{
		".mp4": true, ".webm": true, ".ogg": true,
		".mov": true, ".mkv": true, ".flv": true,
		".avi": true,
	}
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

type FileDetails struct {
	Owner     string
	Downloads int64
}

type Config struct {
	RootDir           string
	LookupFileDetails func(relPath string) (FileDetails, error)
	LookupOwner       func(relPath string) (string, error)
	OwnerFilesURL     func(owner string) string
	OwnerDetailsURL   func(owner string) string
}

type URLOptions struct {
	Variant      string
	Unlocked     bool
	DownloadURL  func(relPath string) string
	ThumbnailURL func(relPath string) string
}

type Previewer struct {
	rootDir string

	lookupFileDetails func(relPath string) (FileDetails, error)
	lookupOwner       func(relPath string) (string, error)
	ownerFilesURL     func(owner string) string
	ownerDetailsURL   func(owner string) string

	dirSizeCache *lruCache[int64]
	thumbCache   *bytesCache
	previewCache *bytesCache
}

type ArchiveEntry struct {
	Name     string `json:"name"`
	Size     string `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Category string `json:"category"`
}

type Payload struct {
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
	VideoNative bool   `json:"video_native"`

	IsText         bool     `json:"is_text"`
	TextLines      []string `json:"text_lines,omitempty"`
	TextLineCount  int      `json:"text_line_count,omitempty"`
	TextWordCount  int      `json:"text_word_count,omitempty"`
	TextCharCount  int      `json:"text_char_count,omitempty"`
	TextLineEnding string   `json:"text_line_ending,omitempty"`

	IsArchive      bool           `json:"is_archive"`
	ArchiveEntries []ArchiveEntry `json:"archive_entries,omitempty"`

	IsPdf        bool `json:"is_pdf"`
	PdfPageCount int  `json:"pdf_page_count,omitempty"`

	IsStl        bool   `json:"is_stl"`
	StlTriangles int    `json:"stl_triangles,omitempty"`
	StlTitle     string `json:"stl_title,omitempty"`
}

func New(cfg Config) (*Previewer, error) {
	if strings.TrimSpace(cfg.RootDir) == "" {
		return nil, fmt.Errorf("root directory is required")
	}
	abs, err := filepath.Abs(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("resolve root directory %q: %w", cfg.RootDir, err)
	}
	if err := os.MkdirAll(abs, os.ModePerm); err != nil {
		return nil, fmt.Errorf("create root directory %q: %w", abs, err)
	}
	return &Previewer{
		rootDir:           abs,
		lookupFileDetails: cfg.LookupFileDetails,
		lookupOwner:       cfg.LookupOwner,
		ownerFilesURL:     cfg.OwnerFilesURL,
		ownerDetailsURL:   cfg.OwnerDetailsURL,
		dirSizeCache:      newLRU[int64](dirSizeCacheCapacity),
		thumbCache:        newBytesCache(thumbCacheCapacity),
		previewCache:      newBytesCache(previewCacheCapacity),
	}, nil
}

func (p *Previewer) RootDir() string {
	if p == nil {
		return ""
	}
	return p.rootDir
}

func (p *Previewer) CleanRelPath(raw string) (string, error) {
	if p == nil {
		return "", ErrInvalidPath
	}
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if strings.ContainsRune(raw, 0) {
		return "", ErrInvalidPath
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", ErrInvalidPath
		}
	}
	raw = filepath.ToSlash(raw)
	raw = strings.TrimPrefix(raw, "/")
	clean := filepath.ToSlash(filepath.Clean("/" + raw))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." {
		clean = ""
	}
	full := filepath.Clean(filepath.Join(p.rootDir, filepath.FromSlash(clean)))
	rootWithSep := p.rootDir + string(filepath.Separator)
	if full != p.rootDir && !strings.HasPrefix(full+string(filepath.Separator), rootWithSep) {
		return "", ErrInvalidPath
	}
	return clean, nil
}

func (p *Previewer) FullPath(relPath string) (string, error) {
	clean, err := p.CleanRelPath(relPath)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(p.rootDir, filepath.FromSlash(clean))), nil
}

func (p *Previewer) ServePreviewJSON(w http.ResponseWriter, r *http.Request, relPath string, opts URLOptions) {
	data, err := p.PreviewJSON(relPath, opts)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch {
		case errors.Is(err, ErrInvalidPath):
			http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		case errors.Is(err, ErrNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"preview failed"}`, http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

func (p *Previewer) PreviewJSON(relPath string, opts URLOptions) ([]byte, error) {
	payload, info, cacheKey, err := p.preview(relPath, opts)
	if err != nil {
		return nil, err
	}
	if cached, ok := p.previewCache.get(cacheKey, info.ModTime()); ok {
		return cached, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	p.previewCache.set(cacheKey, info.ModTime(), data)
	return data, nil
}

func (p *Previewer) Preview(relPath string, opts URLOptions) (Payload, error) {
	payload, _, _, err := p.preview(relPath, opts)
	return payload, err
}

func (p *Previewer) ServeThumbnail(w http.ResponseWriter, r *http.Request, relPath string, unlocked bool) {
	if !unlocked {
		http.Error(w, "Locked", http.StatusForbidden)
		return
	}
	clean, err := p.CleanRelPath(relPath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	fullPath, err := p.FullPath(clean)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if info.IsDir() {
		http.NotFound(w, r)
		return
	}
	if !imageExts[strings.ToLower(filepath.Ext(info.Name()))] {
		http.NotFound(w, r)
		return
	}

	modTime := info.ModTime()
	httpModTime := modTime.Truncate(time.Second)
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !httpModTime.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if cached, ok := p.thumbCache.get(fullPath, modTime); ok {
		writeThumb(w, httpModTime, cached)
		return
	}
	p.generateAndStoreThumb(fullPath, modTime)
	cached, ok := p.thumbCache.get(fullPath, modTime)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeThumb(w, httpModTime, cached)
}

func (p *Previewer) WarmCaches(maxFiles int, urlOpts URLOptions) {
	if p == nil || maxFiles <= 0 {
		return
	}
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
		_ = p.cachedDirSize(dir)
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
			wg.Add(1)
			sem <- struct{}{}
			go func(fPath string, fInfo os.FileInfo) {
				defer wg.Done()
				defer func() { <-sem }()
				relPath := strings.TrimPrefix(filepath.ToSlash(fPath), filepath.ToSlash(p.rootDir)+"/")
				_, _ = p.PreviewJSON(relPath, urlOpts)
				if imageExts[strings.ToLower(filepath.Ext(fInfo.Name()))] {
					p.generateAndStoreThumb(fPath, fInfo.ModTime())
				}
			}(fullPath, info)
		}
	}
	walk(p.rootDir)
	wg.Wait()
	log.Printf("CACHE WARMUP: done - %d files processed in %v", count, time.Since(start).Round(time.Millisecond))
}

func (p *Previewer) InvalidateDirSize(absPath string) {
	if p == nil {
		return
	}
	path := filepath.Clean(absPath)
	for {
		p.dirSizeCache.delete(path)
		if path == p.rootDir {
			break
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
}

func (p *Previewer) preview(relPath string, opts URLOptions) (Payload, os.FileInfo, string, error) {
	clean, err := p.CleanRelPath(relPath)
	if err != nil {
		return Payload{}, nil, "", err
	}
	fullPath, err := p.FullPath(clean)
	if err != nil {
		return Payload{}, nil, "", err
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Payload{}, nil, "", ErrNotFound
		}
		return Payload{}, nil, "", err
	}

	details, ownerFilesURL, ownerDetailsURL := p.fileDetailsForPath(clean)
	variant := strings.TrimSpace(opts.Variant)
	if variant == "" {
		variant = "default"
	}
	cacheKey := fmt.Sprintf("%s:variant=%s:unlocked=%t:owner=%s:downloads=%d", fullPath, variant, opts.Unlocked, details.Owner, details.Downloads)

	var payload Payload
	if info.IsDir() {
		payload = Payload{
			Name:    info.Name(),
			IsDir:   true,
			Size:    FormatBytes(info.Size()),
			ModTime: info.ModTime().Format("2006-01-02 15:04"),
		}
		if clean == "" {
			payload.Name = "root"
		}
		entries, _ := os.ReadDir(fullPath)
		for _, e := range entries {
			if e.IsDir() {
				payload.ChildDirs++
			} else {
				payload.ChildFiles++
			}
		}
		payload.TotalSize = FormatBytes(p.cachedDirSize(fullPath))
	} else {
		payload = p.buildFilePreviewPayload(fullPath, info, clean, opts)
	}

	payload.RelPath = filepath.ToSlash(clean)
	payload.Owner = details.Owner
	payload.Downloads = details.Downloads
	payload.OwnerFilesURL = ownerFilesURL
	payload.OwnerDetailsURL = ownerDetailsURL
	return payload, info, cacheKey, nil
}

func (p *Previewer) buildFilePreviewPayload(fullPath string, info os.FileInfo, relPath string, opts URLOptions) Payload {
	payload := Payload{
		Name:    info.Name(),
		IsDir:   false,
		Size:    FormatBytes(info.Size()),
		ModTime: info.ModTime().Format("2006-01-02 15:04"),
		Ext:     strings.ToLower(filepath.Ext(info.Name())),
	}
	if opts.Unlocked && opts.DownloadURL != nil {
		payload.DownloadURL = opts.DownloadURL(relPath)
	}

	if f, err := os.Open(fullPath); err == nil {
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		payload.MimeType = http.DetectContentType(buf[:n])
		_ = f.Close()
	}

	cat := getCategory(info.Name())
	likelyText := cat == "text" || strings.HasPrefix(payload.MimeType, "text/")
	if !likelyText && payload.Ext == "" {
		likelyText = isLikelyTextFile(fullPath)
	}

	switch {
	case opts.Unlocked && cat == "image":
		payload.IsImage = true
		if opts.ThumbnailURL != nil {
			payload.ThumbURL = opts.ThumbnailURL(relPath)
		}
		if iw, ih, mode := imageStats(fullPath); iw > 0 {
			payload.ImageWidth = iw
			payload.ImageHeight = ih
			payload.ImageMode = mode
		}
		if _, ok := p.thumbCache.get(fullPath, info.ModTime()); !ok {
			p.generateAndStoreThumb(fullPath, info.ModTime())
		}
	case likelyText:
		payload.IsText = true
		payload.TextLines = readFirstLines(fullPath, maxPreviewLines)
		lc, wc, cc, ending := textStats(fullPath)
		payload.TextLineCount = lc
		payload.TextWordCount = wc
		payload.TextCharCount = cc
		payload.TextLineEnding = ending
	case opts.Unlocked && (cat == "video" || strings.HasPrefix(payload.MimeType, "video/")):
		payload.IsVideo = true
		if opts.DownloadURL != nil {
			payload.VideoURL = opts.DownloadURL(relPath)
		}
		payload.VideoNative = isNativeVideo(info.Name())
	case cat == "archive":
		payload.IsArchive = true
		payload.ArchiveEntries = listArchive(fullPath)
	case cat == "pdf":
		payload.IsPdf = true
		payload.PdfPageCount = countPdfPages(fullPath)
	case cat == "stl":
		payload.IsStl = true
		payload.StlTriangles, payload.StlTitle = readStlMeta(fullPath)
	}
	return payload
}

func (p *Previewer) fileDetailsForPath(relPath string) (details FileDetails, filesURL string, detailsURL string) {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relPath)), "/")
	if clean == "." || clean == "" {
		return FileDetails{}, "", ""
	}
	if p.lookupFileDetails != nil {
		found, err := p.lookupFileDetails(clean)
		if err == nil {
			details = found
		}
	} else if p.lookupOwner != nil {
		found, err := p.lookupOwner(clean)
		if err == nil {
			details.Owner = found
		}
	}
	details.Owner = strings.TrimSpace(details.Owner)
	if details.Owner == "" {
		return details, "", ""
	}
	if p.ownerFilesURL != nil {
		filesURL = strings.TrimSpace(p.ownerFilesURL(details.Owner))
	}
	if p.ownerDetailsURL != nil {
		detailsURL = strings.TrimSpace(p.ownerDetailsURL(details.Owner))
	}
	return details, filesURL, detailsURL
}

func (p *Previewer) cachedDirSize(absPath string) int64 {
	if v, ok := p.dirSizeCache.get(absPath); ok {
		return v
	}
	size := computeDirSize(absPath)
	p.dirSizeCache.set(absPath, size)
	return size
}

func (p *Previewer) generateAndStoreThumb(fullPath string, modTime time.Time) {
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
		p.thumbCache.set(fullPath, modTime, bb.b)
	}
}

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

type bytesCacheEntry struct {
	data    []byte
	modTime time.Time
}

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

type byteBuffer struct{ b []byte }

func (bb *byteBuffer) Write(p []byte) (int, error) {
	bb.b = append(bb.b, p...)
	return len(p), nil
}

func writeThumb(w http.ResponseWriter, modTime time.Time, data []byte) {
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	setCacheHeaders(w, thumbBrowserTTL)
	_, _ = w.Write(data)
}

func setCacheHeaders(w http.ResponseWriter, ttl time.Duration) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
	w.Header().Set("Expires", time.Now().Add(ttl).UTC().Format(http.TimeFormat))
}

func computeDirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
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

func isNativeVideo(name string) bool {
	return nativeVideoExts[strings.ToLower(filepath.Ext(name))]
}

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

func listArchive(path string) []ArchiveEntry {
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

func listZip(path string) []ArchiveEntry {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()
	entries := make([]ArchiveEntry, 0, min(len(r.File), maxArchiveEntries))
	for i, file := range r.File {
		if i >= maxArchiveEntries {
			break
		}
		isDir := file.FileInfo().IsDir()
		cat := ""
		if !isDir {
			cat = getCategory(file.Name)
		}
		entries = append(entries, ArchiveEntry{
			Name:     file.Name,
			Size:     FormatBytes(int64(file.UncompressedSize64)),
			IsDir:    isDir,
			Category: cat,
		})
	}
	return entries
}

func listTar(f *os.File, isGzip bool) []ArchiveEntry {
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
	var entries []ArchiveEntry
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
		entries = append(entries, ArchiveEntry{
			Name:     header.Name,
			Size:     FormatBytes(header.Size),
			IsDir:    isDir,
			Category: cat,
		})
	}
	return entries
}

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

func FormatBytes(b int64) string {
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

func ExplorerURL(basePath, relPath string) string {
	rel := strings.TrimSpace(filepath.ToSlash(relPath))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." || rel == "" {
		return strings.TrimRight(basePath, "/") + "/"
	}
	u := url.URL{Path: "/" + rel}
	return strings.TrimRight(basePath, "/") + u.EscapedPath()
}

func ThumbnailAPIURL(relPath string) string {
	q := url.Values{}
	q.Set("path", filepath.ToSlash(relPath))
	return "/admin/api/thumbnail?" + q.Encode()
}

func PreviewAPIURL(relPath string) string {
	q := url.Values{}
	q.Set("path", filepath.ToSlash(relPath))
	return "/admin/api/preview?" + q.Encode()
}
