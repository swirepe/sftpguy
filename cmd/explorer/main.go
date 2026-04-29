package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── constants ─────────────────────────────────────────────────────────────────

//go:embed main.go
var appSrc string

const (
	cookieUnlock = "explorer_unlocked"
	cookieCSRF   = "explorer_csrf"
	headerCSRF   = "X-CSRF-Token"
)

// ── globals ───────────────────────────────────────────────────────────────────

var (
	rootDir             string
	maxFileSize         int64
	headerHTML          template.HTML
	footerHTML          template.HTML
	logger              = newLogger(os.Stderr)
	errUploadBadRequest = errors.New("upload bad request")
	errUploadFailed     = errors.New("upload failed")
)

// ── logging ───────────────────────────────────────────────────────────────────

// sourceOnWarnHandler suppresses file:line source annotations for log levels
// below WARN and includes them at WARN and above.
type sourceOnWarnHandler struct{ slog.Handler }

func (h sourceOnWarnHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		r.PC = 0 // zero PC prevents AddSource from resolving file/line
	}
	return h.Handler.Handle(ctx, r)
}

func (h sourceOnWarnHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return sourceOnWarnHandler{h.Handler.WithAttrs(attrs)}
}

func (h sourceOnWarnHandler) WithGroup(name string) slog.Handler {
	return sourceOnWarnHandler{h.Handler.WithGroup(name)}
}

func newLogger(out io.Writer) *slog.Logger {
	inner := slog.NewTextHandler(out, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src, _ := a.Value.Any().(*slog.Source)
				if src == nil || src.File == "" {
					return slog.Attr{} // no source info — drop the key entirely
				}
				src.File = filepath.Base(src.File)
			}
			if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
				return slog.Attr{} // drop empty values
			}
			return a
		},
	})
	return slog.New(sourceOnWarnHandler{inner})
}

func fatalLog(msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}

// ── log file with rotation support ───────────────────────────────────────────

type rotationAwareLogWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
}

func newRotationAwareLogWriter(path string) (*rotationAwareLogWriter, error) {
	w := &rotationAwareLogWriter{path: path}
	if err := w.reopenLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotationAwareLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureCurrentLocked(); err != nil {
		return 0, err
	}
	n, err := w.file.Write(p)
	if err == nil {
		return n, nil
	}
	// Retry once — handles the case where a log rotator replaced the file
	// and our descriptor went stale between the ensureCurrentLocked check above
	// and the Write call.
	if reopenErr := w.reopenLocked(); reopenErr != nil {
		return n, err
	}
	return w.file.Write(p)
}

func (w *rotationAwareLogWriter) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reopenLocked()
}

func (w *rotationAwareLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotationAwareLogWriter) ensureCurrentLocked() error {
	if w.file == nil {
		return w.reopenLocked()
	}
	cur, err := w.file.Stat()
	if err != nil {
		return w.reopenLocked()
	}
	onDisk, err := os.Stat(w.path)
	if err == nil {
		if os.SameFile(cur, onDisk) {
			return nil
		}
		return w.reopenLocked()
	}
	if os.IsNotExist(err) {
		// Path was removed; keep writing to the old fd until rotation recreates it.
		return nil
	}
	return err
}

func (w *rotationAwareLogWriter) reopenLocked() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if w.file != nil {
		_ = w.file.Close()
	}
	w.file = f
	return nil
}

// watchSIGHUP listens for SIGHUP and reopens the log file, supporting
// log-rotation tools that move the current file and expect writers to reopen.
func watchSIGHUP(lf *rotationAwareLogWriter) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for sig := range ch {
			if err := lf.Reopen(); err != nil {
				logger.Error("log reopen failed", "signal", sig, "err", err)
				continue
			}
			logger.Info("log reopened", "signal", sig)
		}
	}()
}

// initLogger wires the global logger to both stdout and the given log file,
// and installs a SIGHUP handler for log rotation. It returns the log file
// writer so the caller can close it on shutdown.
func initLogger(logPath string) (*rotationAwareLogWriter, error) {
	lf, err := newRotationAwareLogWriter(logPath)
	if err != nil {
		return nil, err
	}
	logger = newLogger(io.MultiWriter(os.Stdout, lf))
	watchSIGHUP(lf)
	return lf, nil
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	var logPath, port, headerPath, footerPath string
	var maxSizeMB int64

	flag.StringVar(&rootDir, "dir", "./shared", "Directory to serve")
	flag.StringVar(&port, "port", "8080", "Port to listen on")
	flag.Int64Var(&maxSizeMB, "maxsize", 1000, "Max upload size in MB")
	flag.StringVar(&logPath, "log", "explorer.log", "Log file path")
	flag.StringVar(&headerPath, "header", "", "Path to an HTML fragment to inject at the top of every page")
	flag.StringVar(&footerPath, "footer", "", "Path to an HTML fragment to inject at the bottom of every page")
	src := flag.Bool("src", false, "Print this program's source and exit")
	flag.Parse()

	if *src {
		fmt.Println(appSrc)
		os.Exit(0)
	}

	maxFileSize = maxSizeMB << 20

	if headerPath != "" {
		b, err := os.ReadFile(headerPath)
		if err != nil {
			fatalLog("read header file", "path", headerPath, "err", err)
		}
		headerHTML = template.HTML(b)
	}
	if footerPath != "" {
		b, err := os.ReadFile(footerPath)
		if err != nil {
			fatalLog("read footer file", "path", footerPath, "err", err)
		}
		footerHTML = template.HTML(b)
	}

	lf, err := initLogger(logPath)
	if err != nil {
		fatalLog("open log", "err", err)
	}
	defer lf.Close()

	abs, err := filepath.Abs(rootDir)
	if err != nil {
		fatalLog("resolve root", "err", err)
	}
	rootDir = abs

	if err := os.MkdirAll(rootDir, 0755); err != nil {
		fatalLog("create root", "path", rootDir, "err", err)
	}

	addr := ":" + port
	logger.Info("serving explorer", "dir", rootDir, "addr", addr, "maxUploadMB", maxSizeMB)
	server := &http.Server{
		Addr:     addr,
		Handler:  http.HandlerFunc(rootHandler),
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	if err := server.ListenAndServe(); err != nil {
		fatalLog("serve http", "addr", addr, "err", err)
	}
}

// ── middleware & routing ──────────────────────────────────────────────────────

func rootHandler(w http.ResponseWriter, r *http.Request) {
	nonce := generateNonce()
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s';", nonce))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	reqLog := requestLogger(logger, r)
	reqLog.Info("request")
	handle(reqLog, w, r, nonce)
}

func requestLogger(base *slog.Logger, r *http.Request) *slog.Logger {
	l := base.With(
		"ip", clientIP(r),
		"unlocked", isUnlocked(r),
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
	)
	if fwd := forwardedClientIP(r); fwd != "" {
		l = l.With("fwd", fwd)
	}

	if r.URL.Path == "/robots.txt" || r.URL.Path == "/favicon.ico" {
		l = l.With("user_agent", r.Header.Get("user-agent"))
	}

	return l
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ── IP helpers ────────────────────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	peer := remoteIP(r)
	if peer == "" {
		return r.RemoteAddr
	}
	if !isTrustedProxy(peer) {
		return peer
	}
	fwd := forwardedClientIP(r)
	if fwd == "" || fwd == peer {
		return peer
	}
	if isLoopbackIP(peer) {
		return fwd
	}
	return fmt.Sprintf("%s via %s", fwd, peer)
}

func remoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}
	return r.RemoteAddr
}

func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := normalizeIP(strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])); ip != "" {
			return ip
		}
	}
	return normalizeIP(strings.TrimSpace(r.Header.Get("X-Real-IP")))
}

func isTrustedProxy(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast())
}

func isLoopbackIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

func normalizeIP(ip string) string {
	if p := net.ParseIP(ip); p != nil {
		return p.String()
	}
	return ""
}

// ── routing ───────────────────────────────────────────────────────────────────

func handle(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, nonce string) {
	if isCrossOrigin(r) {
		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		if ext != "" && ext != ".html" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	relPath := cleanRelPath(r.URL.Path)
	fullPath := filepath.Join(rootDir, relPath)

	if !isUnderRoot(fullPath) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		handleGET(reqLog, w, r, fullPath, relPath, nonce)
	case http.MethodPost:
		handlePOST(reqLog, w, r, fullPath, relPath)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func isCrossOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return true
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil || u.Host != r.Host {
			return true
		}
	}
	return false
}

func cleanRelPath(urlPath string) string {
	p := filepath.Clean(strings.TrimPrefix(urlPath, "/"))
	if p == "." {
		return ""
	}
	return p
}

func isUnderRoot(fullPath string) bool {
	rel, err := filepath.Rel(rootDir, fullPath)
	return err == nil && !strings.HasPrefix(rel, "..")
}

// ── GET/HEAD handler ──────────────────────────────────────────────────────────

func handleGET(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, fullPath, relPath, nonce string) {
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}
	if info.IsDir() {
		serveDir(reqLog, w, r, fullPath, relPath, nonce)
	} else {
		serveFile(reqLog, w, r, fullPath, info, relPath)
	}
}

func serveFile(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, fullPath string, info os.FileInfo, relPath string) {
	if !isUnlocked(r) && !isPublicPath(fullPath) {
		parentRel := filepath.ToSlash(filepath.Dir(relPath))
		if parentRel == "." {
			parentRel = ""
		}
		u := url.URL{Path: "/" + parentRel}
		target := u.EscapedPath()
		if target == "" {
			target = "/"
		}
		target += "?error=locked&wanted=" + url.QueryEscape(info.Name())
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(info.Name()))
	start := time.Now()
	tw := &transferLogWriter{ResponseWriter: w}
	http.ServeFile(tw, r, fullPath)
	dur := time.Since(start)

	reqLog.Info("download",
		"file", relPath,
		"duration", dur,
		"bytes", tw.bytes,
		"size", fmtBytes(tw.bytes),
		"rate", fmtTransferRate(tw.bytes, dur),
	)
}

// ── directory listing ─────────────────────────────────────────────────────────

type entry struct {
	Name     string
	IsDir    bool
	IsPublic bool
	Size     int64
	ModTime  time.Time
	URL      template.URL
}

func (e entry) SizeStr() string {
	if e.IsDir {
		if e.Size == 1 {
			return "1 item"
		}
		return fmt.Sprintf("%d items", e.Size)
	}
	return fmtBytes(e.Size)
}

func (e entry) ModTimeStr() string { return e.ModTime.Format("2006-01-02 15:04") }

func serveDir(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, fullPath, relPath, nonce string) {
	start := time.Now()
	w.Header().Set("Cache-Control", "no-store")

	csrf := csrfToken(w, r)
	q := r.URL.Query()

	sortBy := q.Get("sort")
	if sortBy == "" {
		sortBy = "name"
	}
	order := q.Get("order")
	if order == "" {
		order = "asc"
	}
	directorySortQuery := currentDirectorySortQuery(q)

	entries, err := readDir(fullPath, relPath)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}
	sortEntries(entries, sortBy, order)

	wantedFile := ""
	if q.Get("error") == "locked" {
		wantedFile = q.Get("wanted")
	}

	parentURL := template.URL("")
	if relPath != "" {
		parentRel := filepath.ToSlash(filepath.Dir(relPath))
		if parentRel == "." {
			parentRel = ""
		}
		u := url.URL{Path: "/" + parentRel}
		parentURL = template.URL(u.EscapedPath())
		if parentURL == "" {
			parentURL = "/"
		}
	}

	sortLink := func(col string) template.URL {
		o := "asc"
		if sortBy == col && order == "asc" {
			o = "desc"
		}
		uq := url.Values{}
		uq.Set("sort", col)
		uq.Set("order", o)
		return template.URL((&url.URL{Path: r.URL.Path, RawQuery: uq.Encode()}).String())
	}

	arrow := func(col string) string {
		if sortBy != col {
			return ""
		}
		if order == "asc" {
			return " ▲"
		}
		return " ▼"
	}

	directoryLink := func(rawURL template.URL) template.URL {
		if directorySortQuery == "" {
			return rawURL
		}
		u, err := url.Parse(string(rawURL))
		if err != nil {
			return rawURL
		}
		u.RawQuery = directorySortQuery
		return template.URL(u.String())
	}

	data := struct {
		Title         string
		DirLabel      string
		Crumbs        []crumb
		ParentURL     template.URL
		Entries       []entry
		Unlocked      bool
		IsPublic      bool
		WantedFile    string
		CSRFToken     string
		Nonce         string
		SortLink      func(string) template.URL
		DirectoryLink func(template.URL) template.URL
		Arrow         func(string) string
		UploadPath    string
		Header        template.HTML
		Footer        template.HTML
		RenderTime    time.Duration
	}{
		Title: "Index of /" + relPath,
		DirLabel: func() string {
			if relPath == "" {
				return "root"
			}
			return relPath
		}(),
		Crumbs:        buildCrumbs(relPath),
		ParentURL:     parentURL,
		Entries:       entries,
		Unlocked:      isUnlocked(r),
		IsPublic:      isPublicPath(fullPath),
		WantedFile:    wantedFile,
		CSRFToken:     csrf,
		Nonce:         nonce,
		SortLink:      sortLink,
		DirectoryLink: directoryLink,
		Arrow:         arrow,
		UploadPath:    (&url.URL{Path: "/" + relPath}).EscapedPath(),
		Header:        headerHTML,
		Footer:        footerHTML,
		RenderTime:    time.Since(start),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		reqLog.Error("render directory", "dir", relPath, "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	if r.Method == http.MethodHead {
		return
	}
	if _, err := body.WriteTo(w); err != nil {
		reqLog.Error("write directory", "dir", relPath, "err", err)
	}
}

func readDir(fullPath, relPath string) ([]entry, error) {
	des, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(des))
	for _, de := range des {
		if de.IsDir() && shouldHideListedDirectory(de.Name()) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		entryPath := filepath.Join(fullPath, de.Name())
		entRel := filepath.ToSlash(filepath.Join(relPath, de.Name()))

		var sz int64
		if de.IsDir() {
			sz = countDirItems(entryPath)
		} else {
			sz = info.Size()
		}

		out = append(out, entry{
			Name:     de.Name(),
			IsDir:    de.IsDir(),
			IsPublic: isPublicPath(entryPath),
			Size:     sz,
			ModTime:  info.ModTime(),
			URL:      template.URL((&url.URL{Path: "/" + entRel}).EscapedPath()),
		})
	}
	return out, nil
}

func currentDirectorySortQuery(q url.Values) string {
	uq := url.Values{}
	if _, ok := q["sort"]; ok {
		uq.Set("sort", q.Get("sort"))
	}
	if _, ok := q["order"]; ok {
		uq.Set("order", q.Get("order"))
	}
	return uq.Encode()
}

func countDirItems(path string) int64 {
	des, _ := os.ReadDir(path)
	var n int64
	for _, de := range des {
		if !(de.IsDir() && shouldHideListedDirectory(de.Name())) {
			n++
		}
	}
	return n
}

func shouldHideListedDirectory(name string) bool {
	return name == "#recycle" || name == "@eaDir"
}

func sortEntries(entries []entry, by, order string) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.IsDir != b.IsDir {
			return a.IsDir
		}
		var less bool
		switch by {
		case "size":
			less = a.Size < b.Size
		case "modified":
			less = a.ModTime.Before(b.ModTime)
		default:
			less = strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if order == "desc" {
			return !less
		}
		return less
	})
}

// ── breadcrumbs ───────────────────────────────────────────────────────────────

type crumb struct {
	Name      string
	URL       template.URL
	IsCurrent bool
}

func buildCrumbs(relPath string) []crumb {
	crumbs := []crumb{{Name: "root", URL: "/", IsCurrent: relPath == ""}}
	if relPath == "" {
		return crumbs
	}
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	acc := ""
	for i, p := range parts {
		if p == "" {
			continue
		}
		acc += "/" + p
		crumbs = append(crumbs, crumb{
			Name:      p,
			URL:       template.URL((&url.URL{Path: acc}).EscapedPath()),
			IsCurrent: i == len(parts)-1,
		})
	}
	return crumbs
}

// ── upload (POST) ─────────────────────────────────────────────────────────────

func handlePOST(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
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
		reqLog.Warn("upload rejected", "reason", "target is not a directory", "target", relPath)
		http.Error(w, "Upload target must be a directory", http.StatusBadRequest)
		return
	}
	if r.ContentLength > maxFileSize && r.ContentLength != -1 {
		reqLog.Warn("upload rejected", "reason", "content length exceeds max",
			"contentLength", r.ContentLength, "maxBytes", maxFileSize)
		http.Error(w, "Upload too large", http.StatusRequestEntityTooLarge)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if !validateCSRFHeader(r) {
		ok, handled := validateMultipartCSRF(reqLog, w, r, mr)
		if !ok {
			if !handled {
				reqLog.Warn("upload rejected", "reason", "invalid CSRF token")
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
			return
		}
	}

	savedCount, err := streamParts(reqLog, mr, fullPath)
	if err != nil {
		reqLog.Error("upload failed", "err", err)
		if errors.Is(err, errUploadBadRequest) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Upload failed", http.StatusInternalServerError)
		}
		return
	}
	if savedCount == 0 {
		reqLog.Warn("upload rejected", "reason", "no files")
		http.Error(w, "Bad request", http.StatusBadRequest)
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
	http.Redirect(w, r, "/"+filepath.ToSlash(relPath), http.StatusSeeOther)
}

func streamParts(reqLog *slog.Logger, mr *multipart.Reader, destDir string) (int, error) {
	topRemap := map[string]string{}
	var createdTopDirs []string
	var createdFiles []string
	savedCount := 0

	cleanup := func() {
		for i := len(createdFiles) - 1; i >= 0; i-- {
			_ = os.Remove(createdFiles[i])
		}
		for i := len(createdTopDirs) - 1; i >= 0; i-- {
			_ = os.RemoveAll(createdTopDirs[i])
		}
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return savedCount, nil
		}
		if err != nil {
			cleanup()
			return savedCount, fmt.Errorf("%w: reading multipart: %v", errUploadBadRequest, err)
		}

		rawName := partFilename(part)
		if rawName == "" {
			part.Close()
			continue
		}

		cleanRel := filepath.FromSlash(filepath.Clean("/" + filepath.ToSlash(rawName)))
		cleanRel = strings.TrimPrefix(cleanRel, string(filepath.Separator))
		segments := strings.SplitN(cleanRel, string(filepath.Separator), 2)
		topName := segments[0]
		isNested := len(segments) == 2

		var finalRel string
		if isNested {
			if _, ok := topRemap[topName]; !ok {
				actual, err := atomicMkdirUnique(filepath.Join(destDir, topName))
				if err != nil {
					part.Close()
					cleanup()
					return savedCount, fmt.Errorf("%w: mkdir %q: %v", errUploadFailed, filepath.Join(destDir, topName), err)
				}
				topRemap[topName] = filepath.Base(actual)
				createdTopDirs = append(createdTopDirs, actual)
			}
			finalRel = filepath.Join(topRemap[topName], segments[1])
		} else {
			finalRel = topName
		}

		destPath := filepath.Join(destDir, finalRel)
		if !isUnderRoot(destPath) {
			reqLog.Warn("upload skipped", "reason", "traversal", "file", rawName)
			part.Close()
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			part.Close()
			cleanup()
			return savedCount, fmt.Errorf("%w: mkdir %q: %v", errUploadFailed, filepath.Dir(destPath), err)
		}

		writtenPath, bytesWritten, dur, err := writeFileAtomic(part, destPath, !isNested)
		if err != nil {
			part.Close()
			cleanup()
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				return savedCount, fmt.Errorf("%w: write %q: %v", errUploadFailed, finalRel, err)
			}
			return savedCount, fmt.Errorf("%w: write %q: %v", errUploadBadRequest, finalRel, err)
		}

		createdFiles = append(createdFiles, writtenPath)

		writtenRel, err := filepath.Rel(rootDir, writtenPath)
		if err != nil {
			writtenRel = filepath.Base(writtenPath)
		}
		reqLog.Info("upload",
			"file", filepath.ToSlash(writtenRel),
			"duration", dur,
			"bytes", bytesWritten,
			"size", fmtBytes(bytesWritten),
			"rate", fmtTransferRate(bytesWritten, dur),
		)
		savedCount++
		part.Close()
	}
}

func partFilename(p *multipart.Part) string {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	return params["filename"]
}

func writeFileAtomic(r io.Reader, path string, uniqueNaming bool) (finalPath string, bytesWritten int64, duration time.Duration, err error) {
	var f *os.File
	finalPath = path

	if !uniqueNaming {
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	} else {
		dir, base := filepath.Split(path)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
		for i := 1; i < 1000 && errors.Is(err, os.ErrExist); i++ {
			finalPath = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
			f, err = os.OpenFile(finalPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
		}
	}
	if err != nil {
		return "", 0, 0, err
	}

	defer func() {
		f.Close()
		if err != nil {
			os.Remove(f.Name())
		}
	}()

	start := time.Now()
	bytesWritten, err = io.Copy(f, r)
	return f.Name(), bytesWritten, time.Since(start), err
}

func atomicMkdirUnique(path string) (string, error) {
	if err := os.Mkdir(path, 0755); err == nil {
		return path, nil
	}
	for i := 1; i < 1000; i++ {
		cand := fmt.Sprintf("%s (%d)", path, i)
		if err := os.Mkdir(cand, 0755); err == nil {
			return cand, nil
		}
	}
	return "", errors.New("mkdir collision")
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && len(c.Value) == 64 {
		return c.Value
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func validateCSRFHeader(r *http.Request) bool {
	c, err := r.Cookie(cookieCSRF)
	if err != nil || c.Value == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get(headerCSRF))
	return token != "" && token == c.Value
}

func validateCSRFValue(r *http.Request, token string) bool {
	c, err := r.Cookie(cookieCSRF)
	return err == nil && c.Value != "" && token != "" && token == c.Value
}

func validateMultipartCSRF(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request, mr *multipart.Reader) (ok bool, handled bool) {
	part, err := mr.NextPart()
	if err == io.EOF {
		reqLog.Warn("upload rejected", "reason", "missing csrf_token part")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false, true
	}
	if err != nil {
		reqLog.Warn("upload rejected", "reason", "invalid multipart before csrf", "err", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return false, true
	}
	if part.FormName() != "csrf_token" {
		reqLog.Warn("upload rejected", "reason", "first part is not csrf_token", "part", part.FormName())
		part.Close()
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false, true
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(part, 128))
	part.Close()
	if err != nil {
		reqLog.Warn("upload rejected", "reason", "could not read CSRF token", "err", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return false, true
	}
	return validateCSRFValue(r, string(tokenBytes)), false
}

// ── auth helpers ──────────────────────────────────────────────────────────────

func isUnlocked(r *http.Request) bool {
	c, err := r.Cookie(cookieUnlock)
	return err == nil && c.Value == "true"
}

func isPublicPath(fullPath string) bool {
	if strings.HasSuffix(fullPath, "/robots.txt") || strings.HasSuffix(fullPath, "/favicon.ico") {
		return true
	}
	rel, err := filepath.Rel(filepath.Join(rootDir, "public"), fullPath)
	return err == nil && !strings.HasPrefix(rel, "..")
}

// ── formatting helpers ────────────────────────────────────────────────────────

func fmtBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(1024), 0
	for n := b / 1024; n >= 1024; n /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func fmtTransferRate(bytes int64, duration time.Duration) string {
	if duration <= 0 {
		return "n/a"
	}
	if bytes <= 0 {
		return "0 B/s"
	}
	return fmt.Sprintf("%s/s", fmtBytesFloat(float64(bytes)/duration.Seconds()))
}

func fmtBytesFloat(b float64) string {
	if b < 1024 {
		return fmt.Sprintf("%.0f B", b)
	}
	div, exp := 1024.0, 0
	for n := b / 1024; n >= 1024 && exp < len("KMGTPE")-1; n /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %cB", b/div, "KMGTPE"[exp])
}

// ── response writer wrapper ───────────────────────────────────────────────────

type transferLogWriter struct {
	http.ResponseWriter
	bytes int64
}

func (w *transferLogWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *transferLogWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(w.ResponseWriter, r)
	w.bytes += n
	return n, err
}

func (w *transferLogWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ── template ──────────────────────────────────────────────────────────────────

var tmpl = template.Must(template.New("page").Parse(pageHTML))

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<title>{{.Title}}</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{
  font-family:ui-monospace,Menlo,monospace; font-size:14px; line-height:1.6;
  margin:0; padding:24px 32px; background:#fff; color:#1a1a1a; max-width:980px;
}
a{color:#0550ae; text-decoration:none}
a:hover{text-decoration:underline}
.bc{font-size:13px; color:#57606a; margin-bottom:14px}
.bc a{color:#57606a} .bc .sep{margin:0 3px; opacity:.5} .bc .cur{color:#1a1a1a; font-weight:600}
h1{font-size:15px; font-weight:700; margin:0 0 6px}
hr{border:none; border-top:1px solid #d0d7de; margin:0 0 14px}
.banner{ background:#fff8c5; border:1px solid #d4a72c; border-radius:4px; padding:10px 14px; margin-bottom:14px; font-size:13px; }
.banner-public{ background:#dafbe1; border-color:#2da44e; color:#1a7f37; font-weight:600; }
.banner-contributor{ background:#dafbe1; border-color:#2da44e; color:#1a7f37; }
table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
th, td { padding: 8px 12px 8px 0; border-bottom: 1px solid #eaeef2; vertical-align: top; text-align: left; }
th{ border-bottom:2px solid #d0d7de; font-weight:700; font-size:13px; white-space:nowrap; }
tr:hover td{background:#f6f8fa}
.col-name { overflow-wrap: break-word; word-break: break-word; }

/* Responsive Visibility Fixes */
.dir-tag-desktop { display: inline; color:#57606a; user-select:none; text-wrap: nowrap; }
.dir-tag-mobile  { display: none; }

@media (min-width: 651px) {
  table { table-layout: fixed; }
  .col-name { width: 60%; }
  .col-mod  { width: 160px; }
  .col-size { width: 100px; text-align: right; }
}

@media (max-width: 650px) {
  .col-mod { display: none; }
  .col-size { text-align: right; width: 80px; font-size: 12px; }
  .dir-tag-desktop { display: none; }
  .dir-tag-mobile  { display: inline; margin-right: 4px; }
}

.dir-link{ display:inline-flex; align-items:center; gap:4px; padding:2px 8px; margin-left:-8px; border-radius:999px; }
.dir-link-public { background: #dafbe1; }
.dir-link-public td { border-bottom-color: #bee7c9; }
.dir-link-public:hover td {
  background: #bee7c9 !important;

  font-weight: 600;
  text-decoration: none;
}
 
.public-row td:first-child {
  box-shadow: inset 4px 0 0 #2da44e;
  padding-left: 12px !important; /* Add some space so text doesn't touch the bar */
}

/* Optional: Make the public file links slightly different */
.public-row td a {
  font-weight: 500;
}

.upload{ border:1px solid #d0d7de; border-radius:6px; padding:14px 16px; background:#f6f8fa; margin-bottom: 24px; }
.btn{ padding:5px 14px; font:inherit; font-size:13px; border:1px solid; border-radius:6px; cursor:pointer; }
.btn-primary{ background:#1a7f37; color:#fff; border-color:#1a7f37; }
.btn-secondary{ background:#f6f8fa; color:#24292f; border-color:#d0d7de; }
.progress-wrapper { display: none; margin-top: 16px; background: #eaeef2; height: 18px; position: relative; border-radius: 4px; overflow: hidden; border:1px solid #d0d7de; }
.progress-bar { height: 100%; background: #0969da; width: 0%; transition: width 0.1s; }
.progress-bar.upload-error { background: #cf222e; }
.progress-text { position: absolute; width:100%; text-align:center; font-size:11px; line-height:16px; font-weight:700; mix-blend-mode:multiply; }
.progress-text.upload-error { color: #fff; mix-blend-mode: normal; }
footer{ margin-top:28px; padding-top:12px; border-top:1px solid #eaeef2; font-size:12px; color:#57606a; }
</style>
</head>
<body>
{{if .Header}}{{.Header}}{{end}}
<nav class="bc" id="top">
{{- range $i, $c := .Crumbs}}
  {{- if $i}}<span class="sep">/</span>{{end}}
  {{- if $c.IsCurrent}}<span class="cur">{{$c.Name}}</span>
  {{- else}}<a href="{{call $.DirectoryLink $c.URL}}">{{$c.Name}}</a>{{end}}
{{- end}}
</nav>
<h1>{{.Title}}</h1>
<hr>

{{if and .WantedFile (not .IsPublic)}}
<div class="banner"><strong>Downloads are locked.</strong> Upload a file to download <em>{{.WantedFile}}</em>.</div>
{{else if .IsPublic}}
<div class="banner banner-public">✧ Public directory — downloads always available.</div>
{{else if not .Unlocked}}
<div class="banner"><strong>Downloads are locked.</strong> Upload a file to unlock downloads.</div>
{{end}}

<div class="upload">
  <h2>Upload to /{{.DirLabel}}</h2>
  <form id="upload-form" method="post" enctype="multipart/form-data" action="{{.UploadPath}}">
    <input type="hidden" name="csrf_token" id="csrf_token" value="{{.CSRFToken}}">
    <div class="upload-row">
      <input type="file" name="uploadFiles" id="pick-files" multiple>
      <input type="file" name="uploadFiles" id="pick-folder" webkitdirectory directory style="display:none">
      <button type="button" class="btn btn-secondary" id="btn-folder">📂 Folder</button>
      <button type="submit" class="btn btn-primary" id="btn-submit">⬆ Upload</button>
    </div>
  </form>
  <div class="progress-wrapper" id="progress-wrapper">
    <div class="progress-text" id="progress-text">0%</div>
    <div class="progress-bar" id="progress-bar"></div>
  </div>
</div>

<table>
<thead>
  <tr>
    <th class="col-name"><a href="{{call .SortLink "name"}}">Name{{call .Arrow "name"}}</a></th>
    <th class="col-mod"><a href="{{call .SortLink "modified"}}">Modified{{call .Arrow "modified"}}</a></th>
    <th class="col-size"><a href="{{call .SortLink "size"}}">Size{{call .Arrow "size"}}</a></th>
  </tr>
</thead>
<tbody>
{{if .ParentURL}}<tr><td colspan="3"><a href="{{call .DirectoryLink .ParentURL}}">↑ Parent Directory</a></td></tr>{{end}}
{{range .Entries}}
<tr class="{{if .IsPublic}}public-row{{end}} {{if and .IsPublic .IsDir}}dir-link-public{{end}}">
  <td class="col-name">
    {{- if .IsDir}}
      <a href="{{call $.DirectoryLink .URL}}" class="dir-link">
        <span class="dir-tag-desktop">[DIR]</span>
        <span class="dir-tag-mobile">📂</span>
        <span>{{.Name}}/</span>
      </a>
    {{- else if or $.Unlocked .IsPublic}}
      <a href="{{.URL}}" download>{{.Name}}</a>
    {{- else}}<span style="color:#57606a">{{.Name}}</span>{{end}}
  </td>
  <td class="col-mod">{{.ModTimeStr}}</td>
  <td class="col-size">{{.SizeStr}}</td>
</tr>
{{end}}
</tbody>
</table>

{{if and .Unlocked (not .IsPublic)}}
<div class="banner banner-contributor"><strong>&#9786; Downloads are unlocked.&nbsp;</strong><span>Thank you for contributing.</span></div>
{{end}}

<p><a href="#top">[return to top]</a></p>
{{if .Footer}}{{.Footer}}{{end}}

<footer>Rendered in {{.RenderTime}}</footer>

<script nonce="{{.Nonce}}">
const form = document.getElementById('upload-form');
const fileInput = document.getElementById('pick-files');
const folderInput = document.getElementById('pick-folder');
const submitBtn = document.getElementById('btn-submit');
const folderBtn = document.getElementById('btn-folder');
const progressWrapper = document.getElementById('progress-wrapper');
const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');

// Fixed: Externalized onclick handler to satisfy CSP
folderBtn.addEventListener('click', () => folderInput.click());

function setUploadControlsDisabled(disabled) {
  submitBtn.disabled = disabled;
  folderBtn.disabled = disabled;
  fileInput.disabled = disabled;
  folderInput.disabled = disabled;
}

function resetUploadProgress() {
  progressBar.classList.remove('upload-error');
  progressText.classList.remove('upload-error');
  progressBar.style.width = '0%';
  progressText.innerText = '0%';
}

function showUploadError(message) {
  setUploadControlsDisabled(false);
  progressWrapper.style.display = 'block';
  progressBar.classList.add('upload-error');
  progressText.classList.add('upload-error');
  progressBar.style.width = '100%';
  progressText.innerText = message;
}

function getUploadErrorMessage(xhr) {
  const contentType = (xhr.getResponseHeader('Content-Type') || '').toLowerCase();
  if (contentType.startsWith('text/plain')) {
    const text = (xhr.responseText || '').trim().replace(/\s+/g, ' ');
    if (text) return text;
  }
  if (xhr.status === 400) return 'Upload failed (bad request)';
  if (xhr.status === 403) return 'Upload rejected';
  if (xhr.status === 408 || xhr.status === 504) return 'Upload timed out';
  if (xhr.status === 413) return 'Upload too large';
  if (xhr.status) return 'Upload failed (HTTP ' + xhr.status + ')';
  return 'Upload failed';
}

async function performUpload(files, paths = []) {
  if (!files || files.length === 0) return;
  setUploadControlsDisabled(true);
  resetUploadProgress();
  progressWrapper.style.display = 'block';

  const formData = new FormData();
  const csrfToken = document.getElementById('csrf_token').value;
  formData.append('csrf_token', csrfToken);
  for (let i = 0; i < files.length; i++) {
    const path = paths[i] || files[i].webkitRelativePath || files[i].name;
    formData.append('uploadFiles', files[i], path);
  }

  const xhr = new XMLHttpRequest();
  xhr.open('POST', form.action, true);
  xhr.setRequestHeader('X-CSRF-Token', csrfToken);
  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const p = Math.round((e.loaded / e.total) * 100);
      progressBar.style.width = p + '%';
      progressText.innerText = p + '%';
    }
  };
  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 300) {
      window.location.reload();
      return;
    }
    showUploadError(getUploadErrorMessage(xhr));
  };
  xhr.onerror = () => {
    if (files === fileInput.files || files === folderInput.files) {
      retryWithStandardSubmit(files === folderInput.files ? 'folder' : 'files');
      return;
    }
    showUploadError('Upload failed');
  };
  xhr.onabort = () => showUploadError('Upload canceled');
  xhr.send(formData);
}

function retryWithStandardSubmit(source) {
  const activeInput = source === 'folder' ? folderInput : fileInput;
  const inactiveInput = source === 'folder' ? fileInput : folderInput;
  if (!activeInput.files || activeInput.files.length === 0) {
    showUploadError('Upload failed');
    return;
  }
  setUploadControlsDisabled(false);
  inactiveInput.value = '';
  progressWrapper.style.display = 'block';
  progressBar.classList.remove('upload-error');
  progressText.classList.remove('upload-error');
  progressBar.style.width = '100%';
  progressText.innerText = 'Retrying...';
  HTMLFormElement.prototype.submit.call(form);
}

form.addEventListener('submit', (e) => { e.preventDefault(); performUpload(fileInput.files); });
folderInput.addEventListener('change', () => performUpload(folderInput.files));

document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', async (e) => {
  e.preventDefault();
  const items = e.dataTransfer.items;
  if (!items) return;
  const files = [], paths = [];
  const readAllEntries = async (reader) => {
    const entries = [];
    while (true) {
      const batch = await new Promise(res => reader.readEntries(res));
      if (!batch.length) return entries;
      entries.push(...batch);
    }
  };
  const traverse = async (item, path = "") => {
    if (item.isFile) {
      const f = await new Promise(res => item.file(res));
      files.push(f); paths.push(path + f.name);
    } else if (item.isDirectory) {
      const r = item.createReader();
      const entries = await readAllEntries(r);
      for (const ent of entries) await traverse(ent, path + item.name + "/");
    }
  };
  for (const it of items) { const ent = it.webkitGetAsEntry(); if (ent) await traverse(ent); }
  performUpload(files, paths);
});
</script>
</body>
</html>`
