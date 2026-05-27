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

	"sftpguy/internal/explorerevents"
	"sftpguy/internal/socketactivation"

	"golang.org/x/time/rate"
)

// ── constants ─────────────────────────────────────────────────────────────────

//go:embed main.go
var appSrc string

const (
	cookieUnlock                = "explorer_unlocked"
	cookieCSRF                  = "explorer_csrf"
	cookieSession               = "explorer-_session"
	headerCSRF                  = "X-CSRF-Token"
	defaultShadowBanBytesPerSec = 2 * 1024
	explorerShadowMutateMin     = 2 * time.Second
	explorerShadowMutateMax     = 8 * time.Second
	explorerShadowListMin       = 500 * time.Millisecond
	explorerShadowListMax       = 2 * time.Second
)

// ── globals ───────────────────────────────────────────────────────────────────

var (
	rootDir             string
	maxFileSize         int64
	headerFragment      = &htmlFragmentSource{name: "header"}
	footerFragment      = &htmlFragmentSource{name: "footer"}
	logger              = newLogger(os.Stderr)
	eventClient         *explorerevents.Client
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
			if a.Value.Kind() == slog.KindString && (a.Value.String() == "" || a.Value.String() == "\"\"") {
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
func watchSIGHUP(lf *rotationAwareLogWriter) (stop func()) {
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
	return func() {
		signal.Stop(ch)
		close(ch)
	}
}

// initLogger wires the global logger to both stdout and the given log file,
// and installs a SIGHUP handler for log rotation. It returns the log file
// writer so the caller can close it on shutdown.
func initLogger(logPath string) (*rotationAwareLogWriter, func(), error) {
	lf, err := newRotationAwareLogWriter(logPath)
	if err != nil {
		return nil, func() {}, err
	}
	logger = newLogger(io.MultiWriter(os.Stdout, lf))
	stop := watchSIGHUP(lf)
	return lf, stop, nil
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	var logPath, port, headerPath, footerPath, eventsSocket string
	var maxSizeMB int64
	var requireSystemdSocket bool

	flag.StringVar(&rootDir, "dir", "./shared", "Directory to serve")
	flag.StringVar(&port, "port", "8080", "Port to listen on")
	flag.Int64Var(&maxSizeMB, "maxsize", 1000, "Max upload size in MB; 0 means unlimited")
	flag.StringVar(&logPath, "log", "explorer.log", "Log file path")
	flag.StringVar(&eventsSocket, "events", "", "Unix RPC socket path for sending events and checking IP policy with sftpguy")
	flag.BoolVar(&requireSystemdSocket, "systemd.socket", false, "Require inherited systemd socket instead of binding -port")
	flag.StringVar(&headerPath, "header", "header.html", "Path to an HTML template fragment to inject at the top of directory pages; read per request")
	flag.StringVar(&footerPath, "footer", "footer.html", "Path to an HTML template fragment to inject at the bottom of directory pages; read per request")
	src := flag.Bool("src", false, "Print this program's source and exit")
	flag.Parse()

	if *src {
		fmt.Println(appSrc)
		os.Exit(0)
	}
	if maxSizeMB < 0 {
		fatalLog("invalid maxsize", "maxUploadMB", maxSizeMB)
	}

	maxFileSize = maxSizeMB << 20

	headerFragment = &htmlFragmentSource{name: "header", path: headerPath}
	footerFragment = &htmlFragmentSource{name: "footer", path: footerPath}

	start := time.Now()
	lf, stop, err := initLogger(logPath)
	if err != nil {
		fatalLog("open log", "err", err)
	}
	defer func() {
		logger.Info("Logger closing", "uptime", time.Since(start))
		eventClient.Close(2 * time.Second)
		stop()
		lf.Close()
	}()
	eventClient = explorerevents.NewClient(eventsSocket, logger)

	policy, err := eventClient.CheckIP(context.Background(), "188.166.211.175")
	logger.Info("checking ip blacklist", "policy", policy, "error", err)

	policy, err = eventClient.CheckIP(context.Background(), "127.0.0.1")
	logger.Info("checking ip whitelist", "policy", policy, "error", err)

	abs, err := filepath.Abs(rootDir)
	if err != nil {
		fatalLog("resolve root", "err", err)
	}
	rootDir = abs

	if err := os.MkdirAll(rootDir, 0755); err != nil {
		fatalLog("create root", "path", rootDir, "err", err)
	}

	addr := ":" + port
	listener, inherited, err := explorerListener(addr, requireSystemdSocket)
	if err != nil {
		fatalLog("listen http", "addr", addr, "err", err)
	}
	logger.Info("serving explorer", "dir", rootDir, "addr", listener.Addr().String(), "maxUploadMB", maxSizeMB, "systemd_socket", inherited, "events_socket", eventsSocket)
	server := &http.Server{
		Addr:     listener.Addr().String(),
		Handler:  http.HandlerFunc(rootHandler),
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	// Run server in background so we can wait for a signal.
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Wait for SIGINT/SIGTERM or a fatal server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig, err := waitForShutdown(serverErr, quit, signal.Stop)
	if err != nil {
		fatalLog("serve http", "addr", addr, "err", err)
	}
	logger.Info("shutting down", "signal", sig)

	// Give in-flight requests up to 60 s to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fatalLog("shutdown", "err", err)
	}
	logger.Info("shutdown complete")
}

func waitForShutdown(serverErr <-chan error, quit chan os.Signal, stopSignal func(chan<- os.Signal)) (os.Signal, error) {
	select {
	case err := <-serverErr:
		return nil, err
	case sig := <-quit:
		stopSignal(quit)
		return sig, nil
	}
}

func explorerListener(addr string, requireSystemdSocket bool) (net.Listener, bool, error) {
	if l, ok, err := socketactivation.ListenerByNameOrNetwork("explorer", "tcp", "tcp4", "tcp6"); err != nil {
		return nil, false, err
	} else if ok {
		return l, true, nil
	}
	if requireSystemdSocket {
		return nil, false, fmt.Errorf("systemd socket activation required but socket %q was not inherited", "explorer")
	}
	l, err := net.Listen("tcp", addr)
	return l, false, err
}

// ── middleware & routing ──────────────────────────────────────────────────────

type statusRecorder struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

type explorerRequestIDKey struct{}

func (sr *statusRecorder) WriteHeader(code int) {
	if sr.wroteHeader {
		return
	}

	sr.status = code
	sr.wroteHeader = true
	sr.ResponseWriter.WriteHeader(code)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	nonce := generateNonce()
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s';", nonce))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Accept-CH", "Sec-CH-UA-Model, Sec-CH-UA-Form-Factors, Downlink, ECT, RTT, Sec-CH-Device-Memory, Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version")

	session := SessionCookie(w, r)
	requestID := emitRequestStartEvent(r)
	if requestID != "" {
		r = r.WithContext(context.WithValue(r.Context(), explorerRequestIDKey{}, requestID))
	}

	sr := &statusRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
	}

	reqLog := requestLogger(logger, r).With("session", session)

	handle(reqLog, sr, r, nonce)
	duration := time.Since(start)
	reqLog.Info("request",
		"status", sr.status,
		"duration", duration)
	emitRequestFinishEvent(requestID, r, sr.status, duration)
}

func SessionCookie(w http.ResponseWriter, r *http.Request) string {
	sessionCookie, err := r.Cookie(cookieSession)
	if err != nil {
		sessionCookie = &http.Cookie{
			Name:     cookieSession,
			Value:    generateSessionID(),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, sessionCookie)
		r.AddCookie(sessionCookie)
	}
	return sessionCookie.Value
}

func requestSession(r *http.Request) string {
	if r == nil {
		return ""
	}
	sessionCookie, err := r.Cookie(cookieSession)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(sessionCookie.Value)
}

func requestLogger(base *slog.Logger, r *http.Request) *slog.Logger {
	ip := clientIP(r)
	l := base.With(
		"ip", ip,
		"unlocked", isUnlocked(r),
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"referer", r.Referer(),
	)

	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" && fwd != ip {
		l = l.With("fwd", fwd)
	}

	if r.URL.Path == "/robots.txt" || r.URL.Path == "/favicon.ico" || r.Method == "POST" {
		//l = l.With("user_agent", r.Header.Get("user-agent"))
		l = l.With(clientLogGroup(r))
	}

	if r.URL.Query().Has("please") {
		l = l.With("plz", true)
	}

	return l
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionID() string {
	return fmt.Sprintf("explorer-%s", generateNonce())
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

func clientIdentityIP(r *http.Request) string {
	peer := remoteIP(r)
	if peer == "" {
		return ""
	}
	if !isTrustedProxy(peer) {
		return normalizeIP(peer)
	}
	if fwd := forwardedClientIP(r); fwd != "" {
		return fwd
	}
	return normalizeIP(peer)
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

func getIPPolicy(ctx context.Context, ip string) *explorerevents.IPPolicyResponse {
	if eventClient == nil {
		return nil
	}

	// Fast timeout so checking the policy never hangs the explorer application
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	policy, err := eventClient.CheckIP(ctx, ip)
	if err != nil {
		logger.Debug("failed to check IP policy", "ip", ip, "err", err)
		return nil
	}
	return policy
}

func isBannedByPolicy(policy *explorerevents.IPPolicyResponse) bool {
	return policy != nil && policy.EffectiveBanned
}

func randomExplorerShadowDelay(minDelay, maxDelay time.Duration) time.Duration {
	if maxDelay <= minDelay {
		return minDelay
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return minDelay
	}
	span := maxDelay - minDelay
	return minDelay + time.Duration((uint64(span)*uint64(b[0]))/255)
}

func delayBannedDirectoryListing(reqLog *slog.Logger, r *http.Request) {
	ip := clientIdentityIP(r)
	policy := getIPPolicy(r.Context(), ip)
	if !isBannedByPolicy(policy) {
		return
	}
	delay := randomExplorerShadowDelay(explorerShadowListMin, explorerShadowListMax)
	reqLog.Info("directory listing delayed", "ip", ip, "delay", delay)
	time.Sleep(delay)
}

func rejectBannedUpload(reqLog *slog.Logger, w http.ResponseWriter, r *http.Request) bool {
	ip := clientIdentityIP(r)
	policy := getIPPolicy(r.Context(), ip)
	if policy == nil || policy.UploadAllowed {
		return false
	}
	delay := randomExplorerShadowDelay(explorerShadowMutateMin, explorerShadowMutateMax)
	reqLog.Warn("upload rejected", "reason", "ip policy", "ip", ip, "delay", delay)
	time.Sleep(delay)
	http.Error(w, "Upload failed", http.StatusInternalServerError)
	return true
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
		delayBannedDirectoryListing(reqLog, r)
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

	ip := clientIdentityIP(r)
	policy := getIPPolicy(r.Context(), ip)

	var limiter *rate.Limiter
	if policy != nil && policy.EffectiveBanned {
		rateLimit := policy.ThrottleBytesPerSec
		if rateLimit <= 0 {
			rateLimit = defaultShadowBanBytesPerSec
		}
		limiter = rate.NewLimiter(rate.Limit(rateLimit), rateLimit)
		reqLog.Info("download throttled", "ip", ip, "rateLimit", rateLimit)
	}

	var reporter *explorerTransferReporter
	if r.Method == http.MethodGet {
		reporter = newExplorerTransferReporter(explorerevents.KindDownload, r, relPath, info.Size(), 0)
		reporter.Start()
	}
	tw := &transferLogWriter{
		ResponseWriter: w,
		limiter:        limiter,
		ctx:            r.Context(),
	}
	if reporter != nil {
		tw.progress = reporter.Progress
	}

	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(info.Name()))
	start := time.Now()

	http.ServeFile(tw, r, fullPath)
	dur := time.Since(start)

	reqLog.Info("download",
		"file", relPath,
		"duration", dur,
		"bytes", tw.bytes,
		"size", fmtBytes(tw.bytes),
		"rate", fmtTransferRate(tw.bytes, dur),
		clientLogGroup(r),
	)
	if r.Method == http.MethodGet {
		reporter.Finish(tw.bytes, dur)
	}

}

func clientLogGroup(r *http.Request) slog.Attr {
	return slog.Group("client",
		"user_agent", r.Header.Get("user-agent"),
		"mobile", r.Header.Get("Sec-CH-UA-Mobile"), // ?0 for false, ?1 for true
		"downlink", r.Header.Get("Downlink"), // downlink rate in Mbps, rounded to the nearest 25 kilobits.
		"ect", r.Header.Get("ECT"), // effective connection type, e.g. 4g
		"rtt", r.Header.Get("RTT"), // approximate round trip time in milliseconds, rounded to the nearest 25 milliseconds.
		"model", r.Header.Get("Sec-CH-UA-Model"), // e.g. "Pixel 3 XL"
		"platform", r.Header.Get("Sec-CH-UA-Platform"), // e.g. macOS, Android
		"version", r.Header.Get("Sec-CH-UA-Platform-Version"), // e.g. "11.0.0". The version string on Linux is always empty.
		"form_factors", r.Header.Get("Sec-CH-UA-Form-Factors"), // e.g. Desktop, Mobile, Automotive
		"memory", r.Header.Get("Sec-CH-Device-Memory"), // approximate amount of available RAM on the client device, in gigabytes
		"arch", r.Header.Get("Sec-CH-UA-Arch"), // e.g. arm
	)
}

func newExplorerEventID(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "evt"
	}
	return prefix + "-" + generateNonce()
}

func emitTransferEvent(kind string, r *http.Request, relPath string, bytes, size, delta int64, duration time.Duration) {
	if eventClient == nil || r == nil {
		return
	}
	eventClient.Emit(transferEvent(kind, r, relPath, bytes, size, delta, duration))
}

func transferEvent(kind string, r *http.Request, relPath string, bytes, size, delta int64, duration time.Duration) explorerevents.Event {
	return transferEventWithPhase("", "", kind, r, relPath, bytes, size, delta, duration)
}

func transferEventWithPhase(id, phase, kind string, r *http.Request, relPath string, bytes, size, delta int64, duration time.Duration) explorerevents.Event {
	return explorerevents.Event{
		ID:             id,
		Kind:           kind,
		Phase:          phase,
		ClientIP:       clientIdentityIP(r),
		RemoteAddr:     r.RemoteAddr,
		Session:        requestSession(r),
		Path:           filepath.ToSlash(relPath),
		Bytes:          bytes,
		Size:           size,
		Delta:          delta,
		DurationMS:     durationMillis(duration),
		AvgBytesPerSec: avgBytesPerSecond(bytes, duration),
		Method:         r.Method,
		URLPath:        r.URL.Path,
		Query:          r.URL.RawQuery,
		Meta: map[string]any{
			"file":       filepath.ToSlash(relPath),
			"filename":   filepath.Base(relPath),
			"user_agent": r.Header.Get("user-agent"),
			"headers":    requestHeaders(r),
		},
	}
}

type explorerTransferReporter struct {
	id       string
	kind     string
	r        *http.Request
	relPath  string
	size     int64
	delta    int64
	started  time.Time
	lastEmit time.Time
}

func newExplorerTransferReporter(kind string, r *http.Request, relPath string, size, delta int64) *explorerTransferReporter {
	if eventClient == nil || r == nil {
		return nil
	}
	now := time.Now()
	id := explorerRequestID(r)
	if id == "" {
		id = newExplorerEventID("xfer")
	}
	return &explorerTransferReporter{
		id:       id,
		kind:     kind,
		r:        r,
		relPath:  relPath,
		size:     size,
		delta:    delta,
		started:  now,
		lastEmit: now,
	}
}

func explorerRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(explorerRequestIDKey{}).(string)
	return strings.TrimSpace(id)
}

func (r *explorerTransferReporter) Start() {
	if r == nil || eventClient == nil {
		return
	}
	eventClient.Emit(transferEventWithPhase(r.id, explorerevents.PhaseStart, r.kind, r.r, r.relPath, 0, r.size, r.delta, 0))
}

func (r *explorerTransferReporter) Progress(bytes int64) {
	if r == nil || eventClient == nil || bytes <= 0 {
		return
	}
	now := time.Now()
	if now.Sub(r.lastEmit) < time.Second {
		return
	}
	r.lastEmit = now
	eventClient.Emit(transferEventWithPhase(r.id, explorerevents.PhaseProgress, r.kind, r.r, r.relPath, bytes, r.size, r.delta, now.Sub(r.started)))
}

func (r *explorerTransferReporter) Finish(bytes int64, duration time.Duration) {
	if r == nil || eventClient == nil {
		return
	}
	eventClient.Emit(transferEventWithPhase(r.id, explorerevents.PhaseFinish, r.kind, r.r, r.relPath, bytes, r.size, r.delta, duration))
}

func emitRequestStartEvent(r *http.Request) string {
	if eventClient == nil || r == nil {
		return ""
	}
	id := newExplorerEventID("req")
	eventClient.Emit(requestEventWithPhase(id, explorerevents.PhaseStart, r, 0, 0))
	return id
}

func emitRequestFinishEvent(id string, r *http.Request, status int, duration time.Duration) {
	if eventClient == nil || r == nil {
		return
	}
	if id == "" {
		id = newExplorerEventID("req")
	}
	eventClient.Emit(requestEventWithPhase(id, explorerevents.PhaseFinish, r, status, duration))
}

func emitRequestEvent(r *http.Request, status int, duration time.Duration) {
	if eventClient == nil || r == nil {
		return
	}
	eventClient.Emit(requestEvent(r, status, duration))
}

func requestEvent(r *http.Request, status int, duration time.Duration) explorerevents.Event {
	return requestEventWithPhase("", "", r, status, duration)
}

func requestEventWithPhase(id, phase string, r *http.Request, status int, duration time.Duration) explorerevents.Event {
	return explorerevents.Event{
		ID:         id,
		Kind:       explorerevents.KindRequest,
		Phase:      phase,
		ClientIP:   clientIdentityIP(r),
		RemoteAddr: r.RemoteAddr,
		Session:    requestSession(r),
		Status:     status,
		Method:     r.Method,
		URLPath:    r.URL.Path,
		Query:      r.URL.RawQuery,
		DurationMS: durationMillis(duration),
		Level:      "info",
		Message:    "request",
		Meta: map[string]any{
			"unlocked":   isUnlocked(r),
			"referer":    r.Referer(),
			"user_agent": r.Header.Get("user-agent"),
			"headers":    requestHeaders(r),
		},
	}
}

func requestHeaders(r *http.Request) map[string][]string {
	if r == nil || len(r.Header) == 0 {
		return nil
	}
	headers := make(map[string][]string, len(r.Header))
	for name, values := range r.Header {
		copied := make([]string, len(values))
		copy(copied, values)
		headers[name] = copied
	}
	return headers
}

func avgBytesPerSecond(bytes int64, duration time.Duration) int64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return int64(float64(bytes) / duration.Seconds())
}

func durationMillis(duration time.Duration) float64 {
	if duration <= 0 {
		return 0
	}
	ms := float64(duration) / float64(time.Millisecond)
	if ms < 1 {
		return ms
	}
	return float64(duration.Milliseconds())
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
		RenderTime:    time.Since(start),
	}

	data.Header = headerFragment.Render(data, reqLog)
	data.Footer = footerFragment.Render(data, reqLog)

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

func readHTMLFragmentTemplate(name, path string) (*template.Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", name, err)
	}
	return parseHTMLFragmentTemplate(name, string(b))
}

func parseHTMLFragmentTemplate(name, text string) (*template.Template, error) {
	t, err := template.New(name).Parse(text)
	if err != nil {
		return nil, fmt.Errorf("parse %s template: %w", name, err)
	}
	return t, nil
}

type htmlFragmentSource struct {
	name    string
	path    string
	mu      sync.Mutex
	failing bool
}

func (s *htmlFragmentSource) Render(data any, log *slog.Logger) template.HTML {
	if s == nil || s.path == "" {
		return ""
	}

	t, err := readHTMLFragmentTemplate(s.name, s.path)
	if err != nil {
		s.recordFailure(log, err)
		return ""
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		s.recordFailure(log, fmt.Errorf("execute %s template: %w", s.name, err))
		return ""
	}
	s.recordSuccess()
	return template.HTML(body.String())
}

func (s *htmlFragmentSource) recordFailure(log *slog.Logger, err error) {
	s.mu.Lock()
	shouldLog := !s.failing
	s.failing = true
	s.mu.Unlock()

	if !shouldLog {
		return
	}
	if log == nil {
		log = logger
	}
	log.Warn("optional template fragment unavailable",
		"fragment", s.name,
		"fragment_path", s.path,
		"err", err)
}

func (s *htmlFragmentSource) recordSuccess() {
	s.mu.Lock()
	s.failing = false
	s.mu.Unlock()
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
	if rejectBannedUpload(reqLog, w, r) {
		return
	}
	if maxFileSize > 0 && r.ContentLength > maxFileSize && r.ContentLength != -1 {
		reqLog.Warn("upload rejected", "reason", "content length exceeds max",
			"contentLength", r.ContentLength, "maxBytes", maxFileSize)
		http.Error(w, "Upload too large", http.StatusRequestEntityTooLarge)
		return
	}

	if maxFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	}
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

	reqLog = reqLog.With(clientLogGroup(r))
	savedCount, uploads, err := streamParts(reqLog, mr, fullPath)
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
	for _, upload := range uploads {
		emitTransferEvent(explorerevents.KindUpload, r, upload.relPath, upload.bytes, upload.size, upload.delta, upload.duration)
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

type uploadRecord struct {
	relPath  string
	bytes    int64
	size     int64
	delta    int64
	duration time.Duration
}

func streamParts(reqLog *slog.Logger, mr *multipart.Reader, destDir string) (int, []uploadRecord, error) {
	topRemap := map[string]string{}
	var createdTopDirs []string
	var createdFiles []string
	var uploads []uploadRecord
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
			return savedCount, uploads, nil
		}
		if err != nil {
			cleanup()
			return savedCount, nil, fmt.Errorf("%w: reading multipart: %v", errUploadBadRequest, err)
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
					return savedCount, nil, fmt.Errorf("%w: mkdir %q: %v", errUploadFailed, filepath.Join(destDir, topName), err)
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
			return savedCount, nil, fmt.Errorf("%w: mkdir %q: %v", errUploadFailed, filepath.Dir(destPath), err)
		}

		writtenPath, bytesWritten, size, delta, dur, err := writeFileAtomic(part, destPath, !isNested)
		if err != nil {
			part.Close()
			cleanup()
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				return savedCount, nil, fmt.Errorf("%w: write %q: %v", errUploadFailed, finalRel, err)
			}
			return savedCount, nil, fmt.Errorf("%w: write %q: %v", errUploadBadRequest, finalRel, err)
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
		uploads = append(uploads, uploadRecord{
			relPath:  filepath.ToSlash(writtenRel),
			bytes:    bytesWritten,
			size:     size,
			delta:    delta,
			duration: dur,
		})
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

func writeFileAtomic(r io.Reader, path string, uniqueNaming bool) (finalPath string, bytesWritten, size, delta int64, duration time.Duration, err error) {
	var f *os.File
	finalPath = path
	oldSize := int64(0)

	if !uniqueNaming {
		if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().IsRegular() {
			oldSize = fi.Size()
		}
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
		return "", 0, 0, 0, 0, err
	}

	defer func() {
		f.Close()
		if err != nil {
			os.Remove(f.Name())
		}
	}()

	start := time.Now()
	bytesWritten, err = io.Copy(f, r)
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	delta = size - oldSize
	if delta < 0 {
		delta = 0
	}
	return f.Name(), bytesWritten, size, delta, time.Since(start), err
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
	if r.URL.Query().Has("please") {
		return true
	}

	c, err := r.Cookie(cookieUnlock)
	return err == nil && c.Value == "true"
}

func isPublicPath(fullPath string) bool {
	if fullPath == filepath.Join(rootDir, "robots.txt") || fullPath == filepath.Join(rootDir, "favicon.ico") {
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
	bytes    int64
	limiter  *rate.Limiter
	ctx      context.Context // Needed for limiter.WaitN
	progress func(int64)
}

func (w *transferLogWriter) Write(p []byte) (int, error) {
	if w.limiter == nil {
		n, err := w.ResponseWriter.Write(p)
		w.bytes += int64(n)
		w.reportProgress()
		return n, err
	}

	var total int
	burst := w.limiter.Burst()

	for len(p) > 0 {
		writeSize := len(p)
		if writeSize > burst {
			writeSize = burst
		}

		// Wait for enough tokens to write this chunk.
		// If the client disconnects, ctx is canceled and WaitN returns an error.
		if err := w.limiter.WaitN(w.ctx, writeSize); err != nil {
			return total, err
		}

		n, err := w.ResponseWriter.Write(p[:writeSize])
		total += n
		w.bytes += int64(n)
		w.reportProgress()
		if err != nil {
			return total, err
		}

		p = p[writeSize:]
	}

	return total, nil
}

func (w *transferLogWriter) reportProgress() {
	if w != nil && w.progress != nil {
		w.progress(w.bytes)
	}
}

func (w *transferLogWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.limiter == nil {
		return io.Copy(struct{ io.Writer }{w}, r)
	}
	return io.Copy(struct{ io.Writer }{w}, r)
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
let uploadWakeLock = null;
let uploadWakeLockWanted = false;
let uploadWakeLockPending = false;

// Fixed: Externalized onclick handler to satisfy CSP
folderBtn.addEventListener('click', () => folderInput.click());

async function requestUploadWakeLock() {
  if (!('wakeLock' in navigator) || !navigator.wakeLock || document.visibilityState !== 'visible' || uploadWakeLock || uploadWakeLockPending) {
    return;
  }
  uploadWakeLockPending = true;
  try {
    const lock = await navigator.wakeLock.request('screen');
    uploadWakeLock = lock;
    lock.addEventListener('release', () => {
      if (uploadWakeLock === lock) uploadWakeLock = null;
      if (uploadWakeLockWanted && document.visibilityState === 'visible') requestUploadWakeLock();
    }, { once: true });
  } catch (_err) {
    uploadWakeLock = null;
  } finally {
    uploadWakeLockPending = false;
  }
}

function keepScreenAwakeForUpload() {
  uploadWakeLockWanted = true;
  requestUploadWakeLock();
}

function releaseUploadWakeLock() {
  uploadWakeLockWanted = false;
  const lock = uploadWakeLock;
  uploadWakeLock = null;
  if (lock) lock.release().catch(() => {});
}

document.addEventListener('visibilitychange', () => {
  if (uploadWakeLockWanted && document.visibilityState === 'visible') requestUploadWakeLock();
});

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
  releaseUploadWakeLock();
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
  keepScreenAwakeForUpload();
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
      releaseUploadWakeLock();
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
