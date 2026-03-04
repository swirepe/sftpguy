package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	explorerIdentityPrefix = "explorer-auth:"
	explorerSessionPrefix  = "explorer:"
)

var errExplorerUploadTooLarge = errors.New("upload exceeds configured max size")

type explorerService struct {
	srv         *Server
	rootDir     string
	maxFileSize int64
	logger      *slog.Logger

	cookieIdentity string
	cookieCSRF     string
	signingKey     []byte
}

type explorerIdentity struct {
	Raw       string
	PubHash   string
	SessionID string
}

type explorerEntry struct {
	Name         string
	IsDir        bool
	Size         int64
	ModTime      time.Time
	URL          template.URL
	Downloadable bool
}

func (e explorerEntry) SizeStr() string {
	if e.IsDir {
		if e.Size == 1 {
			return "1 item"
		}
		return fmt.Sprintf("%d items", e.Size)
	}
	return formatBytes(e.Size)
}

func (e explorerEntry) ModTimeStr() string {
	return e.ModTime.Format("2006-01-02 15:04")
}

type explorerCrumb struct {
	Name      string
	URL       template.URL
	IsCurrent bool
}

func newExplorerService(s *Server) (*explorerService, error) {
	if s == nil {
		return nil, errors.New("nil server")
	}

	idCookie, csrfCookie := explorerCookieNames(s.cfg)
	abRoot := s.absUploadDir
	if strings.TrimSpace(abRoot) == "" {
		return nil, errors.New("missing upload root")
	}

	e := &explorerService{
		srv:            s,
		rootDir:        abRoot,
		maxFileSize:    s.cfg.ExplorerMaxFileSize,
		logger:         s.logger.WithGroup("explorer"),
		cookieIdentity: idCookie,
		cookieCSRF:     csrfCookie,
		signingKey:     explorerSigningKey(s.cfg.ExplorerCookieSecret),
	}
	return e, nil
}

func explorerCookiePrefix(cfg Config) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(cfg.Name))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strconv.Itoa(cfg.Port)))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(cfg.UploadDir))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(cfg.ExplorerHTTP))
	return fmt.Sprintf("%x", h.Sum64())[:10]
}

func explorerCookieNames(cfg Config) (identityCookie, csrfCookie string) {
	prefix := explorerCookiePrefix(cfg)
	return "sftpguy_exp_" + prefix + "_id", "sftpguy_exp_" + prefix + "_csrf"
}

func explorerSigningKey(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret != "" {
		sum := sha256.Sum256([]byte(secret))
		return sum[:]
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err == nil {
		return buf
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return sum[:]
}

func (e *explorerService) Handler() http.Handler {
	return http.HandlerFunc(e.handleHTTP)
}

func (e *explorerService) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && explorerCrossOrigin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	identity := e.identityFromRequest(w, r)
	h := e.newPolicyHandler(r, identity)

	relPath, err := explorerCleanRelPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	fullPath, err := explorerJoinRoot(e.rootDir, relPath)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		e.handleGET(w, r, h, identity, relPath, fullPath)
	case http.MethodPost:
		e.handlePOST(w, r, h, identity, relPath, fullPath)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (e *explorerService) handleGET(
	w http.ResponseWriter,
	r *http.Request,
	h *fsHandler,
	identity explorerIdentity,
	relPath, fullPath string,
) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if fi.IsDir() {
		e.serveDir(w, r, h, identity, relPath, fullPath)
		return
	}

	e.serveFile(w, r, h, relPath, fullPath)
}

func (e *explorerService) serveFile(
	w http.ResponseWriter,
	r *http.Request,
	h *fsHandler,
	relPath, fullPath string,
) {
	meta, err := h.examine(relPath)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := h.canRead(meta); err != nil {
		http.Error(w, "downloads locked until contributor threshold is met", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(path.Base(relPath)))
	h.logDownload(meta)
	e.srv.store.RecordDownload(h.pubHash, meta.fi.Size())
	http.ServeFile(w, r, fullPath)
}

func (e *explorerService) serveDir(
	w http.ResponseWriter,
	r *http.Request,
	h *fsHandler,
	identity explorerIdentity,
	relPath, fullPath string,
) {
	w.Header().Set("Cache-Control", "no-store")

	status, statusErr := e.srv.UserStatus(identity.PubHash)
	if statusErr != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	entries, err := e.readDir(fullPath, relPath, status.IsContributor, h)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	sortBy := strings.TrimSpace(q.Get("sort"))
	if sortBy == "" {
		sortBy = "name"
	}
	order := strings.TrimSpace(q.Get("order"))
	if order == "" {
		order = "asc"
	}
	explorerSortEntries(entries, sortBy, order)

	parentURL := ""
	if relPath != "" {
		p := path.Dir(relPath)
		if p == "." {
			p = ""
		}
		parentURL = "/" + p
		if parentURL == "" {
			parentURL = "/"
		}
	}

	sortLink := func(col string) template.URL {
		next := "asc"
		if sortBy == col && order == "asc" {
			next = "desc"
		}
		v := url.Values{}
		v.Set("sort", col)
		v.Set("order", next)
		u := url.URL{Path: r.URL.Path, RawQuery: v.Encode()}
		return template.URL(u.String())
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

	dirLabel := "root"
	if relPath != "" {
		dirLabel = relPath
	}

	uploadPath := "/"
	if relPath != "" {
		uploadPath = "/" + relPath
	}

	data := struct {
		Title            string
		DirLabel         string
		Crumbs           []explorerCrumb
		ParentURL        string
		Entries          []explorerEntry
		Contributor      bool
		BytesNeeded      string
		UploadedBytes    string
		ThresholdBytes   string
		CSRFToken        string
		SortLink         func(string) template.URL
		Arrow            func(string) string
		UploadPath       string
		MaxUploadPerFile string
	}{
		Title:            "Index of /" + relPath,
		DirLabel:         dirLabel,
		Crumbs:           explorerCrumbs(relPath),
		ParentURL:        parentURL,
		Entries:          entries,
		Contributor:      status.IsContributor,
		BytesNeeded:      formatBytes(status.BytesNeeded),
		UploadedBytes:    formatBytes(status.Stats.UploadBytes),
		ThresholdBytes:   formatBytes(e.srv.cfg.ContributorThreshold),
		CSRFToken:        e.csrfToken(w, r, identity),
		SortLink:         sortLink,
		Arrow:            arrow,
		UploadPath:       uploadPath,
		MaxUploadPerFile: explorerMaxUploadLabel(e.maxFileSize),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := explorerTemplate.Execute(w, data); err != nil {
		e.logger.Warn("template execution failed", "err", err)
	}
}

func (e *explorerService) handlePOST(
	w http.ResponseWriter,
	r *http.Request,
	h *fsHandler,
	identity explorerIdentity,
	relPath, fullPath string,
) {
	fi, err := os.Stat(fullPath)
	if err != nil || !fi.IsDir() {
		http.Error(w, "Not a directory", http.StatusBadRequest)
		return
	}

	if _, err := e.srv.store.UpsertUserSession(identity.PubHash); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	csrfPart, err := mr.NextPart()
	if err != nil || csrfPart == nil || csrfPart.FormName() != "csrf_token" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	csrfRaw, _ := io.ReadAll(io.LimitReader(csrfPart, 256))
	_ = csrfPart.Close()
	if !e.validateCSRF(r, identity, strings.TrimSpace(string(csrfRaw))) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := e.streamParts(mr, relPath, h); err != nil {
		if errors.Is(err, errExplorerUploadTooLarge) {
			http.Error(w, "Upload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Upload failed", http.StatusBadRequest)
		return
	}

	target := "/"
	if relPath != "" {
		target = "/" + relPath
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (e *explorerService) streamParts(mr *multipart.Reader, dirRel string, h *fsHandler) error {
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		rawName := explorerPartFilename(part)
		if rawName == "" {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}

		cleanPartRel, err := explorerMultipartCleanPath(rawName)
		if err != nil {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		finalRel := cleanPartRel
		if dirRel != "" {
			finalRel = path.Join(dirRel, cleanPartRel)
		}

		meta, err := h.examine(finalRel)
		if err != nil {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		if err := h.canModify(meta); err != nil {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		if err := h.prepareDirectory(path.Dir(finalRel)); err != nil {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}

		if !meta.exists || strings.TrimSpace(meta.owner) == "" {
			if err := e.srv.store.ClaimFile(h.pubHash, finalRel); err != nil {
				_, _ = io.Copy(io.Discard, part)
				_ = part.Close()
				continue
			}
		}

		oldSize := int64(0)
		if meta.exists && meta.fi != nil {
			oldSize = meta.fi.Size()
		}

		size, err := explorerWriteFileAtomically(meta.full, part, e.maxFileSize)
		_ = part.Close()
		if err != nil {
			if errors.Is(err, errExplorerUploadTooLarge) {
				return err
			}
			continue
		}
		delta := size - oldSize
		if err := e.srv.store.UpdateFileWrite(h.pubHash, finalRel, size, delta); err != nil {
			continue
		}
		h.logUpload(finalRel, size, delta)
	}
}

func explorerWriteFileAtomically(fullPath string, src io.Reader, maxSize int64) (int64, error) {
	tmp := fullPath + ".upload-" + explorerRandomHex(6)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, permFile)
	if err != nil {
		return 0, err
	}

	written, copyErr := explorerCopyWithLimit(f, src, maxSize)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return 0, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return 0, closeErr
	}
	if err := os.Rename(tmp, fullPath); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return written, nil
}

func explorerCopyWithLimit(dst io.Writer, src io.Reader, maxSize int64) (int64, error) {
	if maxSize <= 0 {
		return io.Copy(dst, src)
	}
	lr := &io.LimitedReader{R: src, N: maxSize + 1}
	n, err := io.Copy(dst, lr)
	if n > maxSize {
		return maxSize, errExplorerUploadTooLarge
	}
	return n, err
}

func (e *explorerService) readDir(fullPath, relPath string, contributor bool, h *fsHandler) ([]explorerEntry, error) {
	des, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	out := make([]explorerEntry, 0, len(des))
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue
		}
		name := de.Name()
		entryRel := path.Clean(path.Join(relPath, filepath.ToSlash(name)))
		if entryRel == "." {
			entryRel = ""
		}

		u := url.URL{Path: "/" + entryRel}
		size := info.Size()
		if de.IsDir() {
			size = explorerDirChildren(filepath.Join(fullPath, name))
		}

		downloadable := de.IsDir() || contributor || h.checkUnrestricted(entryRel)
		out = append(out, explorerEntry{
			Name:         name,
			IsDir:        de.IsDir(),
			Size:         size,
			ModTime:      info.ModTime(),
			URL:          template.URL(u.EscapedPath()),
			Downloadable: downloadable,
		})
	}
	return out, nil
}

func explorerDirChildren(dir string) int64 {
	des, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return int64(len(des))
}

func explorerSortEntries(entries []explorerEntry, by, order string) {
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

func explorerCrumbs(relPath string) []explorerCrumb {
	crumbs := []explorerCrumb{{Name: "root", URL: "/", IsCurrent: relPath == ""}}
	if relPath == "" {
		return crumbs
	}
	parts := strings.Split(path.Clean(relPath), "/")
	acc := ""
	for i, p := range parts {
		if p == "" || p == "." {
			continue
		}
		acc = path.Join(acc, p)
		u := url.URL{Path: "/" + acc}
		crumbs = append(crumbs, explorerCrumb{
			Name:      p,
			URL:       template.URL(u.EscapedPath()),
			IsCurrent: i == len(parts)-1,
		})
	}
	return crumbs
}

func explorerCrossOrigin(r *http.Request) bool {
	site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))
	if site != "" && site != "same-origin" && site != "none" {
		return true
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil {
		return true
	}
	return u.Host != r.Host
}

func explorerCleanRelPath(urlPath string) (string, error) {
	clean := path.Clean("/" + strings.TrimSpace(urlPath))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." {
		return "", nil
	}
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("invalid path")
	}
	return clean, nil
}

func explorerJoinRoot(root, rel string) (string, error) {
	full := filepath.Join(root, filepath.FromSlash(rel))
	abs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if abs != rootAbs && !strings.HasPrefix(abs, rootAbs+string(os.PathSeparator)) {
		return "", errors.New("path traversal")
	}
	return abs, nil
}

func explorerPartFilename(p *multipart.Part) string {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(params["filename"])
	if name == "" {
		return ""
	}
	return name
}

func explorerMultipartCleanPath(raw string) (string, error) {
	clean := filepath.Clean("/" + filepath.ToSlash(raw))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("invalid path")
	}
	return filepath.ToSlash(clean), nil
}

func explorerRemoteAddr(remote string) net.Addr {
	host, portRaw, err := net.SplitHostPort(remote)
	if err != nil {
		return explorerStringAddr(remote)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return explorerStringAddr(remote)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return explorerStringAddr(remote)
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

type explorerStringAddr string

func (a explorerStringAddr) Network() string { return "tcp" }
func (a explorerStringAddr) String() string  { return string(a) }

func (e *explorerService) newPolicyHandler(r *http.Request, id explorerIdentity) *fsHandler {
	addr := explorerRemoteAddr(r.RemoteAddr)
	lg := e.logger.With(e.srv.userGroup(id.PubHash, id.SessionID, addr))
	return &fsHandler{
		srv:        e.srv,
		pubHash:    id.PubHash,
		stderr:     io.Discard,
		logger:     *lg,
		remoteAddr: addr,
		sessionID:  id.SessionID,
	}
}

func (e *explorerService) identityFromRequest(w http.ResponseWriter, r *http.Request) explorerIdentity {
	raw := ""
	if c, err := r.Cookie(e.cookieIdentity); err == nil {
		if tok, ok := e.parseSignedCookie(c.Value, "id", ""); ok {
			raw = tok
		}
	}

	if raw == "" {
		raw = explorerRandomHex(32)
		e.setCookie(w, e.cookieIdentity, e.makeSignedCookie(raw, "id", ""), true)
	}

	sum := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(sum[:])
	pubHash := explorerIdentityPrefix + hashHex
	return explorerIdentity{
		Raw:       raw,
		PubHash:   pubHash,
		SessionID: explorerSessionPrefix + hashHex[:16],
	}
}

func (e *explorerService) csrfToken(w http.ResponseWriter, r *http.Request, id explorerIdentity) string {
	if c, err := r.Cookie(e.cookieCSRF); err == nil {
		if token, ok := e.parseSignedCookie(c.Value, "csrf", id.PubHash); ok {
			return token
		}
	}
	token := explorerRandomHex(32)
	e.setCookie(w, e.cookieCSRF, e.makeSignedCookie(token, "csrf", id.PubHash), true)
	return token
}

func (e *explorerService) validateCSRF(r *http.Request, id explorerIdentity, formToken string) bool {
	formToken = strings.TrimSpace(formToken)
	if formToken == "" {
		return false
	}
	c, err := r.Cookie(e.cookieCSRF)
	if err != nil {
		return false
	}
	token, ok := e.parseSignedCookie(c.Value, "csrf", id.PubHash)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(formToken)) == 1
}

func (e *explorerService) makeSignedCookie(token, purpose, subject string) string {
	sig := e.signToken(token, purpose, subject)
	return "v1." + token + "." + sig
}

func (e *explorerService) parseSignedCookie(raw, purpose, subject string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	sig := strings.TrimSpace(parts[2])
	if token == "" || sig == "" {
		return "", false
	}
	want := e.signToken(token, purpose, subject)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return token, true
}

func (e *explorerService) signToken(token, purpose, subject string) string {
	mac := hmac.New(sha256.New, e.signingKey)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(subject))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func (e *explorerService) setCookie(w http.ResponseWriter, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})
}

func explorerRandomHex(nBytes int) string {
	if nBytes <= 0 {
		nBytes = 16
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(sum[:])
}

func explorerMaxUploadLabel(max int64) string {
	if max <= 0 {
		return "unlimited"
	}
	return formatBytes(max)
}

var explorerTemplate = template.Must(template.New("explorer").Parse(explorerPageHTML))

const explorerPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{
  font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
  font-size:14px;line-height:1.6;
  margin:0;padding:24px 32px;
  background:#fff;color:#1a1a1a;
  max-width:1024px;
}
a{color:#0550ae;text-decoration:none}
a:hover{text-decoration:underline}
.bc{font-size:13px;color:#57606a;margin-bottom:14px}
.bc a{color:#57606a}.bc a:hover{color:#0550ae}
.bc .sep{margin:0 3px;opacity:.5}
.bc .cur{color:#1a1a1a;font-weight:600}
h1{font-size:15px;font-weight:700;margin:0 0 6px}
hr{border:none;border-top:1px solid #d0d7de;margin:0 0 14px}
.banner{
  background:#fff8c5;border:1px solid #d4a72c;
  border-radius:4px;padding:10px 14px;
  margin-bottom:14px;font-size:13px;
}
.banner strong{color:#7a4900}
.status-ok{color:#1a7f37;font-weight:600}
.status-locked{color:#57606a}
.table-wrapper { width: 100%; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin-bottom: 24px; table-layout: auto; }
th, td { padding: 8px 12px 8px 0; border-bottom: 1px solid #eaeef2; vertical-align: top; text-align: left; }
th{ border-bottom:2px solid #d0d7de; font-weight:700;white-space:nowrap;font-size:13px; }
th a{color:#1a1a1a}
th a:hover{color:#0550ae;text-decoration:none}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f6f8fa}
.col-name { overflow-wrap: break-word; word-break: break-word; }
@media (min-width: 651px) {
  table { table-layout: fixed; }
  .col-name { width: 60%; }
  .col-mod  { width: 170px; }
  .col-size { width: 120px; text-align: right; }
}
@media (max-width: 650px) {
  .col-mod { display: none; }
  .col-size { text-align: right; white-space: nowrap; width: 92px; font-size: 12px; }
}
.col-mod{white-space:nowrap;color:#57606a}
.col-size{white-space:nowrap;color:#57606a;text-align:right}
.dir-tag{color:#57606a;user-select:none}
.locked-name{color:#57606a}
.parent-link td{border-bottom:2px solid #d0d7de}
.upload{ border:1px solid #d0d7de;border-radius:6px; padding:14px 16px;background:#f6f8fa; margin-bottom: 24px; }
.upload h2{font-size:13px;font-weight:700;margin:0 0 10px;color:#57606a;text-transform:uppercase;letter-spacing:.04em}
.upload-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.upload-row input[type=file]{font:inherit;font-size:13px;max-width:340px}
.btn{ padding:5px 14px;font:inherit;font-size:13px; border:1px solid;border-radius:6px;cursor:pointer; display:inline-flex;align-items:center;justify-content:center; }
.btn-primary{background:#1a7f37;color:#fff;border-color:#1a7f37}
.btn-primary:hover{background:#166d30;border-color:#166d30}
.btn-primary:disabled{background:#8c959f;border-color:#8c959f;cursor:not-allowed}
.btn-secondary{background:#f6f8fa;color:#24292f;border-color:#d0d7de}
.btn-secondary:hover:not(:disabled){background:#f3f4f6;border-color:#1a7f37}
.btn-secondary:disabled{opacity:0.6;cursor:not-allowed}
.progress-wrapper { display: none; margin-top: 16px; background: #eaeef2; border-radius: 4px; height: 18px; position: relative; overflow: hidden; border: 1px solid #d0d7de; }
.progress-bar { height: 100%; background-color: #0969da; width: 0%; transition: width 0.1s ease; }
.progress-text { position: absolute; width: 100%; text-align: center; font-size: 11px; line-height: 16px; font-weight: 700; color: #1a1a1a; }
footer{ margin-top:28px;padding-top:12px; border-top:1px solid #eaeef2; font-size:12px;color:#57606a; }
</style>
</head>
<body>

<nav class="bc" aria-label="Breadcrumb">
{{- range $i, $c := .Crumbs}}
  {{- if $i}}<span class="sep">/</span>{{end}}
  {{- if $c.IsCurrent}}<span class="cur">{{$c.Name}}</span>
  {{- else}}<a href="{{$c.URL}}">{{$c.Name}}</a>{{end}}
{{- end}}
</nav>

<h1>{{.Title}}</h1>
<hr>

{{if .Contributor}}
<div class="banner">
  <span class="status-ok">&#10003; Downloads unlocked.</span>
  Uploaded {{.UploadedBytes}} (threshold {{.ThresholdBytes}}).
</div>
{{else}}
<div class="banner">
  <span class="status-locked">&#8856; Downloads restricted.</span>
  Upload {{.BytesNeeded}} more to unlock non-public files.
</div>
{{end}}

<div class="upload">
  <h2>Upload to /{{.DirLabel}}</h2>
  <form id="upload-form" method="post" enctype="multipart/form-data" action="{{.UploadPath}}">
    <input type="hidden" name="csrf_token" id="csrf_token" value="{{.CSRFToken}}">
    <div class="upload-row">
      <input type="file" name="uploadFiles" id="pick-files" multiple>
      <input type="file" name="uploadFiles" id="pick-folder" webkitdirectory directory style="display:none">
      <button type="button" class="btn btn-secondary" id="btn-folder" onclick="document.getElementById('pick-folder').click()">&#128193; Folder</button>
      <button type="submit" class="btn btn-primary" id="btn-submit">&#8679; Upload</button>
      <span class="status-locked">Max per file: {{.MaxUploadPerFile}}</span>
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
  <th class="col-mod"><a href="{{call .SortLink "modified"}}">Last Modified{{call .Arrow "modified"}}</a></th>
  <th class="col-size"><a href="{{call .SortLink "size"}}">Size{{call .Arrow "size"}}</a></th>
</tr>
</thead>
<tbody>
{{if .ParentURL -}}
<tr class="parent-link"><td colspan="3"><a href="{{.ParentURL}}">&#8593; Parent Directory</a></td></tr>
{{end -}}
{{range .Entries}}
<tr>
  <td class="col-name">
    {{- if .IsDir}}
      <span class="dir-tag">[DIR]</span>&nbsp;<a href="{{.URL}}">{{.Name}}/</a>
    {{- else if .Downloadable}}
      <a href="{{.URL}}" download>{{.Name}}</a>
    {{- else}}
      <span class="locked-name" title="Upload to reach contributor threshold">{{.Name}}</span>
    {{- end}}
  </td>
  <td class="col-mod">{{.ModTimeStr}}</td>
  <td class="col-size">{{.SizeStr}}</td>
</tr>
{{else}}
<tr><td colspan="3" style="color:#57606a;padding:12px 0">Empty directory.</td></tr>
{{end}}
</tbody>
</table>

<footer>
{{if .Contributor -}}
  <span class="status-ok">&#10003; Contributor downloads unlocked</span>
{{- else -}}
  <span class="status-locked">&#8856; Contributor downloads locked</span>
{{- end}}
</footer>

<script>
const form = document.getElementById('upload-form');
const fileInput = document.getElementById('pick-files');
const folderInput = document.getElementById('pick-folder');
const submitBtn = document.getElementById('btn-submit');
const folderBtn = document.getElementById('btn-folder');
const progressWrapper = document.getElementById('progress-wrapper');
const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');

function performUpload(files) {
  if (!files || files.length === 0) return;

  submitBtn.disabled = true;
  folderBtn.disabled = true;
  fileInput.disabled = true;
  progressWrapper.style.display = 'block';

  const formData = new FormData();
  formData.append('csrf_token', document.getElementById('csrf_token').value);
  for (let i = 0; i < files.length; i++) {
    formData.append('uploadFiles', files[i], files[i].webkitRelativePath || files[i].name);
  }

  const xhr = new XMLHttpRequest();
  xhr.open('POST', form.action, true);

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const percent = Math.round((e.loaded / e.total) * 100);
      progressBar.style.width = percent + '%';
      progressText.innerText = percent + '%';
      if (percent >= 100) {
        progressText.innerText = 'Processing on server...';
      }
    }
  };

  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 400) {
      window.location.reload();
      return;
    }
    alert('Upload failed: ' + xhr.responseText);
    resetUI();
  };

  xhr.onerror = () => {
    alert('Network error during upload.');
    resetUI();
  };

  xhr.send(formData);
}

function resetUI() {
  submitBtn.disabled = false;
  folderBtn.disabled = false;
  fileInput.disabled = false;
  progressWrapper.style.display = 'none';
  progressBar.style.width = '0%';
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  performUpload(fileInput.files);
});

folderInput.addEventListener('change', () => {
  performUpload(folderInput.files);
});

document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', (e) => {
  e.preventDefault();
  if (submitBtn.disabled) return;
  const files = e.dataTransfer && e.dataTransfer.files;
  if (files && files.length > 0) {
    performUpload(files);
  }
});
</script>

</body>
</html>`
