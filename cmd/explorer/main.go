package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
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
	"time"
)

// ── constants ─────────────────────────────────────────────────────────────────

//go:embed main.go
var appSrc string

const (
	cookieUnlock = "explorer_unlocked"
	cookieCSRF   = "explorer_csrf"
)

// ── globals ───────────────────────────────────────────────────────────────────

var (
	rootDir     string
	maxFileSize int64
)

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	var logPath, port string
	var maxSizeMB int64

	flag.StringVar(&rootDir, "dir", "./shared", "Directory to serve")
	flag.StringVar(&port, "port", "8080", "Port to listen on")
	flag.Int64Var(&maxSizeMB, "maxsize", 1000, "Max upload size in MB")
	flag.StringVar(&logPath, "log", "explorer.log", "Log file path")
	src := flag.Bool("src", false, "Print this program's source and exit")

	flag.Parse()

	if *src {
		fmt.Println(appSrc)
		os.Exit(0)
	}

	maxFileSize = maxSizeMB << 20

	lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, lf))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	abs, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("resolve root: %v", err)
	}
	rootDir = abs

	if err := os.MkdirAll(rootDir, 0755); err != nil {
		log.Fatalf("create root: %v", err)
	}

	log.Printf("serving %s on :%s (max %d MB per upload)", rootDir, port, maxSizeMB)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(logMiddleware)))
}

// ── logging middleware ────────────────────────────────────────────────────────

func logMiddleware(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s %s", clientIP(r), r.Method, r.URL.Path, r.URL.RawQuery)
	handle(w, r)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.SplitN(xff, ",", 2)[0]
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ── routing ───────────────────────────────────────────────────────────────────

func handle(w http.ResponseWriter, r *http.Request) {
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
		handleGET(w, r, fullPath, relPath)
	case http.MethodPost:
		handlePOST(w, r, fullPath, relPath)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func isCrossOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" && site != "none" {
		return true
	}
	ref := r.Header.Get("Referer")
	if ref != "" {
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
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// ── GET handler ───────────────────────────────────────────────────────────────

func handleGET(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
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
		serveDir(w, r, fullPath, relPath)
	} else {
		serveFile(w, r, fullPath, info, relPath)
	}
}

// ── file download ─────────────────────────────────────────────────────────────

func serveFile(w http.ResponseWriter, r *http.Request, fullPath string, info os.FileInfo, relPath string) {
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
	w.Header().Set("Content-Disposition",
		"attachment; filename*=UTF-8''"+url.PathEscape(info.Name()))
	http.ServeFile(w, r, fullPath)
}

// ── directory listing ─────────────────────────────────────────────────────────

type entry struct {
	Name    string
	IsDir   bool
	Size    int64 // File bytes or Directory item count
	ModTime time.Time
	URL     template.URL
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

func serveDir(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
	w.Header().Set("Cache-Control", "no-store")

	csrf := csrfToken(w, r)

	q := r.URL.Query()
	sortBy := q.Get("sort")
	order := q.Get("order")
	if sortBy == "" {
		sortBy = "name"
	}
	if order == "" {
		order = "asc"
	}

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

	parentURL := ""
	if relPath != "" {
		parentRel := filepath.ToSlash(filepath.Dir(relPath))
		if parentRel == "." {
			parentRel = ""
		}
		u := url.URL{Path: "/" + parentRel}
		parentURL = u.EscapedPath()
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
		u := url.URL{Path: r.URL.Path, RawQuery: uq.Encode()}
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

	// Generate a clean UploadPath
	upURL := url.URL{Path: "/" + relPath}

	// Pass whether this directory itself is under /public so the template
	// can render file links without the lock treatment.
	isPublicDir := isPublicPath(fullPath)

	data := struct {
		Title      string
		DirLabel   string
		Crumbs     []crumb
		ParentURL  string
		Entries    []entry
		Unlocked   bool
		IsPublic   bool
		WantedFile string
		CSRFToken  string
		SortLink   func(string) template.URL
		Arrow      func(string) string
		UploadPath string
	}{
		Title:      "Index of /" + relPath,
		DirLabel:   dirLabel,
		Crumbs:     buildCrumbs(relPath),
		ParentURL:  parentURL,
		Entries:    entries,
		Unlocked:   isUnlocked(r),
		IsPublic:   isPublicDir,
		WantedFile: wantedFile,
		CSRFToken:  csrf,
		SortLink:   sortLink,
		Arrow:      arrow,
		UploadPath: upURL.EscapedPath(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func readDir(fullPath, relPath string) ([]entry, error) {
	des, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(des))
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue
		}
		name := de.Name()
		entRel := filepath.ToSlash(filepath.Join(relPath, name))
		u := url.URL{Path: "/" + entRel}

		var sizeVal int64
		if de.IsDir() {
			sizeVal = countDirItems(filepath.Join(fullPath, name))
		} else {
			sizeVal = info.Size()
		}

		out = append(out, entry{
			Name:    name,
			IsDir:   de.IsDir(),
			Size:    sizeVal,
			ModTime: info.ModTime(),
			URL:     template.URL(u.EscapedPath()),
		})
	}
	return out, nil
}

// countDirItems returns the number of immediate children in a directory.
// Faster than a recursive walk.
func countDirItems(path string) int64 {
	des, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	return int64(len(des))
}

func sortEntries(entries []entry, by, order string) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.IsDir != b.IsDir {
			return a.IsDir // dirs first
		}
		var less bool
		switch by {
		case "size":
			less = a.Size < b.Size
		case "modified":
			less = a.ModTime.Before(b.ModTime)
		default: // "name"
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
		u := url.URL{Path: acc}
		crumbs = append(crumbs, crumb{
			Name:      p,
			URL:       template.URL(u.EscapedPath()),
			IsCurrent: i == len(parts)-1,
		})
	}
	return crumbs
}

// ── upload (POST) ─────────────────────────────────────────────────────────────

func handlePOST(w http.ResponseWriter, r *http.Request, fullPath, relPath string) {
	ip := clientIP(r)

	info, err := os.Stat(fullPath)
	if err != nil || !info.IsDir() {
		http.Error(w, "Not a directory", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	csrfPart, err := mr.NextPart()
	if err != nil || csrfPart.FormName() != "csrf_token" {
		log.Printf("[%s] UPLOAD REJECTED: missing csrf part", ip)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	tokenBytes, _ := io.ReadAll(io.LimitReader(csrfPart, 128))
	csrfPart.Close()
	if !validateCSRF(r, string(tokenBytes)) {
		log.Printf("[%s] UPLOAD REJECTED: invalid csrf token", ip)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := streamParts(mr, fullPath, ip); err != nil {
		log.Printf("[%s] UPLOAD ERROR: %v", ip, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieUnlock,
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})

	target := "/" + filepath.ToSlash(relPath)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func streamParts(mr *multipart.Reader, destDir, ip string) error {
	topRemap := map[string]string{}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// This happens if the connection is dropped or MaxBytesReader is triggered
			return fmt.Errorf("multipart stream interrupted: %w", err)
		}

		rawName := partFilename(part)
		if rawName == "" {
			io.Copy(io.Discard, part)
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
				want := filepath.Join(destDir, topName)
				unique := uniqueDirPath(want)
				topRemap[topName] = filepath.Base(unique)
				if err := os.MkdirAll(unique, 0755); err != nil {
					log.Printf("[%s] MKDIR %q: %v", ip, unique, err)
					io.Copy(io.Discard, part)
					part.Close()
					continue
				}
			}
			finalRel = filepath.Join(topRemap[topName], segments[1])
		} else {
			finalRel = topName
		}

		destPath := filepath.Join(destDir, finalRel)

		if !isUnderRoot(destPath) {
			log.Printf("[%s] UPLOAD SKIP (traversal): %q", ip, rawName)
			io.Copy(io.Discard, part)
			part.Close()
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			log.Printf("[%s] MKDIR parent: %v", ip, err)
			io.Copy(io.Discard, part)
			part.Close()
			continue
		}

		if !isNested {
			destPath = uniqueFilePath(destPath)
		}

		log.Printf("[%s] UPLOAD %q → %q", ip, rawName, destPath)
		if err := writeFile(part, destPath); err != nil {
			part.Close()
			return err
		}
		part.Close()
	}
	return nil
}

func partFilename(p *multipart.Part) string {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	name := params["filename"]
	if name == "" {
		return ""
	}
	base := filepath.Base(filepath.Clean("/" + filepath.ToSlash(name)))
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return name
}

func writeFile(r io.Reader, path string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	// We use a closure in defer to capture the state of 'err'
	// at the moment the function returns.
	defer func() {
		f.Close()
		if err != nil {
			log.Printf("[CLEAN] error occurred during copy, remove the incomplete file: %s, %v", path, err)
			os.Remove(path)
		}
	}()

	_, err = io.Copy(f, r)
	return err
}

func uniqueFilePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 1; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

func uniqueDirPath(path string) string {
	path = filepath.Clean(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	for i := 1; ; i++ {
		candidate := filepath.Join(parent, fmt.Sprintf("%s (%d)", base, i))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && len(c.Value) == 64 {
		return c.Value
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    token,
		Path:     "/",
		HttpOnly: true, // Server-side template handles embedding the token
		MaxAge:   86400 * 30,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func validateCSRF(r *http.Request, formToken string) bool {
	c, err := r.Cookie(cookieCSRF)
	if err != nil || c.Value == "" {
		return false
	}
	return formToken != "" && c.Value == formToken
}

// ── unlock cookie ─────────────────────────────────────────────────────────────

func isUnlocked(r *http.Request) bool {
	c, err := r.Cookie(cookieUnlock)
	return err == nil && c.Value == "true"
}

// isPublicPath returns true when fullPath is the /public directory itself
// or any file/subdirectory nested within it.
func isPublicPath(fullPath string) bool {
	publicRoot := filepath.Join(rootDir, "public")
	rel, err := filepath.Rel(publicRoot, fullPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// ── formatting ────────────────────────────────────────────────────────────────

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

// ── template ──────────────────────────────────────────────────────────────────

var tmpl = template.Must(template.New("page").Parse(pageHTML))

const pageHTML = `<!DOCTYPE html>
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
  max-width:980px;
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
.banner-public{
  background:#dafbe1;border-color:#2da44e;color:#1a7f37;font-weight:600;
}

.table-wrapper {
  width: 100%;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 24px;
  /* Fixed layout only applies to desktop (see media query below) */
  table-layout: auto; 
}

th, td {
  padding: 8px 12px 8px 0;
  border-bottom: 1px solid #eaeef2;
  vertical-align: top;
  text-align: left;
}

th{
  text-align:left;padding:5px 16px 5px 0;
  border-bottom:2px solid #d0d7de;
  font-weight:700;white-space:nowrap;font-size:13px;
}
th a{color:#1a1a1a}
th a:hover{color:#0550ae;text-decoration:none}
td{
  padding:4px 16px 4px 0;
  border-bottom:1px solid #eaeef2;
  vertical-align:top;
  word-wrap: break-word;
}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f6f8fa}
.col-name {
  /* overflow-wrap is more modern than word-wrap */
  overflow-wrap: break-word;
  word-wrap: break-word;
  word-break: break-all; /* Ensures long strings without dots/dashes also break */
}

/* DESKTOP TWEAKS (Screens wider than 650px) */
@media (min-width: 651px) {
  table {
    table-layout: fixed;
  }
  .col-name { width: 60%; }
  .col-mod  { width: 160px; }
  .col-size { width: 100px; text-align: right; }
}

/* MOBILE TWEAKS (Screens 650px and below) */
@media (max-width: 650px) {
  /* Hide the "Last Modified" column to save horizontal space */
  .col-mod {
    display: none;
  }
  
  th, td {
    padding: 10px 8px 10px 0; /* Slightly larger tap targets */
  }

  .col-size {
    text-align: right;
    white-space: nowrap;
    width: 80px;
    font-size: 12px; /* Smaller font for meta info */
  }
  
  .col-name {
    font-size: 14px;
  }

  /* Make the [DIR] tag less prominent to save space */
  .dir-tag {
    font-size: 11px;
  }
}

.col-mod{white-space:nowrap;color:#57606a;width:160px}
.col-size{white-space:nowrap;color:#57606a;text-align:right;width:110px}
.dir-tag{color:#57606a;user-select:none}
.locked-name{color:#57606a}
.parent-link td{border-bottom:2px solid #d0d7de}
.parent-link:hover td{background:#f6f8fa}

.upload{
  border:1px solid #d0d7de;border-radius:6px;
  padding:14px 16px;background:#f6f8fa;
  margin-bottom: 24px;
}
.upload h2{font-size:13px;font-weight:700;margin:0 0 10px;color:#57606a;
  text-transform:uppercase;letter-spacing:.04em}
.upload-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.upload-row input[type=file]{font:inherit;font-size:13px;max-width:340px}
.btn{
  padding:5px 14px;font:inherit;font-size:13px;
  border:1px solid;border-radius:6px;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;
}
.btn-primary{background:#1a7f37;color:#fff;border-color:#1a7f37}
.btn-primary:hover{background:#166d30;border-color:#166d30}
.btn-primary:disabled{background:#8c959f;border-color:#8c959f;cursor:not-allowed}
.btn-secondary{background:#f6f8fa;color:#24292f;border-color:#d0d7de}
.btn-secondary:hover:not(:disabled){background:#f3f4f6;border-color:#1a7f37}
.btn-secondary:disabled{opacity:0.6;cursor:not-allowed}

/* Progress Bar Styles */
.progress-wrapper {
  display: none;
  margin-top: 16px;
  background: #eaeef2;
  border-radius: 4px;
  height: 18px;
  position: relative;
  overflow: hidden;
  border: 1px solid #d0d7de;
}
.progress-bar {
  height: 100%;
  background-color: #0969da;
  width: 0%;
  transition: width 0.1s ease;
}
.progress-text {
  position: absolute;
  width: 100%;
  text-align: center;
  font-size: 11px;
  line-height: 16px;
  font-weight: 700;
  color: #1a1a1a;
  mix-blend-mode: multiply;
}

footer{
  margin-top:28px;padding-top:12px;
  border-top:1px solid #eaeef2;
  font-size:12px;color:#57606a;
}
.status-ok{color:#1a7f37;font-weight:600}
.status-locked{color:#57606a}
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

{{if and .WantedFile (not .IsPublic)}}
<div class="banner">
  <strong>Downloads are locked.</strong>
  To download <em>{{.WantedFile}}</em>, upload any file using the form below.
</div>
{{else if and (not .Unlocked) (not .IsPublic)}}
<div class="banner">
  <span class="status-locked">&#8856; Downloads locked &mdash; upload any file to unlock</span>
</div>
{{else if .IsPublic}}
<div class="banner banner-public">
  &#10022; Public directory &mdash; all files are freely available to download.
</div>
{{end}}

<div class="upload">
  <h2>Upload to /{{.DirLabel}}</h2>
  <form id="upload-form" method="post" enctype="multipart/form-data" action="{{.UploadPath}}">
    <input type="hidden" name="csrf_token" id="csrf_token" value="{{.CSRFToken}}">
    <div class="upload-row">
      <input type="file" name="uploadFiles" id="pick-files" multiple>
      <input type="file" name="uploadFiles" id="pick-folder"
             webkitdirectory directory style="display:none">
      <button type="button" class="btn btn-secondary" id="btn-folder"
              onclick="document.getElementById('pick-folder').click()">&#128193; Folder</button>
      <button type="submit" class="btn btn-primary" id="btn-submit">&#8679; Upload</button>
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
<tr class="parent-link">
  <td colspan="3"><a href="{{.ParentURL}}">&#8593; Parent Directory</a></td>
</tr>
{{end -}}
{{range .Entries}}
<tr>
  <td class="col-name">
    {{- if .IsDir}}
      <span class="dir-tag">[DIR]</span>&nbsp;<a href="{{.URL}}">{{.Name}}/</a>
    {{- else if or $.Unlocked $.IsPublic}}
      <a href="{{.URL}}" download>{{.Name}}</a>
    {{- else}}
      <span class="locked-name" title="Upload a file to unlock downloads">{{.Name}}</span>
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
{{if .Unlocked -}}
  <span class="status-ok">&#10003; Downloads unlocked</span>
{{- else if .IsPublic -}}
  <span class="status-ok">&#10003; Public directory &mdash; downloads always available</span>
{{- else -}}
  <span class="status-locked">&#8856; Downloads locked &mdash; upload any file to unlock</span>
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

  // 1. Disable UI
  submitBtn.disabled = true;
  folderBtn.disabled = true;
  fileInput.disabled = true;
  progressWrapper.style.display = 'block';

  // 2. Prepare Data
  const formData = new FormData();
  formData.append('csrf_token', document.getElementById('csrf_token').value);
  for (let i = 0; i < files.length; i++) {
    // Note: webkitRelativePath is preserved by FormData in modern browsers
    formData.append('uploadFiles', files[i], files[i].webkitRelativePath || files[i].name);
  }

  // 3. Setup XHR
  const xhr = new XMLHttpRequest();
  xhr.open('POST', form.action, true);

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const percent = Math.round((e.loaded / e.total) * 100);
      progressBar.style.width = percent + '%';
      progressText.innerText = percent + '%';
      if (percent >= 100) {
        progressText.innerText = "Processing on server...";
      }
    }
  };

  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 400) {
      // Success: Refresh to show new files and updated "Unlock" status
      window.location.reload();
    } else {
      alert('Upload failed: ' + xhr.responseText);
      resetUI();
    }
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

// Event Listeners
form.addEventListener('submit', (e) => {
  e.preventDefault();
  performUpload(fileInput.files);
});

folderInput.addEventListener('change', () => {
  performUpload(folderInput.files);
});

// Drag and Drop
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
