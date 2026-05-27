package main

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

//go:embed admin/v2/dist
var adminV2EmbeddedFS embed.FS

var adminV2GzipCache sync.Map

func (s *Server) handleAdminV2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dist, err := fs.Sub(adminV2EmbeddedFS, "admin/v2/dist")
	if err != nil {
		http.Error(w, "admin v2 assets unavailable", http.StatusInternalServerError)
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, "/admin/v2/")
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	if rel == "." || rel == "" {
		rel = "index.html"
	}

	data, info, ok := readAdminV2Asset(dist, rel)
	if !ok {
		if strings.HasPrefix(rel, "assets/") || path.Ext(rel) != "" {
			http.NotFound(w, r)
			return
		}
		rel = "index.html"
		data, info, ok = readAdminV2Asset(dist, rel)
		if !ok {
			http.Error(w, "admin v2 index unavailable", http.StatusInternalServerError)
			return
		}
	}

	if rel == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(rel, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else if strings.HasPrefix(rel, "maps/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if contentType := mime.TypeByExtension(path.Ext(rel)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if shouldGzipAdminV2Asset(rel) {
		w.Header().Add("Vary", "Accept-Encoding")
		if requestAcceptsGzip(r) {
			if gz, ok := gzipAdminV2Asset(rel, data); ok {
				w.Header().Set("Content-Encoding", "gzip")
				data = gz
			}
		}
	}

	modTime := time.Time{}
	if info != nil {
		modTime = info.ModTime()
	}
	http.ServeContent(w, r, rel, modTime, bytes.NewReader(data))
}

func readAdminV2Asset(dist fs.FS, rel string) ([]byte, fs.FileInfo, bool) {
	info, err := fs.Stat(dist, rel)
	if err != nil || info.IsDir() {
		return nil, nil, false
	}
	data, err := fs.ReadFile(dist, rel)
	if err != nil {
		return nil, nil, false
	}
	return data, info, true
}

func shouldGzipAdminV2Asset(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".css", ".html", ".js", ".json", ".map", ".svg", ".txt":
		return true
	default:
		return false
	}
}

func requestAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.TrimSpace(strings.SplitN(part, ";", 2)[0]) == "gzip" {
			return true
		}
	}
	return false
}

func gzipAdminV2Asset(rel string, data []byte) ([]byte, bool) {
	if cached, ok := adminV2GzipCache.Load(rel); ok {
		if gz, ok := cached.([]byte); ok {
			return gz, true
		}
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, false
	}
	if err := zw.Close(); err != nil {
		return nil, false
	}
	gz := buf.Bytes()
	adminV2GzipCache.Store(rel, gz)
	return gz, true
}
