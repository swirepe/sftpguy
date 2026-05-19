package main

import (
	"bytes"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed admin/v2/dist
var adminV2EmbeddedFS embed.FS

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
	}
	if contentType := mime.TypeByExtension(path.Ext(rel)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
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
