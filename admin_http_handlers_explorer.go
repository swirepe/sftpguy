package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"sftpguy/internal/adminexplorer"
)

type adminExplorerActionRequest struct {
	Path string `json:"path"`
}

func (s *Server) getAdminExplorerHandler() (http.Handler, error) {
	s.adminExplorerMu.Lock()
	defer s.adminExplorerMu.Unlock()

	if s.adminExplorer != nil || s.adminExplorerErr != nil {
		return s.adminExplorer, s.adminExplorerErr
	}

	h, err := adminexplorer.New(adminexplorer.Config{
		RootDir:        s.absUploadDir,
		BasePath:       adminexplorer.DefaultBasePath,
		EmbedAssets:    false,
		MaxUploadBytes: s.cfg.MaxFileSize,
		WarmCacheMax:   s.cfg.AdminExplorerWarmMax,
		LookupFileDetails: func(relPath string) (adminexplorer.FileDetails, error) {
			meta, err := s.store.GetFileAdminMeta(relPath)
			if err != nil {
				return adminexplorer.FileDetails{}, err
			}
			return adminexplorer.FileDetails{
				Owner:     meta.OwnerHash,
				Downloads: meta.Downloads,
			}, nil
		},
		LookupOwner: func(relPath string) (string, error) {
			return s.store.GetFileOwner(relPath)
		},
		OwnerFilesURL: func(owner string) string {
			owner = strings.TrimSpace(owner)
			if owner == "" || owner == systemOwner {
				return ""
			}
			q := url.Values{}
			q.Set("tab", "files")
			q.Set("owner", owner)
			return "/admin?" + q.Encode()
		},
		OwnerDetailsURL: func(owner string) string {
			owner = strings.TrimSpace(owner)
			if owner == "" || owner == systemOwner {
				return ""
			}
			return "/admin/api/users/" + url.PathEscape(owner)
		},
	})
	if err != nil {
		s.adminExplorerErr = err
		return nil, err
	}

	s.adminExplorer = h
	return s.adminExplorer, nil
}

func (s *Server) handleAdminExplorer(w http.ResponseWriter, r *http.Request) {
	h, err := s.getAdminExplorerHandler()
	if err != nil {
		http.Error(w, fmt.Sprintf("explorer init failed: %v", err), http.StatusInternalServerError)
		return
	}
	h.ServeHTTP(w, r)
}

func (s *Server) decodeAdminExplorerPath(r *http.Request) (string, error) {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()

	var payload adminExplorerActionRequest
	if err := dec.Decode(&payload); err != nil {
		return "", fmt.Errorf("decode request body: %w", err)
	}

	relPath, err := cleanRelativePath(payload.Path)
	if err != nil {
		return "", err
	}
	if relPath == "." {
		return "", fmt.Errorf("path is required")
	}
	return relPath, nil
}

func (s *Server) handleAdminExplorerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	relPath, err := s.decodeAdminExplorerPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(s.absUploadDir, filepath.FromSlash(relPath))
	fullPath = filepath.Clean(fullPath)
	rootWithSep := s.absUploadDir + string(filepath.Separator)
	if !strings.HasPrefix(fullPath+string(filepath.Separator), rootWithSep) {
		http.Error(w, "invalid path", http.StatusForbidden)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "path not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	owner, _ := s.store.GetFileOwner(relPath)
	if err := os.RemoveAll(fullPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.DeletePath(relPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.store.LogEvent(EventDelete, systemOwner, "admin-http", nil,
		"path", relPath,
		"scope", "explorer",
		"owner", owner)
	s.logger.Info("admin explorer deleted path",
		"path", relPath,
		"is_dir", info.IsDir(),
		"owner", shortID(owner))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"path":   relPath,
		"is_dir": info.IsDir(),
		"owner":  owner,
	})
}

func (s *Server) handleAdminExplorerBanOwner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	relPath, err := s.decodeAdminExplorerPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	owner, err := s.store.GetFileOwner(relPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		http.Error(w, "no tracked owner for path", http.StatusNotFound)
		return
	}
	if owner == systemOwner {
		http.Error(w, "refusing to ban system owner", http.StatusBadRequest)
		return
	}

	s.Ban(owner)
	s.store.LogEvent(EventAdminBan, systemOwner, "admin-http", nil,
		"target", owner,
		"scope", "explorer",
		"path", relPath)
	s.logger.Info("admin explorer banned owner",
		"owner", shortID(owner),
		"path", relPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"path":  relPath,
		"owner": owner,
	})
}
