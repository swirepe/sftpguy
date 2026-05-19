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

type adminExplorerRenameRequest struct {
	Path    string `json:"path"`
	NewName string `json:"new_name"`
}

func (s *Server) getAdminExplorerHandler() (http.Handler, error) {
	s.adminExplorerMu.Lock()
	defer s.adminExplorerMu.Unlock()

	if s.adminExplorer != nil || s.adminExplorerErr != nil {
		return s.adminExplorer, s.adminExplorerErr
	}

	sharedPreviewer, err := s.getAdminPreviewer()
	if err != nil {
		s.adminExplorerErr = err
		return nil, err
	}

	h, err := adminexplorer.New(adminexplorer.Config{
		RootDir:        s.absUploadDir,
		BasePath:       adminexplorer.DefaultBasePath,
		EmbedAssets:    false,
		MaxUploadBytes: s.cfg.MaxFileSize,
		WarmCacheMax:   s.cfg.AdminExplorerWarmMax,
		Previewer:      sharedPreviewer,
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

	connID := s.startLiveConnectionFor("explorer-admin", "http", liveHTTPRemoteAddr(r), liveHTTPLocalAddr(r), false)
	sessionID := "admin-explorer:" + connID
	pathLabel := r.URL.Path
	if r.URL.RawQuery != "" {
		pathLabel += "?" + r.URL.RawQuery
	}
	s.startLiveSession(liveSessionStart{
		ConnectionID: connID,
		Source:       "explorer-admin",
		Protocol:     "http",
		SessionID:    sessionID,
		UserID:       systemOwner,
		AuthUser:     "admin-http",
		RemoteAddr:   liveHTTPRemoteAddr(r),
		LocalAddr:    liveHTTPLocalAddr(r),
		LoginType:    "http",
		UserAgent:    r.UserAgent(),
		Admin:        true,
	})
	finishRequest := s.startLiveSFTPRequest(sessionID, r.Method, pathLabel)
	liveWriter := &liveHTTPResponseWriter{
		ResponseWriter: w,
		srv:            s,
		sessionID:      sessionID,
		path:           pathLabel,
	}
	defer func() {
		liveWriter.finish()
		finishRequest(nil)
		s.finishLiveSession(sessionID)
		s.finishLiveConnection(connID)
	}()
	h.ServeHTTP(liveWriter, r)
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

func cleanAdminExplorerNewName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("new name is required")
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("invalid new name")
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("new name cannot contain path separators")
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("invalid new name")
	}
	return name, nil
}

func (s *Server) adminExplorerFullPath(relPath string) (string, error) {
	fullPath := filepath.Join(s.absUploadDir, filepath.FromSlash(relPath))
	fullPath = filepath.Clean(fullPath)
	rootWithSep := s.absUploadDir + string(filepath.Separator)
	if fullPath != s.absUploadDir && strings.HasPrefix(fullPath+string(filepath.Separator), rootWithSep) {
		return fullPath, nil
	}
	return "", fmt.Errorf("invalid path")
}

func (s *Server) decodeAdminExplorerRename(r *http.Request) (oldRel, newRel, newName string, err error) {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()

	var payload adminExplorerRenameRequest
	if err := dec.Decode(&payload); err != nil {
		return "", "", "", fmt.Errorf("decode request body: %w", err)
	}

	oldRel, err = cleanRelativePath(payload.Path)
	if err != nil {
		return "", "", "", err
	}
	if oldRel == "." {
		return "", "", "", fmt.Errorf("path is required")
	}

	newName, err = cleanAdminExplorerNewName(payload.NewName)
	if err != nil {
		return "", "", "", err
	}

	parent := filepath.ToSlash(filepath.Dir(oldRel))
	if parent == "." {
		newRel = newName
	} else {
		newRel = filepath.ToSlash(filepath.Join(parent, newName))
	}
	if newRel == oldRel {
		return "", "", "", fmt.Errorf("new name matches current name")
	}
	if clean, err := cleanRelativePath(newRel); err != nil {
		return "", "", "", err
	} else if clean != newRel {
		return "", "", "", fmt.Errorf("invalid new path")
	}

	return oldRel, newRel, newName, nil
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

	fullPath, err := s.adminExplorerFullPath(relPath)
	if err != nil {
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

func (s *Server) handleAdminExplorerRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	oldRel, newRel, newName, err := s.decodeAdminExplorerRename(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	oldFullPath, err := s.adminExplorerFullPath(oldRel)
	if err != nil {
		http.Error(w, "invalid path", http.StatusForbidden)
		return
	}
	newFullPath, err := s.adminExplorerFullPath(newRel)
	if err != nil {
		http.Error(w, "invalid target path", http.StatusForbidden)
		return
	}

	info, err := os.Stat(oldFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "path not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat(newFullPath); err == nil {
		http.Error(w, "target already exists", http.StatusConflict)
		return
	} else if !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists, err := s.store.PathMetadataExists(newRel); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if exists {
		http.Error(w, "target metadata already exists", http.StatusConflict)
		return
	}

	owner, _ := s.store.GetFileOwner(oldRel)
	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.RenamePath(oldRel, newRel); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.store.LogEvent(EventRename, systemOwner, "admin-http", nil,
		"path", oldRel,
		"target", newRel,
		"scope", "explorer",
		"owner", owner)
	s.logger.Info("admin explorer renamed path",
		"path", oldRel,
		"target", newRel,
		"is_dir", info.IsDir(),
		"owner", shortID(owner))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"path":     oldRel,
		"target":   newRel,
		"new_name": newName,
		"is_dir":   info.IsDir(),
		"owner":    owner,
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
