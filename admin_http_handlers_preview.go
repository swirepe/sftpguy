package main

import (
	"net/http"
	"net/url"
	"strings"

	"sftpguy/internal/adminexplorer"
	"sftpguy/internal/adminpreview"
)

func (s *Server) getAdminPreviewer() (*adminpreview.Previewer, error) {
	s.adminPreviewMu.Lock()
	defer s.adminPreviewMu.Unlock()

	if s.adminPreview != nil || s.adminPreviewErr != nil {
		return s.adminPreview, s.adminPreviewErr
	}

	previewer, err := adminpreview.New(adminpreview.Config{
		RootDir: s.absUploadDir,
		LookupFileDetails: func(relPath string) (adminpreview.FileDetails, error) {
			meta, err := s.store.GetFileAdminMeta(relPath)
			if err != nil {
				return adminpreview.FileDetails{}, err
			}
			return adminpreview.FileDetails{
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
		s.adminPreviewErr = err
		return nil, err
	}

	s.adminPreview = previewer
	return s.adminPreview, nil
}

func (s *Server) adminV2PreviewURLOptions() adminpreview.URLOptions {
	return adminpreview.URLOptions{
		Variant:  "admin-v2",
		Unlocked: true,
		DownloadURL: func(relPath string) string {
			return adminpreview.ExplorerURL(adminexplorer.DefaultBasePath, relPath)
		},
		ThumbnailURL: adminpreview.ThumbnailAPIURL,
	}
}

func (s *Server) handleAdminPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	previewer, err := s.getAdminPreviewer()
	if err != nil {
		http.Error(w, "preview init failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	previewer.ServePreviewJSON(w, r, r.URL.Query().Get("path"), s.adminV2PreviewURLOptions())
}

func (s *Server) handleAdminThumbnail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	previewer, err := s.getAdminPreviewer()
	if err != nil {
		http.Error(w, "preview init failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	previewer.ServeThumbnail(w, r, r.URL.Query().Get("path"), true)
}
