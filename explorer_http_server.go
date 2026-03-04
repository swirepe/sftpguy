package main

import (
	"errors"
	"net/http"
	"time"
)

func (s *Server) ensureExplorerService() (*explorerService, error) {
	s.explorerMu.Lock()
	defer s.explorerMu.Unlock()

	if s.explorerSvc != nil {
		return s.explorerSvc, nil
	}

	svc, err := newExplorerService(s)
	if err != nil {
		return nil, err
	}
	s.explorerSvc = svc
	return svc, nil
}

func (s *Server) ExplorerCookieNames() (identityCookie, csrfCookie string) {
	return explorerCookieNames(s.cfg)
}

func (s *Server) ExplorerHandler() (http.Handler, error) {
	svc, err := s.ensureExplorerService()
	if err != nil {
		return nil, err
	}
	return svc.Handler(), nil
}

func (s *Server) ListenExplorerHTTP() error {
	if s.cfg.ExplorerHTTP == "" {
		return nil
	}

	h, err := s.ExplorerHandler()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              s.cfg.ExplorerHTTP,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.explorerMu.Lock()
	s.explorerShutdown = httpServer.Shutdown
	s.explorerMu.Unlock()
	defer func() {
		s.explorerMu.Lock()
		s.explorerShutdown = nil
		s.explorerMu.Unlock()
	}()

	idCookie, csrfCookie := s.ExplorerCookieNames()
	s.logger.Info("explorer http online",
		"addr", s.cfg.ExplorerHTTP,
		"root", s.absUploadDir,
		"max_file_size", s.cfg.ExplorerMaxFileSize,
		"cookie_identity", idCookie,
		"cookie_csrf", csrfCookie,
	)
	if err := httpServer.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) ExplorerRuntimeSnapshot() map[string]any {
	identityCookie, csrfCookie := s.ExplorerCookieNames()
	return map[string]any{
		"enabled":             s.cfg.ExplorerHTTP != "",
		"addr":                s.cfg.ExplorerHTTP,
		"root":                s.absUploadDir,
		"max_file_size":       s.cfg.ExplorerMaxFileSize,
		"max_file_size_human": explorerMaxUploadLabel(s.cfg.ExplorerMaxFileSize),
		"identity_cookie":     identityCookie,
		"csrf_cookie":         csrfCookie,
	}
}
