package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

func (s *Server) ListenAdminHTTP() error {
	if s.cfg.AdminHTTP == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("/admin", s.adminAuth(s.handleAdminPage))
	mux.HandleFunc("/admin/api/health", s.adminAuth(s.handleAdminHealth))
	mux.HandleFunc("/admin/api/summary", s.adminAuth(s.handleAdminSummary))
	mux.HandleFunc("/admin/api/users", s.adminAuth(s.handleAdminUsers))
	mux.HandleFunc("/admin/api/users/", s.adminAuth(s.handleAdminUser))
	mux.HandleFunc("/admin/api/files", s.adminAuth(s.handleAdminFiles))
	mux.HandleFunc("/admin/api/files/search", s.adminAuth(s.handleAdminFileSearch))
	mux.HandleFunc("/admin/api/audit", s.adminAuth(s.handleAdminAudit))
	mux.HandleFunc("/admin/api/auth-attempts", s.adminAuth(s.handleAdminAuthAttempts))
	mux.HandleFunc("/admin/api/events", s.adminAuth(s.handleAdminEvents))
	mux.HandleFunc("/admin/api/events/stream", s.adminAuth(s.handleAdminEventStream))
	mux.HandleFunc("/admin/api/insights", s.adminAuth(s.handleAdminInsights))
	mux.HandleFunc("/admin/api/sessions", s.adminAuth(s.handleAdminSessions))
	mux.HandleFunc("/admin/api/sessions/", s.adminAuth(s.handleAdminSessionTimeline))
	mux.HandleFunc("/admin/api/uploads/recent", s.adminAuth(s.handleAdminRecentUploads))
	mux.HandleFunc("/admin/api/actor", s.adminAuth(s.handleAdminActor))
	mux.HandleFunc("/admin/api/system-log", s.adminAuth(s.handleAdminSystemLog))
	mux.HandleFunc("/admin/api/system-log/parsed", s.adminAuth(s.handleAdminParsedSystemLog))
	mux.HandleFunc("/admin/api/banned", s.adminAuth(s.handleAdminBanned))
	mux.HandleFunc("/admin/api/banned/ip", s.adminAuth(s.handleAdminBanIP))
	mux.HandleFunc("/admin/api/banned/ip/", s.adminAuth(s.handleAdminUnbanIP))

	httpServer := &http.Server{
		Addr:              s.cfg.AdminHTTP,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.adminShutdownMu.Lock()
	s.adminShutdown = httpServer.Shutdown
	s.adminShutdownMu.Unlock()
	defer func() {
		s.adminShutdownMu.Lock()
		s.adminShutdown = nil
		s.adminShutdownMu.Unlock()
	}()

	s.logger.Info("admin http console online", "addr", s.cfg.AdminHTTP, "token_required", s.cfg.AdminHTTPToken != "")
	if err := httpServer.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminHTTPToken == "" {
			next(w, r)
			return
		}

		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) || strings.TrimSpace(strings.TrimPrefix(header, prefix)) != s.cfg.AdminHTTPToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sftpguy-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(adminHTML))
}
