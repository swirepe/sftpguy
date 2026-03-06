package adminhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Addr  string
	Token string
}

type RouteHandlers struct {
	Page            http.HandlerFunc
	CSS             http.HandlerFunc
	JS              http.HandlerFunc
	Health          http.HandlerFunc
	Summary         http.HandlerFunc
	Users           http.HandlerFunc
	User            http.HandlerFunc
	Files           http.HandlerFunc
	FileSearch      http.HandlerFunc
	Audit           http.HandlerFunc
	AuthAttempts    http.HandlerFunc
	Events          http.HandlerFunc
	EventStream     http.HandlerFunc
	Insights        http.HandlerFunc
	Sessions        http.HandlerFunc
	SessionTimeline http.HandlerFunc
	RecentUploads   http.HandlerFunc
	Actor           http.HandlerFunc
	SystemLog       http.HandlerFunc
	ParsedSystemLog http.HandlerFunc
	Banned          http.HandlerFunc
	BanIP           http.HandlerFunc
	UnbanIP         http.HandlerFunc
	IPLists         http.HandlerFunc
	AdminKeys       http.HandlerFunc
	IPListTest      http.HandlerFunc
	IPList          http.HandlerFunc
	SelfTest        http.HandlerFunc
	SelfTestRun     http.HandlerFunc
}

type Deps interface {
	AdminHTTPConfig() Config
	AdminHTTPHandlers() RouteHandlers
	SetAdminShutdown(func(context.Context) error)
	ClearAdminShutdown()
	Logger() *slog.Logger
}

func Listen(deps Deps) error {
	cfg := deps.AdminHTTPConfig()
	if cfg.Addr == "" {
		return nil
	}

	handlers := deps.AdminHTTPHandlers()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})

	register(mux, "/admin", cfg.Token, handlers.Page)
	register(mux, "/admin/static/admin.css", cfg.Token, handlers.CSS)
	register(mux, "/admin/static/admin.js", cfg.Token, handlers.JS)
	register(mux, "/admin/api/health", cfg.Token, handlers.Health)
	register(mux, "/admin/api/summary", cfg.Token, handlers.Summary)
	register(mux, "/admin/api/users", cfg.Token, handlers.Users)
	register(mux, "/admin/api/users/", cfg.Token, handlers.User)
	register(mux, "/admin/api/files", cfg.Token, handlers.Files)
	register(mux, "/admin/api/files/search", cfg.Token, handlers.FileSearch)
	register(mux, "/admin/api/audit", cfg.Token, handlers.Audit)
	register(mux, "/admin/api/auth-attempts", cfg.Token, handlers.AuthAttempts)
	register(mux, "/admin/api/events", cfg.Token, handlers.Events)
	register(mux, "/admin/api/events/stream", cfg.Token, handlers.EventStream)
	register(mux, "/admin/api/insights", cfg.Token, handlers.Insights)
	register(mux, "/admin/api/sessions", cfg.Token, handlers.Sessions)
	register(mux, "/admin/api/sessions/", cfg.Token, handlers.SessionTimeline)
	register(mux, "/admin/api/uploads/recent", cfg.Token, handlers.RecentUploads)
	register(mux, "/admin/api/actor", cfg.Token, handlers.Actor)
	register(mux, "/admin/api/system-log", cfg.Token, handlers.SystemLog)
	register(mux, "/admin/api/system-log/parsed", cfg.Token, handlers.ParsedSystemLog)
	register(mux, "/admin/api/banned", cfg.Token, handlers.Banned)
	register(mux, "/admin/api/banned/ip", cfg.Token, handlers.BanIP)
	register(mux, "/admin/api/banned/ip/", cfg.Token, handlers.UnbanIP)
	register(mux, "/admin/api/ip-lists", cfg.Token, handlers.IPLists)
	register(mux, "/admin/api/admin-keys", cfg.Token, handlers.AdminKeys)
	register(mux, "/admin/api/ip-lists/test", cfg.Token, handlers.IPListTest)
	register(mux, "/admin/api/ip-lists/", cfg.Token, handlers.IPList)
	register(mux, "/admin/api/self-test", cfg.Token, handlers.SelfTest)
	register(mux, "/admin/api/self-test/run", cfg.Token, handlers.SelfTestRun)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	deps.SetAdminShutdown(httpServer.Shutdown)
	defer deps.ClearAdminShutdown()

	deps.Logger().Info("admin http console online", "addr", cfg.Addr, "token_required", cfg.Token != "")
	if err := httpServer.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	return nil
}

func register(mux *http.ServeMux, path, token string, next http.HandlerFunc) {
	if next == nil {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "admin handler not configured", http.StatusNotImplemented)
		})
		return
	}
	mux.HandleFunc(path, auth(token, next))
}

func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(token) == "" {
			next(w, r)
			return
		}

		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) || strings.TrimSpace(strings.TrimPrefix(header, prefix)) != token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sftpguy-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
