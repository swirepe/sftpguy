package adminhttp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultTokenCookieName = "sftpguy_admin_token"
	OneTimeLoginPath       = "/admin/one-time-login"
	OneTimeLoginTokenParam = "token"
)

type Config struct {
	Addr                string
	Token               string
	TokenCookieName     string
	IssueOneTimeToken   func() (string, error)
	ConsumeOneTimeToken func(string) bool
}

type RouteHandlers struct {
	Page             http.HandlerFunc
	CSS              http.HandlerFunc
	JS               http.HandlerFunc
	Explorer         http.HandlerFunc
	Health           http.HandlerFunc
	Summary          http.HandlerFunc
	Users            http.HandlerFunc
	User             http.HandlerFunc
	Files            http.HandlerFunc
	FileSearch       http.HandlerFunc
	Audit            http.HandlerFunc
	AuthAttempts     http.HandlerFunc
	Events           http.HandlerFunc
	EventStream      http.HandlerFunc
	Insights         http.HandlerFunc
	Sessions         http.HandlerFunc
	SessionTimeline  http.HandlerFunc
	RecentUploads    http.HandlerFunc
	Actor            http.HandlerFunc
	SystemLog        http.HandlerFunc
	ParsedSystemLog  http.HandlerFunc
	Banned           http.HandlerFunc
	BanIP            http.HandlerFunc
	UnbanIP          http.HandlerFunc
	Maintenance      http.HandlerFunc
	MaintenanceRun   http.HandlerFunc
	MaintenanceLogs  http.HandlerFunc
	BadFiles         http.HandlerFunc
	MarkBadFile      http.HandlerFunc
	IPLists          http.HandlerFunc
	AdminKeys        http.HandlerFunc
	IPListTest       http.HandlerFunc
	IPList           http.HandlerFunc
	SelfTest         http.HandlerFunc
	SelfTestRun      http.HandlerFunc
	ExplorerDelete   http.HandlerFunc
	ExplorerBanOwner http.HandlerFunc
	OneTimeLoginURL  http.HandlerFunc
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
	mux.HandleFunc(OneTimeLoginPath, oneTimeLogin(cfg))

	register(mux, "/admin", cfg, handlers.Page)
	register(mux, "/admin/explorer", cfg, handlers.Explorer)
	register(mux, "/admin/explorer/", cfg, handlers.Explorer)
	register(mux, "/admin/static/admin.css", cfg, handlers.CSS)
	register(mux, "/admin/static/admin.js", cfg, handlers.JS)
	register(mux, "/admin/api/health", cfg, handlers.Health)
	register(mux, "/admin/api/summary", cfg, handlers.Summary)
	register(mux, "/admin/api/users", cfg, handlers.Users)
	register(mux, "/admin/api/users/", cfg, handlers.User)
	register(mux, "/admin/api/files", cfg, handlers.Files)
	register(mux, "/admin/api/files/search", cfg, handlers.FileSearch)
	register(mux, "/admin/api/audit", cfg, handlers.Audit)
	register(mux, "/admin/api/auth-attempts", cfg, handlers.AuthAttempts)
	register(mux, "/admin/api/events", cfg, handlers.Events)
	register(mux, "/admin/api/events/stream", cfg, handlers.EventStream)
	register(mux, "/admin/api/insights", cfg, handlers.Insights)
	register(mux, "/admin/api/sessions", cfg, handlers.Sessions)
	register(mux, "/admin/api/sessions/", cfg, handlers.SessionTimeline)
	register(mux, "/admin/api/uploads/recent", cfg, handlers.RecentUploads)
	register(mux, "/admin/api/actor", cfg, handlers.Actor)
	register(mux, "/admin/api/system-log", cfg, handlers.SystemLog)
	register(mux, "/admin/api/system-log/parsed", cfg, handlers.ParsedSystemLog)
	register(mux, "/admin/api/banned", cfg, handlers.Banned)
	register(mux, "/admin/api/banned/ip", cfg, handlers.BanIP)
	register(mux, "/admin/api/banned/ip/", cfg, handlers.UnbanIP)
	register(mux, "/admin/api/maintenance", cfg, handlers.Maintenance)
	register(mux, "/admin/api/maintenance/run", cfg, handlers.MaintenanceRun)
	register(mux, "/admin/api/maintenance/logs", cfg, handlers.MaintenanceLogs)
	register(mux, "/admin/api/maintenance/bad-files", cfg, handlers.BadFiles)
	register(mux, "/admin/api/maintenance/mark-bad", cfg, handlers.MarkBadFile)
	register(mux, "/admin/api/ip-lists", cfg, handlers.IPLists)
	register(mux, "/admin/api/admin-keys", cfg, handlers.AdminKeys)
	register(mux, "/admin/api/ip-lists/test", cfg, handlers.IPListTest)
	register(mux, "/admin/api/ip-lists/", cfg, handlers.IPList)
	register(mux, "/admin/api/self-test", cfg, handlers.SelfTest)
	register(mux, "/admin/api/self-test/run", cfg, handlers.SelfTestRun)
	register(mux, "/admin/api/explorer/delete", cfg, handlers.ExplorerDelete)
	register(mux, "/admin/api/explorer/ban-owner", cfg, handlers.ExplorerBanOwner)
	register(mux, "/admin/api/one-time-login", cfg, handlers.OneTimeLoginURL)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	deps.SetAdminShutdown(httpServer.Shutdown)
	defer deps.ClearAdminShutdown()

	deps.Logger().Info("admin http console online", "addr", cfg.Addr, "token_required", cfg.Token != "")
	if startupURL, err := startupOneTimeLoginURL(cfg); err != nil {
		deps.Logger().Warn("failed to generate one-time admin login URL", "err", err)
	} else if startupURL != "" {
		deps.Logger().Info("admin one-time login URL (single-use)", "url", startupURL)
	}
	if err := httpServer.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	return nil
}

func register(mux *http.ServeMux, path string, cfg Config, next http.HandlerFunc) {
	if next == nil {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "admin handler not configured", http.StatusNotImplemented)
		})
		return
	}
	mux.HandleFunc(path, auth(cfg, next))
}

func auth(cfg Config, next http.HandlerFunc) http.HandlerFunc {
	token := strings.TrimSpace(cfg.Token)
	cookieName := tokenCookieName(cfg.TokenCookieName)
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next(w, r)
			return
		}

		headerToken := bearerToken(r.Header.Get("Authorization"))
		cookieToken := cookieValue(r, cookieName)
		if headerToken != token && cookieToken != token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sftpguy-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func oneTimeLogin(cfg Config) http.HandlerFunc {
	adminToken := strings.TrimSpace(cfg.Token)
	cookieName := tokenCookieName(cfg.TokenCookieName)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if adminToken == "" || cfg.ConsumeOneTimeToken == nil {
			http.NotFound(w, r)
			return
		}

		oneTimeToken := strings.TrimSpace(r.URL.Query().Get(OneTimeLoginTokenParam))
		if oneTimeToken == "" || !cfg.ConsumeOneTimeToken(oneTimeToken) {
			http.Error(w, "invalid or expired one-time login token", http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    adminToken,
			Path:     "/admin",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/admin", http.StatusFound)
	}
}

func startupOneTimeLoginURL(cfg Config) (string, error) {
	adminToken := strings.TrimSpace(cfg.Token)
	if adminToken == "" || cfg.IssueOneTimeToken == nil {
		return "", nil
	}

	oneTimeToken, err := cfg.IssueOneTimeToken()
	if err != nil {
		return "", err
	}

	host := startupURLHost(cfg.Addr)
	if host == "" {
		return "", nil
	}
	return BuildOneTimeLoginURL("http", host, oneTimeToken), nil
}

func startupURLHost(addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr)
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func BuildOneTimeLoginURL(scheme, host, token string) string {
	if strings.TrimSpace(host) == "" {
		return ""
	}
	if strings.TrimSpace(scheme) == "" {
		scheme = "http"
	}
	loginURL := url.URL{
		Scheme: strings.TrimSpace(scheme),
		Host:   strings.TrimSpace(host),
		Path:   OneTimeLoginPath,
	}
	q := loginURL.Query()
	q.Set(OneTimeLoginTokenParam, strings.TrimSpace(token))
	loginURL.RawQuery = q.Encode()
	return loginURL.String()
}

func tokenCookieName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return DefaultTokenCookieName
	}
	return name
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}
