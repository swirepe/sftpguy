package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"sftpguy/internal/adminhttp"
)

func (s *Server) ListenAdminHTTP() error {
	return adminhttp.Listen(s.adminHTTPDeps())
}

func (s *Server) adminHTTPDeps() *adminHTTPDeps {
	return &adminHTTPDeps{srv: s}
}

type adminHTTPDeps struct {
	srv *Server
}

func (d *adminHTTPDeps) AdminHTTPConfig() adminhttp.Config {
	cfg := adminhttp.Config{
		Addr:                d.srv.cfg.AdminHTTP,
		Token:               d.srv.cfg.AdminHTTPToken,
		TokenCookieName:     adminhttp.DefaultTokenCookieName,
		IssueOneTimeToken:   d.srv.issueAdminOneTimeLoginToken,
		ConsumeOneTimeToken: d.srv.consumeAdminOneTimeLoginToken,
		StatsSource:         d,
	}
	if d.srv.metrics != nil {
		cfg.WrapHandler = d.srv.metrics.WrapAdminHandler
	}
	if d.srv.cfg.EnablePrometheus && d.srv.metrics != nil {
		cfg.MetricsPath = d.srv.cfg.PrometheusRoot
		cfg.MetricsHandler = d.srv.metrics.Handler()
	}
	return cfg
}

func (d *adminHTTPDeps) AdminHTTPHandlers() adminhttp.RouteHandlers {
	return adminhttp.RouteHandlers{
		Page:             d.srv.handleAdminPage,
		CSS:              d.srv.handleAdminCSS,
		JS:               d.srv.handleAdminJS,
		Explorer:         d.srv.handleAdminExplorer,
		Health:           adminhttp.HealthHandler(d),
		Summary:          adminhttp.SummaryHandler(d),
		Users:            d.srv.handleAdminUsers,
		User:             d.srv.handleAdminUser,
		Files:            d.srv.handleAdminFiles,
		FileSearch:       d.srv.handleAdminFileSearch,
		Audit:            d.srv.handleAdminAudit,
		AuthAttempts:     d.srv.handleAdminAuthAttempts,
		Events:           d.srv.handleAdminEvents,
		EventStream:      d.srv.handleAdminEventStream,
		Insights:         d.srv.handleAdminInsights,
		Sessions:         d.srv.handleAdminSessions,
		SessionTimeline:  d.srv.handleAdminSessionTimeline,
		RecentUploads:    d.srv.handleAdminRecentUploads,
		Actor:            d.srv.handleAdminActor,
		SystemLog:        d.srv.handleAdminSystemLog,
		ParsedSystemLog:  d.srv.handleAdminParsedSystemLog,
		Banned:           d.srv.handleAdminBanned,
		BanIP:            d.srv.handleAdminBanIP,
		UnbanIP:          d.srv.handleAdminUnbanIP,
		Maintenance:      d.srv.handleAdminMaintenance,
		MaintenanceRun:   d.srv.handleAdminMaintenanceRun,
		MaintenanceLogs:  d.srv.handleAdminMaintenanceLogs,
		BadFiles:         d.srv.handleAdminBadFiles,
		MarkBadFile:      d.srv.handleAdminMarkBadFile,
		IPLists:          d.srv.handleAdminIPLists,
		AdminKeys:        d.srv.handleAdminKeys,
		IPListTest:       d.srv.handleAdminIPListTest,
		IPList:           d.srv.handleAdminIPList,
		SelfTest:         d.srv.handleAdminSelfTest,
		SelfTestRun:      d.srv.handleAdminSelfTestRun,
		ExplorerDelete:   d.srv.handleAdminExplorerDelete,
		ExplorerBanOwner: d.srv.handleAdminExplorerBanOwner,
		OneTimeLoginURL:  d.srv.handleAdminOneTimeLoginURL,
	}
}

func (d *adminHTTPDeps) SetAdminShutdown(fn func(context.Context) error) {
	d.srv.adminShutdownMu.Lock()
	d.srv.adminShutdown = fn
	d.srv.adminShutdownMu.Unlock()
}

func (d *adminHTTPDeps) ClearAdminShutdown() {
	d.srv.adminShutdownMu.Lock()
	d.srv.adminShutdown = nil
	d.srv.adminShutdownMu.Unlock()
}

func (d *adminHTTPDeps) Logger() *slog.Logger {
	return d.srv.logger
}

func (d *adminHTTPDeps) ArchiveName() string {
	return d.srv.cfg.Name
}

func (d *adminHTTPDeps) AppVersion() string {
	return AppVersion
}

func (d *adminHTTPDeps) SSHPort() int {
	return d.srv.cfg.Port
}

func (d *adminHTTPDeps) AdminHTTPAddr() string {
	return d.srv.cfg.AdminHTTP
}

func (d *adminHTTPDeps) Uptime() time.Duration {
	return d.srv.Uptime()
}

func (d *adminHTTPDeps) ContributorThreshold() int64 {
	return d.srv.cfg.ContributorThreshold
}

func (d *adminHTTPDeps) BannerStats(threshold int64) (users, contributors, files, bytes uint64) {
	return d.srv.store.GetBannerStats(threshold)
}

func (d *adminHTTPDeps) DirectoryCount() (int, error) {
	return d.srv.store.GetDirectoryCount()
}

func (d *adminHTTPDeps) FormatBytes(n int64) string {
	return formatBytes(n)
}

func (d *adminHTTPDeps) StatsSnapshot() adminhttp.StatsSnapshot {
	if d == nil || d.srv == nil {
		return adminhttp.StatsSnapshot{}
	}
	if d.srv.metrics != nil {
		snap := d.srv.metrics.StatsSnapshot()
		if snap.UptimeSeconds == 0 {
			snap.UptimeSeconds = d.srv.Uptime().Seconds()
		}
		return snap
	}

	u, c, f, b := d.srv.store.GetBannerStats(d.srv.cfg.ContributorThreshold)
	dirCount, _ := d.srv.store.GetDirectoryCount()

	return adminhttp.StatsSnapshot{
		UptimeSeconds:     d.srv.Uptime().Seconds(),
		UsersTotal:        float64(u),
		ContributorsTotal: float64(c),
		FilesTotal:        float64(f),
		DirectoriesTotal:  float64(dirCount),
		StoredBytes:       float64(b),
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(adminHTML)
}

func (s *Server) handleAdminCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(adminCSS)
}

func (s *Server) handleAdminJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(adminJS)
}
