package adminhttp

import (
	"net/http"
	"sync"
	"time"

	"github.com/arl/statsviz"
)

const adminStatsPath = "/admin/stats"

type StatsSource interface {
	StatsSnapshot() StatsSnapshot
}

type StatsSnapshot struct {
	UptimeSeconds float64

	UsersTotal             float64
	ContributorsTotal      float64
	FilesTotal             float64
	DirectoriesTotal       float64
	StoredBytes            float64
	ShadowBannedUsersTotal float64
	BannedIPsTotal         float64

	SSHConnectionsActive                 float64
	SSHConnectionAcceptsTotal            float64
	SSHConnectionAcceptsThrottledTotal   float64
	SSHHandshakesSuccessTotal            float64
	SSHHandshakesFailureTotal            float64
	AuthAttemptsNoneTotal                float64
	AuthAttemptsPublicKeyTotal           float64
	AuthAttemptsKeyboardInteractiveTotal float64
	AuthAttemptsAdminPublicKeyTotal      float64

	SessionsActive                float64
	SessionsPubKeyTotal           float64
	SessionsPasswordTotal         float64
	SessionsAdminSFTPTotal        float64
	SessionsBannedTotal           float64
	SessionDurationAverageSeconds float64

	SFTPRequestsInFlight      float64
	SFTPReadSuccessTotal      float64
	SFTPReadFailureTotal      float64
	SFTPWriteSuccessTotal     float64
	SFTPWriteFailureTotal     float64
	SFTPPermissionDeniedTotal float64
	SFTPNotFoundTotal         float64
	SFTPUnsupportedTotal      float64
	SFTPFailureTotal          float64
	SFTPErrorTotal            float64
	SFTPListTotal             float64
	SFTPStatTotal             float64
	SFTPLstatTotal            float64
	SFTPMkdirTotal            float64
	SFTPRemoveTotal           float64
	SFTPRmdirTotal            float64
	SFTPRenameTotal           float64
	SFTPSetstatTotal          float64
	SFTPRequestAverageSeconds float64

	SFTPUploadTransfersTotal   float64
	SFTPDownloadTransfersTotal float64
	SFTPUploadBytesTotal       float64
	SFTPDownloadBytesTotal     float64
	SFTPTransferAverageBytes   float64

	PermissionDenialsTotal               float64
	PermissionDeniedContributorLockTotal float64
	PermissionDeniedNotOwnerTotal        float64
	PermissionDeniedQuotaTotal           float64
	PermissionDeniedPathTraversalTotal   float64

	AdminHTTPInFlight               float64
	AdminHTTPRequestTotal           float64
	AdminHTTPDurationAverageSeconds float64
}

func RegisterStatsViz(mux *http.ServeMux, cfg Config) error {
	opts := []statsviz.Option{
		statsviz.Root(adminStatsPath),
		statsviz.SendFrequency(750 * time.Millisecond),
	}

	plotOpts, err := statsvizPlotOptions(cfg.StatsSource)
	if err != nil {
		return err
	}
	opts = append(opts, plotOpts...)

	srv, err := statsviz.NewServer(opts...)
	if err != nil {
		return err
	}

	register(mux, adminStatsPath, cfg, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, adminStatsPath+"/", http.StatusFound)
	})
	registerHandler(mux, adminStatsPath+"/", cfg, srv.Index())
	registerHandler(mux, adminStatsPath+"/ws", cfg, http.HandlerFunc(srv.Ws()))
	return nil
}

type statsSnapshotter struct {
	source StatsSource
	ttl    time.Duration

	mu   sync.Mutex
	at   time.Time
	snap StatsSnapshot
}

func newStatsSnapshotter(source StatsSource, ttl time.Duration) *statsSnapshotter {
	return &statsSnapshotter{
		source: source,
		ttl:    ttl,
	}
}

func (s *statsSnapshotter) snapshot() StatsSnapshot {
	if s == nil || s.source == nil {
		return StatsSnapshot{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if !s.at.IsZero() && now.Sub(s.at) < s.ttl {
		return s.snap
	}

	s.snap = s.source.StatsSnapshot()
	s.at = now
	return s.snap
}

func statsvizPlotOptions(source StatsSource) ([]statsviz.Option, error) {
	if source == nil {
		return nil, nil
	}

	snapshotter := newStatsSnapshotter(source, 750*time.Millisecond)
	plot := func(cfg statsviz.TimeSeriesPlotConfig) (statsviz.Option, error) {
		tsp, err := cfg.Build()
		if err != nil {
			return nil, err
		}
		return statsviz.TimeseriesPlot(tsp), nil
	}

	var opts []statsviz.Option
	appendPlot := func(cfg statsviz.TimeSeriesPlotConfig) error {
		opt, err := plot(cfg)
		if err != nil {
			return err
		}
		opts = append(opts, opt)
		return nil
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_archive_totals",
		Title:      "Archive Totals",
		YAxisTitle: "count",
		InfoText:   "Current archive inventory sizes and contributor counts.",
		Series: []statsviz.TimeSeries{
			{Name: "users", GetValue: func() float64 { return snapshotter.snapshot().UsersTotal }},
			{Name: "contributors", GetValue: func() float64 { return snapshotter.snapshot().ContributorsTotal }},
			{Name: "files", GetValue: func() float64 { return snapshotter.snapshot().FilesTotal }},
			{Name: "directories", GetValue: func() float64 { return snapshotter.snapshot().DirectoriesTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:            "sftpguy_archive_bytes",
		Title:           "Archive Footprint",
		YAxisTitle:      "bytes",
		YAxisTickSuffix: " B",
		InfoText:        "Total regular-file bytes currently tracked by the archive.",
		Series: []statsviz.TimeSeries{
			{Name: "stored bytes", Unitfmt: "~s", GetValue: func() float64 { return snapshotter.snapshot().StoredBytes }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_archive_access_control",
		Title:      "Archive Access Control",
		YAxisTitle: "count",
		InfoText:   "Current shadow-banned users and banned IPs.",
		Series: []statsviz.TimeSeries{
			{Name: "shadow banned users", GetValue: func() float64 { return snapshotter.snapshot().ShadowBannedUsersTotal }},
			{Name: "banned IPs", GetValue: func() float64 { return snapshotter.snapshot().BannedIPsTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_ssh_activity",
		Title:      "SSH Activity",
		YAxisTitle: "count",
		InfoText:   "Current and cumulative SSH connection activity.",
		Series: []statsviz.TimeSeries{
			{Name: "active", GetValue: func() float64 { return snapshotter.snapshot().SSHConnectionsActive }},
			{Name: "accepted", GetValue: func() float64 { return snapshotter.snapshot().SSHConnectionAcceptsTotal }},
			{Name: "throttled accepts", GetValue: func() float64 { return snapshotter.snapshot().SSHConnectionAcceptsThrottledTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_ssh_auth",
		Title:      "SSH Handshakes And Auth",
		YAxisTitle: "count",
		InfoText:   "Handshake results and authentication method totals.",
		Series: []statsviz.TimeSeries{
			{Name: "handshake success", GetValue: func() float64 { return snapshotter.snapshot().SSHHandshakesSuccessTotal }},
			{Name: "handshake failure", GetValue: func() float64 { return snapshotter.snapshot().SSHHandshakesFailureTotal }},
			{Name: "publickey auth", GetValue: func() float64 { return snapshotter.snapshot().AuthAttemptsPublicKeyTotal }},
			{Name: "keyboard-interactive auth", GetValue: func() float64 { return snapshotter.snapshot().AuthAttemptsKeyboardInteractiveTotal }},
			{Name: "no-auth probes", GetValue: func() float64 { return snapshotter.snapshot().AuthAttemptsNoneTotal }},
			{Name: "admin publickey auth", GetValue: func() float64 { return snapshotter.snapshot().AuthAttemptsAdminPublicKeyTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_sessions",
		Title:      "Sessions",
		YAxisTitle: "count",
		InfoText:   "Active sessions and cumulative session mix by login type.",
		Series: []statsviz.TimeSeries{
			{Name: "active", GetValue: func() float64 { return snapshotter.snapshot().SessionsActive }},
			{Name: "pubkey", GetValue: func() float64 { return snapshotter.snapshot().SessionsPubKeyTotal }},
			{Name: "password", GetValue: func() float64 { return snapshotter.snapshot().SessionsPasswordTotal }},
			{Name: "admin sftp", GetValue: func() float64 { return snapshotter.snapshot().SessionsAdminSFTPTotal }},
			{Name: "banned sessions", GetValue: func() float64 { return snapshotter.snapshot().SessionsBannedTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:            "sftpguy_session_duration",
		Title:           "Average Session Duration",
		YAxisTitle:      "seconds",
		YAxisTickSuffix: " s",
		InfoText:        "Average completed session duration observed since process start.",
		Series: []statsviz.TimeSeries{
			{Name: "avg duration", Unitfmt: ".2f", GetValue: func() float64 { return snapshotter.snapshot().SessionDurationAverageSeconds }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_sftp_requests",
		Title:      "SFTP Requests",
		YAxisTitle: "count",
		InfoText:   "In-flight requests plus read and write success/failure totals.",
		Series: []statsviz.TimeSeries{
			{Name: "in flight", GetValue: func() float64 { return snapshotter.snapshot().SFTPRequestsInFlight }},
			{Name: "read success", GetValue: func() float64 { return snapshotter.snapshot().SFTPReadSuccessTotal }},
			{Name: "read failure", GetValue: func() float64 { return snapshotter.snapshot().SFTPReadFailureTotal }},
			{Name: "write success", GetValue: func() float64 { return snapshotter.snapshot().SFTPWriteSuccessTotal }},
			{Name: "write failure", GetValue: func() float64 { return snapshotter.snapshot().SFTPWriteFailureTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_sftp_outcomes",
		Title:      "SFTP Outcomes",
		YAxisTitle: "count",
		InfoText:   "Outcome totals across all SFTP requests.",
		Series: []statsviz.TimeSeries{
			{Name: "permission denied", GetValue: func() float64 { return snapshotter.snapshot().SFTPPermissionDeniedTotal }},
			{Name: "not found", GetValue: func() float64 { return snapshotter.snapshot().SFTPNotFoundTotal }},
			{Name: "unsupported", GetValue: func() float64 { return snapshotter.snapshot().SFTPUnsupportedTotal }},
			{Name: "failure", GetValue: func() float64 { return snapshotter.snapshot().SFTPFailureTotal }},
			{Name: "error", GetValue: func() float64 { return snapshotter.snapshot().SFTPErrorTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_sftp_browse_ops",
		Title:      "SFTP Browse And Metadata",
		YAxisTitle: "count",
		InfoText:   "Directory listings and metadata lookups across SFTP sessions.",
		Series: []statsviz.TimeSeries{
			{Name: "list", GetValue: func() float64 { return snapshotter.snapshot().SFTPListTotal }},
			{Name: "stat/fstat", GetValue: func() float64 { return snapshotter.snapshot().SFTPStatTotal }},
			{Name: "lstat", GetValue: func() float64 { return snapshotter.snapshot().SFTPLstatTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_sftp_mutations",
		Title:      "SFTP Mutations",
		YAxisTitle: "count",
		InfoText:   "Mutation requests observed across uploads, renames, and deletes.",
		Series: []statsviz.TimeSeries{
			{Name: "mkdir", GetValue: func() float64 { return snapshotter.snapshot().SFTPMkdirTotal }},
			{Name: "rename", GetValue: func() float64 { return snapshotter.snapshot().SFTPRenameTotal }},
			{Name: "remove", GetValue: func() float64 { return snapshotter.snapshot().SFTPRemoveTotal }},
			{Name: "rmdir", GetValue: func() float64 { return snapshotter.snapshot().SFTPRmdirTotal }},
			{Name: "setstat", GetValue: func() float64 { return snapshotter.snapshot().SFTPSetstatTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:            "sftpguy_sftp_request_latency",
		Title:           "Average SFTP Request Duration",
		YAxisTitle:      "milliseconds",
		YAxisTickSuffix: " ms",
		InfoText:        "Average SFTP request duration observed since process start.",
		Series: []statsviz.TimeSeries{
			{Name: "avg duration", Unitfmt: ".2f", GetValue: func() float64 { return snapshotter.snapshot().SFTPRequestAverageSeconds * 1000 }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_transfers",
		Title:      "Transfers",
		YAxisTitle: "count",
		InfoText:   "Completed upload and download transfer counts.",
		Series: []statsviz.TimeSeries{
			{Name: "uploads", GetValue: func() float64 { return snapshotter.snapshot().SFTPUploadTransfersTotal }},
			{Name: "downloads", GetValue: func() float64 { return snapshotter.snapshot().SFTPDownloadTransfersTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:            "sftpguy_transfer_volume",
		Title:           "Transfer Volume",
		YAxisTitle:      "bytes",
		YAxisTickSuffix: " B",
		InfoText:        "Cumulative bytes transferred and the average completed transfer size.",
		Series: []statsviz.TimeSeries{
			{Name: "upload bytes", Unitfmt: "~s", GetValue: func() float64 { return snapshotter.snapshot().SFTPUploadBytesTotal }},
			{Name: "download bytes", Unitfmt: "~s", GetValue: func() float64 { return snapshotter.snapshot().SFTPDownloadBytesTotal }},
			{Name: "avg transfer size", Unitfmt: "~s", GetValue: func() float64 { return snapshotter.snapshot().SFTPTransferAverageBytes }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_permission_denials",
		Title:      "Permission Denials",
		YAxisTitle: "count",
		InfoText:   "Total denials plus a few of the most actionable denial reasons.",
		Series: []statsviz.TimeSeries{
			{Name: "total", GetValue: func() float64 { return snapshotter.snapshot().PermissionDenialsTotal }},
			{Name: "contributor lock", GetValue: func() float64 { return snapshotter.snapshot().PermissionDeniedContributorLockTotal }},
			{Name: "not owner", GetValue: func() float64 { return snapshotter.snapshot().PermissionDeniedNotOwnerTotal }},
			{Name: "quota", GetValue: func() float64 { return snapshotter.snapshot().PermissionDeniedQuotaTotal }},
			{Name: "path traversal", GetValue: func() float64 { return snapshotter.snapshot().PermissionDeniedPathTraversalTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:       "sftpguy_admin_http",
		Title:      "Admin HTTP",
		YAxisTitle: "count",
		InfoText:   "In-flight admin requests and cumulative admin HTTP request totals.",
		Series: []statsviz.TimeSeries{
			{Name: "in flight", GetValue: func() float64 { return snapshotter.snapshot().AdminHTTPInFlight }},
			{Name: "requests", GetValue: func() float64 { return snapshotter.snapshot().AdminHTTPRequestTotal }},
		},
	}); err != nil {
		return nil, err
	}

	if err := appendPlot(statsviz.TimeSeriesPlotConfig{
		Name:            "sftpguy_admin_http_latency",
		Title:           "Admin HTTP Latency",
		YAxisTitle:      "milliseconds",
		YAxisTickSuffix: " ms",
		InfoText:        "Average admin HTTP request duration observed since process start.",
		Series: []statsviz.TimeSeries{
			{Name: "avg duration", Unitfmt: ".2f", GetValue: func() float64 { return snapshotter.snapshot().AdminHTTPDurationAverageSeconds * 1000 }},
		},
	}); err != nil {
		return nil, err
	}

	return opts, nil
}
