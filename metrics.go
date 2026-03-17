package main

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"
	"sftpguy/internal/adminhttp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

type serverMetrics struct {
	registry *prometheus.Registry
	handler  http.Handler

	sshConnectionsActive  prometheus.Gauge
	sshConnectionAccepts  *prometheus.CounterVec
	sshHandshakes         *prometheus.CounterVec
	authAttempts          *prometheus.CounterVec
	sessionsActive        prometheus.Gauge
	sessionsTotal         *prometheus.CounterVec
	sessionDuration       *prometheus.HistogramVec
	sftpRequestsInFlight  prometheus.Gauge
	sftpRequestsTotal     *prometheus.CounterVec
	sftpRequestDuration   *prometheus.HistogramVec
	sftpTransfersTotal    *prometheus.CounterVec
	sftpTransferBytes     *prometheus.CounterVec
	sftpTransferSize      *prometheus.HistogramVec
	permissionDenials     *prometheus.CounterVec
	adminHTTPInFlight     prometheus.Gauge
	adminHTTPRequestTotal *prometheus.CounterVec
	adminHTTPDuration     *prometheus.HistogramVec
}

type archiveMetricsSnapshot struct {
	users             int64
	contributors      int64
	files             int64
	directories       int64
	storedBytes       int64
	shadowBannedUsers int64
	bannedIPs         int64
}

type archiveStatsCollector struct {
	store                *Store
	contributorThreshold int64

	usersDesc             *prometheus.Desc
	contributorsDesc      *prometheus.Desc
	filesDesc             *prometheus.Desc
	directoriesDesc       *prometheus.Desc
	storedBytesDesc       *prometheus.Desc
	shadowBannedUsersDesc *prometheus.Desc
	bannedIPsDesc         *prometheus.Desc
}

type metricsReaderAt struct {
	reader    io.ReaderAt
	closer    io.Closer
	h         *fsHandler
	direction string
	bytesRead atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

func NewMetricsHandler() http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
}

func newServerMetrics(srv *Server) *serverMetrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		newArchiveStatsCollector(srv.store, srv.cfg.ContributorThreshold),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sftpguy_uptime_seconds",
			Help: "Server uptime in seconds.",
		}, func() float64 {
			return srv.Uptime().Seconds()
		}),
	)

	m := &serverMetrics{
		registry: reg,
		sshConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sftpguy_ssh_connections_active",
			Help: "Current number of accepted SSH connections.",
		}),
		sshConnectionAccepts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_ssh_connection_accepts_total",
			Help: "Total accepted SSH connections.",
		}, []string{"throttled"}),
		sshHandshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_ssh_handshakes_total",
			Help: "SSH handshake results.",
		}, []string{"result"}),
		authAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_auth_attempts_total",
			Help: "Authentication attempts observed by SSH callbacks.",
		}, []string{"method", "admin"}),
		sessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sftpguy_sessions_active",
			Help: "Current number of active authenticated sessions.",
		}),
		sessionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_sessions_total",
			Help: "Authenticated sessions by login type.",
		}, []string{"login_type", "admin", "banned"}),
		sessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sftpguy_session_duration_seconds",
			Help:    "Authenticated session duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"login_type", "admin", "banned"}),
		sftpRequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sftpguy_sftp_requests_in_flight",
			Help: "Current number of in-flight SFTP requests.",
		}),
		sftpRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_sftp_requests_total",
			Help: "SFTP requests by operation and outcome.",
		}, []string{"operation", "outcome", "admin", "banned"}),
		sftpRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sftpguy_sftp_request_duration_seconds",
			Help:    "Time spent handling SFTP requests.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation", "outcome", "admin", "banned"}),
		sftpTransfersTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_sftp_transfers_total",
			Help: "Completed SFTP upload/download transfers.",
		}, []string{"direction", "admin", "banned"}),
		sftpTransferBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_sftp_transfer_bytes_total",
			Help: "Bytes transferred over SFTP.",
		}, []string{"direction", "admin", "banned"}),
		sftpTransferSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sftpguy_sftp_transfer_size_bytes",
			Help:    "Transfer sizes observed over SFTP.",
			Buckets: prometheus.ExponentialBuckets(512, 4, 9),
		}, []string{"direction", "admin", "banned"}),
		permissionDenials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_permission_denials_total",
			Help: "Permission denials by server-side reason.",
		}, []string{"reason", "admin", "banned"}),
		adminHTTPInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sftpguy_admin_http_requests_in_flight",
			Help: "Current number of in-flight admin HTTP requests.",
		}),
		adminHTTPRequestTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sftpguy_admin_http_requests_total",
			Help: "Admin HTTP requests by route, method, and status code.",
		}, []string{"route", "code", "method"}),
		adminHTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sftpguy_admin_http_request_duration_seconds",
			Help:    "Duration of admin HTTP requests by route and method.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
	}

	reg.MustRegister(
		m.sshConnectionsActive,
		m.sshConnectionAccepts,
		m.sshHandshakes,
		m.authAttempts,
		m.sessionsActive,
		m.sessionsTotal,
		m.sessionDuration,
		m.sftpRequestsInFlight,
		m.sftpRequestsTotal,
		m.sftpRequestDuration,
		m.sftpTransfersTotal,
		m.sftpTransferBytes,
		m.sftpTransferSize,
		m.permissionDenials,
		m.adminHTTPInFlight,
		m.adminHTTPRequestTotal,
		m.adminHTTPDuration,
	)

	m.handler = promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	return m
}

func newArchiveStatsCollector(store *Store, contributorThreshold int64) *archiveStatsCollector {
	return &archiveStatsCollector{
		store:                store,
		contributorThreshold: contributorThreshold,
		usersDesc: prometheus.NewDesc(
			"sftpguy_users_total",
			"Known non-system users tracked by the archive.",
			nil, nil,
		),
		contributorsDesc: prometheus.NewDesc(
			"sftpguy_contributors_total",
			"Known users that have reached the contributor download threshold.",
			nil, nil,
		),
		filesDesc: prometheus.NewDesc(
			"sftpguy_files_total",
			"Files currently registered in the archive.",
			nil, nil,
		),
		directoriesDesc: prometheus.NewDesc(
			"sftpguy_directories_total",
			"Directories currently registered in the archive.",
			nil, nil,
		),
		storedBytesDesc: prometheus.NewDesc(
			"sftpguy_stored_bytes",
			"Total bytes stored in regular files.",
			nil, nil,
		),
		shadowBannedUsersDesc: prometheus.NewDesc(
			"sftpguy_shadow_banned_users_total",
			"Users currently shadow-banned.",
			nil, nil,
		),
		bannedIPsDesc: prometheus.NewDesc(
			"sftpguy_banned_ips_total",
			"IP addresses currently banned in the database.",
			nil, nil,
		),
	}
}

func (c *archiveStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.usersDesc
	ch <- c.contributorsDesc
	ch <- c.filesDesc
	ch <- c.directoriesDesc
	ch <- c.storedBytesDesc
	ch <- c.shadowBannedUsersDesc
	ch <- c.bannedIPsDesc
}

func (c *archiveStatsCollector) Collect(ch chan<- prometheus.Metric) {
	snap, err := readArchiveMetricsSnapshot(c.store, c.contributorThreshold)
	if err != nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.usersDesc, prometheus.GaugeValue, float64(snap.users))
	ch <- prometheus.MustNewConstMetric(c.contributorsDesc, prometheus.GaugeValue, float64(snap.contributors))
	ch <- prometheus.MustNewConstMetric(c.filesDesc, prometheus.GaugeValue, float64(snap.files))
	ch <- prometheus.MustNewConstMetric(c.directoriesDesc, prometheus.GaugeValue, float64(snap.directories))
	ch <- prometheus.MustNewConstMetric(c.storedBytesDesc, prometheus.GaugeValue, float64(snap.storedBytes))
	ch <- prometheus.MustNewConstMetric(c.shadowBannedUsersDesc, prometheus.GaugeValue, float64(snap.shadowBannedUsers))
	ch <- prometheus.MustNewConstMetric(c.bannedIPsDesc, prometheus.GaugeValue, float64(snap.bannedIPs))
}

func readArchiveMetricsSnapshot(store *Store, contributorThreshold int64) (archiveMetricsSnapshot, error) {
	var snap archiveMetricsSnapshot
	if store == nil || store.db == nil {
		return snap, nil
	}

	if err := store.db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE pubkey_hash <> ?),
			COUNT(*) FILTER (WHERE pubkey_hash <> ? AND upload_bytes > ?)
		FROM users
	`, systemOwner, systemOwner, contributorThreshold).Scan(&snap.users, &snap.contributors); err != nil {
		return snap, err
	}

	if err := store.db.QueryRow(`SELECT COUNT(*), IFNULL(SUM(size), 0) FROM files WHERE is_dir = 0`).Scan(&snap.files, &snap.storedBytes); err != nil {
		return snap, err
	}

	if err := store.db.QueryRow(`SELECT COUNT(*) FROM files WHERE is_dir = 1`).Scan(&snap.directories); err != nil {
		return snap, err
	}

	if err := store.db.QueryRow(`SELECT COUNT(*) FROM shadow_banned`).Scan(&snap.shadowBannedUsers); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return snap, err
	}

	if err := store.db.QueryRow(`SELECT COUNT(*) FROM ip_banned`).Scan(&snap.bannedIPs); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return snap, err
	}

	return snap, nil
}

func (m *serverMetrics) Handler() http.Handler {
	if m == nil || m.handler == nil {
		return http.NotFoundHandler()
	}
	return m.handler
}

func (m *serverMetrics) StatsSnapshot() adminhttp.StatsSnapshot {
	var snap adminhttp.StatsSnapshot
	if m == nil || m.registry == nil {
		return snap
	}

	families, _ := m.registry.Gather()
	if len(families) == 0 {
		return snap
	}

	index := metricFamiliesByName(families)

	snap.UptimeSeconds = sumGaugeFamily(index["sftpguy_uptime_seconds"], nil)

	snap.UsersTotal = sumGaugeFamily(index["sftpguy_users_total"], nil)
	snap.ContributorsTotal = sumGaugeFamily(index["sftpguy_contributors_total"], nil)
	snap.FilesTotal = sumGaugeFamily(index["sftpguy_files_total"], nil)
	snap.DirectoriesTotal = sumGaugeFamily(index["sftpguy_directories_total"], nil)
	snap.StoredBytes = sumGaugeFamily(index["sftpguy_stored_bytes"], nil)
	snap.ShadowBannedUsersTotal = sumGaugeFamily(index["sftpguy_shadow_banned_users_total"], nil)
	snap.BannedIPsTotal = sumGaugeFamily(index["sftpguy_banned_ips_total"], nil)

	snap.SSHConnectionsActive = sumGaugeFamily(index["sftpguy_ssh_connections_active"], nil)
	snap.SSHConnectionAcceptsTotal = sumCounterFamily(index["sftpguy_ssh_connection_accepts_total"], nil)
	snap.SSHConnectionAcceptsThrottledTotal = sumCounterFamily(index["sftpguy_ssh_connection_accepts_total"], map[string]string{"throttled": "true"})
	snap.SSHHandshakesSuccessTotal = sumCounterFamily(index["sftpguy_ssh_handshakes_total"], map[string]string{"result": "success"})
	snap.SSHHandshakesFailureTotal = sumCounterFamily(index["sftpguy_ssh_handshakes_total"], map[string]string{"result": "failure"})

	snap.AuthAttemptsNoneTotal = sumCounterFamily(index["sftpguy_auth_attempts_total"], map[string]string{"method": "none", "admin": "false"})
	snap.AuthAttemptsPublicKeyTotal = sumCounterFamily(index["sftpguy_auth_attempts_total"], map[string]string{"method": "publickey", "admin": "false"})
	snap.AuthAttemptsKeyboardInteractiveTotal = sumCounterFamily(index["sftpguy_auth_attempts_total"], map[string]string{"method": "keyboard_interactive", "admin": "false"})
	snap.AuthAttemptsAdminPublicKeyTotal = sumCounterFamily(index["sftpguy_auth_attempts_total"], map[string]string{"method": "publickey", "admin": "true"})

	snap.SessionsActive = sumGaugeFamily(index["sftpguy_sessions_active"], nil)
	snap.SessionsPubKeyTotal = sumCounterFamily(index["sftpguy_sessions_total"], map[string]string{"login_type": "pubkey_hash"})
	snap.SessionsPasswordTotal = sumCounterFamily(index["sftpguy_sessions_total"], map[string]string{"login_type": "pwd_auth"})
	snap.SessionsAdminSFTPTotal = sumCounterFamily(index["sftpguy_sessions_total"], map[string]string{"login_type": "admin_sftp"})
	snap.SessionsBannedTotal = sumCounterFamily(index["sftpguy_sessions_total"], map[string]string{"banned": "true"})
	snap.SessionDurationAverageSeconds = averageHistogramFamily(index["sftpguy_session_duration_seconds"], nil)

	snap.SFTPRequestsInFlight = sumGaugeFamily(index["sftpguy_sftp_requests_in_flight"], nil)
	snap.SFTPReadSuccessTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"operation": "read", "outcome": "success"})
	snap.SFTPReadFailureTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"operation": "read"}) - snap.SFTPReadSuccessTotal
	if snap.SFTPReadFailureTotal < 0 {
		snap.SFTPReadFailureTotal = 0
	}
	snap.SFTPWriteSuccessTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"operation": "write", "outcome": "success"})
	snap.SFTPWriteFailureTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"operation": "write"}) - snap.SFTPWriteSuccessTotal
	if snap.SFTPWriteFailureTotal < 0 {
		snap.SFTPWriteFailureTotal = 0
	}
	snap.SFTPPermissionDeniedTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"outcome": "permission_denied"})
	snap.SFTPNotFoundTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"outcome": "not_found"})
	snap.SFTPUnsupportedTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"outcome": "unsupported"})
	snap.SFTPFailureTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"outcome": "failure"})
	snap.SFTPErrorTotal = sumCounterFamily(index["sftpguy_sftp_requests_total"], map[string]string{"outcome": "error"})

	snap.SFTPUploadTransfersTotal = sumCounterFamily(index["sftpguy_sftp_transfers_total"], map[string]string{"direction": "upload"})
	snap.SFTPDownloadTransfersTotal = sumCounterFamily(index["sftpguy_sftp_transfers_total"], map[string]string{"direction": "download"})
	snap.SFTPUploadBytesTotal = sumCounterFamily(index["sftpguy_sftp_transfer_bytes_total"], map[string]string{"direction": "upload"})
	snap.SFTPDownloadBytesTotal = sumCounterFamily(index["sftpguy_sftp_transfer_bytes_total"], map[string]string{"direction": "download"})
	snap.SFTPTransferAverageBytes = averageHistogramFamily(index["sftpguy_sftp_transfer_size_bytes"], nil)

	snap.PermissionDenialsTotal = sumCounterFamily(index["sftpguy_permission_denials_total"], nil)
	snap.PermissionDeniedContributorLockTotal = sumCounterFamily(index["sftpguy_permission_denials_total"], map[string]string{"reason": "denied_contributor_lock"})
	snap.PermissionDeniedNotOwnerTotal = sumCounterFamily(index["sftpguy_permission_denials_total"], map[string]string{"reason": "denied_not_owner"})
	snap.PermissionDeniedQuotaTotal = sumCounterFamily(index["sftpguy_permission_denials_total"], map[string]string{"reason": "denied_quota"})
	snap.PermissionDeniedPathTraversalTotal = sumCounterFamily(index["sftpguy_permission_denials_total"], map[string]string{"reason": "denied_path_traversal"})

	snap.AdminHTTPInFlight = sumGaugeFamily(index["sftpguy_admin_http_requests_in_flight"], nil)
	snap.AdminHTTPRequestTotal = sumCounterFamily(index["sftpguy_admin_http_requests_total"], nil)
	snap.AdminHTTPDurationAverageSeconds = averageHistogramFamily(index["sftpguy_admin_http_request_duration_seconds"], nil)

	return snap
}

func metricFamiliesByName(families []*dto.MetricFamily) map[string]*dto.MetricFamily {
	index := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		if family == nil {
			continue
		}
		index[family.GetName()] = family
	}
	return index
}

func sumGaugeFamily(family *dto.MetricFamily, labels map[string]string) float64 {
	if family == nil {
		return 0
	}

	var total float64
	for _, metric := range family.GetMetric() {
		if !metricMatchesLabels(metric, labels) {
			continue
		}
		total += metric.GetGauge().GetValue()
	}
	return total
}

func sumCounterFamily(family *dto.MetricFamily, labels map[string]string) float64 {
	if family == nil {
		return 0
	}

	var total float64
	for _, metric := range family.GetMetric() {
		if !metricMatchesLabels(metric, labels) {
			continue
		}
		total += metric.GetCounter().GetValue()
	}
	return total
}

func averageHistogramFamily(family *dto.MetricFamily, labels map[string]string) float64 {
	if family == nil {
		return 0
	}

	var (
		sum   float64
		count uint64
	)
	for _, metric := range family.GetMetric() {
		if !metricMatchesLabels(metric, labels) {
			continue
		}
		hist := metric.GetHistogram()
		sum += hist.GetSampleSum()
		count += hist.GetSampleCount()
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func metricMatchesLabels(metric *dto.Metric, labels map[string]string) bool {
	if len(labels) == 0 {
		return true
	}
	if metric == nil {
		return false
	}

	for key, want := range labels {
		matched := false
		for _, pair := range metric.GetLabel() {
			if pair.GetName() == key && pair.GetValue() == want {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (m *serverMetrics) WrapAdminHandler(route string, next http.Handler) http.Handler {
	if m == nil || next == nil {
		return next
	}

	route = strings.TrimSpace(route)
	if route == "" {
		route = "unknown"
	}

	return promhttp.InstrumentHandlerInFlight(
		m.adminHTTPInFlight,
		promhttp.InstrumentHandlerDuration(
			m.adminHTTPDuration.MustCurryWith(prometheus.Labels{"route": route}),
			promhttp.InstrumentHandlerCounter(
				m.adminHTTPRequestTotal.MustCurryWith(prometheus.Labels{"route": route}),
				next,
			),
		),
	)
}

func (m *serverMetrics) observeAcceptedConnection(throttled bool) {
	if m == nil {
		return
	}
	m.sshConnectionsActive.Inc()
	m.sshConnectionAccepts.WithLabelValues(boolLabel(throttled)).Inc()
}

func (m *serverMetrics) connectionClosed() {
	if m == nil {
		return
	}
	m.sshConnectionsActive.Dec()
}

func (m *serverMetrics) observeHandshake(success bool) {
	if m == nil {
		return
	}
	result := "failure"
	if success {
		result = "success"
	}
	m.sshHandshakes.WithLabelValues(result).Inc()
}

func (m *serverMetrics) observeAuthAttempt(method string, admin bool) {
	if m == nil {
		return
	}
	m.authAttempts.WithLabelValues(normalizeMetricOperation(method), boolLabel(admin)).Inc()
}

func (m *serverMetrics) startSession(loginType string, admin, banned bool) func(time.Duration) {
	if m == nil {
		return func(time.Duration) {}
	}

	loginType = normalizeMetricOperation(loginType)
	adminLabel := boolLabel(admin)
	bannedLabel := boolLabel(banned)

	m.sessionsActive.Inc()
	m.sessionsTotal.WithLabelValues(loginType, adminLabel, bannedLabel).Inc()

	return func(duration time.Duration) {
		m.sessionsActive.Dec()
		m.sessionDuration.WithLabelValues(loginType, adminLabel, bannedLabel).Observe(duration.Seconds())
	}
}

func (m *serverMetrics) startSFTPRequest(operation string, admin, banned bool) func(error) {
	if m == nil {
		return func(error) {}
	}

	start := time.Now()
	operation = normalizeMetricOperation(operation)
	adminLabel := boolLabel(admin)
	bannedLabel := boolLabel(banned)

	m.sftpRequestsInFlight.Inc()
	return func(err error) {
		m.sftpRequestsInFlight.Dec()
		outcome := sftpMetricOutcome(err)
		m.sftpRequestsTotal.WithLabelValues(operation, outcome, adminLabel, bannedLabel).Inc()
		m.sftpRequestDuration.WithLabelValues(operation, outcome, adminLabel, bannedLabel).Observe(time.Since(start).Seconds())
	}
}

func (m *serverMetrics) observeTransferBytes(direction string, n int64, admin, banned bool) {
	if m == nil || n <= 0 {
		return
	}
	m.sftpTransferBytes.WithLabelValues(normalizeMetricOperation(direction), boolLabel(admin), boolLabel(banned)).Add(float64(n))
}

func (m *serverMetrics) observeTransferComplete(direction string, size int64, admin, banned bool) {
	if m == nil {
		return
	}
	if size < 0 {
		size = 0
	}
	direction = normalizeMetricOperation(direction)
	adminLabel := boolLabel(admin)
	bannedLabel := boolLabel(banned)
	m.sftpTransfersTotal.WithLabelValues(direction, adminLabel, bannedLabel).Inc()
	m.sftpTransferSize.WithLabelValues(direction, adminLabel, bannedLabel).Observe(float64(size))
}

func (m *serverMetrics) observeDenied(kind EventKind, admin, banned bool) {
	if m == nil {
		return
	}
	m.permissionDenials.WithLabelValues(normalizeMetricOperation(string(kind)), boolLabel(admin), boolLabel(banned)).Inc()
}

func (s *Server) observeAcceptedConnection(throttled bool) {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.observeAcceptedConnection(throttled)
}

func (s *Server) closeObservedConnection() {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.connectionClosed()
}

func (s *Server) observeHandshake(success bool) {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.observeHandshake(success)
}

func (s *Server) observeAuthAttempt(method string, admin bool) {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.observeAuthAttempt(method, admin)
}

func (s *Server) observeSession(loginType string, admin, banned bool) func(time.Duration) {
	if s == nil || s.metrics == nil {
		return func(time.Duration) {}
	}
	return s.metrics.startSession(loginType, admin, banned)
}

func (h *fsHandler) observeSFTPRequest(operation string) func(error) {
	if h == nil || h.srv == nil || h.srv.metrics == nil {
		return func(error) {}
	}
	return h.srv.metrics.startSFTPRequest(operation, h.isAdmin, h.isBanned)
}

func (h *fsHandler) observeTransferBytes(direction string, n int64) {
	if h == nil || h.srv == nil || h.srv.metrics == nil {
		return
	}
	h.srv.metrics.observeTransferBytes(direction, n, h.isAdmin, h.isBanned)
}

func (h *fsHandler) observeTransferComplete(direction string, size int64) {
	if h == nil || h.srv == nil || h.srv.metrics == nil {
		return
	}
	h.srv.metrics.observeTransferComplete(direction, size, h.isAdmin, h.isBanned)
}

func (h *fsHandler) observeDenied(kind EventKind) {
	if h == nil || h.srv == nil || h.srv.metrics == nil {
		return
	}
	h.srv.metrics.observeDenied(kind, h.isAdmin, h.isBanned)
}

func newMetricsReaderAt(reader io.ReaderAt, h *fsHandler, direction string) *metricsReaderAt {
	m := &metricsReaderAt{
		reader:    reader,
		h:         h,
		direction: direction,
	}
	if closer, ok := reader.(io.Closer); ok {
		m.closer = closer
	}
	return m
}

func (m *metricsReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := m.reader.ReadAt(p, off)
	if n > 0 {
		m.bytesRead.Add(int64(n))
		m.h.observeTransferBytes(m.direction, int64(n))
	}
	return n, err
}

func (m *metricsReaderAt) Close() error {
	m.closeOnce.Do(func() {
		m.h.observeTransferComplete(m.direction, m.bytesRead.Load())
		if m.closer != nil {
			m.closeErr = m.closer.Close()
		}
	})
	return m.closeErr
}

func (t *throttledReaderAt) Close() error {
	if closer, ok := t.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func boolLabel(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func normalizeMetricOperation(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "-", "_")
	raw = strings.ReplaceAll(raw, "/", "_")
	return raw
}

func sftpMetricOutcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, sftp.ErrSSHFxPermissionDenied):
		return "permission_denied"
	case errors.Is(err, os.ErrNotExist), errors.Is(err, sftp.ErrSSHFxNoSuchFile):
		return "not_found"
	case errors.Is(err, sftp.ErrSshFxOpUnsupported):
		return "unsupported"
	case errors.Is(err, sftp.ErrSSHFxFailure):
		return "failure"
	default:
		return "error"
	}
}
