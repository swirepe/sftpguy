package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const liveTransferRateWindow = 10 * time.Second

type liveTracker struct {
	nextConnID     atomic.Uint64
	nextTransferID atomic.Uint64

	mu          sync.Mutex
	connections map[string]*liveConnectionState
	sessions    map[string]*liveSessionState
	transfers   map[string]*liveTransferState
	upload      liveRollingCounter
	download    liveRollingCounter
}

type liveRollingCounter struct {
	total   int64
	buckets map[int64]int64
}

type liveConnectionState struct {
	id              string
	source          string
	protocol        string
	remoteAddr      string
	localAddr       string
	ip              string
	state           string
	sessionID       string
	userID          string
	authUser        string
	loginType       string
	userAgent       string
	startedAt       time.Time
	lastActivityAt  time.Time
	throttled       bool
	admin           bool
	banned          bool
	requestsActive  int
	activeTransfers int
	lastOperation   string
	lastPath        string
	upload          liveRollingCounter
	download        liveRollingCounter
}

type liveSessionState struct {
	sessionID       string
	connectionID    string
	connections     map[string]int
	source          string
	protocol        string
	refs            int
	userID          string
	authUser        string
	remoteAddr      string
	localAddr       string
	ip              string
	loginType       string
	userAgent       string
	startedAt       time.Time
	lastActivityAt  time.Time
	admin           bool
	banned          bool
	requestsActive  int
	activeTransfers int
	lastOperation   string
	lastPath        string
	lastError       string
	upload          liveRollingCounter
	download        liveRollingCounter
}

type liveTransferState struct {
	id             string
	sessionID      string
	connectionID   string
	source         string
	protocol       string
	userID         string
	remoteAddr     string
	ip             string
	direction      string
	path           string
	userAgent      string
	startedAt      time.Time
	lastActivityAt time.Time
	bytes          liveRollingCounter
}

type liveSessionStart struct {
	ConnectionID string
	Source       string
	Protocol     string
	SessionID    string
	UserID       string
	AuthUser     string
	RemoteAddr   net.Addr
	LocalAddr    net.Addr
	LoginType    string
	UserAgent    string
	Admin        bool
	Banned       bool
	SessionStart time.Time
}

type liveAdminSnapshot struct {
	Now             int64                    `json:"now"`
	NowTime         string                   `json:"now_time"`
	RateWindowSec   int64                    `json:"rate_window_sec"`
	ConnectionCount int                      `json:"connection_count"`
	SessionCount    int                      `json:"session_count"`
	TransferCount   int                      `json:"transfer_count"`
	UploadBytes     int64                    `json:"upload_bytes"`
	DownloadBytes   int64                    `json:"download_bytes"`
	UploadRateBPS   float64                  `json:"upload_rate_bps"`
	DownloadRateBPS float64                  `json:"download_rate_bps"`
	TotalRateBPS    float64                  `json:"total_rate_bps"`
	Connections     []liveConnectionSnapshot `json:"connections"`
	Sessions        []liveSessionSnapshot    `json:"sessions"`
	Transfers       []liveTransferSnapshot   `json:"transfers"`
}

type liveConnectionSnapshot struct {
	ID              string  `json:"id"`
	Source          string  `json:"source"`
	Protocol        string  `json:"protocol"`
	RemoteAddr      string  `json:"remote_addr"`
	LocalAddr       string  `json:"local_addr"`
	IP              string  `json:"ip"`
	Geo             any     `json:"geo,omitempty"`
	State           string  `json:"state"`
	Session         string  `json:"session"`
	UserID          string  `json:"user_id"`
	AuthUser        string  `json:"auth_user"`
	LoginType       string  `json:"login_type"`
	UserAgent       string  `json:"user_agent"`
	ClientVersion   string  `json:"client_version"`
	StartedAt       int64   `json:"started_at"`
	StartedTime     string  `json:"started_time"`
	AgeSec          int64   `json:"age_sec"`
	LastActivityAt  int64   `json:"last_activity_at"`
	LastActivity    string  `json:"last_activity"`
	IdleSec         int64   `json:"idle_sec"`
	Throttled       bool    `json:"throttled"`
	Admin           bool    `json:"admin"`
	Banned          bool    `json:"banned"`
	RequestsActive  int     `json:"requests_active"`
	ActiveTransfers int     `json:"active_transfers"`
	LastOperation   string  `json:"last_operation"`
	LastPath        string  `json:"last_path"`
	UploadBytes     int64   `json:"upload_bytes"`
	DownloadBytes   int64   `json:"download_bytes"`
	UploadRateBPS   float64 `json:"upload_rate_bps"`
	DownloadRateBPS float64 `json:"download_rate_bps"`
	TotalRateBPS    float64 `json:"total_rate_bps"`
}

type liveSessionSnapshot struct {
	Session         string  `json:"session"`
	ConnectionID    string  `json:"connection_id"`
	Source          string  `json:"source"`
	Protocol        string  `json:"protocol"`
	UserID          string  `json:"user_id"`
	AuthUser        string  `json:"auth_user"`
	RemoteAddr      string  `json:"remote_addr"`
	LocalAddr       string  `json:"local_addr"`
	IP              string  `json:"ip"`
	Geo             any     `json:"geo,omitempty"`
	LoginType       string  `json:"login_type"`
	UserAgent       string  `json:"user_agent"`
	ClientVersion   string  `json:"client_version"`
	StartedAt       int64   `json:"started_at"`
	StartTime       string  `json:"start_time"`
	AgeSec          int64   `json:"age_sec"`
	LastActivityAt  int64   `json:"last_activity_at"`
	LastActivity    string  `json:"last_activity"`
	IdleSec         int64   `json:"idle_sec"`
	Admin           bool    `json:"admin"`
	Banned          bool    `json:"banned"`
	RequestsActive  int     `json:"requests_active"`
	ActiveTransfers int     `json:"active_transfers"`
	LastOperation   string  `json:"last_operation"`
	LastPath        string  `json:"last_path"`
	LastError       string  `json:"last_error"`
	UploadBytes     int64   `json:"upload_bytes"`
	DownloadBytes   int64   `json:"download_bytes"`
	UploadRateBPS   float64 `json:"upload_rate_bps"`
	DownloadRateBPS float64 `json:"download_rate_bps"`
	TotalRateBPS    float64 `json:"total_rate_bps"`
}

type liveTransferSnapshot struct {
	ID             string  `json:"id"`
	Session        string  `json:"session"`
	ConnectionID   string  `json:"connection_id"`
	Source         string  `json:"source"`
	Protocol       string  `json:"protocol"`
	UserID         string  `json:"user_id"`
	RemoteAddr     string  `json:"remote_addr"`
	IP             string  `json:"ip"`
	Geo            any     `json:"geo,omitempty"`
	Direction      string  `json:"direction"`
	Path           string  `json:"path"`
	UserAgent      string  `json:"user_agent"`
	ClientVersion  string  `json:"client_version"`
	StartedAt      int64   `json:"started_at"`
	StartTime      string  `json:"start_time"`
	AgeSec         int64   `json:"age_sec"`
	LastActivityAt int64   `json:"last_activity_at"`
	LastActivity   string  `json:"last_activity"`
	IdleSec        int64   `json:"idle_sec"`
	Bytes          int64   `json:"bytes"`
	RateBPS        float64 `json:"rate_bps"`
}

type stringAddr string

func (a stringAddr) Network() string { return "addr" }
func (a stringAddr) String() string  { return string(a) }

type liveHTTPResponseWriter struct {
	http.ResponseWriter
	srv        *Server
	sessionID  string
	transferID string
	path       string
}

func (w *liveHTTPResponseWriter) Write(p []byte) (int, error) {
	w.ensureTransfer()
	n, err := w.ResponseWriter.Write(p)
	if n > 0 && w.srv != nil {
		w.srv.recordLiveTransferBytes(w.sessionID, w.transferID, "download", int64(n))
	}
	return n, err
}

func (w *liveHTTPResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *liveHTTPResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *liveHTTPResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *liveHTTPResponseWriter) ensureTransfer() {
	if w == nil || w.srv == nil || w.transferID != "" {
		return
	}
	w.transferID = w.srv.startLiveTransfer(w.sessionID, "download", w.path)
}

func (w *liveHTTPResponseWriter) finish() {
	if w == nil || w.srv == nil || w.transferID == "" {
		return
	}
	w.srv.finishLiveTransfer(w.transferID)
}

func newLiveTracker() *liveTracker {
	return &liveTracker{
		connections: make(map[string]*liveConnectionState),
		sessions:    make(map[string]*liveSessionState),
		transfers:   make(map[string]*liveTransferState),
	}
}

func (s *Server) liveTracker() *liveTracker {
	if s == nil {
		return nil
	}
	if s.live == nil {
		s.live = newLiveTracker()
	}
	return s.live
}

func (s *Server) startLiveConnection(remoteAddr, localAddr net.Addr, throttled bool) string {
	return s.startLiveConnectionFor("sftp", "ssh", remoteAddr, localAddr, throttled)
}

func (s *Server) startLiveConnectionFor(source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) string {
	tracker := s.liveTracker()
	if tracker == nil {
		return ""
	}
	return tracker.startConnection(source, protocol, remoteAddr, localAddr, throttled)
}

func (s *Server) startLiveConnectionWithID(id, source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) string {
	tracker := s.liveTracker()
	if tracker == nil {
		return ""
	}
	return tracker.startConnectionWithID(id, source, protocol, remoteAddr, localAddr, throttled)
}

func (s *Server) ensureLiveConnectionWithID(id, source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) bool {
	tracker := s.liveTracker()
	if tracker == nil {
		return false
	}
	return tracker.ensureConnectionWithID(id, source, protocol, remoteAddr, localAddr, throttled)
}

func (s *Server) finishLiveConnection(id string) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishConnection(id)
}

func (s *Server) markLiveConnectionState(id, state string) {
	if s == nil || s.live == nil {
		return
	}
	s.live.markConnectionState(id, state)
}

func (s *Server) startLiveSession(info liveSessionStart) {
	tracker := s.liveTracker()
	if tracker == nil {
		return
	}
	tracker.startSession(info)
}

func (s *Server) finishLiveSession(sessionID string) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishSession(sessionID)
}

func (s *Server) finishLiveSessionForConnection(sessionID, connectionID string) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishSessionForConnection(sessionID, connectionID)
}

func (s *Server) liveSessionHasConnection(sessionID, connectionID string) bool {
	if s == nil || s.live == nil {
		return false
	}
	return s.live.sessionHasConnection(sessionID, connectionID)
}

func (s *Server) startLiveSFTPRequest(sessionID, operation, path string) func(error) {
	if s == nil || s.live == nil {
		return func(error) {}
	}
	return s.live.startRequest(sessionID, operation, path)
}

func (s *Server) startLiveSFTPRequestForConnection(sessionID, connectionID, operation, path string) func(error) {
	if s == nil || s.live == nil {
		return func(error) {}
	}
	return s.live.startRequestForConnection(sessionID, connectionID, operation, path)
}

func (s *Server) finishLiveRequest(sessionID, operation, path string, err error) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishRequest(sessionID, operation, path, err)
}

func (s *Server) finishLiveRequestForConnection(sessionID, connectionID, operation, path string, err error) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishRequestForConnection(sessionID, connectionID, operation, path, err)
}

func (s *Server) startLiveTransfer(sessionID, direction, path string) string {
	if s == nil || s.live == nil {
		return ""
	}
	return s.live.startTransfer(sessionID, direction, path)
}

func (s *Server) startLiveTransferWithID(transferID, sessionID, direction, path string) string {
	if s == nil || s.live == nil {
		return ""
	}
	return s.live.startTransferWithID(transferID, sessionID, direction, path)
}

func (s *Server) startLiveTransferWithIDForConnection(transferID, sessionID, connectionID, direction, path string) string {
	if s == nil || s.live == nil {
		return ""
	}
	return s.live.startTransferWithIDForConnection(transferID, sessionID, connectionID, direction, path)
}

func (s *Server) recordLiveTransferBytes(sessionID, transferID, direction string, n int64) {
	if s == nil || s.live == nil || n <= 0 {
		return
	}
	s.live.recordTransferBytes(sessionID, transferID, direction, n)
}

func (s *Server) recordLiveTransferBytesAbsolute(sessionID, transferID, direction string, n int64) {
	if s == nil || s.live == nil || n <= 0 {
		return
	}
	s.live.recordTransferBytesAbsolute(sessionID, transferID, direction, n)
}

func (s *Server) finishLiveTransfer(transferID string) {
	if s == nil || s.live == nil {
		return
	}
	s.live.finishTransfer(transferID)
}

func (s *Server) LiveAdminSnapshot() liveAdminSnapshot {
	now := time.Now()
	empty := liveAdminSnapshot{
		Now:           now.Unix(),
		NowTime:       liveTime(now),
		RateWindowSec: int64(liveTransferRateWindow.Seconds()),
		Connections:   []liveConnectionSnapshot{},
		Sessions:      []liveSessionSnapshot{},
		Transfers:     []liveTransferSnapshot{},
	}
	if s == nil || s.live == nil {
		return empty
	}
	return s.live.snapshot()
}

func (t *liveTracker) startConnection(source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) string {
	if t == nil {
		return ""
	}
	id := fmt.Sprintf("conn-%d", t.nextConnID.Add(1))
	return t.startConnectionWithID(id, source, protocol, remoteAddr, localAddr, throttled)
}

func (t *liveTracker) startConnectionWithID(id, source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) string {
	if t == nil {
		return ""
	}
	id = strings.TrimSpace(id)
	if id == "" {
		id = fmt.Sprintf("conn-%d", t.nextConnID.Add(1))
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureMaps()
	t.connections[id] = &liveConnectionState{
		id:             id,
		source:         normalizeLiveSource(source),
		protocol:       strings.TrimSpace(protocol),
		remoteAddr:     liveAddrString(remoteAddr),
		localAddr:      liveAddrString(localAddr),
		ip:             remoteAddrHost(remoteAddr),
		state:          "accepted",
		startedAt:      now,
		lastActivityAt: now,
		throttled:      throttled,
	}
	return id
}

func (t *liveTracker) ensureConnectionWithID(id, source, protocol string, remoteAddr, localAddr net.Addr, throttled bool) bool {
	if t == nil {
		return false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureMaps()
	if conn := t.connections[id]; conn != nil {
		if source = normalizeLiveSource(source); source != "" {
			conn.source = source
		}
		if protocol = strings.TrimSpace(protocol); protocol != "" {
			conn.protocol = protocol
		}
		if remote := liveAddrString(remoteAddr); remote != "" {
			conn.remoteAddr = remote
		}
		if local := liveAddrString(localAddr); local != "" {
			conn.localAddr = local
		}
		if ip := remoteAddrHost(remoteAddr); ip != "" {
			conn.ip = ip
		}
		conn.throttled = conn.throttled || throttled
		conn.lastActivityAt = now
		return false
	}
	t.connections[id] = &liveConnectionState{
		id:             id,
		source:         normalizeLiveSource(source),
		protocol:       strings.TrimSpace(protocol),
		remoteAddr:     liveAddrString(remoteAddr),
		localAddr:      liveAddrString(localAddr),
		ip:             remoteAddrHost(remoteAddr),
		state:          "accepted",
		startedAt:      now,
		lastActivityAt: now,
		throttled:      throttled,
	}
	return true
}

func (t *liveTracker) markConnectionState(id, state string) {
	if t == nil || strings.TrimSpace(id) == "" {
		return
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if conn := t.connections[id]; conn != nil {
		conn.state = state
		conn.lastActivityAt = time.Now()
	}
}

func (t *liveTracker) finishConnection(id string) {
	if t == nil || strings.TrimSpace(id) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.connections, id)
}

func (t *liveTracker) startSession(info liveSessionStart) {
	if t == nil || strings.TrimSpace(info.SessionID) == "" {
		return
	}
	info.Source = normalizeLiveSource(info.Source)
	info.Protocol = strings.TrimSpace(info.Protocol)
	now := info.SessionStart
	if now.IsZero() {
		now = time.Now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureMaps()

	remoteAddr := liveAddrString(info.RemoteAddr)
	localAddr := liveAddrString(info.LocalAddr)
	ip := remoteAddrHost(info.RemoteAddr)
	if conn := t.connections[info.ConnectionID]; conn != nil {
		if info.Source == "" {
			info.Source = conn.source
		}
		if info.Protocol == "" {
			info.Protocol = conn.protocol
		}
		if remoteAddr == "" {
			remoteAddr = conn.remoteAddr
		}
		if localAddr == "" {
			localAddr = conn.localAddr
		}
		if ip == "" {
			ip = conn.ip
		}
		conn.state = "authenticated"
		conn.sessionID = info.SessionID
		conn.source = firstLiveNonEmpty(info.Source, conn.source)
		conn.protocol = firstLiveNonEmpty(info.Protocol, conn.protocol)
		conn.userID = info.UserID
		conn.authUser = info.AuthUser
		conn.loginType = info.LoginType
		conn.userAgent = info.UserAgent
		conn.admin = info.Admin
		conn.banned = info.Banned
		conn.lastActivityAt = now
	}

	if info.Source == "" {
		info.Source = "sftp"
	}
	if info.Protocol == "" {
		info.Protocol = "ssh"
	}
	if existing := t.sessions[info.SessionID]; existing != nil {
		existing.refs++
		if existing.connections == nil {
			existing.connections = make(map[string]int)
		}
		if info.ConnectionID != "" {
			existing.connections[info.ConnectionID]++
			existing.connectionID = info.ConnectionID
		}
		existing.source = firstLiveNonEmpty(info.Source, existing.source)
		existing.protocol = firstLiveNonEmpty(info.Protocol, existing.protocol)
		existing.userID = firstLiveNonEmpty(info.UserID, existing.userID)
		existing.authUser = firstLiveNonEmpty(info.AuthUser, existing.authUser)
		existing.remoteAddr = firstLiveNonEmpty(remoteAddr, existing.remoteAddr)
		existing.localAddr = firstLiveNonEmpty(localAddr, existing.localAddr)
		existing.ip = firstLiveNonEmpty(ip, existing.ip)
		existing.loginType = firstLiveNonEmpty(info.LoginType, existing.loginType)
		existing.userAgent = firstLiveNonEmpty(info.UserAgent, existing.userAgent)
		existing.lastActivityAt = now
		existing.admin = existing.admin || info.Admin
		existing.banned = existing.banned || info.Banned
		return
	}

	connections := make(map[string]int)
	if info.ConnectionID != "" {
		connections[info.ConnectionID] = 1
	}
	t.sessions[info.SessionID] = &liveSessionState{
		sessionID:      info.SessionID,
		connectionID:   info.ConnectionID,
		connections:    connections,
		source:         info.Source,
		protocol:       info.Protocol,
		refs:           1,
		userID:         info.UserID,
		authUser:       info.AuthUser,
		remoteAddr:     remoteAddr,
		localAddr:      localAddr,
		ip:             ip,
		loginType:      info.LoginType,
		userAgent:      info.UserAgent,
		startedAt:      now,
		lastActivityAt: now,
		admin:          info.Admin,
		banned:         info.Banned,
	}
}

func (t *liveTracker) finishSession(sessionID string) {
	t.finishSessionForConnection(sessionID, "")
}

func (t *liveTracker) finishSessionForConnection(sessionID, connectionID string) {
	if t == nil || strings.TrimSpace(sessionID) == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	session := t.sessions[sessionID]
	if session == nil {
		return
	}
	if strings.TrimSpace(connectionID) == "" {
		connectionID = session.connectionID
	}
	if connectionID != "" && session.connections != nil {
		switch refs := session.connections[connectionID]; {
		case refs > 1:
			session.connections[connectionID] = refs - 1
		case refs == 1:
			delete(session.connections, connectionID)
		}
	}
	if conn := t.connections[connectionID]; conn != nil {
		conn.state = "closing"
		conn.sessionID = ""
		conn.requestsActive = 0
		conn.activeTransfers = 0
		conn.lastActivityAt = time.Now()
	}
	if session.refs > 1 {
		session.refs--
		return
	}
	for id, transfer := range t.transfers {
		if transfer.sessionID == sessionID {
			delete(t.transfers, id)
		}
	}
	if connectionID == "" {
		connectionID = session.connectionID
	}
	if conn := t.connections[connectionID]; conn != nil {
		conn.state = "closing"
		conn.sessionID = ""
		conn.requestsActive = 0
		conn.activeTransfers = 0
		conn.lastActivityAt = time.Now()
	}
	delete(t.sessions, sessionID)
}

func (t *liveTracker) startRequest(sessionID, operation, path string) func(error) {
	return t.startRequestForConnection(sessionID, "", operation, path)
}

func (t *liveTracker) startRequestForConnection(sessionID, connectionID, operation, path string) func(error) {
	if t == nil || strings.TrimSpace(sessionID) == "" {
		return func(error) {}
	}
	operation = strings.TrimSpace(operation)
	path = strings.TrimSpace(path)
	now := time.Now()

	t.mu.Lock()
	session := t.sessions[sessionID]
	if session != nil {
		if strings.TrimSpace(connectionID) == "" {
			connectionID = session.connectionID
		}
		session.requestsActive++
		session.lastOperation = operation
		session.lastPath = path
		session.lastActivityAt = now
		if conn := t.connections[connectionID]; conn != nil {
			conn.requestsActive++
			conn.lastOperation = operation
			conn.lastPath = path
			conn.lastActivityAt = now
		}
	}
	t.mu.Unlock()

	var done atomic.Bool
	return func(err error) {
		if !done.CompareAndSwap(false, true) {
			return
		}
		t.finishRequestForConnection(sessionID, connectionID, operation, path, err)
	}
}

func (t *liveTracker) finishRequest(sessionID, operation, path string, err error) {
	t.finishRequestForConnection(sessionID, "", operation, path, err)
}

func (t *liveTracker) finishRequestForConnection(sessionID, connectionID, operation, path string, err error) {
	now := time.Now()
	errText := ""
	if err != nil {
		errText = err.Error()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	session := t.sessions[sessionID]
	if session == nil {
		return
	}
	if strings.TrimSpace(connectionID) == "" {
		connectionID = session.connectionID
	}
	if session.requestsActive > 0 {
		session.requestsActive--
	}
	session.lastOperation = strings.TrimSpace(operation)
	session.lastPath = strings.TrimSpace(path)
	session.lastError = errText
	session.lastActivityAt = now

	if conn := t.connections[connectionID]; conn != nil {
		if conn.requestsActive > 0 {
			conn.requestsActive--
		}
		conn.lastOperation = session.lastOperation
		conn.lastPath = session.lastPath
		conn.lastActivityAt = now
	}
}

func (t *liveTracker) startTransfer(sessionID, direction, path string) string {
	if t == nil || strings.TrimSpace(sessionID) == "" {
		return ""
	}
	direction = normalizeLiveDirection(direction)
	if direction == "" {
		return ""
	}
	id := fmt.Sprintf("xfer-%d", t.nextTransferID.Add(1))
	return t.startTransferWithID(id, sessionID, direction, path)
}

func (t *liveTracker) startTransferWithID(id, sessionID, direction, path string) string {
	return t.startTransferWithIDForConnection(id, sessionID, "", direction, path)
}

func (t *liveTracker) startTransferWithIDForConnection(id, sessionID, connectionID, direction, path string) string {
	if t == nil || strings.TrimSpace(sessionID) == "" {
		return ""
	}
	direction = normalizeLiveDirection(direction)
	if direction == "" {
		return ""
	}
	id = strings.TrimSpace(id)
	if id == "" {
		id = fmt.Sprintf("xfer-%d", t.nextTransferID.Add(1))
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureMaps()

	session := t.sessions[sessionID]
	if session == nil {
		return ""
	}
	if existing := t.transfers[id]; existing != nil {
		existing.lastActivityAt = now
		return id
	}
	if strings.TrimSpace(connectionID) == "" {
		connectionID = session.connectionID
	}
	session.activeTransfers++
	session.lastOperation = direction
	session.lastPath = strings.TrimSpace(path)
	session.lastActivityAt = now
	if conn := t.connections[connectionID]; conn != nil {
		conn.activeTransfers++
		conn.lastOperation = direction
		conn.lastPath = strings.TrimSpace(path)
		conn.lastActivityAt = now
	}

	t.transfers[id] = &liveTransferState{
		id:             id,
		sessionID:      sessionID,
		connectionID:   connectionID,
		source:         session.source,
		protocol:       session.protocol,
		userID:         session.userID,
		remoteAddr:     session.remoteAddr,
		ip:             session.ip,
		direction:      direction,
		path:           strings.TrimSpace(path),
		userAgent:      session.userAgent,
		startedAt:      now,
		lastActivityAt: now,
	}
	return id
}

func (t *liveTracker) recordTransferBytes(sessionID, transferID, direction string, n int64) {
	if t == nil || n <= 0 {
		return
	}
	direction = normalizeLiveDirection(direction)
	if direction == "" {
		return
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	switch direction {
	case "upload":
		t.upload.add(now, n)
	case "download":
		t.download.add(now, n)
	}

	connID := ""
	if transfer := t.transfers[transferID]; transfer != nil {
		if strings.TrimSpace(sessionID) == "" {
			sessionID = transfer.sessionID
		}
		connID = transfer.connectionID
		transfer.bytes.add(now, n)
		transfer.lastActivityAt = now
	}

	session := t.sessions[sessionID]
	if session != nil {
		switch direction {
		case "upload":
			session.upload.add(now, n)
		case "download":
			session.download.add(now, n)
		}
		session.lastOperation = direction
		session.lastActivityAt = now
		if connID == "" {
			connID = session.connectionID
		}
		if conn := t.connections[connID]; conn != nil {
			switch direction {
			case "upload":
				conn.upload.add(now, n)
			case "download":
				conn.download.add(now, n)
			}
			conn.lastOperation = direction
			conn.lastActivityAt = now
		}
	}
}

func (t *liveTracker) recordTransferBytesAbsolute(sessionID, transferID, direction string, absolute int64) {
	if t == nil || absolute <= 0 {
		return
	}

	t.mu.Lock()
	current := int64(0)
	if transfer := t.transfers[transferID]; transfer != nil {
		current = transfer.bytes.total
	}
	t.mu.Unlock()

	delta := absolute - current
	if delta <= 0 {
		return
	}
	t.recordTransferBytes(sessionID, transferID, direction, delta)
}

func (t *liveTracker) finishTransfer(transferID string) {
	if t == nil || strings.TrimSpace(transferID) == "" {
		return
	}
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	transfer := t.transfers[transferID]
	if transfer == nil {
		return
	}
	if session := t.sessions[transfer.sessionID]; session != nil {
		if session.activeTransfers > 0 {
			session.activeTransfers--
		}
		session.lastOperation = transfer.direction
		session.lastPath = transfer.path
		session.lastActivityAt = now
		connID := firstLiveNonEmpty(transfer.connectionID, session.connectionID)
		if conn := t.connections[connID]; conn != nil {
			if conn.activeTransfers > 0 {
				conn.activeTransfers--
			}
			conn.lastOperation = transfer.direction
			conn.lastPath = transfer.path
			conn.lastActivityAt = now
		}
	}
	delete(t.transfers, transferID)
}

func (t *liveTracker) sessionHasConnection(sessionID, connectionID string) bool {
	if t == nil || strings.TrimSpace(sessionID) == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	session := t.sessions[sessionID]
	if session == nil {
		return false
	}
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		return true
	}
	if session.connectionID == connectionID {
		return true
	}
	return session.connections != nil && session.connections[connectionID] > 0
}

func (t *liveTracker) snapshot() liveAdminSnapshot {
	now := time.Now()
	if t == nil {
		return liveAdminSnapshot{
			Now:           now.Unix(),
			NowTime:       liveTime(now),
			RateWindowSec: int64(liveTransferRateWindow.Seconds()),
			Connections:   []liveConnectionSnapshot{},
			Sessions:      []liveSessionSnapshot{},
			Transfers:     []liveTransferSnapshot{},
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	uploadRate := t.upload.rate(now, liveTransferRateWindow)
	downloadRate := t.download.rate(now, liveTransferRateWindow)
	out := liveAdminSnapshot{
		Now:             now.Unix(),
		NowTime:         liveTime(now),
		RateWindowSec:   int64(liveTransferRateWindow.Seconds()),
		ConnectionCount: len(t.connections),
		SessionCount:    len(t.sessions),
		TransferCount:   len(t.transfers),
		UploadBytes:     t.upload.total,
		DownloadBytes:   t.download.total,
		UploadRateBPS:   uploadRate,
		DownloadRateBPS: downloadRate,
		TotalRateBPS:    uploadRate + downloadRate,
		Connections:     make([]liveConnectionSnapshot, 0, len(t.connections)),
		Sessions:        make([]liveSessionSnapshot, 0, len(t.sessions)),
		Transfers:       make([]liveTransferSnapshot, 0, len(t.transfers)),
	}

	for _, conn := range t.connections {
		uploadRate := conn.upload.rate(now, liveTransferRateWindow)
		downloadRate := conn.download.rate(now, liveTransferRateWindow)
		out.Connections = append(out.Connections, liveConnectionSnapshot{
			ID:              conn.id,
			Source:          conn.source,
			Protocol:        conn.protocol,
			RemoteAddr:      conn.remoteAddr,
			LocalAddr:       conn.localAddr,
			IP:              conn.ip,
			State:           conn.state,
			Session:         conn.sessionID,
			UserID:          conn.userID,
			AuthUser:        conn.authUser,
			LoginType:       conn.loginType,
			UserAgent:       conn.userAgent,
			ClientVersion:   conn.userAgent,
			StartedAt:       unixOrZero(conn.startedAt),
			StartedTime:     liveTime(conn.startedAt),
			AgeSec:          liveAgeSeconds(now, conn.startedAt),
			LastActivityAt:  unixOrZero(conn.lastActivityAt),
			LastActivity:    liveTime(conn.lastActivityAt),
			IdleSec:         liveAgeSeconds(now, conn.lastActivityAt),
			Throttled:       conn.throttled,
			Admin:           conn.admin,
			Banned:          conn.banned,
			RequestsActive:  conn.requestsActive,
			ActiveTransfers: conn.activeTransfers,
			LastOperation:   conn.lastOperation,
			LastPath:        conn.lastPath,
			UploadBytes:     conn.upload.total,
			DownloadBytes:   conn.download.total,
			UploadRateBPS:   uploadRate,
			DownloadRateBPS: downloadRate,
			TotalRateBPS:    uploadRate + downloadRate,
		})
	}

	for _, session := range t.sessions {
		uploadRate := session.upload.rate(now, liveTransferRateWindow)
		downloadRate := session.download.rate(now, liveTransferRateWindow)
		out.Sessions = append(out.Sessions, liveSessionSnapshot{
			Session:         session.sessionID,
			ConnectionID:    session.connectionID,
			Source:          session.source,
			Protocol:        session.protocol,
			UserID:          session.userID,
			AuthUser:        session.authUser,
			RemoteAddr:      session.remoteAddr,
			LocalAddr:       session.localAddr,
			IP:              session.ip,
			LoginType:       session.loginType,
			UserAgent:       session.userAgent,
			ClientVersion:   session.userAgent,
			StartedAt:       unixOrZero(session.startedAt),
			StartTime:       liveTime(session.startedAt),
			AgeSec:          liveAgeSeconds(now, session.startedAt),
			LastActivityAt:  unixOrZero(session.lastActivityAt),
			LastActivity:    liveTime(session.lastActivityAt),
			IdleSec:         liveAgeSeconds(now, session.lastActivityAt),
			Admin:           session.admin,
			Banned:          session.banned,
			RequestsActive:  session.requestsActive,
			ActiveTransfers: session.activeTransfers,
			LastOperation:   session.lastOperation,
			LastPath:        session.lastPath,
			LastError:       session.lastError,
			UploadBytes:     session.upload.total,
			DownloadBytes:   session.download.total,
			UploadRateBPS:   uploadRate,
			DownloadRateBPS: downloadRate,
			TotalRateBPS:    uploadRate + downloadRate,
		})
	}

	for _, transfer := range t.transfers {
		out.Transfers = append(out.Transfers, liveTransferSnapshot{
			ID:             transfer.id,
			Session:        transfer.sessionID,
			ConnectionID:   transfer.connectionID,
			Source:         transfer.source,
			Protocol:       transfer.protocol,
			UserID:         transfer.userID,
			RemoteAddr:     transfer.remoteAddr,
			IP:             transfer.ip,
			Direction:      transfer.direction,
			Path:           transfer.path,
			UserAgent:      transfer.userAgent,
			ClientVersion:  transfer.userAgent,
			StartedAt:      unixOrZero(transfer.startedAt),
			StartTime:      liveTime(transfer.startedAt),
			AgeSec:         liveAgeSeconds(now, transfer.startedAt),
			LastActivityAt: unixOrZero(transfer.lastActivityAt),
			LastActivity:   liveTime(transfer.lastActivityAt),
			IdleSec:        liveAgeSeconds(now, transfer.lastActivityAt),
			Bytes:          transfer.bytes.total,
			RateBPS:        transfer.bytes.rate(now, liveTransferRateWindow),
		})
	}

	sort.Slice(out.Connections, func(i, j int) bool {
		return out.Connections[i].StartedAt < out.Connections[j].StartedAt
	})
	sort.Slice(out.Sessions, func(i, j int) bool {
		if out.Sessions[i].LastActivityAt == out.Sessions[j].LastActivityAt {
			return out.Sessions[i].StartedAt < out.Sessions[j].StartedAt
		}
		return out.Sessions[i].LastActivityAt > out.Sessions[j].LastActivityAt
	})
	sort.Slice(out.Transfers, func(i, j int) bool {
		if out.Transfers[i].RateBPS == out.Transfers[j].RateBPS {
			return out.Transfers[i].StartedAt < out.Transfers[j].StartedAt
		}
		return out.Transfers[i].RateBPS > out.Transfers[j].RateBPS
	})

	return out
}

func (t *liveTracker) ensureMaps() {
	if t.connections == nil {
		t.connections = make(map[string]*liveConnectionState)
	}
	if t.sessions == nil {
		t.sessions = make(map[string]*liveSessionState)
	}
	if t.transfers == nil {
		t.transfers = make(map[string]*liveTransferState)
	}
}

func (c *liveRollingCounter) add(now time.Time, n int64) {
	if n <= 0 {
		return
	}
	if c.buckets == nil {
		c.buckets = make(map[int64]int64)
	}
	c.total += n
	c.buckets[now.Unix()] += n
}

func (c *liveRollingCounter) rate(now time.Time, window time.Duration) float64 {
	if c == nil || len(c.buckets) == 0 || window <= 0 {
		return 0
	}
	cutoff := now.Add(-window).Unix() + 1
	var bytes int64
	for sec, n := range c.buckets {
		if sec < cutoff {
			delete(c.buckets, sec)
			continue
		}
		bytes += n
	}
	if bytes <= 0 {
		return 0
	}
	return float64(bytes) / window.Seconds()
}

func liveTracePath(args []any) string {
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok || key != "path" {
			continue
		}
		return strings.TrimSpace(fmt.Sprint(args[i+1]))
	}
	return ""
}

func liveAddrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func liveHTTPRemoteAddr(r *http.Request) net.Addr {
	if r == nil {
		return nil
	}
	addr := strings.TrimSpace(r.RemoteAddr)
	if host, portStr, err := net.SplitHostPort(addr); err == nil {
		port, _ := strconv.Atoi(portStr)
		if ip := net.ParseIP(host); ip != nil {
			return &net.TCPAddr{IP: ip, Port: port}
		}
		return stringAddr(addr)
	}
	if ip := net.ParseIP(addr); ip != nil {
		return &net.TCPAddr{IP: ip}
	}
	return stringAddr(addr)
}

func liveHTTPLocalAddr(r *http.Request) net.Addr {
	if r == nil {
		return nil
	}
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return addr
}

func liveSSHVersion(raw []byte) string {
	return strings.TrimSpace(string(raw))
}

func normalizeLiveDirection(direction string) string {
	direction = strings.ToLower(strings.TrimSpace(direction))
	switch direction {
	case "upload", "download":
		return direction
	default:
		return ""
	}
}

func normalizeLiveSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		return ""
	}
	source = strings.ReplaceAll(source, "_", "-")
	return source
}

func firstLiveNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func liveTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func liveAgeSeconds(now, then time.Time) int64 {
	if then.IsZero() {
		return 0
	}
	if now.Before(then) {
		return 0
	}
	return int64(now.Sub(then).Seconds())
}
