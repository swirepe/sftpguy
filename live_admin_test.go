package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sftpguy/internal/explorerevents"
)

func TestLiveAdminSnapshotTracksActiveSessionAndTransfer(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.44"), Port: 4242}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2022}
	connID := srv.startLiveConnection(remoteAddr, localAddr, true)
	srv.markLiveConnectionState(connID, "handshake")
	srv.startLiveSession(liveSessionStart{
		ConnectionID: connID,
		SessionID:    "sess-live",
		UserID:       "live-user",
		AuthUser:     "anonymous",
		RemoteAddr:   remoteAddr,
		LocalAddr:    localAddr,
		LoginType:    "pubkey-hash",
		UserAgent:    "SSH-2.0-TestClient_1.0",
		Banned:       true,
		SessionStart: time.Now().Add(-2 * time.Second),
	})

	finishReq := srv.startLiveSFTPRequest("sess-live", "read", "dataset.bin")
	transferID := srv.startLiveTransfer("sess-live", "download", "dataset.bin")
	srv.recordLiveTransferBytes("sess-live", transferID, "download", 2048)

	snap := srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 1 || snap.SessionCount != 1 || snap.TransferCount != 1 {
		t.Fatalf("unexpected live counts: connections=%d sessions=%d transfers=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount)
	}
	if snap.DownloadBytes != 2048 || snap.DownloadRateBPS <= 0 {
		t.Fatalf("expected live download bytes and rate, got bytes=%d rate=%f", snap.DownloadBytes, snap.DownloadRateBPS)
	}
	if len(snap.Sessions) != 1 {
		t.Fatalf("expected one live session, got %d", len(snap.Sessions))
	}
	session := snap.Sessions[0]
	if session.Session != "sess-live" || session.UserID != "live-user" || session.IP != "198.51.100.44" {
		t.Fatalf("unexpected session snapshot: %#v", session)
	}
	if session.UserAgent != "SSH-2.0-TestClient_1.0" || session.RequestsActive != 1 || session.ActiveTransfers != 1 {
		t.Fatalf("expected user agent, active request, and active transfer in session snapshot: %#v", session)
	}
	if session.DownloadBytes != 2048 || session.DownloadRateBPS <= 0 {
		t.Fatalf("expected session download bytes and rate, got bytes=%d rate=%f", session.DownloadBytes, session.DownloadRateBPS)
	}
	if len(snap.Transfers) != 1 {
		t.Fatalf("expected one live transfer, got %d", len(snap.Transfers))
	}
	transfer := snap.Transfers[0]
	if transfer.Path != "dataset.bin" || transfer.Direction != "download" || transfer.Bytes != 2048 || transfer.RateBPS <= 0 {
		t.Fatalf("unexpected transfer snapshot: %#v", transfer)
	}

	finishReq(nil)
	srv.finishLiveTransfer(transferID)
	srv.finishLiveSession("sess-live")
	srv.finishLiveConnection(connID)

	snap = srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 0 || snap.SessionCount != 0 || snap.TransferCount != 0 {
		t.Fatalf("expected live rows to clear after close, got connections=%d sessions=%d transfers=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount)
	}
	if snap.DownloadBytes != 2048 {
		t.Fatalf("expected process-level byte total to remain, got %d", snap.DownloadBytes)
	}
}

func TestHandleAdminLiveReturnsSnapshot(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.55"), Port: 5555}
	connID := srv.startLiveConnection(remoteAddr, nil, false)
	srv.startLiveSession(liveSessionStart{
		ConnectionID: connID,
		SessionID:    "sess-handler-live",
		UserID:       "handler-user",
		RemoteAddr:   remoteAddr,
		LoginType:    "pwd-auth",
		UserAgent:    "SSH-2.0-HandlerClient_2.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/live", nil)
	w := httptest.NewRecorder()
	srv.handleAdminLive(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/live status=%d body=%s", w.Code, w.Body.String())
	}

	var payload liveAdminSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode live payload: %v", err)
	}
	if payload.SessionCount != 1 || len(payload.Sessions) != 1 {
		t.Fatalf("expected one session in payload, got count=%d len=%d", payload.SessionCount, len(payload.Sessions))
	}
	if payload.Sessions[0].UserAgent != "SSH-2.0-HandlerClient_2.0" {
		t.Fatalf("expected user agent in live payload, got %#v", payload.Sessions[0])
	}
}

func TestLiveAdminTracksExplorerRequestAndTransferLifecycle(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const (
		eventID   = "req-live-explorer"
		sessionID = "explorer-session-live"
		clientIP  = "198.51.100.88"
		relPath   = "files/big.bin"
	)
	requestStart := explorerevents.Event{
		ID:         eventID,
		Kind:       explorerevents.KindRequest,
		Phase:      explorerevents.PhaseStart,
		ClientIP:   clientIP,
		RemoteAddr: clientIP + ":4567",
		Session:    sessionID,
		Method:     http.MethodGet,
		URLPath:    "/" + relPath,
		Meta:       map[string]any{"user_agent": "ExplorerTest/1.0"},
	}
	if err := srv.recordExplorerEvent(requestStart); err != nil {
		t.Fatalf("record explorer request start: %v", err)
	}

	snap := srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 1 || snap.SessionCount != 1 || snap.TransferCount != 0 {
		t.Fatalf("unexpected request-start counts: connections=%d sessions=%d transfers=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount)
	}
	if got := snap.Connections[0]; got.Source != "explorer" || got.Protocol != "http" || got.RequestsActive != 1 || got.UserAgent != "ExplorerTest/1.0" {
		t.Fatalf("unexpected explorer connection snapshot: %#v", got)
	}

	downloadStart := explorerevents.Event{
		ID:         eventID,
		Kind:       explorerevents.KindDownload,
		Phase:      explorerevents.PhaseStart,
		ClientIP:   clientIP,
		RemoteAddr: clientIP + ":4567",
		Session:    sessionID,
		Path:       relPath,
		Method:     http.MethodGet,
		URLPath:    "/" + relPath,
		Size:       8192,
		Meta:       map[string]any{"user_agent": "ExplorerTest/1.0"},
	}
	if err := srv.recordExplorerEvent(downloadStart); err != nil {
		t.Fatalf("record explorer download start: %v", err)
	}

	snap = srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 1 || snap.SessionCount != 1 || snap.TransferCount != 1 {
		t.Fatalf("unexpected download-start counts: connections=%d sessions=%d transfers=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount)
	}
	if got := snap.Sessions[0]; got.Source != "explorer" || got.Protocol != "http" || got.RequestsActive != 1 || got.ActiveTransfers != 1 || got.LastPath != relPath {
		t.Fatalf("unexpected explorer session snapshot: %#v", got)
	}
	if got := snap.Transfers[0]; got.Source != "explorer" || got.Direction != "download" || got.Path != relPath || got.Bytes != 0 || got.UserAgent != "ExplorerTest/1.0" {
		t.Fatalf("unexpected explorer transfer snapshot: %#v", got)
	}

	progress := downloadStart
	progress.Phase = explorerevents.PhaseProgress
	progress.Bytes = 4096
	if err := srv.recordExplorerEvent(progress); err != nil {
		t.Fatalf("record explorer download progress: %v", err)
	}
	snap = srv.LiveAdminSnapshot()
	if snap.DownloadBytes != 4096 || snap.DownloadRateBPS <= 0 || snap.Transfers[0].Bytes != 4096 || snap.Transfers[0].RateBPS <= 0 {
		t.Fatalf("expected live download progress, got snapshot=%#v transfer=%#v", snap, snap.Transfers[0])
	}

	finishedDownload := downloadStart
	finishedDownload.Phase = explorerevents.PhaseFinish
	finishedDownload.Bytes = 8192
	if err := srv.recordExplorerEvent(finishedDownload); err != nil {
		t.Fatalf("record explorer download finish: %v", err)
	}
	snap = srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 1 || snap.SessionCount != 1 || snap.TransferCount != 0 || snap.DownloadBytes != 8192 {
		t.Fatalf("expected transfer to finish while request remains open, got connections=%d sessions=%d transfers=%d bytes=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount, snap.DownloadBytes)
	}

	requestFinish := requestStart
	requestFinish.Phase = explorerevents.PhaseFinish
	requestFinish.Status = http.StatusOK
	requestFinish.DurationMS = 250
	if err := srv.recordExplorerEvent(requestFinish); err != nil {
		t.Fatalf("record explorer request finish: %v", err)
	}
	snap = srv.LiveAdminSnapshot()
	if snap.ConnectionCount != 0 || snap.SessionCount != 0 || snap.TransferCount != 0 || snap.DownloadBytes != 8192 {
		t.Fatalf("expected explorer live rows to clear after request finish, got connections=%d sessions=%d transfers=%d bytes=%d", snap.ConnectionCount, snap.SessionCount, snap.TransferCount, snap.DownloadBytes)
	}
}
