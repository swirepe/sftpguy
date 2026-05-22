package main

import (
	"context"
	"net"
	"testing"
	"time"

	"sftpguy/internal/explorerevents"
)

func TestLogEventHostnameLookupDoesNotDelayInsert(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	lookedUp := make(chan string, 1)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	srv.store.eventHostnameLookup = func(ctx context.Context, ip string) ([]string, error) {
		lookedUp <- ip
		select {
		case <-release:
			return []string{"remote.example.", "", "remote.example."}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	srv.store.LogEvent(EventLogin, "hostname-user", "hostname-session", &net.TCPAddr{
		IP:   net.ParseIP("8.8.8.8"),
		Port: 2022,
	}, "source", "sftp")

	rowID, rawMeta := latestLogEventRow(t, srv, EventLogin)
	if hosts := stringSliceFromAny(parseJSONMap(rawMeta)["hosts"]); len(hosts) != 0 {
		t.Fatalf("event row had hosts before lookup completed: %#v", hosts)
	}
	select {
	case ip := <-lookedUp:
		if ip != "8.8.8.8" {
			t.Fatalf("lookup ip = %q, want 8.8.8.8", ip)
		}
	case <-time.After(time.Second):
		t.Fatal("hostname lookup did not start")
	}

	close(release)
	hosts := waitForLogEventHosts(t, srv, rowID)
	if len(hosts) != 1 || hosts[0] != "remote.example." {
		t.Fatalf("event hosts = %#v, want [remote.example.]", hosts)
	}
}

func TestLogEventHostnameLookupSkipsLocalIP(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	lookedUp := make(chan string, 1)
	srv.store.eventHostnameLookup = func(_ context.Context, ip string) ([]string, error) {
		lookedUp <- ip
		return []string{"localhost"}, nil
	}

	srv.store.LogEvent(EventLogin, "local-user", "local-session", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 2022,
	})
	latestLogEventRow(t, srv, EventLogin)

	select {
	case ip := <-lookedUp:
		t.Fatalf("looked up local ip %q", ip)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestRecordExplorerEventHostnameLookupUsesClientIP(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	lookedUp := make(chan string, 1)
	srv.store.eventHostnameLookup = func(_ context.Context, ip string) ([]string, error) {
		lookedUp <- ip
		return []string{"explorer.example."}, nil
	}

	if err := srv.recordExplorerEvent(explorerevents.Event{
		Kind:       explorerevents.KindRequest,
		ClientIP:   "8.8.4.4",
		RemoteAddr: "127.0.0.1:58050",
		Method:     "GET",
		URLPath:    "/shared",
		Status:     200,
	}); err != nil {
		t.Fatalf("record explorer request: %v", err)
	}

	rowID, _ := latestLogEventRow(t, srv, EventExplorerRequest)
	select {
	case ip := <-lookedUp:
		if ip != "8.8.4.4" {
			t.Fatalf("lookup ip = %q, want explorer client ip 8.8.4.4", ip)
		}
	case <-time.After(time.Second):
		t.Fatal("explorer hostname lookup did not start")
	}
	hosts := waitForLogEventHosts(t, srv, rowID)
	if len(hosts) != 1 || hosts[0] != "explorer.example." {
		t.Fatalf("explorer event hosts = %#v, want [explorer.example.]", hosts)
	}
}

func latestLogEventRow(t *testing.T, srv *Server, event EventKind) (int64, string) {
	t.Helper()

	var id int64
	var meta string
	if err := srv.store.db.QueryRow(`
		SELECT id, IFNULL(meta, '')
		FROM log
		WHERE event = ?
		ORDER BY id DESC
		LIMIT 1`, string(event)).Scan(&id, &meta); err != nil {
		t.Fatalf("query latest %s event: %v", event, err)
	}
	return id, meta
}

func waitForLogEventHosts(t *testing.T, srv *Server, rowID int64) []string {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		var rawMeta string
		if err := srv.store.db.QueryRow(`SELECT IFNULL(meta, '') FROM log WHERE id = ?`, rowID).Scan(&rawMeta); err != nil {
			t.Fatalf("query event %d meta: %v", rowID, err)
		}
		if hosts := stringSliceFromAny(parseJSONMap(rawMeta)["hosts"]); len(hosts) > 0 {
			return hosts
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %d hosts were not added; meta=%q", rowID, rawMeta)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
