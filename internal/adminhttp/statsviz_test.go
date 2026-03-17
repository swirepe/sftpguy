package adminhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type staticStatsSource struct{}

func (staticStatsSource) StatsSnapshot() StatsSnapshot {
	return StatsSnapshot{
		UsersTotal:             12,
		ContributorsTotal:      4,
		FilesTotal:             42,
		DirectoriesTotal:       9,
		StoredBytes:            8192,
		ShadowBannedUsersTotal: 1,
		BannedIPsTotal:         2,
	}
}

func TestHandlerRegistersStatsVizRoute(t *testing.T) {
	mux := Handler(Config{
		Token:           "topsecret",
		TokenCookieName: "admin_cookie",
		StatsSource:     staticStatsSource{},
	}, RouteHandlers{})

	unauthReq := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	unauthW := httptest.NewRecorder()
	mux.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /admin/stats request, got %d", unauthW.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	authReq.Header.Set("Authorization", "Bearer topsecret")
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusFound {
		t.Fatalf("expected redirect for /admin/stats, got %d", authW.Code)
	}
	if got := authW.Header().Get("Location"); got != "/admin/stats/" {
		t.Fatalf("expected /admin/stats redirect to slash form, got %q", got)
	}

	pageReq := httptest.NewRequest(http.MethodGet, "/admin/stats/", nil)
	pageReq.Header.Set("Authorization", "Bearer topsecret")
	pageW := httptest.NewRecorder()
	mux.ServeHTTP(pageW, pageReq)
	if pageW.Code != http.StatusOK {
		t.Fatalf("expected /admin/stats/ to serve statsviz, got %d", pageW.Code)
	}
	if ct := pageW.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected statsviz html response, got content-type %q", ct)
	}
	if pageW.Body.Len() == 0 {
		t.Fatal("expected statsviz page body to be non-empty")
	}

	wsReq := httptest.NewRequest(http.MethodGet, "/admin/stats/ws", nil)
	wsW := httptest.NewRecorder()
	mux.ServeHTTP(wsW, wsReq)
	if wsW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /admin/stats/ws request, got %d", wsW.Code)
	}
}
