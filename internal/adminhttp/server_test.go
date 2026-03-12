package adminhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthAcceptsBearerOrCookie(t *testing.T) {
	hits := 0
	protected := auth(Config{Token: "topsecret", TokenCookieName: "admin_cookie"}, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	})

	unauthReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	unauthW := httptest.NewRecorder()
	protected(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing credentials, got %d", unauthW.Code)
	}

	bearerReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	bearerReq.Header.Set("Authorization", "Bearer topsecret")
	bearerW := httptest.NewRecorder()
	protected(bearerW, bearerReq)
	if bearerW.Code != http.StatusNoContent {
		t.Fatalf("expected bearer auth to pass, got %d", bearerW.Code)
	}

	cookieReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	cookieReq.Header.Set("Authorization", "Bearer wrong")
	cookieReq.AddCookie(&http.Cookie{Name: "admin_cookie", Value: "topsecret"})
	cookieW := httptest.NewRecorder()
	protected(cookieW, cookieReq)
	if cookieW.Code != http.StatusNoContent {
		t.Fatalf("expected cookie auth to pass, got %d", cookieW.Code)
	}

	if hits != 2 {
		t.Fatalf("expected next handler hits=2, got %d", hits)
	}
}

func TestOneTimeLoginConsumesTokenAndSetsCookie(t *testing.T) {
	remaining := map[string]bool{"abc123": true}
	handler := oneTimeLogin(Config{
		Token:           "master-token",
		TokenCookieName: "sftpguy_admin",
		ConsumeOneTimeToken: func(token string) bool {
			if !remaining[token] {
				return false
			}
			delete(remaining, token)
			return true
		},
	})

	req := httptest.NewRequest(http.MethodGet, OneTimeLoginPath+"?"+OneTimeLoginTokenParam+"=abc123", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 on first token use, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/admin" {
		t.Fatalf("expected redirect to /admin, got %q", got)
	}
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "sftpguy_admin=master-token") {
		t.Fatalf("expected auth cookie to be set, got %q", setCookie)
	}

	replayReq := httptest.NewRequest(http.MethodGet, OneTimeLoginPath+"?"+OneTimeLoginTokenParam+"=abc123", nil)
	replayW := httptest.NewRecorder()
	handler(replayW, replayReq)
	if replayW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when reusing one-time token, got %d", replayW.Code)
	}
}

func TestBuildOneTimeLoginURL(t *testing.T) {
	u := BuildOneTimeLoginURL("https", "admin.example.com:8443", "onetimetoken")
	want := "https://admin.example.com:8443/admin/one-time-login?token=onetimetoken"
	if u != want {
		t.Fatalf("unexpected login url: got=%q want=%q", u, want)
	}
}
