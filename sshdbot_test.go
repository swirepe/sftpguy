package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPurgeSSHDBotPurgesUserAndSeedsLists(t *testing.T) {
	srv := newMaintenanceTestServer(t)
	defer srv.Shutdown()

	const ownerHash = "sshdbot-owner-hash"
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.44"), Port: 2222}
	if _, err := srv.store.UpsertUserSession(ownerHash, remoteAddr); err != nil {
		t.Fatalf("upsert owner session: %v", err)
	}

	botDir := "." + stRandDigits()
	botRel := path.Join(botDir, "sshd")
	victimRel := path.Join("sshdbot", "other.txt")
	botFullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(botRel))
	victimFullPath := filepath.Join(srv.absUploadDir, filepath.FromSlash(victimRel))
	botPayload := []byte("malware payload")
	victimPayload := []byte("innocent bystander")

	for _, dir := range []string{filepath.Dir(botFullPath), filepath.Dir(victimFullPath)} {
		if err := os.MkdirAll(dir, permDir); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(botFullPath, botPayload, permFile); err != nil {
		t.Fatalf("write bot payload: %v", err)
	}
	if err := os.WriteFile(victimFullPath, victimPayload, permFile); err != nil {
		t.Fatalf("write victim payload: %v", err)
	}

	if err := srv.store.EnsureDirectory(ownerHash, botDir); err != nil {
		t.Fatalf("ensure bot dir: %v", err)
	}
	if err := srv.store.EnsureDirectory(ownerHash, path.Dir(victimRel)); err != nil {
		t.Fatalf("ensure victim dir: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, botRel, int64(len(botPayload)), int64(len(botPayload))); err != nil {
		t.Fatalf("register bot payload: %v", err)
	}
	if err := srv.store.UpdateFileWrite(ownerHash, ownerHash, victimRel, int64(len(victimPayload)), int64(len(victimPayload))); err != nil {
		t.Fatalf("register victim payload: %v", err)
	}

	callbackIPs := []string{"198.51.100.10", "203.0.113.77"}
	cmd := fmt.Sprintf("chmod +x ./%s;nohup ./%s %s %s &", botRel, botRel, callbackIPs[0], callbackIPs[1])
	payload := ssh.Marshal(struct{ Value string }{Value: cmd})

	srv.PurgeSSHDBot(ownerHash, "sess-sshdbot", remoteAddr, payload)

	if _, _, err := srv.store.blacklist.Reload(); err != nil {
		t.Fatalf("reload blacklist: %v", err)
	}
	if _, err := srv.store.badFileList.Reload(); err != nil {
		t.Fatalf("reload bad file list: %v", err)
	}

	for _, fullPath := range []string{botFullPath, victimFullPath} {
		if _, err := os.Stat(fullPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be removed, got err=%v", fullPath, err)
		}
	}
	for _, rel := range []string{botRel, victimRel, botDir, path.Dir(victimRel)} {
		if srv.store.FileExistsInDB(rel) {
			t.Fatalf("expected %s to be removed from the database", rel)
		}
	}

	stats, err := srv.store.GetUserStats(ownerHash)
	if err != nil {
		t.Fatalf("get user stats after purge: %v", err)
	}
	if !stats.FirstTimer {
		t.Fatalf("expected purged user %q to be removed from users table", ownerHash)
	}

	payloadHash := fmt.Sprintf("%x", sha256.Sum256(botPayload))
	if !srv.store.badFileList.Matches(payloadHash) {
		t.Fatal("expected sshdbot payload hash to be added to bad file list")
	}
	if !srv.store.blacklist.Matches(remoteAddr.IP.String()) {
		t.Fatal("expected sshdbot source IP to be blacklisted")
	}
	for _, ip := range callbackIPs {
		if !srv.store.blacklist.Matches(ip) {
			t.Fatalf("expected callback IP %s to be blacklisted", ip)
		}
	}

	var eventPath, eventMeta, eventIP string
	err = srv.store.db.QueryRow(`
		SELECT
			IFNULL(path, ''),
			IFNULL(meta, ''),
			IFNULL(ip_address, '')
		FROM log
		WHERE event = ? AND user_id = ?
		ORDER BY id DESC
		LIMIT 1
	`, EventAdminSSHDBotDetected, ownerHash).Scan(&eventPath, &eventMeta, &eventIP)
	if err != nil {
		t.Fatalf("query sshdbot detection event: %v", err)
	}
	if want := "./" + botRel; eventPath != want {
		t.Fatalf("unexpected sshdbot event path: got=%q want=%q", eventPath, want)
	}
	if eventIP != remoteAddr.IP.String() {
		t.Fatalf("unexpected sshdbot event ip: got=%q want=%q", eventIP, remoteAddr.IP.String())
	}

	var meta struct {
		Cmd string   `json:"cmd"`
		Ips []string `json:"ips"`
	}
	if err := json.Unmarshal([]byte(eventMeta), &meta); err != nil {
		t.Fatalf("parse sshdbot event meta: %v", err)
	}
	if meta.Cmd != cmd {
		t.Fatalf("unexpected sshdbot event command: got=%q want=%q", meta.Cmd, cmd)
	}
	if len(meta.Ips) != len(callbackIPs) || meta.Ips[0] != callbackIPs[0] || meta.Ips[1] != callbackIPs[1] {
		t.Fatalf("unexpected sshdbot event callback IPs: got=%v want=%v", meta.Ips, callbackIPs)
	}
}
