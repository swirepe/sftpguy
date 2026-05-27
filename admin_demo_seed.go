package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const adminDemoBannedIP = "9.9.9.9"

type AdminDemoSeedStats struct {
	Users     int
	Files     int
	Events    int
	BannedIPs int
}

type adminDemoActor struct {
	Hash    string
	IP      string
	Port    int
	Host    string
	Session string
}

type adminDemoFile struct {
	Path    string
	Content string
	Owner   adminDemoActor
}

func (a adminDemoActor) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(a.IP), Port: a.Port}
}

func SeedAdminDemoData(cfg Config, logger *slog.Logger) (AdminDemoSeedStats, error) {
	store, err := NewStore(cfg, logger)
	if err != nil {
		return AdminDemoSeedStats{}, err
	}
	defer store.Close()

	absUploadDir, err := filepath.Abs(cfg.UploadDir)
	if err != nil {
		return AdminDemoSeedStats{}, fmt.Errorf("resolve upload dir: %w", err)
	}
	if err := os.MkdirAll(absUploadDir, permDir); err != nil {
		return AdminDemoSeedStats{}, fmt.Errorf("create upload dir: %w", err)
	}

	return seedAdminDemoData(store, absUploadDir, time.Now().UTC())
}

func seedAdminDemoData(store *Store, absUploadDir string, now time.Time) (AdminDemoSeedStats, error) {
	batch := now.Format("20060102T150405Z")
	uploader := adminDemoActor{
		Hash:    "demo-map-uploader",
		IP:      "8.8.8.8",
		Port:    51022,
		Host:    "dns.google",
		Session: "demo-upload-" + batch,
	}
	downloader := adminDemoActor{
		Hash:    "demo-map-downloader",
		IP:      "1.1.1.1",
		Port:    51023,
		Host:    "one.one.one.one",
		Session: "demo-download-" + batch,
	}
	operator := adminDemoActor{
		Hash:    "demo-map-operator",
		IP:      "151.101.1.69",
		Port:    51024,
		Host:    "demo-edge.sftpguy.test",
		Session: "demo-exec-" + batch,
	}
	scanner := adminDemoActor{
		Hash:    "demo-map-scanner",
		IP:      adminDemoBannedIP,
		Port:    51025,
		Host:    "dns9.quad9.net",
		Session: "demo-scan-" + batch,
	}
	local := adminDemoActor{
		Hash:    "demo-map-local",
		IP:      "127.0.0.1",
		Port:    51026,
		Host:    "localhost",
		Session: "demo-local-" + batch,
	}
	actors := []adminDemoActor{uploader, downloader, operator, scanner, local}
	for _, actor := range actors {
		if _, err := store.UpsertUserSession(actor.Hash, actor.Addr()); err != nil {
			return AdminDemoSeedStats{}, fmt.Errorf("upsert demo user %s: %w", actor.Hash, err)
		}
	}

	files := []adminDemoFile{
		{
			Path: "demo/reports/connection-hostnames.csv",
			Content: "ip,hostname,activity\n" +
				"8.8.8.8,dns.google,upload\n" +
				"1.1.1.1,one.one.one.one,download\n",
			Owner: uploader,
		},
		{
			Path: "demo/notes/admin-map-observations.txt",
			Content: "Demo admin activity seed\n\n" +
				"- uploads and downloads create file overlays\n" +
				"- denied auth and path attempts create security overlays\n" +
				"- event metadata carries hostnames for inspection\n",
			Owner: operator,
		},
	}
	for _, file := range files {
		if err := writeAdminDemoFile(store, absUploadDir, file); err != nil {
			return AdminDemoSeedStats{}, err
		}
	}

	stats := AdminDemoSeedStats{Users: len(actors), Files: len(files)}
	logEvent := func(kind EventKind, actor adminDemoActor, args ...any) {
		args = append(args,
			"hosts", []string{actor.Host},
			"demo_seed", true,
		)
		store.LogEvent(kind, actor.Hash, actor.Session, actor.Addr(), args...)
		stats.Events++
	}

	logEvent(EventConnect, uploader, "source", "sftp")
	logEvent(EventSessionStart, uploader, "source", "sftp")
	logEvent(EventLogin, uploader,
		"source", "sftp",
		"auth_method", "publickey",
		"client", "OpenSSH_9.9")
	for _, file := range files {
		logEvent(EventUpload, file.Owner,
			"path", file.Path,
			"source", "sftp",
			"size", int64(len(file.Content)),
			"delta", int64(len(file.Content)),
			"transferred", int64(len(file.Content)),
			"duration_ms", 38,
			"avg_bytes_per_sec", int64(len(file.Content))*26)
	}

	firstFile := files[0]
	if err := store.RecordDownload(downloader.Hash, firstFile.Path, int64(len(firstFile.Content))); err != nil {
		return AdminDemoSeedStats{}, fmt.Errorf("record demo download: %w", err)
	}
	logEvent(EventSessionStart, downloader, "source", "sftp")
	logEvent(EventDownload, downloader,
		"path", firstFile.Path,
		"source", "explorer",
		"phase", "finish",
		"size", int64(len(firstFile.Content)),
		"bytes", int64(len(firstFile.Content)),
		"user_agent", "Mozilla/5.0 (Admin v2 demo explorer)")

	logEvent(EventSessionStart, operator, "source", "sftp")
	logEvent(EventExec, operator,
		"path", "uname -a",
		"source", "sftp",
		"cmd", "uname -a",
		"status", "rejected")
	logEvent(EventDeniedSystemFile, operator,
		"path", "RULES.txt",
		"source", "sftp",
		"reason", "protected system file")
	logEvent(EventRename, operator,
		"path", "demo/notes/admin-map-observations.txt",
		"new_path", "demo/notes/admin-map-field-notes.txt",
		"source", "sftp",
		"operation", "rename")
	logEvent(EventDelete, downloader,
		"path", "demo/tmp/stale-report.tmp",
		"source", "sftp",
		"operation", "delete")
	logEvent(EventAdminConfig, operator,
		"source", "admin",
		"action", "rotate demo admin key")

	logEvent(EventConnect, scanner, "source", "sftp")
	for _, deniedPath := range []string{"../private/keys.txt", "../../etc/shadow", ".ssh/authorized_keys"} {
		logEvent(EventDeniedPathTraversal, scanner,
			"path", deniedPath,
			"source", "sftp",
			"reason", "demo denied path attempt")
	}
	for _, password := range []string{"admin", "password123"} {
		logEvent(EventAuthAttempt, scanner,
			"source", "sftp",
			"username", "root",
			"password", password,
			"auth_method", "keyboard-interactive",
			"generated_hash", scanner.Hash)
	}
	store.LogConnectionLimitExceeded(scanner.Addr(), 7, 4)
	stats.Events++

	logEvent(EventSessionStart, local,
		"source", "sftp",
		"note", "local activity shows up in map coverage without a GeoIP dot")

	added, err := store.blacklist.AddExactIPWithComment(adminDemoBannedIP, adminIPBanComment(now)+" admin v2 demo seed")
	if err != nil {
		return AdminDemoSeedStats{}, fmt.Errorf("ban demo IP: %w", err)
	}
	if added {
		stats.BannedIPs = 1
	}
	store.LogEvent(EventAdminBan, systemOwner, "admin-demo-"+batch, nil,
		"target", adminDemoBannedIP,
		"type", "ip",
		"source", "admin",
		"demo_seed", true)
	stats.Events++

	return stats, nil
}

func writeAdminDemoFile(store *Store, absUploadDir string, file adminDemoFile) error {
	cleanRel := strings.TrimPrefix(path.Clean("/"+file.Path), "/")
	if cleanRel == "." || cleanRel == "" {
		return fmt.Errorf("demo file has empty path")
	}

	fullPath := filepath.Join(absUploadDir, filepath.FromSlash(cleanRel))
	if err := os.MkdirAll(filepath.Dir(fullPath), permDir); err != nil {
		return fmt.Errorf("create demo file dir %s: %w", cleanRel, err)
	}
	if err := os.WriteFile(fullPath, []byte(file.Content), permFile); err != nil {
		return fmt.Errorf("write demo file %s: %w", cleanRel, err)
	}

	if dir := path.Dir(cleanRel); dir != "." && dir != "" {
		if err := store.EnsureDirectory(file.Owner.Hash, dir); err != nil {
			return fmt.Errorf("register demo dir %s: %w", dir, err)
		}
	}
	if err := store.UpdateFileWrite(file.Owner.Hash, file.Owner.Hash, cleanRel, int64(len(file.Content)), int64(len(file.Content))); err != nil {
		return fmt.Errorf("register demo file %s: %w", cleanRel, err)
	}
	return nil
}
