package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	EventAdminLogin       EventKind = "admin/login"
	EventAdminBan         EventKind = "admin/ban"
	EventAdminUnban       EventKind = "admin/unban"
	EventAdminPurge       EventKind = "admin/purge"
	EventAdminSelf        EventKind = "admin/selftest"
	EventAdminConfig      EventKind = "admin/config"
	EventAdminMaintenance EventKind = "admin/maintenance"
)

const adminBanner = `
┏━┓╺┳┓┏┳┓╻┏┓╻╻┏━┓╺┳╸┏━┓┏━┓╺┳╸┏━┓┏━┓
┣━┫ ┃┃┃┃┃┃┃┗┫┃┗━┓ ┃ ┣┳┛┣━┫ ┃ ┃ ┃┣┳┛
╹ ╹╺┻┛╹ ╹╹╹ ╹╹┗━┛ ╹ ╹┗╸╹ ╹ ╹ ┗━┛╹┗╸
`

func (s *Server) WelcomeAdmin(wUnbuf io.Writer, loginKeyHash string) {
	w := bufio.NewWriter(wUnbuf)
	keyID := shortID(loginKeyHash)
	if keyID == "" {
		keyID = "unknown"
	}

	fmt.Fprintf(w, "\r\n%s\r\n", red.Bold(adminBanner))
	fmt.Fprintln(w, red.Bold("* ADMIN MODE ACTIVE"))
	fmt.Fprintln(w, "* You are connected as the system owner.")
	fmt.Fprintln(w, "* Read/write/rename/delete operations are unrestricted.")
	fmt.Fprintf(w, "* Login key hash: %s\r\n", cyan.Bold(keyID))
	if maxSize := s.cfg.MaxFileSize; maxSize > 0 {
		fmt.Fprintf(w, "* Max file size still applies: %s\r\n", bold.Fmt(formatBytes(maxSize)))
	}
	fmt.Fprintln(w, "* Use caution: actions affect all users immediately.")
	fmt.Fprintf(w, "\r\n")

	u, c, f, b := s.store.GetBannerStats(s.cfg.ContributorThreshold)
	fmt.Fprintf(w, "\r\nUptime: %s, Users: %d | Contributors: %d | Files: %d | Size: %s\r\n", s.Uptime(), u, c, f, formatBytes(int64(b)))
	w.Flush()
}

func (s *Server) Uptime() time.Duration {
	return time.Since(s.startedAt)
}

func (s *Store) IsBanned(pubkeyHash string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM shadow_banned WHERE pubkey_hash = ?", pubkeyHash).Scan(&exists)
	return exists
}

func (s *Store) IsIPBanned(ip string) bool {
	if s.whitelist.Matches(ip) {
		s.logger.Debug("IP is whitelisted", "ip", ip)
		return false
	}

	if s.blacklist.Matches(ip) {
		s.logger.Debug("IP is blacklisted", "ip", ip)
		return true
	}

	var exists bool
	s.db.QueryRow("SELECT 1 FROM ip_banned WHERE ip_address = ?", ip).Scan(&exists)
	return exists
}

func (s *Store) IsBannedByIp(remoteAddr net.Addr) bool {
	if remoteAddr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return s.IsIPBanned(remoteAddr.String())
	}
	return s.IsIPBanned(host)
}

func (s *Server) isAdminConn(permissions *ssh.Permissions) bool {
	return permissions != nil && permissions.Extensions["admin"] == "1"
}

func (s *Server) checkAdminKey(key ssh.PublicKey) bool {
	hash := publicKeyHash(key)
	if hash == "" {
		return false
	}

	if hash == s.adminHostKeyHash() {
		return true
	}

	return s.store != nil && s.store.adminKeys != nil && s.store.adminKeys.ContainsHash(hash)
}

func (s *Server) ensureAdminHostKeyInAdminKeysFile() error {
	if !s.cfg.AdminSFTP {
		return nil
	}

	adminKeysPath := strings.TrimSpace(s.cfg.AdminKeysPath)
	if s.store != nil {
		if p := strings.TrimSpace(s.store.adminKeysPath); p != "" {
			adminKeysPath = p
		}
	}
	if adminKeysPath == "" {
		adminKeysPath = "admin_keys.txt"
	}

	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return fmt.Errorf("read host key %q: %w", s.cfg.HostKeyFile, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parse host key %q: %w", s.cfg.HostKeyFile, err)
	}

	hostPub := signer.PublicKey()
	hostHash := publicKeyHash(hostPub)
	if hostHash == "" {
		return fmt.Errorf("derive host key hash from %q: empty hash", s.cfg.HostKeyFile)
	}

	existing, err := os.ReadFile(adminKeysPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read admin key file %q: %w", adminKeysPath, err)
	}
	hashes, _ := parseAdminKeysContent(string(existing))
	if _, ok := hashes[hostHash]; ok {
		return nil
	}

	hostKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPub)))
	content := strings.TrimRight(string(existing), "\n")
	if content != "" {
		content += "\n"
	}
	content += hostKeyLine + "\n"

	if err := os.WriteFile(adminKeysPath, []byte(content), permFile); err != nil {
		return fmt.Errorf("write admin key file %q: %w", adminKeysPath, err)
	}

	if s.store != nil && s.store.adminKeys != nil {
		if _, err := s.store.adminKeys.Reload(adminKeysPath); err != nil {
			return fmt.Errorf("reload admin key list %q: %w", adminKeysPath, err)
		}
	}

	s.logger.Info("added server host key to admin key list",
		"path", adminKeysPath,
		"host_key_hash", shortID(hostHash))
	return nil
}

func (s *Server) adminHostKeyHash() string {
	if s.adminHash != "" {
		return s.adminHash
	}

	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return ""
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return ""
	}
	h := publicKeyHash(signer.PublicKey())
	s.adminHash = h
	return h
}

func (s *Server) logAdminLogin(pubkeyHash, sessionID string, remoteAddress net.Addr) {
	s.store.LogEvent(EventAdminLogin, pubkeyHash, sessionID, remoteAddress)
}

func (s *Server) Ban(pubHash string) {
	s.store.exec("INSERT OR IGNORE INTO shadow_banned (pubkey_hash) VALUES (?)", pubHash)
}

func (s *Server) Unban(pubHash string) {
	s.store.exec("DELETE FROM shadow_banned WHERE pubkey_hash = ?", pubHash)
	s.store.exec("DELETE FROM ip_banned WHERE ip_address = ?", pubHash)
}

func (s *Server) PurgeUser(pubHash string) error {
	if pubHash == systemOwner || pubHash == "" {
		return nil
	}
	paths, err := s.store.FilesByOwner(pubHash)
	if err != nil {
		return err
	}

	for _, rel := range paths {
		full := filepath.Join(s.absUploadDir, filepath.FromSlash(rel))
		os.RemoveAll(full)
	}
	s.store.exec("DELETE FROM files WHERE owner_hash = ?", pubHash)
	s.store.exec("DELETE FROM shadow_banned WHERE pubkey_hash = ?", pubHash)
	_, err = s.store.exec("DELETE FROM users WHERE pubkey_hash = ?", pubHash)
	s.store.LogEvent(EventAdminPurge, systemOwner, "admin", nil, "target", pubHash, "purged", paths)
	return err
}

func (s *Server) PurgeByFile(relPath string) error {
	relPath = strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(relPath)), "/")
	if relPath == "" || relPath == "." {
		return nil
	}

	owner, err := s.store.GetFileOwner(relPath)
	if err != nil {
		return err
	}

	if owner != "" && owner != systemOwner {
		if err := s.PurgeUser(owner); err != nil {
			return err
		}
	}

	full := filepath.Join(s.absUploadDir, filepath.FromSlash(relPath))
	if err := os.RemoveAll(full); err != nil {
		return err
	}
	if err := s.store.DeletePath(relPath); err != nil {
		return err
	}
	return nil
}

func tailFile(filename string, n int, filter string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		txt := scanner.Text()
		if filter == "" || strings.Contains(txt, filter) {
			lines = append(lines, txt)
			if len(lines) > n {
				lines = lines[1:]
			}
		}
	}

	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines, scanner.Err()
}
