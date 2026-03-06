package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	EventAdminLogin  EventKind = "admin/login"
	EventAdminBan    EventKind = "admin/ban"
	EventAdminUnban  EventKind = "admin/unban"
	EventAdminPurge  EventKind = "admin/purge"
	EventAdminSelf   EventKind = "admin/selftest"
	EventAdminConfig EventKind = "admin/config"
)

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
