package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type badFileMatch struct {
	relPath   string
	ownerHash string
	ownerAddr string
	knownAs   string
}

type MaintenanceResult struct {
	CleanDeletedResult          CleanDeletedResult
	ReconcileOrphansResult      ReconcileOrphansResult
	PurgeBlackListedFilesResult PurgeBlackListedFilesResult
}

func (s *Server) RunMaintenancePass(ctx context.Context) (bool, MaintenanceResult) {
	var mr MaintenanceResult
	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	mr.CleanDeletedResult = s.cleanDeleted()

	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	mr.ReconcileOrphansResult = s.reconcileOrphans()

	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	s.purgeBlacklistedFiles()
	return true, mr
}

func (s *Server) cleanAndReconcile(ctx context.Context, dur time.Duration) {
	var prev MaintenanceResult
	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			halted, res := s.RunMaintenancePass(ctx)
			// TODO: compare prev and res. if different, log
			if !halted {
				s.logger.Info("Stopping clean and reconcile loop")
				return
			}
			prev = res
		case <-ctx.Done():
			s.logger.Info("Stopping clean and reconcile loop")
			return
		}
	}
}

type CleanDeletedResult struct {
}

func (s *Server) cleanDeleted() CleanDeletedResult {
	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "clean_deleted")
	var numDeleted int64
	defer func() {
		logger.Info("Finished cleaning deleted files", "deleted", numDeleted, "duration", time.Since(start))
	}()

	rows, err := s.store.db.Query("SELECT path FROM files ORDER BY LENGTH(path), path")
	if err != nil {
		logger.Error("failed to query file records for cleanup", "err", err)
		return
	}
	defer rows.Close()

	var staleRoots []string
	staleSet := make(map[string]struct{})
	for rows.Next() {
		var relPath string
		if err := rows.Scan(&relPath); err != nil {
			logger.Error("failed to scan file record during cleanup", "err", err)
			return
		}

		if hasDeletedAncestor(relPath, staleSet) {
			continue
		}

		fullPath := filepath.Join(s.absUploadDir, filepath.FromSlash(relPath))
		if _, err := os.Lstat(fullPath); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			logger.Warn("failed to stat path during cleanup", "path", relPath, "err", err)
			continue
		}

		staleRoots = append(staleRoots, relPath)
		staleSet[relPath] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		logger.Error("failed to iterate file records during cleanup", "err", err)
		return
	}

	if len(staleRoots) == 0 {
		return
	}

	if err := rows.Close(); err != nil {
		logger.Error("failed to close file record cursor during cleanup", "err", err)
		return
	}

	tx, err := s.store.db.Begin()
	if err != nil {
		logger.Error("failed to begin cleanup transaction", "err", err)
		return
	}
	defer tx.Rollback()

	for _, relPath := range staleRoots {
		prefixLen := len(relPath) + 1
		res, err := tx.Exec(`
			DELETE FROM files
			WHERE path = ? OR substr(path, 1, ?) = ?`,
			relPath, prefixLen, relPath+"/")
		if err != nil {
			logger.Error("failed to delete stale file record", "path", relPath, "err", err)
			return
		}

		deleted, err := res.RowsAffected()
		if err != nil {
			logger.Warn("failed to count deleted file records", "path", relPath, "err", err)
			continue
		}
		numDeleted += deleted
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit cleanup transaction", "err", err)
		numDeleted = 0
	}
}

func hasDeletedAncestor(relPath string, staleSet map[string]struct{}) bool {
	for parent := path.Dir(relPath); parent != "." && parent != "/"; parent = path.Dir(parent) {
		if _, ok := staleSet[parent]; ok {
			return true
		}
	}
	return false
}

// I bet there's no easy way to see what orphans were added, but we can add other information
type ReconcileOrphansResult struct {
}

func (s *Server) reconcileOrphans() ReconcileOrphansResult {
	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "reconcile_orphans")
	var sysFiles []string
	for p := range s.cfg.unrestrictedMap {
		if strings.HasSuffix(p, "/") {
			cleanPath := path.Clean(strings.TrimSuffix(p, "/"))
			full := filepath.Join(s.absUploadDir, filepath.FromSlash(cleanPath))

			os.MkdirAll(full, permDir)
			s.store.EnsureDirectory(systemOwner, cleanPath)
		} else {
			sysFiles = append(sysFiles, p)
		}
	}
	s.store.RegisterSystemFiles(s.absUploadDir, sysFiles)

	var candidates []FileRecord

	err := filepath.WalkDir(s.absUploadDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == s.absUploadDir {
			return nil
		}

		rel, _ := filepath.Rel(s.absUploadDir, p)
		rel = filepath.ToSlash(rel)

		fi, err := d.Info()
		if err != nil {
			return nil
		}

		candidates = append(candidates, FileRecord{
			Path:      rel,
			OwnerHash: systemOwner,
			Size:      fi.Size(),
			IsDir:     d.IsDir(),
		})
		return nil
	})

	if err != nil {
		logger.Error("error walking upload directory", "duration", time.Since(start), "error", err)
	}

	if len(candidates) > 0 {
		inserted, err := s.store.RegisterFilesBatch(candidates)
		if err != nil {
			logger.Error("failed to batch reconcile files", "duration", time.Since(start), "error", err)
		} else if inserted > 0 {
			logger.Info("reconciled orphan files", "new_count", inserted, "duration", time.Since(start))
		}
	}
	return ReconcileOrphansResult{}
}

type PurgeBlackListedFilesResult struct {
}

func (s *Server) purgeBlacklistedFiles() PurgeBlackListedFilesResult {
	if s.store == nil || s.store.badFileList == nil {
		return PurgeBlackListedFilesResult{}
	}

	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "purge_blacklisted_files")
	matches := s.findBadFileMatches()
	if len(matches) == 0 {
		return PurgeBlackListedFilesResult{}
	}

	var purgeCount int
	var blacklistCount int
	purgedOwners := make(map[string]struct{})

	for _, match := range matches {
		if match.ownerHash != "" && match.ownerHash != systemOwner {
			if _, alreadyPurged := purgedOwners[match.ownerHash]; alreadyPurged {
				continue
			}
		}

		if err := s.PurgeByFile(match.relPath); err != nil {
			s.logger.Error("failed to purge blacklisted file",
				"path", match.relPath,
				"owner", match.ownerHash,
				"match", match.knownAs,
				"err", err)
			continue
		}
		purgeCount++

		if match.ownerHash != "" && match.ownerHash != systemOwner {
			purgedOwners[match.ownerHash] = struct{}{}
		}

		if _, added, err := s.blacklistLastAddress(match.ownerHash, match.ownerAddr, match.knownAs); err != nil {
			logger.Warn("failed to blacklist owner address for bad file",
				"path", match.relPath,
				"owner", match.ownerHash,
				"address", match.ownerAddr,
				"err", err)
		} else if added {
			blacklistCount++
		}
	}

	logger.Warn("bad file maintenance completed",
		"matches", len(matches),
		"purges", purgeCount,
		"blacklist_updates", blacklistCount,
		"duration", time.Since(start))
	return PurgeBlackListedFilesResult{}
}

func (s *Server) findBadFileMatches() []badFileMatch {
	matches := make([]badFileMatch, 0, 4)

	_ = filepath.WalkDir(s.absUploadDir, func(absPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Warn("failed to inspect path during bad file maintenance", "path", absPath, "err", walkErr)
			return nil
		}
		if absPath == s.absUploadDir || d.IsDir() {
			return nil
		}

		matchName, matched, err := s.store.badFileList.MatchFile(absPath)
		if err != nil {
			s.logger.Warn("failed to hash file during bad file maintenance", "path", absPath, "err", err)
			return nil
		}
		if !matched {
			return nil
		}

		relPath, err := filepath.Rel(s.absUploadDir, absPath)
		if err != nil {
			s.logger.Warn("failed to derive relative path for bad file", "path", absPath, "err", err)
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		ownerHash, err := s.store.GetFileOwner(relPath)
		if err != nil {
			s.logger.Warn("failed to resolve owner for bad file", "path", relPath, "err", err)
		}

		ownerAddr := ""
		if ownerHash != "" && ownerHash != systemOwner {
			stats, err := s.store.GetUserStats(ownerHash)
			if err != nil {
				s.logger.Warn("failed to resolve owner address for bad file", "path", relPath, "owner", ownerHash, "err", err)
			} else {
				ownerAddr = strings.TrimSpace(stats.LastAddress)
			}
		}

		matches = append(matches, badFileMatch{
			relPath:   relPath,
			ownerHash: ownerHash,
			ownerAddr: ownerAddr,
			knownAs:   matchName,
		})
		return nil
	})

	return matches
}

func (s *Server) blacklistLastAddress(ownerHash, ownerAddr, matchedName string) (cidr string, added bool, err error) {
	if ownerHash == "" || ownerHash == systemOwner || s.store == nil || s.store.blacklist == nil {
		return "", false, nil
	}
	if strings.TrimSpace(ownerAddr) == "" {
		return "", false, nil
	}

	host, mask, cidr, err := maintenanceBlacklistRange(ownerAddr)
	if err != nil {
		return "", false, err
	}
	if s.store.blacklist.Matches(host) {
		return cidr, false, nil
	}

	comment := "auto bad file owner"
	if matchedName != "" {
		comment = fmt.Sprintf("auto bad file owner (%s)", matchedName)
	}

	if err := s.store.blacklist.AddRange(host, mask, comment); err != nil {
		return cidr, false, err
	}
	if _, _, err := s.store.blacklist.Reload(); err != nil {
		return cidr, false, err
	}

	return cidr, true, nil
}

func maintenanceBlacklistRange(addr string) (host string, mask int, cidr string, err error) {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return "", 0, "", fmt.Errorf("invalid IP address %q", addr)
	}

	bits := 128
	mask = 64
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
		mask = 24
	}

	network := &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(mask, bits)),
		Mask: net.CIDRMask(mask, bits),
	}
	return ip.String(), mask, network.String(), nil
}
