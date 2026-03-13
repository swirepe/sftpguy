package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
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
	CleanDeleted          CleanDeletedResult          `json:"clean_deleted"`
	ReconcileOrphans      ReconcileOrphansResult      `json:"reconcile_orphans"`
	PurgeBlacklistedFiles PurgeBlackListedFilesResult `json:"purge_blacklisted_files"`
}

func (s *Server) RunMaintenancePass(ctx context.Context) (bool, MaintenanceResult) {
	var mr MaintenanceResult
	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	mr.CleanDeleted = s.cleanDeleted()

	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	mr.ReconcileOrphans = s.reconcileOrphans()

	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	mr.PurgeBlacklistedFiles = s.purgeBlacklistedFiles()
	return true, mr
}

func (s *Server) cleanAndReconcile(ctx context.Context, dur time.Duration) {
	logger := s.logger.WithGroup("maintenance").With("operation", "loop")
	var prev MaintenanceResult
	havePrev := false
	if snap := s.maintenanceStatusSnapshot(); snap.LastRun != nil {
		prev = snap.LastRun.Result
		havePrev = true
	}

	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			started, halted, res := s.runTrackedMaintenancePass(ctx, "loop")
			if !started {
				logger.Warn("skipping scheduled maintenance pass", "reason", "already_running")
				continue
			}
			if havePrev && !reflect.DeepEqual(prev, res) {
				logger.Info("maintenance pass result changed", "previous_result", prev, "result", res)
			}
			prev = res
			havePrev = true
			if !halted {
				s.logger.Info("Stopping clean and reconcile loop")
				return
			}
		case <-ctx.Done():
			s.logger.Info("Stopping clean and reconcile loop")
			return
		}
	}
}

type CleanDeletedResult struct {
	StaleRoots int64  `json:"stale_roots"`
	Deleted    int64  `json:"deleted"`
	Error      string `json:"error,omitempty"`
}

func (s *Server) cleanDeleted() CleanDeletedResult {
	result := CleanDeletedResult{}
	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "clean_deleted")
	var numDeleted int64
	defer func() {
		logger.Info("Finished cleaning deleted files", "deleted", numDeleted, "duration", time.Since(start))
	}()

	rows, err := s.store.db.Query("SELECT path FROM files ORDER BY LENGTH(path), path")
	if err != nil {
		logger.Error("failed to query file records for cleanup", "err", err)
		result.Error = err.Error()
		return result
	}
	defer rows.Close()

	var staleRoots []string
	staleSet := make(map[string]struct{})
	for rows.Next() {
		var relPath string
		if err := rows.Scan(&relPath); err != nil {
			logger.Error("failed to scan file record during cleanup", "err", err)
			result.Error = err.Error()
			return result
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
		result.Error = err.Error()
		return result
	}

	result.StaleRoots = int64(len(staleRoots))
	if len(staleRoots) == 0 {
		return result
	}

	if err := rows.Close(); err != nil {
		logger.Error("failed to close file record cursor during cleanup", "err", err)
		result.Error = err.Error()
		return result
	}

	tx, err := s.store.db.Begin()
	if err != nil {
		logger.Error("failed to begin cleanup transaction", "err", err)
		result.Error = err.Error()
		return result
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
			result.Error = err.Error()
			return result
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
		result.Error = err.Error()
	}
	result.Deleted = numDeleted
	return result
}

func hasDeletedAncestor(relPath string, staleSet map[string]struct{}) bool {
	for parent := path.Dir(relPath); parent != "." && parent != "/"; parent = path.Dir(parent) {
		if _, ok := staleSet[parent]; ok {
			return true
		}
	}
	return false
}

type ReconcileOrphansResult struct {
	SystemDirectories int64        `json:"system_directories"`
	SystemFiles       int64        `json:"system_files"`
	Candidates        int64        `json:"candidates"`
	Unorphaned        []FileRecord `json:"unorphaned"`
	Error             string       `json:"error,omitempty"`
}

func (s *Server) reconcileOrphans() ReconcileOrphansResult {
	result := ReconcileOrphansResult{}
	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "reconcile_orphans")
	var sysFiles []string
	for p := range s.cfg.unrestrictedMap {
		if strings.HasSuffix(p, "/") {
			cleanPath := path.Clean(strings.TrimSuffix(p, "/"))
			full := filepath.Join(s.absUploadDir, filepath.FromSlash(cleanPath))

			os.MkdirAll(full, permDir)
			s.store.EnsureDirectory(systemOwner, cleanPath)
			result.SystemDirectories++
		} else {
			sysFiles = append(sysFiles, p)
		}
	}
	result.SystemFiles = int64(len(sysFiles))
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
		result.Error = err.Error()
	}

	result.Candidates = int64(len(candidates))
	if len(candidates) > 0 {
		newFiles, err := s.store.RegisterFilesBatch(candidates)
		if err != nil {
			logger.Error("failed to batch reconcile files", "duration", time.Since(start), "error", err)
			result.Error = err.Error()
		} else if len(newFiles) > 0 {
			result.Unorphaned = newFiles
			logger.Info("reconciled orphan files", "new_count", len(newFiles), "duration", time.Since(start))
		}
	}
	return result
}

type PurgeBlackListedFilesResult struct {
	Matches          int64  `json:"matches"`
	Purges           int64  `json:"purges"`
	OwnersPurged     int64  `json:"owners_purged"`
	BlacklistUpdates int64  `json:"blacklist_updates"`
	Error            string `json:"error,omitempty"`
}

func (s *Server) purgeBlacklistedFiles() PurgeBlackListedFilesResult {
	result := PurgeBlackListedFilesResult{}
	if s.store == nil || s.store.badFileList == nil {
		return result
	}

	start := time.Now()
	logger := s.logger.WithGroup("maintenance").With("operation", "purge_blacklisted_files")
	matches := s.findBadFileMatches(logger)
	result.Matches = int64(len(matches))
	if len(matches) == 0 {
		return result
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
			logger.Error("failed to purge blacklisted file",
				"path", match.relPath,
				"owner", match.ownerHash,
				"match", match.knownAs,
				"err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
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
			if result.Error == "" {
				result.Error = err.Error()
			}
		} else if added {
			blacklistCount++
		}
	}

	result.Purges = int64(purgeCount)
	result.OwnersPurged = int64(len(purgedOwners))
	result.BlacklistUpdates = int64(blacklistCount)
	logger.Warn("bad file maintenance completed",
		"matches", len(matches),
		"purges", purgeCount,
		"blacklist_updates", blacklistCount,
		"duration", time.Since(start))
	return result
}

func (s *Server) findBadFileMatches(logger *slog.Logger) []badFileMatch {
	matches := make([]badFileMatch, 0, 4)

	_ = filepath.WalkDir(s.absUploadDir, func(absPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Warn("failed to inspect path during bad file maintenance", "path", absPath, "err", walkErr)
			return nil
		}
		if absPath == s.absUploadDir || d.IsDir() {
			return nil
		}

		matchName, matched, err := s.store.badFileList.MatchFile(absPath)
		if err != nil {
			logger.Warn("failed to hash file during bad file maintenance", "path", absPath, "err", err)
			return nil
		}
		if !matched {
			return nil
		}

		relPath, err := filepath.Rel(s.absUploadDir, absPath)
		if err != nil {
			logger.Warn("failed to derive relative path for bad file", "path", absPath, "err", err)
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		ownerHash, err := s.store.GetFileOwner(relPath)
		if err != nil {
			logger.Warn("failed to resolve owner for bad file", "path", relPath, "err", err)
		}

		ownerAddr := ""
		if ownerHash != "" && ownerHash != systemOwner {
			stats, err := s.store.GetUserStats(ownerHash)
			if err != nil {
				logger.Warn("failed to resolve owner address for bad file", "path", relPath, "owner", ownerHash, "err", err)
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

type MaintenanceRunSnapshot struct {
	Trigger    string            `json:"trigger"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	Duration   string            `json:"duration"`
	Halted     bool              `json:"halted"`
	Result     MaintenanceResult `json:"result"`
}

type MaintenanceStateSnapshot struct {
	Running           bool                    `json:"running"`
	CurrentTrigger    string                  `json:"current_trigger,omitempty"`
	CurrentStartedAt  string                  `json:"current_started_at,omitempty"`
	CurrentRunningFor string                  `json:"current_running_for,omitempty"`
	LastRun           *MaintenanceRunSnapshot `json:"last_run,omitempty"`
}

func (s *Server) runTrackedMaintenancePass(ctx context.Context, trigger string) (started bool, halted bool, res MaintenanceResult) {
	if !s.maintenanceRunMu.TryLock() {
		return false, false, res
	}

	startedAt := time.Now()
	s.setMaintenanceRunning(trigger, startedAt)
	defer func() {
		finishedAt := time.Now()
		s.finishMaintenanceRun(trigger, startedAt, finishedAt, halted, res)
		s.maintenanceRunMu.Unlock()
	}()

	halted, res = s.RunMaintenancePass(ctx)
	s.logger.WithGroup("maintenance").With("operation", "pass").Info("maintenance pass completed",
		"trigger", trigger,
		"halted", halted,
		"clean_deleted.deleted", res.CleanDeleted.Deleted,
		"clean_deleted.stale_roots", res.CleanDeleted.StaleRoots,
		"reconcile_orphans.inserted", len(res.ReconcileOrphans.Unorphaned),
		"reconcile_orphans.candidates", res.ReconcileOrphans.Candidates,
		"purge_blacklisted_files.matches", res.PurgeBlacklistedFiles.Matches,
		"purge_blacklisted_files.purges", res.PurgeBlacklistedFiles.Purges,
		"purge_blacklisted_files.blacklist_updates", res.PurgeBlacklistedFiles.BlacklistUpdates,
		"duration", time.Since(startedAt))
	return true, halted, res
}

func (s *Server) setMaintenanceRunning(trigger string, startedAt time.Time) {
	s.maintenanceStateMu.Lock()
	defer s.maintenanceStateMu.Unlock()

	s.maintenanceState.running = true
	s.maintenanceState.currentTrigger = trigger
	s.maintenanceState.currentStartedAt = startedAt
}

func (s *Server) finishMaintenanceRun(trigger string, startedAt, finishedAt time.Time, halted bool, res MaintenanceResult) {
	s.maintenanceStateMu.Lock()
	defer s.maintenanceStateMu.Unlock()

	s.maintenanceState.running = false
	s.maintenanceState.currentTrigger = ""
	s.maintenanceState.currentStartedAt = time.Time{}
	s.maintenanceState.lastRun = &MaintenanceRunSnapshot{
		Trigger:    trigger,
		StartedAt:  formatMaintenanceTime(startedAt),
		FinishedAt: formatMaintenanceTime(finishedAt),
		Duration:   finishedAt.Sub(startedAt).Round(time.Millisecond).String(),
		Halted:     halted,
		Result:     res,
	}
}

func (s *Server) maintenanceStatusSnapshot() MaintenanceStateSnapshot {
	s.maintenanceStateMu.Lock()
	defer s.maintenanceStateMu.Unlock()

	out := MaintenanceStateSnapshot{
		Running:           s.maintenanceState.running,
		CurrentTrigger:    s.maintenanceState.currentTrigger,
		CurrentStartedAt:  formatMaintenanceTime(s.maintenanceState.currentStartedAt),
		CurrentRunningFor: "",
	}
	if s.maintenanceState.running && !s.maintenanceState.currentStartedAt.IsZero() {
		out.CurrentRunningFor = time.Since(s.maintenanceState.currentStartedAt).Round(time.Millisecond).String()
	}
	if s.maintenanceState.lastRun != nil {
		last := *s.maintenanceState.lastRun
		out.LastRun = &last
	}
	return out
}

func formatMaintenanceTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
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
