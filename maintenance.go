package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
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
	PurgeSSHDBot          PurgeSSHDBotResult          `json:"purge_sshdbot"`
	PurgeBlacklistedFiles PurgeBlackListedFilesResult `json:"purge_blacklisted_files"`
}

const maintenanceSkippedRoot = "#recycle"

func isMaintenanceSkippedRelPath(relPath string) bool {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" {
		return false
	}

	relPath = strings.TrimLeft(filepath.ToSlash(relPath), "/")
	if relPath == "" || relPath == "." {
		return false
	}

	relPath = path.Clean(relPath)
	return relPath == maintenanceSkippedRoot || strings.HasPrefix(relPath, maintenanceSkippedRoot+"/")
}

func (s *Store) migrateLegacyIPBans() (migrated int, err error) {
	if s == nil || s.db == nil || s.blacklist == nil {
		return -1, nil
	}

	exists, err := s.tableExists("ip_banned")
	if err != nil || !exists {
		return 0, err
	}

	rows, err := s.db.Query(`SELECT ip_address, banned_at FROM ip_banned ORDER BY banned_at ASC`)
	if err != nil {
		return 0, err
	}

	type legacyIPBan struct {
		ip       string
		bannedAt string
	}
	legacyBans := make([]legacyIPBan, 0, 8)

	logger := s.logger.WithGroup("maintenance").With("operation", "migrate_legacy_ip_bans")
	for rows.Next() {
		var ip string
		var bannedAt string
		if err := rows.Scan(&ip, &bannedAt); err != nil {
			_ = rows.Close()
			return 0, err
		}
		legacyBans = append(legacyBans, legacyIPBan{ip: ip, bannedAt: bannedAt})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	for _, legacy := range legacyBans {
		added, err := s.blacklist.AddExactIPWithComment(legacy.ip, legacyIPBanComment(legacy.bannedAt))
		if err != nil {
			logger.Warn("failed to migrate legacy ip ban", "ip", legacy.ip, "err", err)
			continue
		}
		// Note: We delete even if 'added' is false, because 'false'  means
		// the IP was already in the new blacklist, so it's safe to remove from legacy.
		_, delErr := s.db.Exec(`DELETE FROM ip_banned WHERE ip_address = ?`, legacy.ip)
		if delErr != nil {
			logger.Error("failed to remove migrated ip from legacy table", "ip", legacy.ip, "err", delErr)
		}
		if added {
			migrated++
		}
	}
	if migrated > 0 {
		logger.Info("migrated legacy ip bans to blacklist", "count", migrated)
	}
	return migrated, nil
}

func (s *Store) tableExists(name string) (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func legacyIPBanComment(bannedAt string) string {
	return fmt.Sprintf("[%s] migrated from ip_banned; banned_at=%s", time.Now().Format(time.RFC3339), normalizeBanTimestamp(bannedAt))
}

func normalizeBanTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Now().Format(time.RFC3339)
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.Format(time.RFC3339)
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return parsed.Format(time.RFC3339)
	}
	return value
}

func (s *Server) RunMaintenancePass(ctx context.Context) (bool, MaintenanceResult) {
	return s.runMaintenancePass(ctx, true)
}

func (s *Server) runMaintenancePass(ctx context.Context, includeBadFilePurge bool) (bool, MaintenanceResult) {
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

	mr.PurgeSSHDBot = s.PurgeSSHDBot()

	select {
	case <-ctx.Done():
		return false, mr
	default:
	}

	if includeBadFilePurge {
		mr.PurgeBlacklistedFiles = s.purgeBlacklistedFiles()
	}
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
			started, halted, res := s.runTrackedMaintenancePass(ctx, "loop", false)
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
		if isMaintenanceSkippedRelPath(relPath) {
			continue
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
		if isMaintenanceSkippedRelPath(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

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

		purged, added, err := s.purgeMatchedBadFile(logger, "maintenance", match)
		if purged {
			purgeCount++
			if match.ownerHash != "" && match.ownerHash != systemOwner {
				purgedOwners[match.ownerHash] = struct{}{}
			}
		}
		if err != nil {
			if result.Error == "" {
				result.Error = err.Error()
			}
			continue
		}
		if added {
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

var sshdUploadPathRegex = regexp.MustCompile(`(?:\.?\d+)/(?:sshd|xinetd)$`)

func (s *Server) findBadFileMatches(logger *slog.Logger) []badFileMatch {
	matches := make([]badFileMatch, 0, 4)

	_ = filepath.WalkDir(s.absUploadDir, func(absPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Warn("failed to inspect path during bad file maintenance", "path", absPath, "err", walkErr)
			return nil
		}
		if absPath == s.absUploadDir {
			return nil
		}

		relPath, err := filepath.Rel(s.absUploadDir, absPath)
		if err != nil {
			logger.Warn("failed to derive relative path for bad file", "path", absPath, "err", err)
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if isMaintenanceSkippedRelPath(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		matchName, matched, err := s.store.badFileList.MatchFile(absPath)
		if err != nil {
			logger.Warn("failed to hash file during bad file maintenance", "path", absPath, "err", err)
			return nil
		}

		if sshdUploadPathRegex.MatchString(absPath) {
			logger.Info("sshdbot activity detected", "path", absPath)
			matched = true
			s.store.badFileList.AddFile(absPath)
		}
		if !matched {
			return nil
		}

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

func (s *Server) purgeMatchedBadFile(logger *slog.Logger, trigger string, match badFileMatch) (purged bool, blacklisted bool, err error) {
	if err := s.PurgeByFile(match.relPath); err != nil {
		logger.Error("failed to purge bad file",
			"trigger", trigger,
			"path", match.relPath,
			"owner", match.ownerHash,
			"match", match.knownAs,
			"err", err)
		return false, false, err
	}

	cidr, added, err := s.blacklistLastAddress(match.ownerHash, match.ownerAddr, match.knownAs)
	if err != nil {
		logger.Warn("failed to blacklist owner address for bad file",
			"trigger", trigger,
			"path", match.relPath,
			"owner", match.ownerHash,
			"address", match.ownerAddr,
			"err", err)
		return true, false, err
	}

	logger.Warn("bad file purged",
		"trigger", trigger,
		"path", match.relPath,
		"owner", match.ownerHash,
		"owner_address", match.ownerAddr,
		"match", match.knownAs,
		"blacklisted", added,
		"cidr", cidr)
	return true, added, nil
}

type PurgeSSHDBotResult struct {
	Matches          []SSHDBotMatch `json:"matches"`
	Purges           int64          `json:"purges"`
	OwnersBanned     int64          `json:"owners_banned"`
	BlacklistUpdates int64          `json:"blacklist_updates"`

	Error string `json:"error,omitempty"`
}

type SSHDBotMatch struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time"`
	IP         string    `json:"ip"`
	Sha256Hash string    `json:"sha256_hash"`
}

func (s *Server) PurgeSSHDBot() PurgeSSHDBotResult {
	result := PurgeSSHDBotResult{}
	logger := s.logger.WithGroup("maintenance").With("operation", "purge_sshdbot")
	bannedOwners := make(map[string]struct{})
	_ = filepath.WalkDir(s.absUploadDir, func(absPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Warn("failed to inspect path during bad file maintenance", "path", absPath, "err", walkErr)
			if result.Error == "" {
				result.Error = walkErr.Error()
			}
			return nil
		}
		if absPath == s.absUploadDir {
			return nil
		}

		relPath, err := filepath.Rel(s.absUploadDir, absPath)
		if err != nil {
			logger.Warn("failed to derive relative path for bad file", "path", absPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if isMaintenanceSkippedRelPath(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		if !sshdUploadPathRegex.MatchString(absPath) {
			return nil
		}
		match := SSHDBotMatch{
			Path: absPath,
		}
		defer func() {
			result.Matches = append(result.Matches, match)
		}()

		fInfo, err := os.Stat(absPath)
		if err != nil {
			logger.Warn("failed to stat sshdbot candidate", "path", absPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
			return nil
		}

		match.Path = relPath

		ownerHash, err := s.store.GetFileOwner(relPath)
		if err != nil {
			logger.Warn("failed to resolve owner for bad file", "path", relPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
		}

		ip := ""
		if ownerHash != "" && ownerHash != systemOwner {
			if _, alreadyBanned := bannedOwners[ownerHash]; !alreadyBanned {
				s.Ban(ownerHash)
				bannedOwners[ownerHash] = struct{}{}
			}
			stats, err := s.store.GetUserStats(ownerHash)
			if err != nil {
				logger.Warn("failed to resolve owner address for bad file", "path", relPath, "owner", ownerHash, "err", err)
				if result.Error == "" {
					result.Error = err.Error()
				}
			} else {
				ip = strings.TrimSpace(stats.LastAddress)
				if ip != "" {
					added, err := s.store.blacklist.AddExactIPWithComment(ip, fmt.Sprintf("[sshdbot] %s %s", time.Now(), absPath))
					if err != nil {
						logger.Warn("failed to blacklist sshdbot owner address", "path", relPath, "owner", ownerHash, "address", ip, "err", err)
						if result.Error == "" {
							result.Error = err.Error()
						}
					} else if added {
						result.BlacklistUpdates++
					}
				}
			}
		}

		hash, err := s.store.badFileList.AddFile(absPath)
		if err != nil {
			logger.Warn("failed to add sshdbot hash to bad file list", "path", relPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
		}
		match.IP = ip
		match.Sha256Hash = hash
		match.Size = fInfo.Size()
		match.ModTime = fInfo.ModTime()
		logger.Info("sshdbot activity detected", "path", absPath, "remote_addr", ip, "user", ownerHash,
			"size", fInfo.Size(), "modtime", fInfo.ModTime(), "sha256", hash)

		if err := os.Remove(absPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Warn("failed to remove sshdbot payload", "path", absPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
			return nil
		}
		result.Purges++
		if err := s.store.DeletePath(relPath); err != nil {
			logger.Warn("failed to remove sshdbot payload metadata", "path", relPath, "err", err)
			if result.Error == "" {
				result.Error = err.Error()
			}
		}

		parentRel := filepath.ToSlash(filepath.Dir(relPath))
		parentAbs := filepath.Dir(absPath)
		if parentRel != "." {
			if err := os.Remove(parentAbs); err == nil {
				if err := s.store.DeletePath(parentRel); err != nil {
					logger.Warn("failed to remove sshdbot parent metadata", "path", parentRel, "err", err)
					if result.Error == "" {
						result.Error = err.Error()
					}
				}
			}
		}
		return nil
	})
	result.OwnersBanned = int64(len(bannedOwners))
	return result
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

func (s *Server) runTrackedMaintenancePass(ctx context.Context, trigger string, includeBadFilePurge bool) (started bool, halted bool, res MaintenanceResult) {
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

	halted, res = s.runMaintenancePass(ctx, includeBadFilePurge)
	s.logger.WithGroup("maintenance").With("operation", "pass").Info("maintenance pass completed",
		"trigger", trigger,
		"include_bad_file_purge", includeBadFilePurge,
		"halted", halted,
		"clean_deleted.deleted", res.CleanDeleted.Deleted,
		"clean_deleted.stale_roots", res.CleanDeleted.StaleRoots,
		"reconcile_orphans.inserted", len(res.ReconcileOrphans.Unorphaned),
		"reconcile_orphans.candidates", res.ReconcileOrphans.Candidates,
		"purge_sshdbot.matches", len(res.PurgeSSHDBot.Matches),
		"purge_sshdbot.purges", res.PurgeSSHDBot.Purges,
		"purge_sshdbot.owners_banned", res.PurgeSSHDBot.OwnersBanned,
		"purge_sshdbot.blacklist_updates", res.PurgeSSHDBot.BlacklistUpdates,
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
