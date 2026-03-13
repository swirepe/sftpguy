package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type adminMaintenanceLogEntry struct {
	Raw       string            `json:"raw"`
	Time      string            `json:"time"`
	Level     string            `json:"level"`
	Operation string            `json:"operation"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (s *Server) handleAdminMaintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, s.maintenanceStatusSnapshot())
}

func (s *Server) handleAdminMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	started, halted, res := s.runTrackedMaintenancePass(r.Context(), "admin-http", true)
	if !started {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":     false,
			"error":  "maintenance pass already running",
			"status": s.maintenanceStatusSnapshot(),
		})
		return
	}

	s.store.LogEvent(EventAdminMaintenance, systemOwner, "admin-http", nil,
		"action", "run",
		"trigger", "admin-http",
		"halted", halted,
		"clean_deleted", res.CleanDeleted.Deleted,
		"orphans_inserted", len(res.ReconcileOrphans.Unorphaned),
		"bad_matches", res.PurgeBlacklistedFiles.Matches,
		"purges", res.PurgeBlacklistedFiles.Purges,
		"blacklist_updates", res.PurgeBlacklistedFiles.BlacklistUpdates,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"halted": halted,
		"result": res,
		"status": s.maintenanceStatusSnapshot(),
	})
}

func (s *Server) handleAdminMaintenanceLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := parseIntQuery(r, "limit", 200, 10, 1000)
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	entries, err := readMaintenanceLogEntries(s.cfg.LogFile, limit, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
	})
}

func (s *Server) handleAdminBadFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		info, err := s.readAdminBadFileFile(s.store.badFilesPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, info)
	case http.MethodPost:
		var payload struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}

		content := strings.ReplaceAll(payload.Content, "\r\n", "\n")
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}

		if err := os.WriteFile(s.store.badFilesPath, []byte(content), permFile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reloadEntries := 0
		if s.store.badFileList != nil {
			entries, reloadErr := s.store.badFileList.Reload()
			if reloadErr != nil {
				http.Error(w, reloadErr.Error(), http.StatusInternalServerError)
				return
			}
			reloadEntries = entries
		}

		info, err := s.readAdminBadFileFile(s.store.badFilesPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		info["reloaded_entries"] = reloadEntries

		s.store.LogEvent(EventAdminConfig, systemOwner, "admin-http", nil,
			"action", "bad-files-save",
			"path", s.store.badFilesPath,
			"entries", reloadEntries,
			"invalid", info["invalid_count"],
		)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bad_files": info})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminMarkBadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil || s.store.badFileList == nil {
		http.Error(w, "bad file list is not configured", http.StatusInternalServerError)
		return
	}

	relPath, err := s.decodeAdminExplorerPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(s.absUploadDir, filepath.FromSlash(relPath))
	fullPath = filepath.Clean(fullPath)
	rootWithSep := s.absUploadDir + string(filepath.Separator)
	if !strings.HasPrefix(fullPath+string(filepath.Separator), rootWithSep) {
		http.Error(w, "invalid path", http.StatusForbidden)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "path not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.Error(w, "directories cannot be marked as bad", http.StatusBadRequest)
		return
	}

	hash, err := s.store.badFileList.calculateSHA256(fullPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, alreadyPresent := s.store.badFileList.Lookup(hash)
	if !alreadyPresent {
		if err := s.store.badFileList.AddHash(hash, filepath.Base(fullPath)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := s.store.badFileList.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s.store.LogEvent(EventAdminMaintenance, systemOwner, "admin-http", nil,
		"action", "mark-bad",
		"path", relPath,
		"hash", hash,
		"already_present", alreadyPresent,
	)

	fileInfo, err := s.readAdminBadFileFile(s.store.badFilesPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"path":            relPath,
		"hash":            hash,
		"already_present": alreadyPresent,
		"bad_files":       fileInfo,
	})
}

func (s *Server) readAdminBadFileFile(path string) (map[string]any, error) {
	content := ""
	if b, err := os.ReadFile(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		content = string(b)
	}

	entries, invalid := validateAdminBadFileContent(content)
	return map[string]any{
		"path":          path,
		"content":       content,
		"entries":       entries,
		"invalid_count": len(invalid),
		"invalid_lines": invalid,
	}, nil
}

func validateAdminBadFileContent(content string) (entries int, invalid []string) {
	lines := strings.Split(content, "\n")
	invalid = make([]string, 0, 8)

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 || !isValidSHA256Hash(parts[0]) {
			invalid = append(invalid, line)
			continue
		}
		entries++
	}

	return entries, invalid
}

func readMaintenanceLogEntries(path string, limit int, filter string) ([]adminMaintenanceLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []adminMaintenanceLogEntry{}, nil
		}
		return nil, err
	}
	defer file.Close()

	filter = strings.ToLower(strings.TrimSpace(filter))
	lines := make([]string, 0, limit)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, "maintenance.") {
			continue
		}
		if filter != "" && !strings.Contains(lineLower, filter) {
			continue
		}
		lines = append(lines, line)
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	entries := make([]adminMaintenanceLogEntry, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		fields := parseLogKV(lines[i])
		details := map[string]string{}
		for key, value := range fields {
			if strings.HasPrefix(key, "maintenance.") {
				details[strings.TrimPrefix(key, "maintenance.")] = value
			}
		}
		entries = append(entries, adminMaintenanceLogEntry{
			Raw:       lines[i],
			Time:      fields["time"],
			Level:     strings.ToUpper(fields["level"]),
			Operation: details["operation"],
			Message:   fields["msg"],
			Fields:    details,
		})
	}
	return entries, nil
}
