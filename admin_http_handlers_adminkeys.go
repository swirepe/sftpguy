package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
)

func (s *Server) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		info, err := s.readAdminKeyFile(s.store.adminKeysPath)
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

		if err := os.WriteFile(s.store.adminKeysPath, []byte(content), permFile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reloadEntries := 0
		if s.store.adminKeys != nil {
			entries, reloadErr := s.store.adminKeys.Reload(s.store.adminKeysPath)
			if reloadErr != nil {
				http.Error(w, reloadErr.Error(), http.StatusInternalServerError)
				return
			}
			reloadEntries = entries
		}

		info, err := s.readAdminKeyFile(s.store.adminKeysPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		info["reloaded_entries"] = reloadEntries

		s.store.LogEvent(EventAdminConfig, systemOwner, "admin-http", nil,
			"action", "admin-keys-save",
			"path", s.store.adminKeysPath,
			"entries", reloadEntries,
			"invalid", info["invalid_count"],
		)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "keys": info})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) readAdminKeyFile(path string) (map[string]any, error) {
	content := ""
	if b, err := os.ReadFile(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		content = string(b)
	}

	hashes, invalid := parseAdminKeysContent(content)
	hashList := make([]string, 0, len(hashes))
	for hash := range hashes {
		hashList = append(hashList, hash)
	}
	sort.Strings(hashList)

	return map[string]any{
		"path":          path,
		"content":       content,
		"entries":       len(hashList),
		"invalid_count": len(invalid),
		"invalid_lines": invalid,
		"hashes":        hashList,
	}, nil
}
