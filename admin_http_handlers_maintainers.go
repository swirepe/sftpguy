package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
)

func (s *Server) handleAdminMaintainers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		info, err := s.readMaintainersFile(s.store.maintainersPath)
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

		if err := os.WriteFile(s.store.maintainersPath, []byte(content), permFile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reloadEntries := 0
		if s.store.scopedMaintainers != nil {
			entries, reloadErr := s.store.scopedMaintainers.Reload(s.store.maintainersPath)
			if reloadErr != nil {
				http.Error(w, reloadErr.Error(), http.StatusInternalServerError)
				return
			}
			reloadEntries = entries
		}

		info, err := s.readMaintainersFile(s.store.maintainersPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		info["reloaded_entries"] = reloadEntries

		s.store.LogEvent(EventAdminConfig, systemOwner, "admin-http", nil,
			"action", "maintainers-save",
			"path", s.store.maintainersPath,
			"entries", reloadEntries,
			"invalid", info["invalid_count"],
		)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "maintainers": info})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) readMaintainersFile(filePath string) (map[string]any, error) {
	content := ""
	if b, err := os.ReadFile(filePath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		content = string(b)
	}

	grants, invalid := parseScopedMaintainersContent(content)
	grantList := make([]map[string]string, 0, countScopedMaintainerEntries(grants))
	for hash, scopes := range grants {
		for _, scope := range scopes {
			grantList = append(grantList, map[string]string{
				"hash": hash,
				"path": scope,
			})
		}
	}
	sort.Slice(grantList, func(i, j int) bool {
		if grantList[i]["path"] == grantList[j]["path"] {
			return grantList[i]["hash"] < grantList[j]["hash"]
		}
		return grantList[i]["path"] < grantList[j]["path"]
	})

	return map[string]any{
		"path":          filePath,
		"content":       content,
		"entries":       len(grantList),
		"invalid_count": len(invalid),
		"invalid_lines": invalid,
		"grants":        grantList,
	}, nil
}
