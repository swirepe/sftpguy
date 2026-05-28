package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

type ScopedMaintainerList struct {
	grants atomic.Value // map[string][]string, keyed by public-key hash
	logger *slog.Logger
	cancel context.CancelFunc
}

type scopedMaintainerReloadResult struct {
	entries int
	err     string
}

func newScopedMaintainerReloadResult(entries int, err error) scopedMaintainerReloadResult {
	result := scopedMaintainerReloadResult{entries: entries}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func (r scopedMaintainerReloadResult) equals(other scopedMaintainerReloadResult) bool {
	return r.entries == other.entries && r.err == other.err
}

func NewScopedMaintainerList(ctx context.Context, filePath string, logger *slog.Logger) *ScopedMaintainerList {
	log := logger.With("maintainers", filePath)
	ctx, cancel := context.WithCancel(ctx)

	list := &ScopedMaintainerList{
		logger: log,
		cancel: cancel,
	}

	entries, err := list.Reload(filePath)
	if err != nil {
		log.Warn("initial scoped maintainer list load failed", "error", err)
	} else {
		log.Info("initial scoped maintainer list load complete", "entries", entries)
	}

	firstReload := newScopedMaintainerReloadResult(entries, err)
	go func(lastLoggedReload scopedMaintainerReloadResult) {
		const period = 30 * time.Second
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		defer recoverAndLogPanic(log, "scoped maintainer list reloader")

		for {
			select {
			case <-ticker.C:
				start := time.Now()
				entries, err := list.Reload(filePath)
				currentReload := newScopedMaintainerReloadResult(entries, err)

				if !currentReload.equals(lastLoggedReload) {
					list.logger.Info("reloaded scoped maintainer list file",
						"entries", entries,
						"duration", time.Since(start),
						"error", err)
					lastLoggedReload = currentReload
				}
			case <-ctx.Done():
				log.Info("stopping scoped maintainer list reloader")
				return
			}
		}
	}(firstReload)

	return list
}

func (m *ScopedMaintainerList) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *ScopedMaintainerList) Reload(filePath string) (entries int, err error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) && m.grants.Load() == nil {
			m.grants.Store(map[string][]string{})
			return 0, nil
		}
		return 0, fmt.Errorf("failed to open file: %w", err)
	}

	grants, invalid := parseScopedMaintainersContent(string(b))
	for _, line := range invalid {
		m.logger.Warn("skipping invalid scoped maintainer line", "line", line)
	}

	m.grants.Store(grants)
	return countScopedMaintainerEntries(grants), nil
}

func (m *ScopedMaintainerList) Maintains(hash, relPath string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return false
	}
	rel, ok := normalizeMaintainerScope(relPath)
	if !ok {
		return false
	}

	val := m.grants.Load()
	if val == nil {
		return false
	}
	for _, scope := range val.(map[string][]string)[hash] {
		if rel == scope || strings.HasPrefix(rel, scope+"/") {
			return true
		}
	}
	return false
}

func (m *ScopedMaintainerList) ScopesForHash(hash string) []string {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return nil
	}
	val := m.grants.Load()
	if val == nil {
		return nil
	}
	scopes := val.(map[string][]string)[hash]
	if len(scopes) == 0 {
		return nil
	}
	out := append([]string(nil), scopes...)
	sort.Strings(out)
	return out
}

func (m *ScopedMaintainerList) HasGrant(hash string) bool {
	return len(m.ScopesForHash(hash)) > 0
}

func parseScopedMaintainersContent(content string) (grants map[string][]string, invalid []string) {
	grants = make(map[string][]string)
	invalid = make([]string, 0, 8)
	lines := strings.Split(content, "\n")
	for _, rawLine := range lines {
		scope, hash, ok := parseScopedMaintainerLine(rawLine)
		if ok {
			if !containsString(grants[hash], scope) {
				grants[hash] = append(grants[hash], scope)
			}
			continue
		}

		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		invalid = append(invalid, line)
	}

	for hash := range grants {
		sort.Strings(grants[hash])
	}
	return grants, invalid
}

func parseScopedMaintainerLine(rawLine string) (scope, hash string, ok bool) {
	line := strings.TrimSpace(rawLine)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	rawScope, credential, ok := splitMaintainerLine(line)
	if !ok {
		return "", "", false
	}
	scope, ok = normalizeMaintainerScope(rawScope)
	if !ok {
		return "", "", false
	}
	hash, ok = parseAdminKeyLine(credential)
	if !ok {
		return "", "", false
	}
	return scope, hash, true
}

func splitMaintainerLine(line string) (scope, credential string, ok bool) {
	if strings.Contains(line, "\t") {
		scope, credential, ok = strings.Cut(line, "\t")
		return strings.TrimSpace(scope), strings.TrimSpace(credential), ok && strings.TrimSpace(credential) != ""
	}

	idx := strings.IndexFunc(line, unicode.IsSpace)
	if idx < 0 {
		return "", "", false
	}
	scope = strings.TrimSpace(line[:idx])
	credential = strings.TrimSpace(line[idx:])
	return scope, credential, scope != "" && credential != ""
}

func normalizeMaintainerScope(raw string) (string, bool) {
	raw = strings.TrimSpace(filepath.ToSlash(raw))
	if raw == "" {
		return "", false
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", false
		}
	}
	clean := path.Clean("/" + strings.TrimLeft(raw, "/"))
	scope := strings.TrimPrefix(clean, "/")
	if scope == "" || scope == "." {
		return "", false
	}
	return scope, true
}

func countScopedMaintainerEntries(grants map[string][]string) int {
	total := 0
	for _, scopes := range grants {
		total += len(scopes)
	}
	return total
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (s *Server) canMaintainPath(hash, relPath string) bool {
	return s != nil &&
		s.store != nil &&
		s.store.scopedMaintainers != nil &&
		s.store.scopedMaintainers.Maintains(hash, relPath)
}

func (s *Server) isScopedMaintainer(hash string) bool {
	return s != nil &&
		s.store != nil &&
		s.store.scopedMaintainers != nil &&
		s.store.scopedMaintainers.HasGrant(hash)
}

func (s *Server) maintainerScopes(hash string) []string {
	if s == nil || s.store == nil || s.store.scopedMaintainers == nil {
		return nil
	}
	return s.store.scopedMaintainers.ScopesForHash(hash)
}
