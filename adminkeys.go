package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type AdminKeyList struct {
	hashes atomic.Value // map[string]struct{}
	logger *slog.Logger
	cancel context.CancelFunc
}

type adminKeyReloadResult struct {
	entries int
	err     string
}

func newAdminKeyReloadResult(entries int, err error) adminKeyReloadResult {
	result := adminKeyReloadResult{entries: entries}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func (r adminKeyReloadResult) equals(other adminKeyReloadResult) bool {
	return r.entries == other.entries && r.err == other.err
}

func NewAdminKeyList(ctx context.Context, filepath string, logger *slog.Logger) *AdminKeyList {
	log := logger.With("admin_keys", filepath)
	ctx, cancel := context.WithCancel(ctx)

	keys := &AdminKeyList{
		logger: log,
		cancel: cancel,
	}

	entries, err := keys.Reload(filepath)
	if err != nil {
		log.Warn("initial admin key list load failed", "error", err)
	} else {
		log.Info("initial admin key list load complete", "entries", entries)
	}
	firstReload := newAdminKeyReloadResult(entries, err)
	go func(lastLoggedReload adminKeyReloadResult) {
		const period = 30 * time.Second
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		defer recoverAndLogPanic(log, "admin key list reloader")

		// var lastLoggedReload adminKeyReloadResult
		// var hasLastLoggedReload bool

		for {
			select {
			case <-ticker.C:
				start := time.Now()
				entries, err := keys.Reload(filepath)
				currentReload := newAdminKeyReloadResult(entries, err)

				if !currentReload.equals(lastLoggedReload) {
					keys.logger.Info("reloaded admin key list file",
						"entries", entries,
						"duration", time.Since(start),
						"error", err)
					lastLoggedReload = currentReload
				}
			case <-ctx.Done():
				log.Info("stopping admin key list reloader")
				return
			}
		}
	}(firstReload)

	return keys
}

func (k *AdminKeyList) Stop() {
	if k.cancel != nil {
		k.cancel()
	}
}

func (k *AdminKeyList) ContainsHash(hash string) bool {
	val := k.hashes.Load()
	if val == nil {
		return false
	}
	hashes := val.(map[string]struct{})
	_, ok := hashes[strings.ToLower(strings.TrimSpace(hash))]
	return ok
}

func (k *AdminKeyList) ContainsKey(key ssh.PublicKey) bool {
	if key == nil {
		return false
	}
	return k.ContainsHash(publicKeyHash(key))
}

func (k *AdminKeyList) Reload(filepath string) (entries int, err error) {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}

	hashes, invalid := parseAdminKeysContent(string(b))
	for _, line := range invalid {
		k.logger.Warn("skipping invalid admin key line", "line", line)
	}

	k.hashes.Store(hashes)
	return len(hashes), nil
}

func parseAdminKeysContent(content string) (hashes map[string]struct{}, invalid []string) {
	hashes = make(map[string]struct{})
	invalid = make([]string, 0, 8)
	lines := strings.Split(content, "\n")
	for _, rawLine := range lines {
		hash, ok := parseAdminKeyLine(rawLine)
		if ok {
			hashes[hash] = struct{}{}
			continue
		}

		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		invalid = append(invalid, line)
	}
	return hashes, invalid
}

func parseAdminKeyLine(rawLine string) (hash string, ok bool) {
	line := strings.TrimSpace(rawLine)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}

	if isHexSHA256(line) {
		return strings.ToLower(line), true
	}

	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
		return publicKeyHash(key), true
	}

	// Allow trailing comments using '#', e.g. "<key> # admin laptop"
	if idx := strings.Index(line, "#"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
		if line == "" {
			return "", false
		}
		if isHexSHA256(line) {
			return strings.ToLower(line), true
		}
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
			return publicKeyHash(key), true
		}
	}

	return "", false
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

func publicKeyHash(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
}
