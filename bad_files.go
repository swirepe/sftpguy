package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type HashList struct {
	hashes      atomic.Value
	addlineChan chan struct{}
	logger      *slog.Logger
	cancel      context.CancelFunc
	filepath    string
	mu          sync.Mutex
}

type hashReloadResult struct {
	entries int
	err     string
}

func newHashReloadResult(entries int, err error) hashReloadResult {
	result := hashReloadResult{entries: entries}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func (r hashReloadResult) equals(other hashReloadResult) bool {
	return r.entries == other.entries && r.err == other.err
}

// NewHashList initializes the list and starts the background reloader.
func NewHashList(ctx context.Context, filepath string, logger *slog.Logger) *HashList {
	log := logger.With("hash_list", filepath)
	ctx, cancel := context.WithCancel(ctx)

	hl := &HashList{
		logger:      log,
		addlineChan: make(chan struct{}, 1),
		cancel:      cancel,
		filepath:    filepath,
	}

	// Initial load
	entries, err := hl.Reload()
	if err != nil {
		log.Warn("initial hash list load failed", "error", err)
	} else {
		log.Info("initial hash list load complete", "entries", entries)
	}

	firstReload := newHashReloadResult(entries, err)

	go func(lastReload hashReloadResult) {
		const period = 30 * time.Second
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		var lastChanged = time.Now()

		for {
			select {
			case <-hl.addlineChan:
				lastReload, lastChanged = hl.performReload(lastReload, &lastChanged)
			case <-ticker.C:
				lastReload, lastChanged = hl.performReload(lastReload, &lastChanged)
			case <-ctx.Done():
				log.Info("stopping hash list reloader")
				return
			}
		}
	}(firstReload)

	return hl
}

func (hl *HashList) performReload(lastReload hashReloadResult, lastChanged *time.Time) (hashReloadResult, time.Time) {
	start := time.Now()
	entries, err := hl.Reload()
	currentReload := newHashReloadResult(entries, err)

	if !currentReload.equals(lastReload) {
		hl.logger.Info("reloaded hash list file",
			"entries", entries,
			"duration", time.Since(start),
			"last_changed", time.Since(*lastChanged),
			"error", err)
		return currentReload, time.Now()
	}
	return lastReload, *lastChanged
}
func (hl *HashList) AddHash(hash, filename string) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) == 0 {
		return fmt.Errorf("empty hash")
	}

	if _, exists := hl.Lookup(hash); exists {
		return nil
	}

	hl.mu.Lock()
	defer hl.mu.Unlock()

	// Ensure the file exists or create it
	f, err := os.OpenFile(hl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	line := fmt.Sprintf("%s  %s\n", hash, filename)
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	select {
	case hl.addlineChan <- struct{}{}:
	default:
	}

	return nil
}

func (hl *HashList) Reload() (entries int, err error) {
	newMap := make(map[string]string)
	file, err := os.Open(hl.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		hash := strings.ToLower(parts[0])
		name := ""
		if len(parts) > 1 {
			name = strings.Join(parts[1:], " ")
		}
		newMap[hash] = name
		entries++
	}

	hl.hashes.Store(newMap)
	return entries, nil
}

func (hl *HashList) Lookup(hash string) (string, bool) {
	val := hl.hashes.Load()
	if val == nil {
		return "", false
	}
	m := val.(map[string]string)
	name, ok := m[strings.ToLower(strings.TrimSpace(hash))]
	return name, ok
}

func (hl *HashList) Matches(hash string) bool {
	_, exists := hl.Lookup(hash)
	return exists
}

func (hl *HashList) MatchFile(absPath string) (string, bool, error) {
	hash, err := hl.calculateSHA256(absPath)
	if err != nil {
		return "", false, fmt.Errorf("hash failed: %w", err)
	}

	name, exists := hl.Lookup(hash)
	return name, exists, nil
}

func (hl *HashList) AddFile(absPath string) error {
	hash, err := hl.calculateSHA256(absPath)
	if err != nil {
		return fmt.Errorf("hash failed: %w", err)
	}

	// Use the base name of the file (e.g., /home/user/Photo.scr -> Photo.scr)
	filename := filepath.Base(absPath)

	return hl.AddHash(hash, filename)
}

// calculateSHA256 performs a streaming hash of a file to handle large files efficiently.
func (hl *HashList) calculateSHA256(absPath string) (string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (hl *HashList) Stop() {
	if hl.cancel != nil {
		hl.cancel()
	}
}
