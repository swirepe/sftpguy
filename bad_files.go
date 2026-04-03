package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// It's an unfortunate name for a list of hashes,
// e.g. hashes of files we want to delete
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

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var errZeroLengthBadFile = errors.New("zero-length files cannot be marked as bad")

const emptyFileSHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func isZeroLengthFileHash(hash string) bool {
	return strings.EqualFold(strings.TrimSpace(hash), emptyFileSHA256Hex)
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
		defer recoverAndLogPanic(log, "hash list reloader")
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
	hash, err := normalizeSHA256Hash(hash)
	if err != nil {
		return err
	}
	if isZeroLengthFileHash(hash) {
		return errZeroLengthBadFile
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

	scanner := newLongLineScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		hash, err := normalizeSHA256Hash(parts[0])
		if err != nil {
			hl.logger.Warn("skipping invalid bad file hash", "hash", parts[0])
			continue
		}
		if isZeroLengthFileHash(hash) {
			hl.logger.Warn("skipping zero-length bad file hash", "hash", hash)
			continue
		}
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
	if isZeroLengthFileHash(hash) {
		return "", false
	}
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
		if errors.Is(err, errZeroLengthBadFile) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("hash failed: %w", err)
	}

	name, exists := hl.Lookup(hash)
	return name, exists, nil
}

func (hl *HashList) AddFile(absPath string) (string, error) {
	hash, err := hl.calculateSHA256(absPath)
	if err != nil {
		return "", fmt.Errorf("hash failed: %w", err)
	}

	// Use the base name of the file (e.g., /home/user/Photo.scr -> Photo.scr)
	filename := filepath.Base(absPath)

	return hash, hl.AddHash(hash, filename)
}

func (hl *HashList) EnsureContent(content string) (int, error) {
	scanner := newLongLineScanner(strings.NewReader(content))
	type pendingHash struct {
		hash     string
		filename string
	}
	pending := make([]pendingHash, 0, 16)
	seen := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		hash := parts[0]
		filename := ""
		if len(parts) > 1 {
			filename = strings.Join(parts[1:], " ")
		}

		hash, err := normalizeSHA256Hash(hash)
		if err != nil {
			return len(pending), err
		}
		if isZeroLengthFileHash(hash) {
			return len(pending), errZeroLengthBadFile
		}
		if _, exists := hl.Lookup(hash); exists {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		pending = append(pending, pendingHash{hash: hash, filename: filename})
	}

	if err := scanner.Err(); err != nil {
		return len(pending), err
	}
	if len(pending) == 0 {
		return 0, nil
	}

	hl.mu.Lock()
	f, err := os.OpenFile(hl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		hl.mu.Unlock()
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	for _, entry := range pending {
		line := fmt.Sprintf("%s  %s\n", entry.hash, entry.filename)
		if _, err := f.WriteString(line); err != nil {
			f.Close()
			hl.mu.Unlock()
			return 0, fmt.Errorf("failed to write to file: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		hl.mu.Unlock()
		return 0, fmt.Errorf("failed to close file: %w", err)
	}
	hl.mu.Unlock()

	if _, err := hl.Reload(); err != nil {
		return len(pending), err
	}
	return len(pending), nil
}

// calculateSHA256 performs a streaming hash of a file to handle large files efficiently.
func (hl *HashList) calculateSHA256(absPath string) (string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() == 0 {
		return "", errZeroLengthBadFile
	}

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

func isValidSHA256Hash(hash string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	return sha256HexPattern.MatchString(hash)
}

func normalizeSHA256Hash(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return "", fmt.Errorf("empty hash")
	}
	if !isValidSHA256Hash(hash) {
		return "", fmt.Errorf("invalid sha256 hash %q", hash)
	}
	return hash, nil
}
