package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yl2chen/cidranger"
)

type IPList struct {
	ranger      atomic.Value // stores cidranger.Ranger
	addlineChan chan struct{}
	logger      *slog.Logger
	cancel      context.CancelFunc
	filepath    string
	mu          sync.Mutex // Protects file writes
}

type IPListEntry struct {
	Raw        string
	Value      string
	Normalized string
	Comment    string
	ExactIP    string
}

type ipReloadResult struct {
	entries   int
	addresses uint64
	err       string
}

func newIPReloadResult(entries int, addresses uint64, err error) ipReloadResult {
	result := ipReloadResult{entries: entries, addresses: addresses}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func (r ipReloadResult) equals(other ipReloadResult) bool {
	return r.entries == other.entries && r.addresses == other.addresses && r.err == other.err
}

func NewIPList(ctx context.Context, filepath string, logger *slog.Logger) *IPList {
	log := logger.With("ip_list", filepath)
	ctx, cancel := context.WithCancel(ctx)

	bl := &IPList{
		logger:      log,
		addlineChan: make(chan struct{}, 1),
		cancel:      cancel,
		filepath:    filepath,
	}

	// Initial load
	entries, addresses, err := bl.Reload()
	if err != nil {
		log.Warn("initial ip list load failed", "error", err)
	} else {
		log.Info("initial ip list load complete", "entries", entries, "addresses", addresses)
	}

	firstReload := newIPReloadResult(entries, addresses, err)

	go func(lastReload ipReloadResult) {
		const period = 30 * time.Second
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		var lastChanged = time.Now()

		for {
			select {
			case <-bl.addlineChan:
				// Triggered by AddRange
				lastReload, lastChanged = bl.performReload(lastReload, &lastChanged)
			case <-ticker.C:
				// Periodic reload
				lastReload, lastChanged = bl.performReload(lastReload, &lastChanged)
			case <-ctx.Done():
				log.Info("stopping ip list reloader")
				return
			}
		}
	}(firstReload)

	return bl
}

// performReload wraps the Reload logic for the background loop
func (bl *IPList) performReload(lastReload ipReloadResult, lastChanged *time.Time) (ipReloadResult, time.Time) {
	start := time.Now()
	entries, addresses, err := bl.Reload()
	currentReload := newIPReloadResult(entries, addresses, err)

	if !currentReload.equals(lastReload) {
		bl.logger.Info("reloaded ip list file",
			"entries", entries,
			"addresses", addresses,
			"duration", time.Since(start),
			"last_changed", time.Since(*lastChanged),
			"error", err)
		return currentReload, time.Now()
	}
	return lastReload, *lastChanged
}

func (bl *IPList) AddWithComment(comment string, ips ...string) {
	if len(ips) == 0 {
		return
	}

	var sb strings.Builder
	cleanComment := sanitizeIPListComment(comment)

	if len(ips) == 1 {
		sb.WriteString(fmt.Sprintf("%s # %s\n", ips[0], cleanComment))
	} else {
		sb.WriteString(fmt.Sprintf("# %s\n", cleanComment))
		for _, ip := range ips {
			sb.WriteString(ip + "\n")
		}
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	f, err := os.OpenFile(bl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(sb.String())

		// Signal reload
		select {
		case bl.addlineChan <- struct{}{}:
		default:
		}
	}
}

func (bl *IPList) AddExactIPWithComment(ip, comment string) (bool, error) {
	exactIP := canonicalExactIPEntry(ip)
	if exactIP == "" {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	content, err := bl.readContentUnlocked()
	if err != nil {
		return false, err
	}
	for _, entry := range parseIPListEntries(content) {
		if entry.ExactIP == exactIP {
			return false, nil
		}
	}

	line := exactIP
	if cleanComment := sanitizeIPListComment(comment); cleanComment != "" {
		line = fmt.Sprintf("%s # %s", exactIP, cleanComment)
	}

	f, err := os.OpenFile(bl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false, fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(line + "\n"); err != nil {
		return false, fmt.Errorf("failed to write to file: %w", err)
	}

	if _, _, err := bl.reloadUnlocked(); err != nil {
		return true, err
	}
	return true, nil
}

func (bl *IPList) ExactEntries() ([]IPListEntry, error) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	content, err := bl.readContentUnlocked()
	if err != nil {
		return nil, err
	}

	all := parseIPListEntries(content)
	exact := make([]IPListEntry, 0, len(all))
	for _, entry := range all {
		if entry.ExactIP != "" {
			exact = append(exact, entry)
		}
	}
	return exact, nil
}

func (bl *IPList) RemoveExactIP(ip string) (bool, error) {
	exactIP := canonicalExactIPEntry(ip)
	if exactIP == "" {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	content, err := bl.readContentUnlocked()
	if err != nil {
		return false, err
	}
	if content == "" {
		return false, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lines := make([]string, 0, strings.Count(content, "\n")+1)
	removed := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		entry, ok := parseIPListEntry(rawLine)
		if ok && entry.ExactIP == exactIP {
			removed = true
			continue
		}
		lines = append(lines, rawLine)
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan file: %w", err)
	}
	if !removed {
		return false, nil
	}

	rewritten := strings.Join(lines, "\n")
	if rewritten != "" {
		rewritten += "\n"
	}
	if err := os.WriteFile(bl.filepath, []byte(rewritten), 0644); err != nil {
		return false, fmt.Errorf("failed to rewrite file: %w", err)
	}

	if _, _, err := bl.reloadUnlocked(); err != nil {
		return true, err
	}
	return true, nil
}

// AddRange adds a new IP or CIDR to the file and triggers a reload.
func (bl *IPList) AddRange(host string, mask int, comment string) error {
	// Construct CIDR string
	cidrStr := host
	if mask > 0 {
		cidrStr = fmt.Sprintf("%s/%d", host, mask)
	}

	// Validate input
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Try parsing as single IP
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", host)
		}
		maskLen := 32
		if ip.To4() == nil {
			maskLen = 128
		}
		network = &net.IPNet{IP: ip, Mask: net.CIDRMask(maskLen, maskLen)}
		cidrStr = network.String()
	} else {
		cidrStr = network.String()
	}

	// Prevent duplicates by checking existing ranger
	if bl.Matches(network.IP.String()) {
		return nil // Already covered
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	f, err := os.OpenFile(bl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer f.Close()

	line := cidrStr
	if comment != "" {
		line = fmt.Sprintf("%s # %s", cidrStr, sanitizeIPListComment(comment))
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	// Signal the reloader (non-blocking)
	select {
	case bl.addlineChan <- struct{}{}:
	default:
	}

	return nil
}

func (bl *IPList) Stop() {
	if bl.cancel != nil {
		bl.cancel()
	}
}

func (bl *IPList) Reload() (entries int, addresses uint64, err error) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	return bl.reloadUnlocked()
}

func (bl *IPList) reloadUnlocked() (entries int, addresses uint64, err error) {
	newRanger := cidranger.NewPCTrieRanger()

	file, err := os.Open(bl.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cidrStr := normalizeIPPattern(line)
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			if ip := net.ParseIP(cidrStr); ip != nil {
				maskLen := 32
				if ip.To4() == nil {
					maskLen = 128
				}
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(maskLen, maskLen)}
			} else {
				bl.logger.Warn("skipping invalid line", "line", line)
				continue
			}
		}

		newRanger.Insert(cidranger.NewBasicRangerEntry(*network))
		entries++

		ones, bits := network.Mask.Size()
		diff := bits - ones
		if diff < 64 {
			addresses += 1 << uint64(diff)
		} else {
			addresses = ^uint64(0)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, addresses, fmt.Errorf("scanner error: %w", err)
	}

	bl.ranger.Store(newRanger)
	return entries, addresses, nil
}

func (bl *IPList) EnsureContent(content string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	linesToAppend := make([]string, 0, 8)

	for scanner.Scan() {
		rawLine := strings.TrimSpace(scanner.Text())
		if rawLine == "" || strings.HasPrefix(rawLine, "#") {
			continue
		}

		line := rawLine
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cidrStr := normalizeIPPattern(line)
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			ip := net.ParseIP(cidrStr)
			if ip == nil {
				return len(linesToAppend), fmt.Errorf("invalid IP or CIDR: %s", line)
			}
			maskLen := 32
			if ip.To4() == nil {
				maskLen = 128
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(maskLen, maskLen)}
		}

		if bl.Matches(network.IP.String()) {
			continue
		}
		linesToAppend = append(linesToAppend, rawLine)
	}

	if err := scanner.Err(); err != nil {
		return len(linesToAppend), err
	}
	if len(linesToAppend) == 0 {
		return 0, nil
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	f, err := os.OpenFile(bl.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer f.Close()

	for _, line := range linesToAppend {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return 0, fmt.Errorf("failed to write to file: %w", err)
		}
	}

	if _, _, err := bl.reloadUnlocked(); err != nil {
		return len(linesToAppend), err
	}
	return len(linesToAppend), nil
}

func sanitizeIPListComment(comment string) string {
	return strings.TrimSpace(strings.ReplaceAll(comment, "\n", " "))
}

func canonicalExactIPEntry(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil || network == nil || network.IP == nil {
		return ""
	}
	ones, bits := network.Mask.Size()
	if ones != bits {
		return ""
	}
	return network.IP.String()
}

func parseIPListEntry(raw string) (IPListEntry, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return IPListEntry{}, false
	}

	entry := IPListEntry{Raw: raw}
	if idx := strings.Index(line, "#"); idx >= 0 {
		entry.Comment = strings.TrimSpace(line[idx+1:])
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return IPListEntry{}, false
	}

	entry.Value = line
	entry.Normalized = normalizeIPPattern(line)
	entry.ExactIP = canonicalExactIPEntry(entry.Normalized)
	return entry, true
}

func parseIPListEntries(content string) []IPListEntry {
	scanner := bufio.NewScanner(strings.NewReader(content))
	entries := make([]IPListEntry, 0, 8)
	for scanner.Scan() {
		if entry, ok := parseIPListEntry(scanner.Text()); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (bl *IPList) readContentUnlocked() (string, error) {
	b, err := os.ReadFile(bl.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return string(b), nil
}

func normalizeIPPattern(input string) string {
	if !strings.Contains(input, "*") {
		return input
	}
	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		return input
	}
	mask := 0
	for i, part := range parts {
		if part == "*" {
			parts[i] = "0"
		} else {
			mask = (i + 1) * 8
		}
	}
	return fmt.Sprintf("%s/%d", strings.Join(parts, "."), mask)
}

func (bl *IPList) Matches(ipStr string) bool {
	val := bl.ranger.Load()
	if val == nil {
		return false
	}
	ranger := val.(cidranger.Ranger)

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}

	contains, err := ranger.Contains(ip)
	if err != nil {
		return false
	}
	return contains
}
