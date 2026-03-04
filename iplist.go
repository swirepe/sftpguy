package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yl2chen/cidranger"
)

type IPList struct {
	// ranger stores the cidranger.Ranger interface
	ranger atomic.Value
	logger *slog.Logger
	cancel context.CancelFunc
}

// NewIPList initializes the list and starts a background reloader.
func NewIPList(ctx context.Context, filepath string, logger *slog.Logger) *IPList {
	log := logger.With("ip_list", filepath)
	ctx, cancel := context.WithCancel(ctx)

	bl := &IPList{
		logger: log,
		cancel: cancel,
	}

	if entries, addresses, err := bl.reload(filepath); err != nil {
		log.Error("initial load failed", "error", err)
	} else {
		log.Info("initial load complete", "entries", entries, "addresses", addresses)
	}

	go func() {
		const period = 30 * time.Second
		ticker := time.NewTicker(period)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				start := time.Now()
				entries, addresses, err := bl.reload(filepath)

				bl.logger.Debug("reloaded ip list file",
					"entries", entries,
					"addresses", addresses,
					"duration", time.Since(start),
					"error", err)
			case <-ctx.Done():
				log.Info("stopping ip list reloader")
				return
			}
		}
	}()

	return bl
}

// Stop halts the background reloader.
func (bl *IPList) Stop() {
	if bl.cancel != nil {
		bl.cancel()
	}
}

func (bl *IPList) reload(filepath string) (entries int, addresses uint64, err error) {
	newRanger := cidranger.NewPCTrieRanger()

	file, err := os.Open(filepath)
	if err != nil {
		// IMPORTANT: Do not Store an empty ranger here.
		// Return the error so the system keeps using the last successful version.
		return 0, 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Remove comments
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
			// Try parsing as a single IP
			if ip := net.ParseIP(cidrStr); ip != nil {
				maskLen := 32
				if ip.To4() == nil {
					maskLen = 128
				}
				network = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(maskLen, maskLen),
				}
			} else {
				bl.logger.Warn("skipping invalid line", "line", line)
				continue
			}
		}

		newRanger.Insert(cidranger.NewBasicRangerEntry(*network))
		entries++

		// Calculate address count safely
		ones, bits := network.Mask.Size()
		diff := bits - ones
		if diff < 64 {
			addresses += 1 << uint64(diff)
		} else {
			// For IPv6 /64 or larger, math/big would be needed.
			// We cap it at MaxUint64 to prevent overflow panics.
			addresses = ^uint64(0)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, addresses, fmt.Errorf("scanner error: %w", err)
	}

	// Swap the old ranger with the new one atomically
	bl.ranger.Store(newRanger)
	return entries, addresses, nil
}

// normalizeIPPattern converts 1.2.*.* to 1.2.0.0/16
func normalizeIPPattern(input string) string {
	if !strings.Contains(input, "*") {
		return input
	}

	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		return input // Only handle IPv4 wildcards
	}

	mask := 0
	for i, part := range parts {
		if part == "*" {
			parts[i] = "0"
		} else {
			// The mask length is determined by the last non-wildcard octet
			mask = (i + 1) * 8
		}
	}

	return fmt.Sprintf("%s/%d", strings.Join(parts, "."), mask)
}

// Matches returns true if the IP is found in the current range list.
func (bl *IPList) Matches(ipStr string) bool {
	// Retrieve the interface from atomic.Value
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
