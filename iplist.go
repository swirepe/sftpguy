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
	ranger atomic.Pointer[cidranger.Ranger]
	logger *slog.Logger
	cancel context.CancelFunc
}

func NewIPList(ctx context.Context, filepath string, logger *slog.Logger) *IPList {
	log := logger.With("ip_list", filepath)
	bl := &IPList{logger: log}
	bl.reload(filepath) // Initial load

	go func() {
		const period = 30 * time.Second
		log.Info("Starting ip list reloader", "period", period)
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
				log.Info("Stopping ip list reloader")
				return
			}
		}
	}()

	return bl
}

func (bl *IPList) Stop() {
	if bl.cancel != nil {
		bl.cancel()
	}
}

func (bl *IPList) reload(filepath string) (entries, addresses int, err error) {
	newRanger := cidranger.NewPCTrieRanger()

	file, err := os.Open(filepath)
	if err != nil {
		bl.ranger.Store(&newRanger)
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cidrStr := normalizeIPPattern(line)

		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Try parsing as a single IP if CIDR failed
			if ip := net.ParseIP(cidrStr); ip != nil {
				mask := 32
				if ip.To4() == nil {
					mask = 128
				}
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(mask, mask)}
			} else {
				continue // Skip invalid lines
			}
		}

		newRanger.Insert(cidranger.NewBasicRangerEntry(*network))
		ones, bits := network.Mask.Size()
		count := 1 << uint(bits-ones)
		addresses += count
		entries += 1
	}

	bl.ranger.Store(&newRanger)
	return entries, addresses, nil
}

// normalizeIPPattern converts 1.2.*.* to 1.2.0.0/16
func normalizeIPPattern(input string) string {
	if !strings.Contains(input, "*") {
		return input
	}

	parts := strings.Split(input, ".")
	wildcards := 0
	for i, part := range parts {
		if part == "*" {
			parts[i] = "0"
			wildcards++
		}
	}

	// If it's IPv4 (4 parts), calculate mask
	if len(parts) == 4 {
		mask := (4 - wildcards) * 8
		return fmt.Sprintf("%s/%d", strings.Join(parts, "."), mask)
	}
	return input
}

func (bl *IPList) Matches(ipStr string) bool {
	ranger := *bl.ranger.Load()
	if ranger == nil {
		return false
	}

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

// func main() {
// 	blacklist := NewIPList("ips.txt")

// 	// Example usage
// 	for {
// 		testIP := "23.45.1.1"
// 		if blacklist.Matches(testIP) {
// 			fmt.Printf("IP %s is blocked!\n", testIP)
// 		}
// 		time.Sleep(5 * time.Second)
// 	}
// }
