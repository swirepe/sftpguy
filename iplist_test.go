package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeIPPattern(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.*.*", "1.2.0.0/16"},
		{"192.168.1.*", "192.168.1.0/24"},
		{"10.*.*.*", "10.0.0.0/8"},
		{"*", "*"},                   // Not a valid IPv4 pattern, returns as-is
		{"2001:db8::", "2001:db8::"}, // IPv6 untouched
	}

	for _, tt := range tests {
		if got := normalizeIPPattern(tt.input); got != tt.expected {
			t.Errorf("normalizeIPPattern(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIPList_Matches(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ips.txt")

	content := `
# Rules
1.2.3.4
10.0.0.0/24
192.168.*.*
2001:db8::/32
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Discard logs during tests to keep output clean
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	list := NewIPList(ctx, tmpFile, logger)
	defer list.Stop()

	tests := []struct {
		ip    string
		want  bool
		label string
	}{
		{"1.2.3.4", true, "Exact IPv4 match"},
		{"1.2.3.5", false, "No match IPv4"},
		{"10.0.0.50", true, "Subnet CIDR match"},
		{"10.0.1.1", false, "Outside subnet CIDR"},
		{"192.168.5.5", true, "Wildcard match"},
		{"2001:db8::1", true, "IPv6 match"},
		{"invalid-ip", false, "Invalid string"},
		{"", false, "Empty string"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			if got := list.Matches(tt.ip); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIPList_ReloadFaultTolerance(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "fault.txt")

	// 1. Initial Load
	os.WriteFile(tmpFile, []byte("1.1.1.1"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	list := NewIPList(ctx, tmpFile, slog.Default())
	defer list.Stop()

	if !list.Matches("1.1.1.1") {
		t.Fatal("Initial IP should match")
	}

	// 2. Corrupt/Delete the file
	if err := os.Remove(tmpFile); err != nil {
		t.Fatal(err)
	}

	// 3. Manually trigger reload (simulating the ticker)
	_, _, err := list.Reload(tmpFile)
	if err == nil {
		t.Error("Reload should have failed because file is missing")
	}

	// 4. Verify original list is still active (fault tolerance)
	if !list.Matches("1.1.1.1") {
		t.Error("IPList was cleared on failed reload; it should have kept the old data")
	}
}

func TestIPList_DynamicUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "dynamic.txt")

	os.WriteFile(tmpFile, []byte("1.1.1.1"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	list := NewIPList(ctx, tmpFile, slog.Default())
	defer list.Stop()

	// Update the file content
	os.WriteFile(tmpFile, []byte("2.2.2.2"), 0644)

	// Manually trigger reload
	entries, _, err := list.Reload(tmpFile)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if entries != 1 {
		t.Errorf("Expected 1 entry, got %d", entries)
	}

	if list.Matches("1.1.1.1") {
		t.Error("Old IP should no longer match")
	}
	if !list.Matches("2.2.2.2") {
		t.Error("New IP should match")
	}
}

func TestIPList_IPv6AddressCalculation(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ipv6_calc.txt")

	// Create a large IPv6 range that would overflow a standard uint32/uint64 shift
	// /32 is 2^96 addresses.
	content := "2001:db8::/32"
	os.WriteFile(tmpFile, []byte(content), 0644)

	list := &IPList{logger: slog.Default()}
	entries, addresses, err := list.Reload(tmpFile)

	if err != nil {
		t.Fatalf("Failed to load large IPv6 range: %v", err)
	}

	if entries != 1 {
		t.Errorf("Expected 1 entry, got %d", entries)
	}

	// Should be MaxUint64 based on our code logic for ranges > 64 bits
	if addresses != ^uint64(0) {
		t.Errorf("Expected MaxUint64 for large IPv6 range, got %d", addresses)
	}
}

func TestIPList_Stop(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "stop.txt")
	os.WriteFile(tmpFile, []byte("1.1.1.1"), 0644)

	ctx := context.Background()
	list := NewIPList(ctx, tmpFile, slog.Default())

	// This is checking if Stop() causes a panic or blocks indefinitely
	// In a real scenario, you'd check goroutine counts, but Stop() is simple here.
	list.Stop()
}
