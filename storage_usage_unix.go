//go:build unix

package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"sftpguy/internal/adminhttp"

	"golang.org/x/sys/unix"
)

type storageTarget struct {
	ID        string
	Kind      string
	Label     string
	Path      string
	UseParent bool
}

func storageVolumeForTarget(target storageTarget, format func(int64) string) adminhttp.StorageVolume {
	volume := adminhttp.StorageVolume{
		ID:    target.ID,
		Kind:  target.Kind,
		Label: target.Label,
		Path:  absStoragePath(target.Path),
	}
	if volume.Path == "" {
		volume.Error = "path is not configured"
		return volume
	}

	statPath, err := storageStatPath(volume.Path, target.UseParent)
	if err != nil {
		volume.Error = err.Error()
		return volume
	}
	volume.StatPath = statPath

	var stat unix.Statfs_t
	if err := unix.Statfs(statPath, &stat); err != nil {
		volume.Error = err.Error()
		return volume
	}

	var fileStat unix.Stat_t
	if err := unix.Stat(statPath, &fileStat); err == nil {
		volume.DeviceID = fmt.Sprintf("%d", fileStat.Dev)
	}

	blockSize := int64(stat.Bsize)
	if blockSize <= 0 {
		blockSize = 1
	}
	total := blockBytes(uint64(stat.Blocks), blockSize)
	free := blockBytes(uint64(stat.Bavail), blockSize)
	used := total - free
	if used < 0 {
		used = 0
	}

	volume.TotalBytes = total
	volume.FreeBytes = free
	volume.UsedBytes = used
	volume.Total = format(total)
	volume.Free = format(free)
	volume.Used = format(used)
	if total > 0 {
		volume.UsedPercent = math.Round((float64(used)/float64(total))*1000) / 10
		volume.FreePercent = math.Round((float64(free)/float64(total))*1000) / 10
	}
	return volume
}

func absStoragePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

func storageStatPath(path string, useParent bool) (string, error) {
	if useParent {
		path = filepath.Dir(path)
	}
	path = filepath.Clean(path)
	for {
		if info, err := os.Stat(path); err == nil {
			if !info.IsDir() {
				return filepath.Dir(path), nil
			}
			return path, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(path)
		if parent == path {
			return "", os.ErrNotExist
		}
		path = parent
	}
}

func blockBytes(blocks uint64, blockSize int64) int64 {
	if blockSize <= 0 || blocks == 0 {
		return 0
	}
	const maxInt64 = int64(1<<63 - 1)
	maxBlocks := uint64(maxInt64 / blockSize)
	if blocks > maxBlocks {
		return maxInt64
	}
	return int64(blocks) * blockSize
}
