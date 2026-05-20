package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sftpguy/internal/adminhttp"
)

func addStorageFileInfo(volume *adminhttp.StorageVolume, target storageTarget, format func(int64) string) {
	if volume == nil || volume.Path == "" || !target.UseParent {
		return
	}

	file := storageFileInfo(target.Label, volume.Path, format)
	volume.FileExists = file.Exists
	volume.FileBytes = file.SizeBytes
	volume.FileSize = file.Size

	sidecarPaths := storageSidecarPaths(target.Kind, volume.Path)
	if len(sidecarPaths) == 0 {
		return
	}

	volume.Sidecars = make([]adminhttp.StorageFile, 0, len(sidecarPaths))
	for _, item := range sidecarPaths {
		info := storageFileInfo(item.label, item.path, format)
		if info.Exists || info.Error != "" {
			volume.Sidecars = append(volume.Sidecars, info)
		}
	}
}

func storageFileInfo(label, path string, format func(int64) string) adminhttp.StorageFile {
	out := adminhttp.StorageFile{
		Label: label,
		Path:  path,
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		out.Error = err.Error()
		return out
	}
	if info.IsDir() {
		return out
	}
	out.Exists = true
	out.SizeBytes = info.Size()
	out.Size = format(info.Size())
	return out
}

type storageSidecarPath struct {
	label string
	path  string
}

func storageSidecarPaths(kind, path string) []storageSidecarPath {
	switch kind {
	case "database":
		return []storageSidecarPath{
			{label: "WAL", path: path + "-wal"},
			{label: "SHM", path: path + "-shm"},
		}
	case "log":
		return storageLogSidecarPaths(path)
	default:
		return nil
	}
}

var (
	logrotateNumberedSuffixRE = regexp.MustCompile(`^\.[1-9][0-9]*$`)
	logrotateDatedSuffixRE    = regexp.MustCompile(`^-(?:[0-9]{8}(?:[-_.]?[0-9]{2}){0,3}|[0-9]{4}[-_.][0-9]{2}[-_.][0-9]{2}(?:[-_.]?[0-9]{2}){0,3})$`)
)

var logrotateCompressionExts = []string{
	".gz",
	".bz2",
	".xz",
	".zst",
	".lz4",
	".zip",
	".Z",
}

func storageLogSidecarPaths(path string) []storageSidecarPath {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	out := make([]storageSidecarPath, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		suffix, ok := strings.CutPrefix(name, base)
		if !ok || !isLogrotateSuffix(suffix) {
			continue
		}
		out = append(out, storageSidecarPath{
			label: "Rotated " + suffix,
			path:  filepath.Join(dir, name),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return logSidecarLess(base, out[i].path, out[j].path)
	})
	return out
}

func isLogrotateSuffix(suffix string) bool {
	stem := trimLogrotateCompressionExt(suffix)
	return logrotateNumberedSuffixRE.MatchString(stem) || logrotateDatedSuffixRE.MatchString(stem)
}

func trimLogrotateCompressionExt(suffix string) string {
	for _, ext := range logrotateCompressionExts {
		if strings.HasSuffix(suffix, ext) {
			return strings.TrimSuffix(suffix, ext)
		}
	}
	return suffix
}

func logSidecarLess(base, leftPath, rightPath string) bool {
	leftGroup, leftNumber, leftDate, leftName := logSidecarSortKey(base, leftPath)
	rightGroup, rightNumber, rightDate, rightName := logSidecarSortKey(base, rightPath)
	if leftGroup != rightGroup {
		return leftGroup < rightGroup
	}
	if leftGroup == 0 && leftNumber != rightNumber {
		return leftNumber < rightNumber
	}
	if leftGroup == 1 && leftDate != rightDate {
		return leftDate > rightDate
	}
	return leftName < rightName
}

func logSidecarSortKey(base, path string) (group, number int, date, name string) {
	name = filepath.Base(path)
	suffix, ok := strings.CutPrefix(name, base)
	if !ok {
		return 2, 0, "", name
	}

	stem := trimLogrotateCompressionExt(suffix)
	if logrotateNumberedSuffixRE.MatchString(stem) {
		number, _ = strconv.Atoi(strings.TrimPrefix(stem, "."))
		return 0, number, "", name
	}
	if logrotateDatedSuffixRE.MatchString(stem) {
		return 1, 0, strings.TrimPrefix(stem, "-"), name
	}
	return 2, 0, "", name
}
