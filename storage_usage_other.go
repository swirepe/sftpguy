//go:build !unix

package main

import "sftpguy/internal/adminhttp"

type storageTarget struct {
	ID        string
	Kind      string
	Label     string
	Path      string
	UseParent bool
}

func storageVolumeForTarget(target storageTarget, _ func(int64) string) adminhttp.StorageVolume {
	return adminhttp.StorageVolume{
		ID:    target.ID,
		Kind:  target.Kind,
		Label: target.Label,
		Path:  target.Path,
		Error: "filesystem free-space reporting is not supported on this platform",
	}
}
