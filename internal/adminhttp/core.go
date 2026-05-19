package adminhttp

import (
	"encoding/json"
	"net/http"
	"time"
)

type CoreDeps interface {
	ArchiveName() string
	AppVersion() string
	SSHPort() int
	AdminHTTPAddr() string
	Uptime() time.Duration
	ContributorThreshold() int64
	BannerStats(threshold int64) (users, contributors, files, bytes uint64)
	DirectoryCount() (int, error)
	FormatBytes(int64) string
	StorageVolumes() []StorageVolume
}

type StorageVolume struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"`
	Label       string  `json:"label"`
	Path        string  `json:"path"`
	StatPath    string  `json:"stat_path,omitempty"`
	DeviceID    string  `json:"device_id,omitempty"`
	TotalBytes  int64   `json:"total_bytes"`
	FreeBytes   int64   `json:"free_bytes"`
	UsedBytes   int64   `json:"used_bytes"`
	Total       string  `json:"total,omitempty"`
	Free        string  `json:"free,omitempty"`
	Used        string  `json:"used,omitempty"`
	UsedPercent float64 `json:"used_percent"`
	FreePercent float64 `json:"free_percent"`
	Error       string  `json:"error,omitempty"`
}

func HealthHandler(deps CoreDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"archive": deps.ArchiveName(),
			"version": deps.AppVersion(),
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func SummaryHandler(deps CoreDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u, c, f, b := deps.BannerStats(deps.ContributorThreshold())
		dirCount, _ := deps.DirectoryCount()

		writeJSON(w, http.StatusOK, map[string]any{
			"archive":               deps.ArchiveName(),
			"version":               deps.AppVersion(),
			"ssh_port":              deps.SSHPort(),
			"admin_http":            deps.AdminHTTPAddr(),
			"uptime":                deps.Uptime().Round(time.Second).String(),
			"uptime_seconds":        int64(deps.Uptime().Seconds()),
			"users":                 u,
			"contributors":          c,
			"files":                 f,
			"directories":           dirCount,
			"bytes":                 b,
			"formatted_bytes":       deps.FormatBytes(int64(b)),
			"contributor_threshold": deps.ContributorThreshold(),
			"storage":               deps.StorageVolumes(),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
