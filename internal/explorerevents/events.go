package explorerevents

const (
	Version = 1

	KindUpload   = "upload"
	KindDownload = "download"
	KindLog      = "log"
	KindRequest  = "request"
)

type Event struct {
	Version        int            `json:"version"`
	Kind           string         `json:"kind"`
	Timestamp      int64          `json:"timestamp,omitempty"`
	ClientIP       string         `json:"client_ip,omitempty"`
	RemoteAddr     string         `json:"remote_addr,omitempty"`
	Path           string         `json:"path,omitempty"`
	Bytes          int64          `json:"bytes,omitempty"`
	Size           int64          `json:"size,omitempty"`
	Delta          int64          `json:"delta,omitempty"`
	DurationMS     float64        `json:"duration_ms,omitempty"`
	AvgBytesPerSec int64          `json:"avg_bytes_per_sec,omitempty"`
	Status         int            `json:"status,omitempty"`
	Method         string         `json:"method,omitempty"`
	URLPath        string         `json:"url_path,omitempty"`
	Query          string         `json:"query,omitempty"`
	Level          string         `json:"level,omitempty"`
	Message        string         `json:"message,omitempty"`
	Meta           map[string]any `json:"meta,omitempty"`
}
