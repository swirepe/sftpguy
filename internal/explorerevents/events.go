package explorerevents

const (
	Version = 1

	KindUpload   = "upload"
	KindDownload = "download"
	KindLog      = "log"
	KindRequest  = "request"

	RPCServiceName = "ExplorerEvents"
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

type Ack struct{}

type IPPolicyRequest struct {
	IP string `json:"ip"`
}

type IPPolicyResponse struct {
	Version             int    `json:"version"`
	IP                  string `json:"ip,omitempty"`
	Whitelisted         bool   `json:"whitelisted,omitempty"`
	Blacklisted         bool   `json:"blacklisted,omitempty"`
	EffectiveBanned     bool   `json:"effective_banned,omitempty"`
	UploadAllowed       bool   `json:"upload_allowed,omitempty"`
	ThrottleBytesPerSec int    `json:"throttle_bytes_per_sec,omitempty"`
}
