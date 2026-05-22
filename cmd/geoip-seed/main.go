package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type seedDatabase struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	FileName  string `json:"file_name"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type manifest struct {
	GeneratedAt string         `json:"generated_at"`
	Databases   []seedDatabase `json:"databases"`
}

var databases = []seedDatabase{
	{
		ID:       "dbip-city-lite",
		Name:     "DB-IP City Lite",
		FileName: "dbip-city-lite.mmdb.gz",
		URL:      "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz",
	},
	{
		ID:       "geolite2-city",
		Name:     "GeoLite2 City",
		FileName: "GeoLite2-City.mmdb.gz",
		URL:      "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz",
	},
}

func main() {
	outDir := flag.String("out", "internal/geoip/seed", "directory for compressed seed databases")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal(err)
	}

	client := &http.Client{Timeout: 20 * time.Minute}
	man := manifest{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, db := range databases {
		path := filepath.Join(*outDir, db.FileName)
		size, sum, err := download(client, db.URL, path)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", db.ID, err))
		}
		db.SizeBytes = size
		db.SHA256 = sum
		man.Databases = append(man.Databases, db)
		fmt.Printf("downloaded %s to %s (%d bytes)\n", db.ID, path, size)
	}

	manifestPath := filepath.Join(*outDir, "manifest.json")
	f, err := os.Create(manifestPath)
	if err != nil {
		fatal(err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(man); err != nil {
		_ = f.Close()
		fatal(err)
	}
	if err := f.Close(); err != nil {
		fatal(err)
	}
}

func download(client *http.Client, url, path string) (int64, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "sftpguy-geoip-seed-generator")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, "", fmt.Errorf("download failed: %s", resp.Status)
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, hash), resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return 0, "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return 0, "", closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, "", err
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
