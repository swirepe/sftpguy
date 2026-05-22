package geoip

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

//go:generate go run ../../cmd/geoip-seed -out seed

//go:embed seed/*
var seedFS embed.FS

const (
	IDDBIPCityLite  = "dbip-city-lite"
	IDGeoLite2City  = "geolite2-city"
	defaultProvider = IDDBIPCityLite
	updateHourUTC   = 6
)

type Config struct {
	Enabled    bool
	AutoUpdate bool
	DataDir    string
	Provider   string
}

type Manager struct {
	mu         sync.RWMutex
	enabled    bool
	autoUpdate bool
	dataDir    string
	provider   string
	client     *http.Client
	logger     *slog.Logger
	databases  map[string]*databaseState
}

type databaseState struct {
	def       DatabaseDefinition
	reader    *maxminddb.Reader
	path      string
	size      int64
	fileTime  time.Time
	buildTime time.Time
	lastError string
	sha256    string
}

type DatabaseDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	FileName    string `json:"file_name"`
	SeedName    string `json:"seed_name"`
	SourceURL   string `json:"source_url"`
	SourceRepo  string `json:"source_repo"`
	License     string `json:"license"`
	Attribution string `json:"attribution"`
	Cadence     string `json:"cadence"`
}

type Status struct {
	Enabled    bool             `json:"enabled"`
	AutoUpdate bool             `json:"auto_update"`
	DataDir    string           `json:"data_dir"`
	Provider   string           `json:"provider"`
	Databases  []DatabaseStatus `json:"databases"`
}

type DatabaseStatus struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	SourceURL    string `json:"source_url"`
	SourceRepo   string `json:"source_repo"`
	License      string `json:"license"`
	Attribution  string `json:"attribution"`
	Cadence      string `json:"cadence"`
	Present      bool   `json:"present"`
	Loaded       bool   `json:"loaded"`
	SizeBytes    int64  `json:"size_bytes"`
	Size         string `json:"size"`
	FileTime     string `json:"file_time,omitempty"`
	BuildTime    string `json:"build_time,omitempty"`
	NextUpdate   string `json:"next_update,omitempty"`
	UpdateDue    bool   `json:"update_due"`
	DatabaseType string `json:"database_type,omitempty"`
	IPVersion    uint   `json:"ip_version,omitempty"`
	NodeCount    uint   `json:"node_count,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

type UpdateResult struct {
	Enabled bool             `json:"enabled"`
	Checked int              `json:"checked"`
	Updated int              `json:"updated"`
	Skipped int              `json:"skipped"`
	Errors  []string         `json:"errors,omitempty"`
	Status  []DatabaseStatus `json:"status"`
}

type Location struct {
	IP             string  `json:"ip"`
	Database       string  `json:"database"`
	DatabaseID     string  `json:"database_id"`
	City           string  `json:"city,omitempty"`
	Region         string  `json:"region,omitempty"`
	RegionCode     string  `json:"region_code,omitempty"`
	Country        string  `json:"country,omitempty"`
	CountryCode    string  `json:"country_code,omitempty"`
	Continent      string  `json:"continent,omitempty"`
	ContinentCode  string  `json:"continent_code,omitempty"`
	Latitude       float64 `json:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty"`
	Timezone       string  `json:"timezone,omitempty"`
	PostalCode     string  `json:"postal_code,omitempty"`
	AccuracyRadius uint16  `json:"accuracy_radius,omitempty"`
	Attribution    string  `json:"attribution,omitempty"`
}

type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		TimeZone       string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
}

var databaseDefinitions = []DatabaseDefinition{
	{
		ID:          IDDBIPCityLite,
		Name:        "DB-IP City Lite",
		FileName:    "dbip-city-lite.mmdb",
		SeedName:    "dbip-city-lite.mmdb.gz",
		SourceURL:   "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz",
		SourceRepo:  "https://github.com/wp-statistics/DbIP-City-lite",
		License:     "CC BY 4.0",
		Attribution: "Contains data from DB-IP Lite, licensed under CC BY 4.0.",
		Cadence:     "monthly",
	},
	{
		ID:          IDGeoLite2City,
		Name:        "GeoLite2 City",
		FileName:    "GeoLite2-City.mmdb",
		SeedName:    "GeoLite2-City.mmdb.gz",
		SourceURL:   "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz",
		SourceRepo:  "https://github.com/wp-statistics/GeoLite2-City",
		License:     "CC BY-SA 4.0",
		Attribution: "Contains GeoLite2 data created by MaxMind, licensed under CC BY-SA 4.0.",
		Cadence:     "tuesday-friday",
	},
}

func Definitions() []DatabaseDefinition {
	out := make([]DatabaseDefinition, len(databaseDefinitions))
	copy(out, databaseDefinitions)
	return out
}

func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
	dataDir := strings.TrimSpace(cfg.DataDir)
	if dataDir == "" {
		dataDir = "geoip"
	}
	m := &Manager{
		enabled:    cfg.Enabled,
		autoUpdate: cfg.AutoUpdate,
		dataDir:    dataDir,
		provider:   normalizeProvider(cfg.Provider),
		client: &http.Client{
			Timeout: 10 * time.Minute,
		},
		logger:    logger,
		databases: make(map[string]*databaseState, len(databaseDefinitions)),
	}
	for _, def := range databaseDefinitions {
		m.databases[def.ID] = &databaseState{
			def:  def,
			path: filepath.Join(dataDir, def.FileName),
		}
	}
	if !cfg.Enabled {
		return m, nil
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	m.seedMissing()
	m.reloadAll()
	return m, nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, state := range m.databases {
		if state.reader != nil {
			errs = append(errs, state.reader.Close())
			state.reader = nil
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) Lookup(ipText string) (*Location, bool) {
	if m == nil || !m.enabled {
		return nil, false
	}
	ip := parseIP(ipText)
	if !isLookupableIP(ip) {
		return nil, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, id := range m.lookupOrderLocked() {
		state := m.databases[id]
		if state == nil || state.reader == nil {
			continue
		}
		var record cityRecord
		if err := state.reader.Lookup(ip, &record); err != nil {
			continue
		}
		if loc, ok := record.location(ip.String(), state.def); ok {
			return &loc, true
		}
	}
	return nil, false
}

func (m *Manager) Status(now time.Time) Status {
	if now.IsZero() {
		now = time.Now()
	}
	out := Status{
		Enabled:    m != nil && m.enabled,
		AutoUpdate: m != nil && m.autoUpdate,
		Provider:   defaultProvider,
	}
	if m == nil {
		return out
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out.DataDir = m.dataDir
	out.Provider = m.provider
	out.Databases = m.statusLocked(now)
	return out
}

func (m *Manager) UpdateDue(ctx context.Context, now time.Time) UpdateResult {
	if now.IsZero() {
		now = time.Now()
	}
	result := UpdateResult{Enabled: m != nil && m.enabled}
	if m == nil || !m.enabled {
		return result
	}
	if !m.autoUpdate {
		result.Status = m.Status(now).Databases
		return result
	}

	var due []DatabaseDefinition
	m.mu.RLock()
	for _, id := range orderedDatabaseIDs() {
		state := m.databases[id]
		if state == nil {
			continue
		}
		result.Checked++
		if databaseUpdateDue(state, now) {
			due = append(due, state.def)
		} else {
			result.Skipped++
		}
	}
	m.mu.RUnlock()

	for _, def := range due {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, ctx.Err().Error())
			result.Status = m.Status(now).Databases
			return result
		default:
		}
		if err := m.downloadAndSwap(ctx, def); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", def.ID, err))
			m.setLastError(def.ID, err)
			continue
		}
		result.Updated++
	}
	result.Status = m.Status(time.Now()).Databases
	return result
}

func (m *Manager) seedMissing() {
	for _, def := range databaseDefinitions {
		target := filepath.Join(m.dataDir, def.FileName)
		if fileExists(target) {
			continue
		}
		data, err := seedFS.ReadFile("seed/" + def.SeedName)
		if err != nil || len(data) == 0 {
			continue
		}
		if err := writeGzipDatabase(data, target); err != nil {
			if m.logger != nil {
				m.logger.Warn("failed to seed geoip database", "database", def.ID, "err", err)
			}
			continue
		}
		if m.logger != nil {
			m.logger.Info("seeded geoip database", "database", def.ID, "path", target)
		}
	}
}

func (m *Manager) reloadAll() {
	for _, def := range databaseDefinitions {
		if err := m.reload(def.ID); err != nil && m.logger != nil {
			m.logger.Warn("failed to load geoip database", "database", def.ID, "err", err)
		}
	}
}

func (m *Manager) reload(id string) error {
	if m == nil {
		return nil
	}
	state := m.databases[id]
	if state == nil {
		return fmt.Errorf("unknown geoip database %q", id)
	}

	info, err := os.Stat(state.path)
	if err != nil {
		if os.IsNotExist(err) {
			m.setLastError(id, nil)
			return nil
		}
		m.setLastError(id, err)
		return err
	}
	reader, err := maxminddb.Open(state.path)
	if err != nil {
		m.setLastError(id, err)
		return err
	}
	sum, _ := fileSHA256(state.path)

	m.mu.Lock()
	defer m.mu.Unlock()
	state = m.databases[id]
	if state == nil {
		_ = reader.Close()
		return nil
	}
	old := state.reader
	state.reader = reader
	state.size = info.Size()
	state.fileTime = info.ModTime()
	state.buildTime = unixBuildTime(reader.Metadata.BuildEpoch)
	state.lastError = ""
	state.sha256 = sum
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (m *Manager) downloadAndSwap(ctx context.Context, def DatabaseDefinition) error {
	if m.logger != nil {
		m.logger.Info("updating geoip database", "database", def.ID, "url", def.SourceURL)
	}
	if err := os.MkdirAll(m.dataDir, 0755); err != nil {
		return err
	}
	target := filepath.Join(m.dataDir, def.FileName)
	tmp, err := os.CreateTemp(m.dataDir, def.FileName+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, def.SourceURL, nil)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	req.Header.Set("User-Agent", "sftpguy-geoip-updater")
	resp, err := m.client.Do(req)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = tmp.Close()
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, gz); err != nil {
		_ = gz.Close()
		_ = tmp.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	reader, err := maxminddb.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("downloaded database did not validate: %w", err)
	}
	if err := reader.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	if err := m.reload(def.ID); err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Info("geoip database updated", "database", def.ID, "path", target)
	}
	return nil
}

func (m *Manager) setLastError(id string, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if state := m.databases[id]; state != nil {
		if err == nil {
			state.lastError = ""
		} else {
			state.lastError = err.Error()
		}
	}
}

func (m *Manager) statusLocked(now time.Time) []DatabaseStatus {
	out := make([]DatabaseStatus, 0, len(databaseDefinitions))
	for _, id := range orderedDatabaseIDs() {
		state := m.databases[id]
		if state == nil {
			continue
		}
		status := DatabaseStatus{
			ID:          state.def.ID,
			Name:        state.def.Name,
			Path:        state.path,
			SourceURL:   state.def.SourceURL,
			SourceRepo:  state.def.SourceRepo,
			License:     state.def.License,
			Attribution: state.def.Attribution,
			Cadence:     state.def.Cadence,
			Present:     state.size > 0 || fileExists(state.path),
			Loaded:      state.reader != nil,
			SizeBytes:   state.size,
			Size:        formatBytes(state.size),
			UpdateDue:   databaseUpdateDue(state, now),
			SHA256:      state.sha256,
			LastError:   state.lastError,
		}
		if !state.fileTime.IsZero() {
			status.FileTime = state.fileTime.UTC().Format(time.RFC3339)
			status.NextUpdate = nextUpdateAfter(state.def, state.fileTime).Format(time.RFC3339)
		}
		if !state.buildTime.IsZero() {
			status.BuildTime = state.buildTime.UTC().Format(time.RFC3339)
		}
		if state.reader != nil {
			status.DatabaseType = state.reader.Metadata.DatabaseType
			status.IPVersion = state.reader.Metadata.IPVersion
			status.NodeCount = state.reader.Metadata.NodeCount
		}
		out = append(out, status)
	}
	return out
}

func (m *Manager) lookupOrderLocked() []string {
	first := normalizeProvider(m.provider)
	ids := []string{first}
	for _, id := range orderedDatabaseIDs() {
		if id != first {
			ids = append(ids, id)
		}
	}
	return ids
}

func orderedDatabaseIDs() []string {
	return []string{IDDBIPCityLite, IDGeoLite2City}
}

func databaseUpdateDue(state *databaseState, now time.Time) bool {
	if state == nil {
		return false
	}
	if state.reader == nil || state.size <= 0 || state.fileTime.IsZero() {
		return true
	}
	next := nextUpdateAfter(state.def, state.fileTime)
	return !next.IsZero() && !now.UTC().Before(next)
}

func nextUpdateAfter(def DatabaseDefinition, from time.Time) time.Time {
	from = from.UTC()
	switch def.Cadence {
	case "monthly":
		next := time.Date(from.Year(), from.Month(), 1, updateHourUTC, 0, 0, 0, time.UTC)
		if !next.After(from) {
			next = time.Date(from.Year(), from.Month()+1, 1, updateHourUTC, 0, 0, 0, time.UTC)
		}
		return next
	default:
		for day := 0; day <= 8; day++ {
			candidate := time.Date(from.Year(), from.Month(), from.Day()+day, updateHourUTC, 0, 0, 0, time.UTC)
			weekday := candidate.Weekday()
			if (weekday == time.Tuesday || weekday == time.Friday) && candidate.After(from) {
				return candidate
			}
		}
	}
	return time.Time{}
}

func (r cityRecord) location(ip string, def DatabaseDefinition) (Location, bool) {
	country := bestName(r.Country.Names)
	countryCode := strings.TrimSpace(r.Country.ISOCode)
	if country == "" {
		country = bestName(r.RegisteredCountry.Names)
	}
	if countryCode == "" {
		countryCode = strings.TrimSpace(r.RegisteredCountry.ISOCode)
	}

	region := ""
	regionCode := ""
	if len(r.Subdivisions) > 0 {
		region = bestName(r.Subdivisions[0].Names)
		regionCode = strings.TrimSpace(r.Subdivisions[0].ISOCode)
	}

	loc := Location{
		IP:             ip,
		Database:       def.Name,
		DatabaseID:     def.ID,
		City:           bestName(r.City.Names),
		Region:         region,
		RegionCode:     regionCode,
		Country:        country,
		CountryCode:    countryCode,
		Continent:      bestName(r.Continent.Names),
		ContinentCode:  strings.TrimSpace(r.Continent.Code),
		Latitude:       r.Location.Latitude,
		Longitude:      r.Location.Longitude,
		Timezone:       strings.TrimSpace(r.Location.TimeZone),
		PostalCode:     strings.TrimSpace(r.Postal.Code),
		AccuracyRadius: r.Location.AccuracyRadius,
		Attribution:    def.Attribution,
	}
	if loc.City == "" && loc.Country == "" && loc.CountryCode == "" && loc.Continent == "" && loc.Latitude == 0 && loc.Longitude == 0 {
		return Location{}, false
	}
	return loc, true
}

func bestName(names map[string]string) string {
	if len(names) == 0 {
		return ""
	}
	if value := strings.TrimSpace(names["en"]); value != "" {
		return value
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if value := strings.TrimSpace(names[key]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeProvider(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	switch value {
	case "", "auto", "dbip", "db-ip", "dbip-city", "dbip-city-lite":
		return IDDBIPCityLite
	case "geolite", "geolite2", "geolite2-city", "maxmind", "maxmind-geolite2":
		return IDGeoLite2City
	default:
		return defaultProvider
	}
}

func parseIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return net.ParseIP(strings.Trim(value, "[]"))
}

func isLookupableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writeGzipDatabase(data []byte, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tmp, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.seed")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, gz); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	reader, err := maxminddb.Open(tmpPath)
	if err != nil {
		return err
	}
	if err := reader.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func unixBuildTime(epoch uint) time.Time {
	if epoch == 0 {
		return time.Time{}
	}
	return time.Unix(int64(epoch), 0).UTC()
}

func formatBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	const unit = 1024
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(n)
	i := 0
	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", value, units[i])
}
