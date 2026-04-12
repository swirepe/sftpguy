package caid

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

const MinimumSizeBytes int64 = 1024

type Matcher struct {
	db      *sql.DB
	hasSize *sql.Stmt
	exact   *sql.Stmt
}

func NewMatcher(dbPath string) (*Matcher, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("empty CAID database path")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("stat CAID database: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)

	hasSize, err := db.Prepare(`SELECT 1 FROM caid_hashes WHERE size = ? LIMIT 1`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	exact, err := db.Prepare(`
		SELECT filetype, category
		FROM caid_hashes
		WHERE size = ? AND md5 = ? COLLATE NOCASE AND sha1 = ? COLLATE NOCASE
		LIMIT 1
	`)
	if err != nil {
		_ = hasSize.Close()
		_ = db.Close()
		return nil, err
	}

	var ignored int
	if err := hasSize.QueryRow(MinimumSizeBytes + 1).Scan(&ignored); err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = exact.Close()
		_ = hasSize.Close()
		_ = db.Close()
		return nil, err
	}

	return &Matcher{
		db:      db,
		hasSize: hasSize,
		exact:   exact,
	}, nil
}

func (m *Matcher) Count() (count int) {
	_ = m.db.
		QueryRow("SELECT COUNT(*) FROM caid_hashes WHERE size > ?", MinimumSizeBytes).
		Scan(&count)
	return
}

type Match struct {
	Info      os.FileInfo
	Size      int64
	IsAllZero bool
	Md5Hex    string
	Sha1Hex   string
	FileType  string
	Category  int
}

func (m *Matcher) MatchFile(absPath string) (Match, bool, error) {
	if m == nil {
		return Match{}, false, nil
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return Match{}, false, err
	}
	match := Match{
		Info: info,
		Size: info.Size(),
	}
	if !info.Mode().IsRegular() || info.Size() <= MinimumSizeBytes {
		return match, false, nil
	}

	var ignored int
	err = m.hasSize.QueryRow(info.Size()).Scan(&ignored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return match, false, nil
	case err != nil:
		return match, false, err
	}

	sums, err := sumFile(absPath)
	if err != nil {
		return match, false, err
	}
	match.Md5Hex = sums.Md5Hex
	match.Sha1Hex = sums.Sha1Hex
	match.IsAllZero = sums.IsAllZero

	err = m.exact.QueryRow(info.Size(), match.Md5Hex, match.Sha1Hex).Scan(&match.FileType, &match.Category)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return match, false, nil
	case err != nil:
		return match, false, err
	default:
		return match, true, nil
	}
}

func (m *Matcher) Close() error {
	if m == nil {
		return nil
	}
	return errors.Join(
		closeStmt(m.exact),
		closeStmt(m.hasSize),
		closeDB(m.db),
	)
}

func closeStmt(stmt *sql.Stmt) error {
	if stmt == nil {
		return nil
	}
	return stmt.Close()
}

func closeDB(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return db.Close()
}

func (m Match) FormatLabel() string {
	fileType := strings.TrimSpace(m.FileType)
	sha1Hex := strings.TrimSpace(m.Sha1Hex)
	switch {
	case fileType != "" && m.Category != 0 && sha1Hex != "":
		return fmt.Sprintf("caid:%s (category %d):sha1-%s", fileType, m.Category, sha1Hex)
	case fileType != "" && sha1Hex != "":
		return fmt.Sprintf("caid:%s:sha1-%s", fileType, sha1Hex)
	case m.Category != 0 && sha1Hex != "":
		return fmt.Sprintf("caid:category %d:sha1-%s", m.Category, sha1Hex)
	case sha1Hex != "":
		return fmt.Sprintf("caid:%s", sha1Hex)
	case fileType != "" && m.Category != 0:
		return fmt.Sprintf("caid:%s (category %d)", fileType, m.Category)
	case fileType != "":
		return fmt.Sprintf("caid:%s", fileType)
	case m.Category != 0:
		return fmt.Sprintf("caid:category %d", m.Category)
	default:
		return "caid"
	}
}

type Sums struct {
	Md5Hex    string
	Sha1Hex   string
	Sha256Hex string
	IsAllZero bool
}

func sumFile(absPath string) (Sums, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return Sums{}, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	allZero := zeroDetector{isAllZero: true}

	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256, &allZero), f); err != nil {
		return Sums{}, err
	}

	return Sums{
		Md5Hex:    hex.EncodeToString(hMD5.Sum(nil)),
		Sha1Hex:   hex.EncodeToString(hSHA1.Sum(nil)),
		Sha256Hex: hex.EncodeToString(hSHA256.Sum(nil)),
		IsAllZero: allZero.isAllZero,
	}, nil
}

func hashFileMD5SHA1(absPath string) (string, string, error) {
	sums, err := sumFile(absPath)
	if err != nil {
		return "", "", err
	}
	return sums.Md5Hex, sums.Sha1Hex, nil
}

type zeroDetector struct {
	isAllZero bool
}

func (z *zeroDetector) Write(p []byte) (int, error) {
	if !z.isAllZero {
		return len(p), nil
	}
	for _, b := range p {
		if b != 0 {
			z.isAllZero = false
			break
		}
	}
	return len(p), nil
}
