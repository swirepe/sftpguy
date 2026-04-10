package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const caidMinimumSizeBytes int64 = 1024

type CAIDMatcher struct {
	db      *sql.DB
	hasSize *sql.Stmt
	exact   *sql.Stmt
}

func NewCAIDMatcher(dbPath string) (*CAIDMatcher, error) {
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
	if err := hasSize.QueryRow(caidMinimumSizeBytes + 1).Scan(&ignored); err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = exact.Close()
		_ = hasSize.Close()
		_ = db.Close()
		return nil, err
	}

	return &CAIDMatcher{
		db:      db,
		hasSize: hasSize,
		exact:   exact,
	}, nil
}

func (m *CAIDMatcher) Count() (count int) {
	_ = m.db.
		QueryRow("SELECT COUNT(*) FROM caid_hashes WHERE size > ?", caidMinimumSizeBytes).
		Scan(&count)
	return
}

func (m *CAIDMatcher) MatchFile(absPath string) (string, bool, error) {
	if m == nil {
		return "", false, nil
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= caidMinimumSizeBytes {
		return "", false, nil
	}

	var ignored int
	err = m.hasSize.QueryRow(info.Size()).Scan(&ignored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	}

	md5Hex, sha1Hex, err := hashFileMD5SHA1(absPath)
	if err != nil {
		return "", false, err
	}

	var fileType string
	var category int
	err = m.exact.QueryRow(info.Size(), md5Hex, sha1Hex).Scan(&fileType, &category)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	default:
		return formatCAIDMatchLabel(fileType, category, sha1Hex), true, nil
	}
}

func (m *CAIDMatcher) Close() error {
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

func formatCAIDMatchLabel(fileType string, category int, sha1Hex string) string {
	fileType = strings.TrimSpace(fileType)
	switch {
	case fileType != "" && category != 0:
		return fmt.Sprintf("caid:%s (category %d):sha1-%s", fileType, category, sha1Hex)
	case fileType != "":
		return fmt.Sprintf("caid:%s:sha1-%s", fileType, sha1Hex)
	case category != 0:
		return fmt.Sprintf("caid:category %d:sha1-%s", category, sha1Hex)
	default:
		return fmt.Sprintf("caid:%s", sha1Hex)
	}
}

func hashFileMD5SHA1(absPath string) (string, string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()

	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1), f); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(hMD5.Sum(nil)), hex.EncodeToString(hSHA1.Sum(nil)), nil
}

func (s *Store) MatchBadFile(absPath string) (string, bool, error) {
	if s == nil {
		return "", false, nil
	}
	if s.caidMatcher != nil {
		name, matched, err := s.caidMatcher.MatchFile(absPath)
		if err != nil {
			return "", false, err
		}
		if matched {
			return name, true, nil
		}
	}
	if s.badFileList != nil {
		return s.badFileList.MatchFile(absPath)
	}
	return "", false, nil
}
