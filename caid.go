package main

import (
	"database/sql"
)

func closeDB(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return db.Close()
}

func (s *Store) MatchBadFile(absPath string) (string, bool, error) {
	if s == nil {
		return "", false, nil
	}
	if s.caidMatcher != nil {
		match, matched, err := s.caidMatcher.MatchFile(absPath)
		if err != nil {
			return "", false, err
		}
		if matched {
			return match.FormatLabel(), true, nil
		}
	}
	if s.badFileList != nil {
		return s.badFileList.MatchFile(absPath)
	}
	return "", false, nil
}
