package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadOrCreateAdminHTTPToken(path string) (token string, wrote bool, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, fmt.Errorf("token file path is required")
	}

	if b, readErr := os.ReadFile(path); readErr == nil {
		token = strings.TrimSpace(string(b))
		if token != "" {
			return token, false, nil
		}
	} else if !os.IsNotExist(readErr) {
		return "", false, readErr
	}

	token, err = randomHexSecret(24)
	if err != nil {
		return "", false, err
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, permDir); err != nil {
			return "", false, err
		}
	}
	if err := os.WriteFile(path, []byte(token+"\n"), permHostKey); err != nil {
		return "", false, err
	}
	return token, true, nil
}

func randomHexSecret(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		bytesLen = 24
	}
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
