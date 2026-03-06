//go:build !linux

package main

import "log/slog"

func (cfg Config) getSyslogHandler() (slog.Handler, error) {
	return nil, nil
}
