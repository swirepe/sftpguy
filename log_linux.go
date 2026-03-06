//go:build linux

package main

import (
	"log/slog"
	"log/syslog"
)

func (cfg Config) getSyslogHandler() (slog.Handler, error) {
	if !cfg.Syslog {
		return nil, nil
	}

	// Connect to the local syslog server
	// We use LOG_DAEMON as the facility since this is a background server
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, cfg.Name)
	if err != nil {
		return nil, err
	}

	// Use JSONHandler so syslog captures structured data,
	// or TextHandler if you want it to look like traditional logs.
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}), nil
}
