package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestNextShutdownSignalIgnoresSIGHUPAndReopensLogs(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logFile := &stubReopenableLogFile{}

	sigChan := make(chan os.Signal, 2)
	sigChan <- syscall.SIGHUP
	sigChan <- syscall.SIGTERM

	got := nextShutdownSignal(sigChan, logger, logFile)
	if got != syscall.SIGTERM {
		t.Fatalf("nextShutdownSignal() = %v, want %v", got, syscall.SIGTERM)
	}
	if logFile.reopenCalls != 1 {
		t.Fatalf("reopenCalls = %d, want %d", logFile.reopenCalls, 1)
	}
	if !strings.Contains(logBuf.String(), "reopened log file") {
		t.Fatalf("expected reopen log message, got %q", logBuf.String())
	}
}

func TestReopenLogFileLogsFailures(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logFile := &stubReopenableLogFile{reopenErr: errors.New("boom")}

	reopenLogFile(logger, logFile, syscall.SIGHUP)

	if logFile.reopenCalls != 1 {
		t.Fatalf("reopenCalls = %d, want %d", logFile.reopenCalls, 1)
	}
	if !strings.Contains(logBuf.String(), "failed to reopen log file") {
		t.Fatalf("expected reopen failure log message, got %q", logBuf.String())
	}
}

type stubReopenableLogFile struct {
	reopenCalls int
	reopenErr   error
}

func (s *stubReopenableLogFile) Reopen() error {
	s.reopenCalls++
	return s.reopenErr
}

func (s *stubReopenableLogFile) Close() error {
	return nil
}
