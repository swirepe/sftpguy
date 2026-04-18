package main

import (
	"log/slog"
	"os"
	"syscall"
)

type reopenableLogFile interface {
	Reopen() error
	Close() error
}

func reopenLogFile(logger *slog.Logger, logFile reopenableLogFile, sig os.Signal) {
	if logFile == nil {
		return
	}

	if err := logFile.Reopen(); err != nil {
		if logger != nil {
			logger.Error("failed to reopen log file", "signal", signalName(sig), "err", err)
		}
		return
	}

	if logger != nil {
		logger.Info("reopened log file", "signal", signalName(sig))
	}
}

func nextShutdownSignal(sigChan <-chan os.Signal, logger *slog.Logger, logFile reopenableLogFile) os.Signal {
	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			reopenLogFile(logger, logFile, sig)
			continue
		}
		return sig
	}
}

func signalName(sig os.Signal) string {
	if sig == nil {
		return "<nil>"
	}
	return sig.String()
}
