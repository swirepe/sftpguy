package logutil

import (
	"os"
	"sync"
)

// FileWriter appends to a path and can reopen that path after log rotation.
type FileWriter struct {
	path string
	mode os.FileMode

	mu   sync.Mutex
	file *os.File
}

func NewFileWriter(path string, mode os.FileMode) (*FileWriter, error) {
	w := &FileWriter{
		path: path,
		mode: mode,
	}
	if err := w.reopenLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *FileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureCurrentLocked(); err != nil {
		return 0, err
	}

	n, err := w.file.Write(p)
	if err == nil {
		return n, nil
	}

	// Retry once after reopening so a stale descriptor from rotation
	// does not permanently break file logging.
	if reopenErr := w.reopenLocked(); reopenErr != nil {
		return n, err
	}
	return w.file.Write(p)
}

func (w *FileWriter) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.reopenLocked()
}

func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *FileWriter) ensureCurrentLocked() error {
	if w.file == nil {
		return w.reopenLocked()
	}

	currentInfo, err := w.file.Stat()
	if err != nil {
		return w.reopenLocked()
	}

	pathInfo, err := os.Stat(w.path)
	if err == nil {
		if os.SameFile(currentInfo, pathInfo) {
			return nil
		}
		return w.reopenLocked()
	}
	if os.IsNotExist(err) {
		// Keep writing to the old descriptor until rotation recreates the path.
		return nil
	}
	return err
}

func (w *FileWriter) reopenLocked() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, w.mode)
	if err != nil {
		return err
	}
	oldFile := w.file
	w.file = f
	if oldFile != nil {
		_ = oldFile.Close()
	}
	return nil
}
