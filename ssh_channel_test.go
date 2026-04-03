package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type stubSSHChannel struct {
	closed bool
	stderr bytes.Buffer
}

func (c *stubSSHChannel) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *stubSSHChannel) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *stubSSHChannel) Close() error {
	c.closed = true
	return nil
}

func (c *stubSSHChannel) CloseWrite() error {
	return nil
}

func (c *stubSSHChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
	return false, nil
}

func (c *stubSSHChannel) Stderr() io.ReadWriter {
	return &c.stderr
}

type stubNewChannel struct {
	channelType   string
	acceptChannel ssh.Channel
	acceptReqs    <-chan *ssh.Request
	acceptErr     error
	rejectErr     error
	acceptCalls   int
	rejected      bool
	rejectReason  ssh.RejectionReason
	rejectMessage string
}

func (c *stubNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	c.acceptCalls++
	return c.acceptChannel, c.acceptReqs, c.acceptErr
}

func (c *stubNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	c.rejected = true
	c.rejectReason = reason
	c.rejectMessage = message
	return c.rejectErr
}

func (c *stubNewChannel) ChannelType() string {
	return c.channelType
}

func (c *stubNewChannel) ExtraData() []byte {
	return nil
}

func newChannelTestLogger(dst io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(dst, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestAcceptSessionChannelRejectsUnknownChannelType(t *testing.T) {
	newCh := &stubNewChannel{channelType: "direct-tcpip"}

	ch, reqs, ok := acceptSessionChannel(newCh, newChannelTestLogger(io.Discard))
	if ok {
		t.Fatal("expected unsupported channel type to be skipped")
	}
	if ch != nil || reqs != nil {
		t.Fatal("expected no accepted channel values for unsupported channel type")
	}
	if !newCh.rejected {
		t.Fatal("expected unsupported channel type to be rejected")
	}
	if newCh.rejectReason != ssh.UnknownChannelType {
		t.Fatalf("unexpected rejection reason: got=%v want=%v", newCh.rejectReason, ssh.UnknownChannelType)
	}
	if newCh.rejectMessage != "unknown channel type" {
		t.Fatalf("unexpected rejection message: got=%q", newCh.rejectMessage)
	}
	if newCh.acceptCalls != 0 {
		t.Fatalf("expected Accept not to be called, got %d call(s)", newCh.acceptCalls)
	}
}

func TestAcceptSessionChannelSkipsFailedAccept(t *testing.T) {
	var logBuf bytes.Buffer
	newCh := &stubNewChannel{
		channelType: "session",
		acceptErr:   errors.New("boom"),
	}

	ch, reqs, ok := acceptSessionChannel(newCh, newChannelTestLogger(&logBuf))
	if ok {
		t.Fatal("expected failed Accept to be skipped")
	}
	if ch != nil || reqs != nil {
		t.Fatal("expected no accepted channel values after Accept failure")
	}
	if newCh.acceptCalls != 1 {
		t.Fatalf("expected one Accept call, got %d", newCh.acceptCalls)
	}
	if !strings.Contains(logBuf.String(), "failed to accept session channel") {
		t.Fatalf("expected accept failure to be logged, got %q", logBuf.String())
	}
}

func TestHandleChannelReturnsWhenChannelIsNil(t *testing.T) {
	var logBuf bytes.Buffer
	logger := newChannelTestLogger(&logBuf)
	srv := &Server{logger: logger}

	srv.handleChannel(nil, nil, "hash", "session", userStats{}, nil, logger, false, false, &sessionCounters{})

	if !strings.Contains(logBuf.String(), "handleChannel called without ssh channel") {
		t.Fatalf("expected nil channel warning, got %q", logBuf.String())
	}
}

func TestHandleChannelRejectsMalformedSubsystemRequest(t *testing.T) {
	var logBuf bytes.Buffer
	logger := newChannelTestLogger(&logBuf)
	srv := &Server{logger: logger}
	ch := &stubSSHChannel{}
	reqs := make(chan *ssh.Request, 1)
	reqs <- &ssh.Request{Type: "subsystem", Payload: []byte{0x01, 0x02}, WantReply: false}
	close(reqs)

	srv.handleChannel(ch, reqs, "hash", "session", userStats{}, nil, logger, false, false, &sessionCounters{})

	if !ch.closed {
		t.Fatal("expected channel to be closed when handleChannel returns")
	}
	if !strings.Contains(logBuf.String(), "malformed subsystem request") {
		t.Fatalf("expected malformed subsystem warning, got %q", logBuf.String())
	}
}
