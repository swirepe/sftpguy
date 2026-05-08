package explorerevents

import (
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultQueueSize = 256
	defaultTimeout   = 750 * time.Millisecond
)

type Client struct {
	path    string
	logger  *slog.Logger
	timeout time.Duration
	queue   chan Event
	done    chan struct{}
	once    sync.Once
}

func NewClient(path string, logger *slog.Logger) *Client {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	c := &Client{
		path:    path,
		logger:  logger,
		timeout: defaultTimeout,
		queue:   make(chan Event, defaultQueueSize),
		done:    make(chan struct{}),
	}
	go c.run()
	return c
}

func (c *Client) Emit(evt Event) {
	if c == nil {
		return
	}
	if evt.Version == 0 {
		evt.Version = Version
	}
	if evt.Timestamp == 0 {
		evt.Timestamp = time.Now().Unix()
	}
	select {
	case c.queue <- evt:
	default:
		if c.logger != nil {
			c.logger.Warn("dropping explorer event; queue full", "kind", evt.Kind, "path", evt.Path)
		}
	}
}

func (c *Client) Close(timeout time.Duration) {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.queue)
	})
	if timeout <= 0 {
		timeout = time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
		if c.logger != nil {
			c.logger.Warn("timed out flushing explorer events", "socket", c.path)
		}
	}
}

func (c *Client) run() {
	defer close(c.done)
	for evt := range c.queue {
		if err := c.send(evt); err != nil && c.logger != nil {
			c.logger.Debug("failed to send explorer event", "socket", c.path, "kind", evt.Kind, "err", err)
		}
	}
}

func (c *Client) send(evt Event) error {
	conn, err := net.DialTimeout("unix", c.path, c.timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	return json.NewEncoder(conn).Encode(evt)
}
