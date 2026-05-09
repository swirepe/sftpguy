package explorerevents

import (
	"context"
	"log/slog"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"sync"
	"time"
)

const (
	defaultQueueSize = 256
	defaultTimeout   = 750 * time.Millisecond
	defaultPolicyTTL = 1 * time.Minute // How long to cache IPs
)

type Client struct {
	path    string
	logger  *slog.Logger
	timeout time.Duration
	queue   chan Event
	done    chan struct{}
	once    sync.Once

	policyCache   map[string]ipPolicyCacheEntry
	policyCacheMu sync.RWMutex
	policyTTL     time.Duration
}

type ipPolicyCacheEntry struct {
	response  IPPolicyResponse // Stored by value to prevent pointer mutation
	expiresAt time.Time
}

func NewClient(path string, logger *slog.Logger) *Client {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	c := &Client{
		path:        path,
		logger:      logger,
		timeout:     defaultTimeout,
		queue:       make(chan Event, defaultQueueSize),
		done:        make(chan struct{}),
		policyCache: make(map[string]ipPolicyCacheEntry),
		policyTTL:   defaultPolicyTTL,
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
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	var ack Ack
	return c.call(ctx, "RecordEvent", evt, &ack)
}

func (c *Client) CheckIP(ctx context.Context, ip string) (*IPPolicyResponse, error) {
	if c == nil {
		return nil, net.ErrClosed
	}
	ip = strings.TrimSpace(ip)
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	if ip == "" {
		return nil, net.InvalidAddrError("empty IP")
	}

	c.policyCacheMu.RLock()
	entry, exists := c.policyCache[ip]
	c.policyCacheMu.RUnlock()

	if exists && time.Now().Before(entry.expiresAt) {
		resp := entry.response
		return &resp, nil
	}

	response := &IPPolicyResponse{}
	if err := c.call(ctx, "CheckIP", IPPolicyRequest{IP: ip}, response); err != nil {
		return nil, err
	}

	c.policyCacheMu.Lock()
	defer c.policyCacheMu.Unlock()

	// OOM Protection: If the cache grows too large (e.g. from an IP spoofing attack),
	// dump it entirely. This is a cheap and effective alternative to a complex LRU.
	if len(c.policyCache) > 10000 {
		c.policyCache = make(map[string]ipPolicyCacheEntry)
	}

	c.policyCache[ip] = ipPolicyCacheEntry{
		response:  *response,
		expiresAt: time.Now().Add(c.policyTTL),
	}

	return response, nil
}

func (c *Client) call(ctx context.Context, method string, args any, reply any) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	client := jsonrpc.NewClient(conn)
	defer client.Close()

	if err := client.Call(RPCServiceName+"."+method, args, reply); err != nil {
		if err == rpc.ErrShutdown {
			return net.ErrClosed
		}
		return err
	}
	return nil
}
