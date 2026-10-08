package oob

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

type Hit struct {
	Label    string
	Protocol string
	Remote   string
	Time     time.Time
}

type Client struct {
	c      *client.Client
	mu     sync.Mutex
	m      map[string]string
	hits   []Hit
	nHits  int64
	sample string
	onHit  func(Hit)
}

const defaultServers = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"

func NewClient(serverURL, token string, onHit func(Hit)) (*Client, error) {
	if serverURL == "" {
		serverURL = defaultServers
	}
	ic, err := client.New(&client.Options{
		ServerURL:         serverURL,
		Token:             token,
		KeepAliveInterval: time.Minute,
	})
	if err != nil {
		return nil, err
	}
	cl := &Client{c: ic, m: map[string]string{}, onHit: onHit}
	cl.sample = ic.URL()
	if err := ic.StartPolling(5*time.Second, cl.handle); err != nil {
		ic.Close()
		return nil, err
	}
	return cl, nil
}

func (c *Client) Enabled() bool { return c != nil && c.c != nil }

func (c *Client) Alloc() string { return c.c.URL() }

func (c *Client) Record(host, label string) {
	key := strings.ToLower(firstLabel(host))
	if key == "" {
		return
	}
	c.mu.Lock()
	c.m[key] = label
	c.mu.Unlock()
}

func (c *Client) handle(i *server.Interaction) {
	key := strings.ToLower(i.UniqueID)
	c.mu.Lock()
	label := c.m[key]
	c.mu.Unlock()
	if label == "" {
		label = "(unmapped) " + i.FullId
	}
	h := Hit{Label: label, Protocol: i.Protocol, Remote: i.RemoteAddress, Time: i.Timestamp}
	c.mu.Lock()
	c.hits = append(c.hits, h)
	c.mu.Unlock()
	atomic.AddInt64(&c.nHits, 1)
	if c.onHit != nil {
		c.onHit(h)
	}
}

func (c *Client) Domain() string {
	if i := strings.IndexByte(c.sample, '.'); i >= 0 {
		return c.sample[i+1:]
	}
	return c.sample
}

func (c *Client) Count() int64 { return atomic.LoadInt64(&c.nHits) }

func (c *Client) Hits() []Hit {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Hit, len(c.hits))
	copy(out, c.hits)
	return out
}

func (c *Client) Close() {
	if c == nil || c.c == nil {
		return
	}
	c.c.StopPolling()
	c.c.Close()
}

func firstLabel(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[:i]
	}
	return host
}
