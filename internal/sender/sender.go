package sender

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 4 << 20

type Options struct {
	DialAddr        string
	TLS             bool
	Proxy           string
	TargetHost      string
	Method          string
	SNI             string
	Insecure        bool
	Timeout         time.Duration
	Retries         int
	FollowRedirects int // max 3xx hops to follow (0 = don't follow)
}

type Result struct {
	Status    int
	BodyLen   int
	Body      []byte
	Header    http.Header
	Err       error
	Kind      string // on error: "dial" | "tls" | "write" | "read"
	Duration  time.Duration
	Redirects int // number of 3xx hops followed to reach this response
}

func Send(opts Options, reqBytes []byte) Result {
	start := time.Now()
	res := sendWithRetries(opts, reqBytes)

	// Follow 3xx hops (opt-in): the fuzzed app itself may 30x the client, and the
	// final response - not the redirect - carries the SSRF/rebind outcome.
	hops := 0
	for res.Err == nil && opts.FollowRedirects > 0 && hops < opts.FollowRedirects && isRedirect(res.Status) {
		loc := res.Header.Get("Location")
		if loc == "" {
			break
		}
		nopts, nreq, ok := nextHop(opts, reqBytes, loc, res.Status)
		if !ok {
			break
		}
		opts, reqBytes = nopts, nreq
		res = sendWithRetries(opts, reqBytes)
		hops++
	}
	res.Redirects = hops
	res.Duration = time.Since(start)
	return res
}

func sendWithRetries(opts Options, reqBytes []byte) Result {
	res := sendOnce(opts, reqBytes)
	for attempt := 0; res.Err != nil && attempt < opts.Retries; attempt++ {
		time.Sleep(150 * time.Millisecond)
		res = sendOnce(opts, reqBytes)
	}
	return res
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// nextHop builds the options and raw request for the next redirect hop. Location
// is resolved against the request's own Host header (not the dial target), so an
// injected Host (e.g. "admin.local" while dialing localhost:9090) survives a
// relative redirect - the whole point of a redirect-chain host-header attack. The
// dial target/SNI/TLS are only retargeted when the redirect goes to a genuinely
// different host. 301/302/303 downgrade to GET and drop the body.
func nextHop(opts Options, reqBytes []byte, loc string, status int) (Options, []byte, bool) {
	line, headers, body := splitRequest(reqBytes)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return opts, nil, false
	}
	method, curTarget, proto := parts[0], parts[1], parts[2]

	curHostHdr := ""
	for _, h := range headers {
		if len(h) >= 5 && strings.EqualFold(h[:5], "host:") {
			curHostHdr = strings.TrimSpace(h[5:])
			break
		}
	}
	authority := curHostHdr
	if authority == "" {
		authority = opts.TargetHost
	}

	scheme := "http"
	if opts.TLS {
		scheme = "https"
	}
	cur := &url.URL{Scheme: scheme, Host: authority}
	if u, err := url.Parse(curTarget); err == nil {
		cur.Path, cur.RawQuery = u.Path, u.RawQuery
	}

	locTrim := strings.TrimSpace(loc)
	next, err := cur.Parse(locTrim)
	if err != nil {
		return opts, nil, false
	}
	locParsed, _ := url.Parse(locTrim)
	relative := locParsed == nil || locParsed.Host == ""

	newHostHdr := authority
	if !relative {
		locHost := next.Host
		// Keep dialing the same place when the redirect stays on the host we're
		// already talking to (our injected Host, or the real dial target) - only a
		// redirect to a different host re-points the dial/SNI/TLS.
		sameSite := strings.EqualFold(locHost, curHostHdr) || strings.EqualFold(locHost, opts.TargetHost)
		newHostHdr = locHost
		if !sameSite {
			opts.TLS = next.Scheme == "https"
			host := next.Hostname()
			port := next.Port()
			if port == "" {
				if opts.TLS {
					port = "443"
				} else {
					port = "80"
				}
			}
			opts.SNI = host
			opts.TargetHost = locHost
			if opts.Proxy == "" {
				opts.DialAddr = net.JoinHostPort(host, port)
			}
		}
	}

	// 303 always, and 301/302 by common practice, switch to GET without a body.
	drop := status == 303 || status == 301 || status == 302
	if drop {
		method = "GET"
		body = nil
	}

	target := next.RequestURI()
	var b bytes.Buffer
	b.WriteString(method + " " + target + " " + proto + "\r\n")
	for _, h := range headers {
		lower := strings.ToLower(h)
		if strings.HasPrefix(lower, "host:") {
			continue
		}
		if drop && (strings.HasPrefix(lower, "content-length:") || strings.HasPrefix(lower, "content-type:")) {
			continue
		}
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Host: " + newHostHdr + "\r\n\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return opts, b.Bytes(), true
}

// splitRequest splits a raw HTTP/1.x request into its request line, header lines
// (without CRLF), and body.
func splitRequest(b []byte) (line string, headers []string, body []byte) {
	sep := []byte("\r\n\r\n")
	head := b
	if i := bytes.Index(b, sep); i >= 0 {
		head = b[:i]
		body = b[i+len(sep):]
	}
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 {
		return "", nil, body
	}
	return lines[0], lines[1:], body
}

func sendOnce(opts Options, reqBytes []byte) Result {
	start := time.Now()
	res := Result{}
	fail := func(kind string, err error) Result {
		res.Err = err
		res.Kind = kind
		res.Duration = time.Since(start)
		return res
	}

	d := net.Dialer{Timeout: opts.Timeout}
	var conn net.Conn
	var err error
	useAbsoluteForm := false

	if opts.Proxy != "" {
		conn, err = d.Dial("tcp", opts.Proxy)
		if err != nil {
			return fail("dial", fmt.Errorf("dial proxy: %w", err))
		}
		if opts.TLS {
			if err := connectTunnel(conn, opts.TargetHost, opts.Timeout); err != nil {
				conn.Close()
				return fail("dial", err)
			}
		} else {
			useAbsoluteForm = true
		}
	} else {
		conn, err = d.Dial("tcp", opts.DialAddr)
		if err != nil {
			return fail("dial", fmt.Errorf("dial: %w", err))
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	if opts.TLS {
		tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: opts.Insecure, ServerName: opts.SNI})
		if err := tconn.Handshake(); err != nil {
			return fail("tls", fmt.Errorf("tls handshake: %w", err))
		}
		conn = tconn
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	}

	out := reqBytes
	if useAbsoluteForm {
		out = toAbsoluteForm(reqBytes, opts.TargetHost)
	}
	if _, err := conn.Write(out); err != nil {
		return fail("write", fmt.Errorf("write: %w", err))
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: opts.Method})
	if err != nil {
		return fail("read", fmt.Errorf("read response: %w", err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	res.Status = resp.StatusCode
	res.Body = body
	res.BodyLen = len(body)
	res.Header = resp.Header
	res.Duration = time.Since(start)
	return res
}

func connectTunnel(conn net.Conn, hostport string, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := "CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("proxy connect write: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return fmt.Errorf("proxy connect read: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("proxy CONNECT -> %s", resp.Status)
	}
	return nil
}

func toAbsoluteForm(reqBytes []byte, hostport string) []byte {
	i := bytes.IndexByte(reqBytes, '\n')
	if i < 0 {
		return reqBytes
	}
	line := strings.TrimRight(string(reqBytes[:i]), "\r")
	rest := reqBytes[i+1:]
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return reqBytes
	}
	method, target, proto := parts[0], parts[1], parts[2]
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return reqBytes
	}
	newLine := method + " http://" + hostport + target + " " + proto + "\r\n"
	return append([]byte(newLine), rest...)
}
