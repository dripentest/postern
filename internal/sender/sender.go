package sender

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxBody = 4 << 20

type Options struct {
	DialAddr   string
	TLS        bool
	Proxy      string
	TargetHost string
	Method     string
	SNI        string
	Insecure   bool
	Timeout    time.Duration
	Retries    int
}

type Result struct {
	Status   int
	BodyLen  int
	Body     []byte
	Header   http.Header
	Err      error
	Duration time.Duration
}

func Send(opts Options, reqBytes []byte) Result {
	res := sendOnce(opts, reqBytes)
	for attempt := 0; res.Err != nil && attempt < opts.Retries; attempt++ {
		time.Sleep(150 * time.Millisecond)
		res = sendOnce(opts, reqBytes)
	}
	return res
}

func sendOnce(opts Options, reqBytes []byte) Result {
	start := time.Now()
	res := Result{}
	fail := func(err error) Result {
		res.Err = err
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
			return fail(fmt.Errorf("dial proxy: %w", err))
		}
		if opts.TLS {
			if err := connectTunnel(conn, opts.TargetHost, opts.Timeout); err != nil {
				conn.Close()
				return fail(err)
			}
		} else {
			useAbsoluteForm = true
		}
	} else {
		conn, err = d.Dial("tcp", opts.DialAddr)
		if err != nil {
			return fail(fmt.Errorf("dial: %w", err))
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	if opts.TLS {
		tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: opts.Insecure, ServerName: opts.SNI})
		if err := tconn.Handshake(); err != nil {
			return fail(fmt.Errorf("tls handshake: %w", err))
		}
		conn = tconn
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	}

	out := reqBytes
	if useAbsoluteForm {
		out = toAbsoluteForm(reqBytes, opts.TargetHost)
	}
	if _, err := conn.Write(out); err != nil {
		return fail(fmt.Errorf("write: %w", err))
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: opts.Method})
	if err != nil {
		return fail(fmt.Errorf("read response: %w", err))
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
