package sender

import (
	"strings"
	"testing"
)

func firstLine(b []byte) string {
	if i := strings.Index(string(b), "\r\n"); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func hostHeader(b []byte) string {
	for _, l := range strings.Split(string(b), "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			return strings.TrimSpace(l[5:])
		}
	}
	return ""
}

func TestNextHopRelativePreservesInjectedHost(t *testing.T) {
	// Dialing localhost:9090 but with an injected Host: admin.local. A relative
	// redirect must keep admin.local (the B6 regression) and keep dialing the
	// same target.
	opts := Options{DialAddr: "localhost:9090", TargetHost: "localhost:9090"}
	req := []byte("GET /redir1 HTTP/1.1\r\nHost: admin.local\r\nConnection: close\r\n\r\n")
	nopts, nreq, ok := nextHop(opts, req, "/redir2", 302)
	if !ok {
		t.Fatal("nextHop returned ok=false")
	}
	if h := hostHeader(nreq); h != "admin.local" {
		t.Errorf("Host = %q, want admin.local", h)
	}
	if fl := firstLine(nreq); fl != "GET /redir2 HTTP/1.1" {
		t.Errorf("request line = %q, want GET /redir2 HTTP/1.1", fl)
	}
	if nopts.DialAddr != "localhost:9090" {
		t.Errorf("DialAddr changed to %q on a relative redirect", nopts.DialAddr)
	}
}

func TestNextHopCrossHostRetargets(t *testing.T) {
	opts := Options{DialAddr: "localhost:9090", TargetHost: "localhost:9090"}
	req := []byte("GET /go HTTP/1.1\r\nHost: localhost:9090\r\nConnection: close\r\n\r\n")
	nopts, nreq, ok := nextHop(opts, req, "http://evil.example:8080/x", 302)
	if !ok {
		t.Fatal("ok=false")
	}
	if nopts.DialAddr != "evil.example:8080" {
		t.Errorf("DialAddr = %q, want evil.example:8080", nopts.DialAddr)
	}
	if h := hostHeader(nreq); h != "evil.example:8080" {
		t.Errorf("Host = %q, want evil.example:8080", h)
	}
}

func TestNextHop303DowngradesToGet(t *testing.T) {
	opts := Options{DialAddr: "h:80", TargetHost: "h:80"}
	req := []byte("POST /a HTTP/1.1\r\nHost: h:80\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
	_, nreq, ok := nextHop(opts, req, "/next", 303)
	if !ok {
		t.Fatal("ok=false")
	}
	if fl := firstLine(nreq); !strings.HasPrefix(fl, "GET /next") {
		t.Errorf("303 should downgrade to GET, got %q", fl)
	}
	if strings.Contains(string(nreq), "body") {
		t.Error("303 must drop the request body")
	}
	if strings.Contains(strings.ToLower(string(nreq)), "content-length:") {
		t.Error("303 to GET must drop Content-Length")
	}
}

func TestNextHop307KeepsMethodAndBody(t *testing.T) {
	opts := Options{DialAddr: "h:80", TargetHost: "h:80"}
	req := []byte("POST /a HTTP/1.1\r\nHost: h:80\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
	_, nreq, ok := nextHop(opts, req, "/next", 307)
	if !ok {
		t.Fatal("ok=false")
	}
	if fl := firstLine(nreq); !strings.HasPrefix(fl, "POST /next") {
		t.Errorf("307 should keep POST, got %q", fl)
	}
	if !strings.HasSuffix(string(nreq), "body") {
		t.Error("307 must preserve the body")
	}
}
