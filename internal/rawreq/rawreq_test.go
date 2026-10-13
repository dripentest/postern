package rawreq

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func mkReq(ct, body string) []byte {
	head := "POST /f HTTP/1.1\r\nHost: target\r\nConnection: close\r\n"
	if ct != "" {
		head += "Content-Type: " + ct + "\r\n"
	}
	head += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	return []byte(head + body)
}

func bodyOf(b []byte) string {
	if i := strings.Index(string(b), "\r\n\r\n"); i >= 0 {
		return string(b[i+4:])
	}
	return ""
}

func TestDiscoverParamsContexts(t *testing.T) {
	cases := []struct {
		name, ct, body, wantName, wantLoc string
	}{
		{"form", "application/x-www-form-urlencoded", "url=x", "url", "form"},
		{"json", "application/json", `{"url":"x"}`, "url", "json"},
		{"json-nested", "application/json", `{"meta":{"url":"x"}}`, "url", "json"},
		{"json-array", "application/json", `{"urls":["x"]}`, "urls", "json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse(mkReq(c.ct, c.body))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, p := range r.DiscoverParams() {
				if p.Name == c.wantName && p.Loc == c.wantLoc {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: param %q (%s) not discovered in %v", c.name, c.wantName, c.wantLoc, r.DiscoverParams())
			}
		})
	}
}

func TestInjectRecalculatesContentLength(t *testing.T) {
	r, err := Parse(mkReq("application/x-www-form-urlencoded", "url=x"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.InjectParam("url", "http://169.254.169.254/latest/")
	if err != nil {
		t.Fatal(err)
	}
	b := out.Bytes()
	body := bodyOf(b)
	// Content-Length header must match the actual body length after injection.
	var cl int
	for _, line := range strings.Split(string(b), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			cl, _ = strconv.Atoi(strings.TrimSpace(line[len("content-length:"):]))
		}
	}
	if cl != len(body) {
		t.Errorf("Content-Length=%d but body is %d bytes", cl, len(body))
	}
	if !strings.Contains(body, "169.254.169.254") {
		t.Errorf("payload not present in body: %q", body)
	}
}

func TestInjectJSONArrayStaysArray(t *testing.T) {
	r, err := Parse(mkReq("application/json", `{"urls":["x"]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.InjectParam("urls", "http://evil/")
	if err != nil {
		t.Fatalf("array injection failed: %v", err)
	}
	body := bodyOf(out.Bytes())
	if !strings.Contains(body, `["http://evil/"]`) {
		t.Errorf("array not preserved, got %q", body)
	}
}

func TestInjectJSONKeepsStructure(t *testing.T) {
	r, _ := Parse(mkReq("application/json", `{"meta":{"url":"x"},"keep":1}`))
	out, err := r.InjectParam("url", "http://e/")
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(out.Bytes())
	if !strings.Contains(body, `"http://e/"`) || !strings.Contains(body, `"keep":1`) {
		t.Errorf("nested json mangled: %q", body)
	}
}

func TestInjectUnknownParamErrors(t *testing.T) {
	r, _ := Parse(mkReq("application/x-www-form-urlencoded", "url=x"))
	if _, err := r.InjectParam("nope", "p"); err == nil {
		t.Error("expected error for unknown param")
	}
}
