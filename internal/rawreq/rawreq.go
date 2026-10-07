package rawreq

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strconv"
	"strings"
)

const Marker = "FUZZ"

type Header struct {
	Name  string
	Value string
}

type Request struct {
	Method  string
	Target  string
	Proto   string
	Headers []Header
	Body    []byte
	Host    string
	TLS     bool
}

func Parse(raw []byte) (*Request, error) {
	var head, body []byte
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		head, body = raw[:idx], raw[idx+4:]
	} else if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		head, body = raw[:idx], raw[idx+2:]
	} else {
		head, body = raw, nil
	}

	lines := splitLines(head)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("empty request")
	}
	parts := strings.SplitN(strings.TrimSpace(lines[0]), " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line: %q", lines[0])
	}
	r := &Request{Method: parts[0], Target: parts[1], Proto: parts[2]}
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		ci := strings.IndexByte(ln, ':')
		if ci < 0 {
			continue
		}
		r.Headers = append(r.Headers, Header{Name: ln[:ci], Value: strings.TrimLeft(ln[ci+1:], " ")})
	}
	r.Body = body
	r.Host = r.HeaderValue("Host")
	return r, nil
}

func splitLines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

func (r *Request) Bytes() []byte {
	var sb bytes.Buffer
	sb.WriteString(r.Method + " " + r.Target + " " + r.Proto + "\r\n")
	for _, h := range r.Headers {
		sb.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	sb.WriteString("\r\n")
	sb.Write(r.Body)
	return sb.Bytes()
}

func (r *Request) Clone() *Request {
	c := &Request{Method: r.Method, Target: r.Target, Proto: r.Proto, Host: r.Host, TLS: r.TLS}
	c.Headers = make([]Header, len(r.Headers))
	copy(c.Headers, r.Headers)
	c.Body = append([]byte(nil), r.Body...)
	return c
}

func (r *Request) HeaderValue(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func (r *Request) UpsertHeader(name, val string) {
	for i := range r.Headers {
		if strings.EqualFold(r.Headers[i].Name, name) {
			r.Headers[i].Value = val
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: val})
}

func (r *Request) SetBody(b []byte) {
	r.Body = b
	for i := range r.Headers {
		if strings.EqualFold(r.Headers[i].Name, "Content-Length") {
			r.Headers[i].Value = strconv.Itoa(len(b))
			return
		}
	}
	if len(b) > 0 {
		r.Headers = append(r.Headers, Header{Name: "Content-Length", Value: strconv.Itoa(len(b))})
	}
}

func (r *Request) HasMarker() bool {
	if strings.Contains(r.Target, Marker) {
		return true
	}
	for _, h := range r.Headers {
		if strings.Contains(h.Value, Marker) {
			return true
		}
	}
	return bytes.Contains(r.Body, []byte(Marker))
}

func (r *Request) HasParam(name string) bool {
	_, err := r.InjectParam(name, "probe")
	return err == nil
}

type Param struct {
	Name  string
	Loc   string
	Value string
}

func (r *Request) DiscoverParams() []Param {
	var out []Param
	seen := map[string]bool{}
	add := func(name, loc, val string) {
		if name == "" || seen[loc+":"+name] {
			return
		}
		seen[loc+":"+name] = true
		out = append(out, Param{Name: name, Loc: loc, Value: val})
	}

	if i := strings.IndexByte(r.Target, '?'); i >= 0 {
		for _, kv := range strings.Split(r.Target[i+1:], "&") {
			if kv == "" {
				continue
			}
			p := strings.SplitN(kv, "=", 2)
			v := ""
			if len(p) > 1 {
				v, _ = url.QueryUnescape(p[1])
			}
			add(p[0], "query", v)
		}
	}

	ct := strings.ToLower(r.HeaderValue("Content-Type"))
	body := string(r.Body)

	if strings.Contains(ct, "x-www-form-urlencoded") || looksForm(body) {
		for _, kv := range strings.Split(body, "&") {
			if kv == "" {
				continue
			}
			p := strings.SplitN(kv, "=", 2)
			v := ""
			if len(p) > 1 {
				v, _ = url.QueryUnescape(p[1])
			}
			add(p[0], "form", v)
		}
	}

	if strings.Contains(ct, "json") || looksJSON(body) {
		var val interface{}
		if json.Unmarshal(r.Body, &val) == nil {
			var walk func(x interface{})
			walk = func(x interface{}) {
				switch t := x.(type) {
				case map[string]interface{}:
					for k, v := range t {
						switch vv := v.(type) {
						case string:
							add(k, "json", vv)
						case float64:
							add(k, "json", fmt.Sprint(vv))
						case bool:
							add(k, "json", fmt.Sprint(vv))
						default:
							walk(v)
						}
					}
				case []interface{}:
					for _, e := range t {
						walk(e)
					}
				}
			}
			walk(val)
		}
	}

	if strings.Contains(ct, "multipart/form-data") {
		if _, params, err := mime.ParseMediaType(r.HeaderValue("Content-Type")); err == nil {
			mr := multipart.NewReader(bytes.NewReader(r.Body), params["boundary"])
			for {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				content, _ := io.ReadAll(part)
				add(part.FormName(), "multipart", string(content))
				part.Close()
			}
		}
	}

	return out
}

func (r *Request) InjectParam(name, payload string) (*Request, error) {
	if i := strings.IndexByte(r.Target, '?'); i >= 0 {
		path, rawq := r.Target[:i], r.Target[i+1:]
		if nq, ok := replaceFormParam(rawq, name, payload); ok {
			c := r.Clone()
			c.Target = path + "?" + nq
			return c, nil
		}
	}
	ct := strings.ToLower(r.HeaderValue("Content-Type"))
	body := string(r.Body)

	if strings.Contains(ct, "x-www-form-urlencoded") || looksForm(body) {
		if nb, ok := replaceFormParam(body, name, payload); ok {
			c := r.Clone()
			c.SetBody([]byte(nb))
			return c, nil
		}
	}
	if strings.Contains(ct, "json") || looksJSON(body) {
		if nb, ok := replaceJSONString(body, name, payload); ok {
			c := r.Clone()
			c.SetBody([]byte(nb))
			return c, nil
		}
	}
	if strings.Contains(ct, "multipart/form-data") {
		if nb, ok := replaceMultipart(r.Body, r.HeaderValue("Content-Type"), name, payload); ok {
			c := r.Clone()
			c.SetBody(nb)
			return c, nil
		}
	}
	return nil, fmt.Errorf("parameter %q not found in query/form/json/multipart body", name)
}

func (r *Request) InjectMarker(payload string) *Request {
	c := r.Clone()
	if strings.Contains(c.Target, Marker) {
		c.Target = strings.ReplaceAll(c.Target, Marker, url.QueryEscape(payload))
	}
	safe := strings.NewReplacer("\r", "", "\n", "").Replace(payload)
	for i := range c.Headers {
		if strings.Contains(c.Headers[i].Value, Marker) {
			c.Headers[i].Value = strings.ReplaceAll(c.Headers[i].Value, Marker, safe)
		}
	}
	if bytes.Contains(c.Body, []byte(Marker)) {
		ct := strings.ToLower(r.HeaderValue("Content-Type"))
		var enc string
		switch {
		case strings.Contains(ct, "json") || looksJSON(string(c.Body)):
			enc = jsonEscape(payload)
		case strings.Contains(ct, "form") || looksForm(string(c.Body)):
			enc = url.QueryEscape(payload)
		default:
			enc = payload
		}
		c.SetBody(bytes.ReplaceAll(c.Body, []byte(Marker), []byte(enc)))
	}
	return c
}

func (r *Request) WithHostReplaced(val string) *Request {
	c := r.Clone()
	c.UpsertHeader("Host", val)
	return c
}

func (r *Request) WithDupHost(val string) *Request {
	c := r.Clone()
	c.Headers = append(c.Headers, Header{Name: "Host", Value: val})
	return c
}

func (r *Request) WithAddedHeader(name, val string) *Request {
	c := r.Clone()
	c.Headers = append(c.Headers, Header{Name: name, Value: val})
	return c
}

func replaceFormParam(raw, name, payload string) (string, bool) {
	parts := strings.Split(raw, "&")
	found := false
	for i, p := range parts {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if kv[0] == name {
			parts[i] = name + "=" + url.QueryEscape(payload)
			found = true
		}
	}
	return strings.Join(parts, "&"), found
}

func replaceJSONString(body, name, payload string) (string, bool) {
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return body, false
	}
	found := false
	var walk func(x interface{})
	walk = func(x interface{}) {
		switch t := x.(type) {
		case map[string]interface{}:
			for k := range t {
				if k == name {
					t[k] = payload
					found = true
				} else {
					walk(t[k])
				}
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	if !found {
		return body, false
	}
	nb, err := json.Marshal(v)
	if err != nil {
		return body, false
	}
	return string(nb), true
}

func replaceMultipart(body []byte, ct, name, payload string) ([]byte, bool) {
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, false
	}
	found := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		content, _ := io.ReadAll(part)
		pw, err := w.CreatePart(part.Header)
		if err != nil {
			return nil, false
		}
		if part.FormName() == name {
			pw.Write([]byte(payload))
			found = true
		} else {
			pw.Write(content)
		}
		part.Close()
	}
	if err := w.Close(); err != nil {
		return nil, false
	}
	if !found {
		return nil, false
	}
	return buf.Bytes(), true
}

func looksForm(b string) bool {
	t := strings.TrimSpace(b)
	return t != "" && strings.Contains(t, "=") && !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[")
}

func looksJSON(b string) bool {
	t := strings.TrimSpace(b)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return s
}
