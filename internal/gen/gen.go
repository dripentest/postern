package gen

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Params struct {
	LHOST     string
	TARGET    string
	EVIL      string
	HOST      string
	Sweep     []string
	ScanHosts []string
	Ports     []int
}

type OOB interface {
	Enabled() bool
	Sub(id string) string
	Record(id, label string)
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
}

var ssrfFiles = []string{"ssrf-targets.txt", "metadata.txt", "schemes.txt", "redirect-rebind.txt"}

func SSRF(dir string, p Params, o OOB) ([]Case, error) {
	if len(p.Ports) > 0 {
		return scanCases(p), nil
	}
	var cases []Case
	n := 0
	for _, fname := range ssrfFiles {
		lines, err := loadLines(filepath.Join(dir, fname))
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
				o.Record(id, val)
			}
			cases = append(cases, Case{ID: id, Mode: "ssrf", Source: fname, Payload: val, OOB: oobHost, Label: val})
		}
	}
	for _, ip := range sweepIPs(p.Sweep) {
		id := fmt.Sprintf("s%04d", n)
		n++
		val := "http://" + ip
		cases = append(cases, Case{ID: id, Mode: "ssrf", Source: "sweep", Payload: val, Label: val})
	}
	return cases, nil
}

func LoadHostHeaders(dir string) ([]string, error) {
	return loadLines(filepath.Join(dir, "host-headers.txt"))
}

func Host(dir string, p Params, o OOB, allow map[string]bool, paths []string) ([]Case, error) {
	headers, err := loadLines(filepath.Join(dir, "host-headers.txt"))
	if err != nil {
		return nil, err
	}
	values, err := loadLines(filepath.Join(dir, "host-values.txt"))
	if err != nil {
		return nil, err
	}

	values = append(values, sweepIPs(p.Sweep)...)
	if len(paths) == 0 {
		paths = []string{""}
	}

	var cases []Case
	n := 0
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
					n++
					label := fmt.Sprintf("%s: %s [%s]", h, val, v[0])
					if path != "" {
						label += " " + path
					}
					if oobHost != "" {
						o.Record(id, label)
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
	var cases []Case
	n := 0
	for _, host := range hosts {
		for _, port := range p.Ports {
			scheme := "http"
			if port == 443 || port == 8443 {
				scheme = "https"
			}
			val := fmt.Sprintf("%s://%s:%d", scheme, host, port)
			cases = append(cases, Case{ID: fmt.Sprintf("p%05d", n), Mode: "ssrf", Source: "scan", Payload: val, Label: val})
			n++
		}
	}
	return cases
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
		sub := o.Sub(id)
		s = strings.ReplaceAll(s, "{{OOB}}", sub)
		s = strings.ReplaceAll(s, "{{COLLAB}}", sub)
		oobHost = sub
	}

	if strings.Contains(s, "{{EVIL}}") {
		switch {
		case p.EVIL != "":
			s = strings.ReplaceAll(s, "{{EVIL}}", p.EVIL)
		case o != nil && o.Enabled():
			sub := o.Sub(id)
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

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
