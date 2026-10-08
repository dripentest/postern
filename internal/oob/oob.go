package oob

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

type Mapper struct {
	base    string
	enabled bool
	n       int64
	mu      sync.Mutex
	w       *os.File
}

func New(base, path string) (*Mapper, error) {
	m := &Mapper{base: base, enabled: base != ""}
	if m.enabled && path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		m.w = f
		fmt.Fprintf(f, "# postern OOB map: <subdomain>\\t<payload/label>\n")
	}
	return m, nil
}

func (m *Mapper) Enabled() bool { return m != nil && m.enabled }

func (m *Mapper) Alloc() string {
	if !m.Enabled() {
		return ""
	}
	n := atomic.AddInt64(&m.n, 1)
	return fmt.Sprintf("p%05d.%s", n, m.base)
}

func (m *Mapper) Record(host, label string) {
	if m == nil || m.w == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(m.w, "%s\t%s\n", host, label)
}

func (m *Mapper) Close() {
	if m != nil && m.w != nil {
		m.w.Close()
	}
}
