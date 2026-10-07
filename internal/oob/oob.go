package oob

import (
	"fmt"
	"os"
	"sync"
)

type Mapper struct {
	base    string
	enabled bool
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
		fmt.Fprintf(f, "# ssrfuzz OOB map: <subdomain>\\t<payload/label>\n")
	}
	return m, nil
}

func (m *Mapper) Enabled() bool { return m != nil && m.enabled }

func (m *Mapper) Sub(id string) string {
	if !m.Enabled() {
		return ""
	}
	return id + "." + m.base
}

func (m *Mapper) Record(id, label string) {
	if m == nil || m.w == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(m.w, "%s.%s\t%s\n", id, m.base, label)
}

func (m *Mapper) Close() {
	if m != nil && m.w != nil {
		m.w.Close()
	}
}
