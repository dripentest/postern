package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Baseline struct {
	Status  int
	BodyLen int
	Hash    string
	Mean    time.Duration
	Std     time.Duration
	markers map[string]bool
	body    string
}

func NewBaseline(status int, body []byte, mean, std time.Duration, markers []string) Baseline {
	b := Baseline{Status: status, BodyLen: len(body), Hash: HashBody(body), Mean: mean, Std: std, markers: map[string]bool{}, body: string(body)}
	low := strings.ToLower(string(body))
	for _, m := range markers {
		if m == "" {
			continue
		}
		if strings.Contains(low, strings.ToLower(m)) {
			b.markers[m] = true
		}
	}
	return b
}

// SlowThreshold returns the latency above which a response is "slow": mean + 3*std,
// with a floor so a very stable baseline doesn't flag on minor jitter.
func (b Baseline) SlowThreshold() time.Duration {
	if b.Mean <= 0 {
		return 0
	}
	t := b.Mean + 3*b.Std
	if floor := b.Mean + 500*time.Millisecond; t < floor {
		t = floor
	}
	return t
}

type Signal struct {
	Interesting bool
	Strong      bool
	Reasons     []string
}

func Analyze(b Baseline, status int, body []byte, dur time.Duration, markers []string, lenPct int, reflect string, hdr http.Header, flagSlow bool) Signal {
	var s Signal
	low := strings.ToLower(string(body))

	for _, m := range markers {
		if m == "" || b.markers[m] {
			continue
		}
		if strings.Contains(low, strings.ToLower(m)) {
			s.Strong = true
			s.Interesting = true
			s.Reasons = append(s.Reasons, "marker:"+m)
		}
	}

	if distinctive(reflect) {
		if strings.Contains(string(body), reflect) && !strings.Contains(b.body, reflect) {
			s.Strong = true
			s.Interesting = true
			s.Reasons = append(s.Reasons, "reflected-body")
		}
		for name, vals := range hdr {
			for _, v := range vals {
				if strings.Contains(v, reflect) {
					s.Strong = true
					s.Interesting = true
					s.Reasons = append(s.Reasons, "reflected-header:"+name)
				}
			}
		}
	}

	// Status/length diffing is only meaningful against a real baseline. When the
	// baseline request failed (status 0 = no response), comparing against it would
	// flag every single response as "differs", so fall back to absolute signals
	// only (markers / reflection / OOB).
	if b.Status != 0 {
		if status != b.Status {
			s.Interesting = true
			s.Reasons = append(s.Reasons, fmt.Sprintf("status %d->%d", b.Status, status))
		}

		if b.BodyLen > 0 {
			delta := len(body) - b.BodyLen
			if delta < 0 {
				delta = -delta
			}
			if pct := delta * 100 / b.BodyLen; pct >= lenPct {
				s.Interesting = true
				s.Reasons = append(s.Reasons, fmt.Sprintf("len %d->%d (%+d%%)", b.BodyLen, len(body), (len(body)-b.BodyLen)*100/b.BodyLen))
			}
		} else if len(body) > 0 {
			s.Interesting = true
			s.Reasons = append(s.Reasons, fmt.Sprintf("len 0->%d", len(body)))
		}
	}

	// Timing is opt-in: on jittery links (VPN/THM) a slow-but-identical response
	// is almost always the network, not SSRF, and floods the output with noise.
	if flagSlow {
		if th := b.SlowThreshold(); th > 0 && dur > th {
			s.Interesting = true
			s.Reasons = append(s.Reasons, fmt.Sprintf("slow %s (base mean %s)", dur.Round(time.Millisecond), b.Mean.Round(time.Millisecond)))
		}
	}

	if len(s.Reasons) == 0 {
		s.Reasons = append(s.Reasons, "-")
	}
	return s
}

func HashBody(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:6])
}

// distinctive reports whether a reflected value is specific enough that finding
// it in a response (and not the baseline) is a real signal rather than noise. An
// injected payload is controlled, so we accept full URLs and bare numeric/hex
// host tokens (decimal/hex/IPv6 IP forms) too - not just dotted hostnames, which
// the previous dot-requiring check missed for exactly the strongest encodings.
func distinctive(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return false
	}
	if strings.Contains(s, "://") {
		return true // a full URL we injected
	}
	if strings.Contains(s, ".") && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") {
		return true // dotted hostname
	}
	// A long bare IP token: decimal (2887712788), hex (0xac1f0014), IPv6-hex
	// ([::ffff:ac1f:14]). Only [0-9a-fx:.\[\]] and long enough to be specific.
	if len(s) >= 9 {
		for _, c := range s {
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F',
				c == 'x', c == 'X', c == ':', c == '.', c == '[', c == ']':
			default:
				return false
			}
		}
		return true
	}
	return false
}
