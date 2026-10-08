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

func Analyze(b Baseline, status int, body []byte, dur time.Duration, markers []string, lenPct int, reflect string, hdr http.Header) Signal {
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

	if th := b.SlowThreshold(); th > 0 && dur > th {
		s.Interesting = true
		s.Reasons = append(s.Reasons, fmt.Sprintf("slow %s (base mean %s)", dur.Round(time.Millisecond), b.Mean.Round(time.Millisecond)))
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

func distinctive(s string) bool {
	return len(s) >= 8 && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") && strings.Contains(s, ".")
}
