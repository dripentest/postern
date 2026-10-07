package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Baseline struct {
	Status  int
	BodyLen int
	Hash    string
	Dur     time.Duration
	markers map[string]bool
}

func NewBaseline(status int, body []byte, dur time.Duration, markers []string) Baseline {
	b := Baseline{Status: status, BodyLen: len(body), Hash: HashBody(body), Dur: dur, markers: map[string]bool{}}
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

type Signal struct {
	Interesting bool
	Strong      bool
	Reasons     []string
}

func Analyze(b Baseline, status int, body []byte, dur time.Duration, markers []string, lenPct int) Signal {
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

	if b.Dur > 0 && dur > b.Dur*3 && dur > b.Dur+2*time.Second {
		s.Interesting = true
		s.Reasons = append(s.Reasons, fmt.Sprintf("slow %s (base %s)", dur.Round(time.Millisecond), b.Dur.Round(time.Millisecond)))
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
