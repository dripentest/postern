package detect

import "testing"

func TestDistinctive(t *testing.T) {
	yes := []string{
		"http://2887712788:7000",  // full URL with decimal host
		"2887712788",              // bare decimal IP
		"0xac1f0014",              // hex IP
		"[::ffff:ac1f:14]",        // IPv6-hex
		"admin.local",             // dotted hostname
		"169.254.169.254",         // dotted IP
	}
	for _, s := range yes {
		if !distinctive(s) {
			t.Errorf("distinctive(%q) = false, want true", s)
		}
	}
	no := []string{"short", "ok", "error here now", "1234"}
	for _, s := range no {
		if distinctive(s) {
			t.Errorf("distinctive(%q) = true, want false", s)
		}
	}
}

func TestAnalyzeReflectionNumeric(t *testing.T) {
	// A reflected decimal host must be caught even though it has no dot - the gap
	// the oracle lab exposed.
	bl := NewBaseline(200, []byte("could not load image"), 0, 0, nil)
	payload := "http://2887712788:7000"
	body := []byte("could not load image from http://2887712788:7000 sorry")
	sig := Analyze(bl, 200, body, 0, nil, 25, payload, nil, false)
	if !sig.Strong {
		t.Errorf("reflected decimal payload not flagged strong; reasons=%v", sig.Reasons)
	}
}

func TestAnalyzeMarkerNotInBaseline(t *testing.T) {
	markers := []string{"root:x:0:0"}
	bl := NewBaseline(200, []byte("home page"), 0, 0, markers)
	sig := Analyze(bl, 200, []byte("root:x:0:0:root:/root"), 0, markers, 25, "", nil, false)
	if !sig.Strong {
		t.Error("marker in body (not baseline) should be strong")
	}
}

func TestAnalyzeMarkerAlreadyInBaselineIgnored(t *testing.T) {
	markers := []string{"root:x:0:0"}
	bl := NewBaseline(200, []byte("root:x:0:0 shown on every page"), 0, 0, markers)
	sig := Analyze(bl, 200, []byte("root:x:0:0 shown on every page"), 0, markers, 25, "", nil, false)
	if sig.Strong {
		t.Error("marker present in baseline must not be flagged")
	}
}

func TestAnalyzeStatusAndLength(t *testing.T) {
	bl := NewBaseline(403, []byte("forbidden"), 0, 0, nil)
	sig := Analyze(bl, 200, []byte("a much longer successful response body here"), 0, nil, 25, "", nil, false)
	if !sig.Interesting {
		t.Error("status 403->200 should be interesting")
	}
}

func TestAnalyzeTimingOptIn(t *testing.T) {
	bl := NewBaseline(200, []byte("x"), 100, 1, nil) // mean=100ns
	slow := bl.SlowThreshold() + 1
	if s := Analyze(bl, 200, []byte("x"), slow, nil, 25, "", nil, false); s.Interesting {
		t.Error("slow response must NOT be flagged when flagSlow=false")
	}
	if s := Analyze(bl, 200, []byte("x"), slow, nil, 25, "", nil, true); !s.Interesting {
		t.Error("slow response must be flagged when flagSlow=true")
	}
}

func TestAnalyzeNoBaselineOnlyAbsoluteSignals(t *testing.T) {
	// Baseline failed (status 0 = no response). Status/length diffs must NOT fire
	// against it, or every response is flagged. Only markers/reflection count.
	bl := NewBaseline(0, nil, 0, 0, []string{"ami-id"})
	if s := Analyze(bl, 200, []byte("ordinary page body"), 0, []string{"ami-id"}, 25, "", nil, false); s.Interesting {
		t.Errorf("no baseline: a plain 200 must not be flagged; reasons=%v", s.Reasons)
	}
	if s := Analyze(bl, 200, []byte("ami-id: ami-0lab"), 0, []string{"ami-id"}, 25, "", nil, false); !s.Strong {
		t.Error("no baseline: a marker hit must still be flagged")
	}
}
