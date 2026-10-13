package ipenc

import "testing"

func byKind(reps []Rep) map[string]string {
	m := map[string]string{}
	for _, r := range reps {
		m[r.Kind] = r.Value
	}
	return m
}

func TestEncodeForms(t *testing.T) {
	// 172.31.0.20 = 2887712788 (0xac1f0014)
	got := byKind(Encode("172.31.0.20"))
	want := map[string]string{
		"decimal":          "2887712788",
		"hex":              "0xac1f0014",
		"hex-dotted":       "0xac.0x1f.0x0.0x14",
		"octal":            "0254.037.00.024",
		"octal-padded":     "00254.00037.00000.00024",
		"mixed":            "0xac.31.0.20",
		"dotless-2":        "172.2031636",
		"dotless-3":        "172.31.20",
		"ipv6-mapped":      "[::ffff:172.31.0.20]",
		"ipv6-hex":         "[::ffff:ac1f:14]",
		"ipv6-mapped-full": "[0:0:0:0:0:ffff:172.31.0.20]",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("kind %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestLeadingZerosRemoved(t *testing.T) {
	// A "%03d" zero-padded form is read as OCTAL by inet_aton and resolves to the
	// wrong address, so it must never be emitted.
	for _, r := range Encode("172.31.0.20") {
		if r.Kind == "leading-zeros" {
			t.Fatalf("leading-zeros must not be emitted (got %q)", r.Value)
		}
	}
}

func TestEncodeLoopbackDecimal(t *testing.T) {
	if got := byKind(Encode("127.0.0.1"))["decimal"]; got != "2130706433" {
		t.Errorf("127.0.0.1 decimal = %q, want 2130706433", got)
	}
}

func TestEncodeRejectsNonIPv4(t *testing.T) {
	for _, s := range []string{"", "example.com", "not-an-ip", "::1", "2001:db8::1"} {
		if reps := Encode(s); reps != nil {
			t.Errorf("Encode(%q) = %v, want nil", s, reps)
		}
	}
}

func TestEncodeKindsPrefixFilter(t *testing.T) {
	kinds := byKind(EncodeKinds("172.31.0.20", []string{"hex"}))
	if _, ok := kinds["hex"]; !ok {
		t.Error(`"hex" filter should include kind "hex"`)
	}
	if _, ok := kinds["hex-dotted"]; !ok {
		t.Error(`"hex" filter should include kind "hex-dotted" (prefix match)`)
	}
	if _, ok := kinds["decimal"]; ok {
		t.Error(`"hex" filter should not include "decimal"`)
	}

	ipv6 := byKind(EncodeKinds("172.31.0.20", []string{"ipv6"}))
	if len(ipv6) != 3 {
		t.Errorf(`"ipv6" filter should match 3 kinds, got %d`, len(ipv6))
	}

	if n := len(EncodeKinds("172.31.0.20", nil)); n != len(Encode("172.31.0.20")) {
		t.Errorf("empty kinds should return all (%d)", n)
	}
}
