package gen

import (
	"strings"
	"testing"
	"testing/fstest"
)

// fakeOOB is a disabled OOB provider: {{OOB}}/{{EVIL}} payloads skip, which keeps
// these tests focused on the generation logic rather than interactsh.
type fakeOOB struct{ n int }

func (f *fakeOOB) Enabled() bool            { return false }
func (f *fakeOOB) Alloc() string            { f.n++; return "oob" }
func (f *fakeOOB) Record(host, label string) {}

// ssrfFS builds the four files SSRF() reads, so a non-scan run doesn't error on a
// missing file. Empty strings are fine (loadLines returns no lines).
func ssrfFS(targets, metadata, schemes, redirect string) fstest.MapFS {
	return fstest.MapFS{
		"ssrf-targets.txt":    {Data: []byte(targets)},
		"metadata.txt":        {Data: []byte(metadata)},
		"schemes.txt":         {Data: []byte(schemes)},
		"redirect-rebind.txt": {Data: []byte(redirect)},
	}
}

// --- #1  scanCases must ENCODE the host (regression guard for bug B1) ----------

func TestScanCasesSweepEncodeProducesEncodedNotPlain(t *testing.T) {
	// 172.31.0.20 decimal = 2887712788
	p := Params{ScanHosts: []string{"172.31.0.20"}, Ports: []int{5000}, SweepEnc: []string{"decimal"}}
	cases, err := SSRF(fstest.MapFS{}, p, &fakeOOB{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cases {
		if strings.Contains(c.Payload, "172.31.0.20") {
			t.Errorf("scan payload still contains the PLAIN IP (B1 regressed): %s", c.Payload)
		}
		if strings.Contains(c.Payload, "2887712788") && strings.HasSuffix(c.Payload, ":5000") {
			found = true
			if c.Tag != "decimal" {
				t.Errorf("tag = %q, want decimal", c.Tag)
			}
		}
	}
	if !found {
		t.Error("no decimal-encoded scan case was produced")
	}
}

func TestScanCasesScanEncTakesPriorityOverSweepEnc(t *testing.T) {
	p := Params{ScanHosts: []string{"127.0.0.1"}, Ports: []int{80}, ScanEnc: []string{"hex"}, SweepEnc: []string{"decimal"}}
	cases, _ := SSRF(fstest.MapFS{}, p, &fakeOOB{})
	if len(cases) == 0 {
		t.Fatal("no scan cases produced")
	}
	for _, c := range cases {
		// ScanEnc=hex must win: every tag is in the hex family (prefix match also
		// yields hex-dotted), and none is the SweepEnc "decimal".
		if !strings.HasPrefix(c.Tag, "hex") {
			t.Errorf("ScanEnc should win over SweepEnc: tag=%q want hex*", c.Tag)
		}
	}
}

func TestScanCasesPlainAndScheme(t *testing.T) {
	p := Params{ScanHosts: []string{"127.0.0.1"}, Ports: []int{80, 443}}
	cases, _ := SSRF(fstest.MapFS{}, p, &fakeOOB{})
	got := map[string]bool{}
	for _, c := range cases {
		got[c.Payload] = true
	}
	if !got["http://127.0.0.1:80"] {
		t.Error("missing http scheme for port 80")
	}
	if !got["https://127.0.0.1:443"] {
		t.Error("port 443 must use https")
	}
}

// --- #2  metadataHeader attaches the right header, and only to metadata --------

func TestMetadataHeader(t *testing.T) {
	cases := []struct{ url, want string }{
		{"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "Metadata-Flavor: Google"},
		{"http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor: Google"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata: true"},
		{"http://169.254.169.254/metadata/identity/oauth2/token", "Metadata: true"},
		{"http://169.254.169.254/latest/meta-data/", ""}, // AWS: no header
		{"http://127.0.0.1/", ""},
		{"file:///etc/passwd", ""},
	}
	for _, c := range cases {
		if got := metadataHeader(c.url); got != c.want {
			t.Errorf("metadataHeader(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestSSRFAttachesMetadataHeaderToPayload(t *testing.T) {
	fsys := ssrfFS(
		"http://127.0.0.1\n",
		"http://169.254.169.254/computeMetadata/v1/\nhttp://169.254.169.254/latest/meta-data/\n",
		"", "")
	cases, err := SSRF(fsys, Params{}, &fakeOOB{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		switch {
		case strings.Contains(c.Payload, "computeMetadata"):
			if c.ReqHdr != "Metadata-Flavor: Google" {
				t.Errorf("GCP payload ReqHdr=%q, want Metadata-Flavor: Google", c.ReqHdr)
			}
		case strings.Contains(c.Payload, "/latest/meta-data/"):
			if c.ReqHdr != "" {
				t.Errorf("AWS payload must carry no header, got %q", c.ReqHdr)
			}
		}
	}
}

// --- #3  Host dedup keeps the distinct variants, drops exact duplicates --------

func TestHostDedupKeepsVariantsDropsDuplicates(t *testing.T) {
	fsys := fstest.MapFS{
		"host-headers.txt": {Data: []byte("Host\n")},
		"host-values.txt":  {Data: []byte("127.0.0.1\n127.0.0.1\nlocalhost\n")}, // 127.0.0.1 duplicated
	}
	cases, err := Host(fsys, Params{}, &fakeOOB{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, c := range cases {
		seen[c.Variant+"|"+c.Payload]++
	}
	// no (variant,value) pair may appear twice - the duplicate line must collapse
	for k, v := range seen {
		if v > 1 {
			t.Errorf("duplicate case %s x%d (dedup failed)", k, v)
		}
	}
	// but all three Host variants must survive for a value
	for _, variant := range []string{"replace", "dup", "absolute"} {
		if seen[variant+"|127.0.0.1"] != 1 {
			t.Errorf("variant %q for 127.0.0.1 missing or wrong count=%d", variant, seen[variant+"|127.0.0.1"])
		}
	}
}

// --- #4  expand: substitute when the flag is set, skip when not, never leak {{ -

func TestExpandNeverLeaksLiteralPlaceholder(t *testing.T) {
	fsys := ssrfFS("http://{{HOST}}@127.0.0.1\nhttp://127.0.0.1\n", "", "", "")
	// HOST unset -> the {{HOST}} line must be SKIPPED, not sent literally
	cases, _ := SSRF(fsys, Params{}, &fakeOOB{})
	for _, c := range cases {
		if strings.Contains(c.Payload, "{{") {
			t.Errorf("literal placeholder leaked onto the wire: %s", c.Payload)
		}
		if strings.Contains(c.Payload, "{{HOST}}@") {
			t.Errorf("unexpanded {{HOST}} case present: %s", c.Payload)
		}
	}
}

func TestExpandSubstitutesWhenFlagSet(t *testing.T) {
	fsys := ssrfFS("http://{{HOST}}@127.0.0.1\n", "", "", "")
	cases, _ := SSRF(fsys, Params{HOST: "legit.example"}, &fakeOOB{})
	found := false
	for _, c := range cases {
		if strings.Contains(c.Payload, "legit.example@127.0.0.1") {
			found = true
		}
		if strings.Contains(c.Payload, "{{") {
			t.Errorf("placeholder not fully expanded: %s", c.Payload)
		}
	}
	if !found {
		t.Error("{{HOST}} was not substituted when HOST is set")
	}
}

// --- supporting generators -----------------------------------------------------

func TestSweepIPsEnumeratesFull24(t *testing.T) {
	if got := len(sweepIPs([]string{"10.0.0"})); got != 256 {
		t.Errorf("sweepIPs(10.0.0) = %d hosts, want 256", got)
	}
	if got := len(sweepIPs([]string{"10.0.0", "192.168.1"})); got != 512 {
		t.Errorf("two /24 bases = %d, want 512", got)
	}
}

func TestRebindOnlyGeneratesOnlyRebind(t *testing.T) {
	p := Params{Rebind: []string{"r1.example", "r2.example"}, RebindOnly: true}
	cases, err := SSRF(ssrfFS("http://127.0.0.1\n", "", "", ""), p, &fakeOOB{})
	if err != nil {
		t.Fatal(err)
	}
	// rebind-only must skip the standard set entirely: 2 hosts x 2 URLs each = 4
	if len(cases) != 4 {
		t.Errorf("rebind-only produced %d cases, want 4 (2 hosts x 2 urls)", len(cases))
	}
	for _, c := range cases {
		if c.Source != "rebind" {
			t.Errorf("non-rebind case leaked into rebind-only run: %+v", c)
		}
	}
}

func TestSSRFGeneratesEncodingsForDefaultTargets(t *testing.T) {
	// With no files, SSRF still generates ipenc encodings for 127.0.0.1 and
	// 169.254.169.254; a tagged decimal form for each must appear.
	cases, err := SSRF(ssrfFS("", "", "", ""), Params{}, &fakeOOB{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"http://2130706433": false, "http://2852039166": false} // 127.0.0.1, 169.254.169.254
	for _, c := range cases {
		if _, ok := want[c.Payload]; ok && c.Tag == "decimal" {
			want[c.Payload] = true
		}
	}
	for p, ok := range want {
		if !ok {
			t.Errorf("missing decimal encoding for default target: %s", p)
		}
	}
}
