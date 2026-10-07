package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ssrfuzz/internal/detect"
	"ssrfuzz/internal/gen"
	"ssrfuzz/internal/oob"
	"ssrfuzz/internal/rawreq"
	"ssrfuzz/internal/sender"
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type config struct {
	reqFile    string
	mode       string
	param      string
	urlFlag    string
	tls        bool
	proxy      string
	conc       int
	rate       float64
	delay      time.Duration
	jitter     time.Duration
	timeout    time.Duration
	insecure   bool
	oobBase    string
	oobMap     string
	lhost      string
	evil       string
	itarget    string
	sweep      string
	path       string
	paths      string
	payloads   string
	out        string
	verbose    bool
	lenPct     int
	match      string
	probe      bool
	max        int
	maxErrors  int
	listParams bool
	extraHdrs  headerList
}

var ssrfParamKeywords = []string{
	"url", "uri", "urn", "link", "src", "source", "dest", "destination",
	"redirect", "redir", "return", "returnto", "returnurl", "rurl", "next",
	"continue", "forward", "callback", "webhook", "hook", "feed", "host",
	"hostname", "domain", "site", "server", "port", "path", "file", "filename",
	"filepath", "folder", "dir", "document", "data", "reference", "ref", "load",
	"fetch", "remote", "target", "proxy", "image", "img", "avatar", "photo",
	"upload", "download", "page", "view", "window", "open", "endpoint",
	"location", "addr", "address", "to", "from",
}

var coreHeaders = map[string]bool{
	"host": true, "x-forwarded-host": true, "x-forwarded-for": true,
	"x-real-ip": true, "x-forwarded-server": true, "forwarded": true,
	"x-original-url": true, "x-rewrite-url": true, "x-host": true,
	"true-client-ip": true, "x-client-ip": true, "cf-connecting-ip": true,
}

const usageText = `ssrfuzz - SSRF and Host-Header fuzzing toolkit (authorized testing only)

USAGE:
  ssrfuzz -r <raw-request-file> -mode <ssrf|host|both> [options]

MODES:
  ssrf   Fuzz an injection point with SSRF payloads (localhost bypasses,
         IP encodings, cloud metadata, schemes, redirect/rebind).
         Requires -p <param> or a FUZZ marker in the request.
  host   Host-Header attacks: matrix of override headers x values, with
         replace / duplicate-Host / absolute-URI / add-header variants.
  both   Run ssrf then host.

TARGETING:
  -r string        Raw HTTP request file (saved from Burp "Copy to file"). Required.
  -p string        Parameter to fuzz (query / form-urlencoded / JSON / multipart):
                   a name, "auto" (SSRF-candidate params), or "all" (every param).
                   If omitted in ssrf mode, a literal FUZZ marker is used.
  -list-params     Discover and print request parameters (candidates marked), then exit.
  -url string      Override target as scheme://host[:port] (else taken from Host header).
  -tls             Force TLS when -url is not given.
  -proxy string    HTTP proxy host:port (e.g. Burp 127.0.0.1:8080).
  -H value         Extra header added to every request (repeatable): -H "Name: Value".

PAYLOADS / PLACEHOLDERS:
  -payloads string Directory with payload files (default "payloads").
  -lhost string    Value for {{LHOST}} (redirect tricks, your server).
  -evil string     Value for {{EVIL}} (host poisoning). If empty, falls back to OOB.
  -itarget string  Value for {{TARGET}} internal address (default "127.0.0.1").
  -sweep string    Last-octet sweep of /24 bases: "private"
                   (192.168.0,10.0.0,172.16.0,127.0.0) or a custom list
                   like "10.10.10,192.168.56".
  -path string     Host mode: single request path (e.g. /admin), overrides the
                   request path for routing-based SSRF.
  -paths string    Host mode: path list - "default" (built-in paths.txt) or a
                   file. Multiplies the host matrix by each path.

DETECTION:
  -match string    Extra body signatures (comma-separated), treated as strong hits.
  -probe           Host mode: probe each header with canaries first and skip the
                   ones with no visible effect (core SSRF headers are always kept).
                   Cuts wasted requests; may miss blind-only headers (use -oob then).
  -lenpct int      Body-length delta threshold in %% to flag (default 25).
  -oob string      interactsh base domain for blind detection (e.g. abc.oast.fun).
  -oobmap string   File for the OOB correlation map (default oob-map-<ts>.txt).

RATE CONTROL / SAFETY:
  -c int           Concurrent workers (default 10).
  -rate float      Global requests/sec (default 25; 0 = unlimited, use with care).
  -delay duration  Delay before each request (e.g. 200ms).
  -jitter duration Random extra delay up to this value.
  -timeout duration Per-request timeout (default 10s).
  -max int         Abort before start if case count exceeds this (0 = no cap).
  -max-errors int  Circuit breaker: consecutive errors / sustained slow responses
                   before auto-stop (default 25). Ctrl-C stops gracefully too.

OUTPUT:
  -v               Print all results, not only interesting ones.
  -o string        Write results as JSONL to this file.
  -k               Skip TLS certificate verification (default true).

EXAMPLES:
  ssrfuzz -r req.txt -mode ssrf -p imageUrl -oob abc.oast.fun -rate 15
  ssrfuzz -r req.txt -mode host -evil evil.attacker.com -match "ADMIN PANEL" -rate 20
  ssrfuzz -r req.txt -mode host -sweep private -rate 10 -c 5
  ssrfuzz -r req.txt -mode both -proxy 127.0.0.1:8080 -v
`

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() *config {
	cfg := &config{}
	flag.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	flag.StringVar(&cfg.reqFile, "r", "", "raw HTTP request file (required)")
	flag.StringVar(&cfg.mode, "mode", "ssrf", "mode: ssrf | host | both")
	flag.StringVar(&cfg.param, "p", "", "parameter to fuzz (ssrf): a name, 'auto' (SSRF-candidate params), or 'all'; else FUZZ marker")
	flag.BoolVar(&cfg.listParams, "list-params", false, "discover and print request parameters (candidates marked), then exit")
	flag.StringVar(&cfg.urlFlag, "url", "", "override target: scheme://host[:port]")
	flag.BoolVar(&cfg.tls, "tls", false, "target over TLS (when -url not given)")
	flag.StringVar(&cfg.proxy, "proxy", "", "HTTP proxy host:port (e.g. Burp 127.0.0.1:8080)")
	flag.IntVar(&cfg.conc, "c", 10, "concurrent workers")
	flag.Float64Var(&cfg.rate, "rate", 25, "global requests/sec (0 = unlimited, use with care)")
	flag.DurationVar(&cfg.delay, "delay", 0, "delay before each request (e.g. 200ms)")
	flag.DurationVar(&cfg.jitter, "jitter", 0, "random extra delay up to this value")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.insecure, "k", true, "skip TLS certificate verification")
	flag.StringVar(&cfg.oobBase, "oob", "", "interactsh base domain for blind detection")
	flag.StringVar(&cfg.oobMap, "oobmap", "", "file for the OOB correlation map")
	flag.StringVar(&cfg.lhost, "lhost", "", "value for {{LHOST}}")
	flag.StringVar(&cfg.evil, "evil", "", "value for {{EVIL}} host poisoning (else OOB)")
	flag.StringVar(&cfg.itarget, "itarget", "127.0.0.1", "value for {{TARGET}} internal address")
	flag.StringVar(&cfg.sweep, "sweep", "", "last-octet /24 sweep: 'private' or custom list like '10.10.10,192.168.56'")
	flag.StringVar(&cfg.path, "path", "", "host mode: single request path to use (e.g. /admin), overrides the request path")
	flag.StringVar(&cfg.paths, "paths", "", "host mode: path list - 'default' (built-in paths.txt) or a file; multiplies the host matrix")
	flag.StringVar(&cfg.payloads, "payloads", "payloads", "directory with payload files")
	flag.StringVar(&cfg.out, "o", "", "write results as JSONL to this file")
	flag.BoolVar(&cfg.verbose, "v", false, "print all results, not only interesting")
	flag.IntVar(&cfg.lenPct, "lenpct", 25, "body-length delta threshold (%) to flag")
	flag.StringVar(&cfg.match, "match", "", "extra body signatures (comma-separated), treated as strong hits")
	flag.BoolVar(&cfg.probe, "probe", false, "host mode: probe each header first, skip the ones with no visible effect (keeps core headers)")
	flag.IntVar(&cfg.max, "max", 0, "abort before start if case count exceeds this (0 = no cap)")
	flag.IntVar(&cfg.maxErrors, "max-errors", 25, "circuit breaker: consecutive errors / sustained slow responses before auto-stop")
	flag.Var(&cfg.extraHdrs, "H", "extra header for every request (repeatable): -H 'Name: Value'")
	flag.Parse()
	return cfg
}

func run(cfg *config) error {
	if cfg.reqFile == "" {
		flag.Usage()
		return fmt.Errorf("missing -r (raw request file)")
	}
	cfg.mode = strings.ToLower(cfg.mode)
	if cfg.mode != "ssrf" && cfg.mode != "host" && cfg.mode != "both" {
		return fmt.Errorf("unknown -mode %q (ssrf|host|both)", cfg.mode)
	}

	rawBytes, err := os.ReadFile(cfg.reqFile)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	base, err := rawreq.Parse(rawBytes)
	if err != nil {
		return fmt.Errorf("parse request: %w", err)
	}

	dialAddr, targetHost, sni, useTLS, err := resolveTarget(base, cfg.urlFlag, cfg.tls)
	if err != nil {
		return err
	}

	base.UpsertHeader("Connection", "close")
	for _, h := range cfg.extraHdrs {
		ci := strings.IndexByte(h, ':')
		if ci < 0 {
			return fmt.Errorf("invalid -H %q (expected 'Name: Value')", h)
		}
		base.UpsertHeader(strings.TrimSpace(h[:ci]), strings.TrimSpace(h[ci+1:]))
	}

	if cfg.listParams {
		printParams(base.DiscoverParams())
		return nil
	}

	var targetParams []string
	useMarker := false
	if cfg.mode == "ssrf" || cfg.mode == "both" {
		switch cfg.param {
		case "":
			if !base.HasMarker() {
				return fmt.Errorf("ssrf mode needs -p <param|auto|all> or a FUZZ marker in the request")
			}
			useMarker = true
		case "auto", "all":
			disc := base.DiscoverParams()
			if len(disc) == 0 {
				return fmt.Errorf("no parameters discovered; place a FUZZ marker or use -p <name>")
			}
			seen := map[string]bool{}
			for _, p := range disc {
				if seen[p.Name] {
					continue
				}
				if cfg.param == "all" || isCandidate(p) {
					seen[p.Name] = true
					targetParams = append(targetParams, p.Name)
				}
			}
			if len(targetParams) == 0 {
				return fmt.Errorf("no SSRF-candidate parameters found; use -p all or -p <name> (run -list-params to see them)")
			}
			fmt.Printf("[*] fuzzing %d parameter(s): %s\n", len(targetParams), strings.Join(targetParams, ", "))
		default:
			if !base.HasParam(cfg.param) {
				return fmt.Errorf("parameter %q not found in request (query/form/json/multipart)", cfg.param)
			}
			targetParams = []string{cfg.param}
		}
	}

	markers, _ := loadMarkers(filepath.Join(cfg.payloads, "markers.txt"))
	for _, m := range strings.Split(cfg.match, ",") {
		if m = strings.TrimSpace(m); m != "" {
			markers = append(markers, m)
		}
	}

	oobMapPath := cfg.oobMap
	if cfg.oobBase != "" && oobMapPath == "" {
		oobMapPath = fmt.Sprintf("oob-map-%d.txt", time.Now().Unix())
	}
	mapper, err := oob.New(cfg.oobBase, oobMapPath)
	if err != nil {
		return fmt.Errorf("oob map: %w", err)
	}
	defer mapper.Close()

	params := gen.Params{LHOST: cfg.lhost, TARGET: cfg.itarget, EVIL: cfg.evil, HOST: sni, Sweep: parseSweep(cfg.sweep)}

	sopts := sender.Options{
		DialAddr: dialAddr, TLS: useTLS, Proxy: cfg.proxy, TargetHost: targetHost,
		Method: base.Method, SNI: sni, Insecure: cfg.insecure, Timeout: cfg.timeout,
	}

	fmt.Printf("[*] target: %s  TLS=%v  proxy=%q  method=%s\n", targetHost, useTLS, cfg.proxy, base.Method)
	baseRes := sender.Send(sopts, base.Bytes())
	var bl detect.Baseline
	if baseRes.Err != nil {
		fmt.Printf("[!] baseline failed: %v - diff will be coarser\n", baseRes.Err)
		bl = detect.NewBaseline(0, nil, 0, markers)
	} else {
		bl = detect.NewBaseline(baseRes.Status, baseRes.Body, baseRes.Duration, markers)
		fmt.Printf("[*] baseline: status=%d len=%d hash=%s dur=%s\n",
			baseRes.Status, baseRes.BodyLen, detect.HashBody(baseRes.Body), baseRes.Duration.Round(time.Millisecond))
	}

	var cases []gen.Case
	if cfg.mode == "ssrf" || cfg.mode == "both" {
		sc, err := gen.SSRF(cfg.payloads, params, mapper)
		if err != nil {
			return err
		}
		if useMarker {
			cases = append(cases, sc...)
		} else {
			for _, pname := range targetParams {
				for _, c := range sc {
					c.Param = pname
					c.Label = pname + "=" + c.Payload
					cases = append(cases, c)
				}
			}
		}
	}
	if cfg.mode == "host" || cfg.mode == "both" {
		var allow map[string]bool
		if cfg.probe {
			allow = probeHeaders(cfg, base, sopts, bl, markers)
		}
		pathList, err := resolvePaths(cfg)
		if err != nil {
			return err
		}
		hc, err := gen.Host(cfg.payloads, params, mapper, allow, pathList)
		if err != nil {
			return err
		}
		cases = append(cases, hc...)
	}
	if len(cases) == 0 {
		return fmt.Errorf("no cases generated (check payload files and placeholders)")
	}

	if cfg.max > 0 && len(cases) > cfg.max {
		return fmt.Errorf("case count %d exceeds -max %d; narrow scope (-probe, smaller -sweep/-paths) or raise -max", len(cases), cfg.max)
	}

	fmt.Printf("[*] cases: %d | workers: %d | rate: %.0f req/s", len(cases), cfg.conc, cfg.rate)
	if mapper.Enabled() {
		fmt.Printf(" | OOB: %s (map: %s)", cfg.oobBase, oobMapPath)
	}
	fmt.Println()
	if cfg.rate > 0 {
		eta := time.Duration(float64(len(cases)) / cfg.rate * float64(time.Second))
		fmt.Printf("[*] estimated duration at %.0f req/s: ~%s\n", cfg.rate, eta.Round(time.Second))
	} else {
		fmt.Printf("[!] rate is UNLIMITED (-rate 0): this can overwhelm the target; Ctrl-C to abort\n")
	}
	fmt.Println(strings.Repeat("-", 72))

	var outFile *os.File
	if cfg.out != "" {
		outFile, err = os.Create(cfg.out)
		if err != nil {
			return fmt.Errorf("create -o: %w", err)
		}
		defer outFile.Close()
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()

	var (
		printMu       sync.Mutex
		nSent, nErr   int64
		nInt, nStrong int64
		nOOB          int64
		consecErr     int64
		slowStreak    int64
		tripped       int32
		clMu          sync.Mutex
		clusters      = map[string]*cluster{}
	)

	trip := func(reason string) {
		if atomic.CompareAndSwapInt32(&tripped, 0, 1) {
			printMu.Lock()
			fmt.Printf("\n[!] circuit breaker: %s - stopping to avoid overloading the target\n", reason)
			printMu.Unlock()
			stopSignals()
		}
	}

	recordCluster := func(sig, example string) {
		clMu.Lock()
		c := clusters[sig]
		if c == nil {
			c = &cluster{}
			clusters[sig] = c
		}
		c.count++
		if c.example == "" {
			c.example = example
		}
		clMu.Unlock()
	}

	slowCut := bl.Dur * 10
	if slowCut < 3*time.Second {
		slowCut = 3 * time.Second
	}

	process := func(c gen.Case) {
		req, err := buildRequest(base, c, cfg.param, useTLS, base.Host)
		if err != nil {
			atomic.AddInt64(&nErr, 1)
			printMu.Lock()
			fmt.Printf("[err] %-6s build: %v\n", c.ID, err)
			printMu.Unlock()
			return
		}
		res := sender.Send(sopts, req.Bytes())
		atomic.AddInt64(&nSent, 1)
		if c.OOB != "" {
			atomic.AddInt64(&nOOB, 1)
		}

		if res.Err != nil {
			atomic.AddInt64(&nErr, 1)
			recordCluster("ERR", short(c.Label, 50))
			if atomic.AddInt64(&consecErr, 1) >= int64(cfg.maxErrors) {
				trip(fmt.Sprintf("%d consecutive request errors", cfg.maxErrors))
			}
			if cfg.verbose {
				printMu.Lock()
				fmt.Printf("[err] %-6s %-40s %v\n", c.ID, short(c.Label, 40), res.Err)
				printMu.Unlock()
			}
			writeJSON(outFile, &printMu, c, res, detect.Signal{}, err)
			return
		}
		atomic.StoreInt64(&consecErr, 0)
		if bl.Dur > 0 && res.Duration > slowCut {
			if atomic.AddInt64(&slowStreak, 1) >= int64(cfg.maxErrors) {
				trip("sustained latency blowup (target degrading)")
			}
		} else {
			atomic.StoreInt64(&slowStreak, 0)
		}

		recordCluster(fmt.Sprintf("%d/%d", res.Status, res.BodyLen), short(c.Label, 50))
		sig := detect.Analyze(bl, res.Status, res.Body, res.Duration, markers, cfg.lenPct, c.Payload, res.Header)
		if sig.Strong {
			atomic.AddInt64(&nStrong, 1)
		}
		if sig.Interesting {
			atomic.AddInt64(&nInt, 1)
		}

		if sig.Interesting || cfg.verbose || c.OOB != "" {
			tag := "    "
			switch {
			case sig.Strong:
				tag = "STRONG"
			case sig.Interesting:
				tag = "hit "
			case c.OOB != "":
				tag = "oob "
			}
			line := fmt.Sprintf("[%-6s] %-6s %3d %7d  %-28s | %s",
				tag, c.ID, res.Status, res.BodyLen, short(strings.Join(sig.Reasons, ","), 28), short(c.Label, 60))
			if c.OOB != "" {
				line += "  (OOB: " + c.OOB + ")"
			}
			printMu.Lock()
			fmt.Println(line)
			printMu.Unlock()
		}
		writeJSON(outFile, &printMu, c, res, sig, nil)
	}

	var ticker *time.Ticker
	var tickC <-chan time.Time
	if cfg.rate > 0 {
		ticker = time.NewTicker(time.Duration(float64(time.Second) / cfg.rate))
		defer ticker.Stop()
		tickC = ticker.C
	}

	casesCh := make(chan gen.Case)
	var wg sync.WaitGroup
	for i := 0; i < cfg.conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range casesCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if tickC != nil {
					select {
					case <-ctx.Done():
						return
					case <-tickC:
					}
				}
				if cfg.delay > 0 || cfg.jitter > 0 {
					d := cfg.delay
					if cfg.jitter > 0 {
						d += time.Duration(rand.Int63n(int64(cfg.jitter)))
					}
					time.Sleep(d)
				}
				process(c)
			}
		}()
	}
feed:
	for _, c := range cases {
		select {
		case <-ctx.Done():
			break feed
		case casesCh <- c:
		}
	}
	close(casesCh)
	wg.Wait()

	fmt.Println(strings.Repeat("-", 72))
	if ctx.Err() != nil && atomic.LoadInt32(&tripped) == 0 {
		fmt.Printf("[!] aborted by user (Ctrl-C)\n")
	}
	fmt.Printf("[*] done: sent=%d interesting=%d strong=%d errors=%d oob-sent=%d\n",
		nSent, nInt, nStrong, nErr, nOOB)
	printClusters(clusters)
	if mapper.Enabled() {
		fmt.Printf("[*] check interactsh-client for callbacks; payload mapping in %s\n", oobMapPath)
	}
	return nil
}

type cluster struct {
	count   int
	example string
}

func printClusters(clusters map[string]*cluster) {
	if len(clusters) == 0 {
		return
	}
	type kv struct {
		sig string
		c   *cluster
	}
	all := make([]kv, 0, len(clusters))
	for s, c := range clusters {
		all = append(all, kv{s, c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].c.count < all[j].c.count })
	fmt.Printf("[*] response clusters (status/len, rare first) - %d unique:\n", len(all))
	limit := len(all)
	if limit > 20 {
		limit = 20
	}
	for _, e := range all[:limit] {
		fmt.Printf("    %6dx  %-14s  e.g. %s\n", e.c.count, e.sig, short(e.c.example, 50))
	}
}

func isCandidate(p rawreq.Param) bool {
	name := strings.ToLower(p.Name)
	for _, kw := range ssrfParamKeywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	v := strings.ToLower(strings.TrimSpace(p.Value))
	return strings.Contains(v, "://") || strings.HasPrefix(v, "http") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/")
}

func printParams(ps []rawreq.Param) {
	if len(ps) == 0 {
		fmt.Println("[*] no parameters discovered (query/form/json/multipart)")
		return
	}
	fmt.Printf("[*] discovered %d parameter(s):\n", len(ps))
	for _, p := range ps {
		tag := " "
		if isCandidate(p) {
			tag = "*"
		}
		fmt.Printf("  %s %-9s %-24s = %s\n", tag, p.Loc, p.Name, short(p.Value, 40))
	}
	fmt.Println("  (* = SSRF candidate; fuzz with -p auto, or -p all for every param)")
}

func probeHeaders(cfg *config, base *rawreq.Request, sopts sender.Options, bl detect.Baseline, markers []string) map[string]bool {
	headers, err := gen.LoadHostHeaders(cfg.payloads)
	if err != nil {
		return nil
	}
	allow := map[string]bool{}
	kept, skipped := 0, 0
	for _, h := range headers {
		if coreHeaders[strings.ToLower(h)] {
			allow[h] = true
			kept++
			continue
		}
		live := false
		token := randToken()
		for _, val := range []string{token + ".example.com", "127.0.0.1"} {
			var req *rawreq.Request
			if strings.EqualFold(h, "Host") {
				req = base.WithHostReplaced(val)
			} else {
				req = base.WithAddedHeader(h, val)
			}
			res := sender.Send(sopts, req.Bytes())
			if res.Err != nil {
				continue
			}
			if strings.HasPrefix(val, token) && strings.Contains(string(res.Body), token) {
				live = true
				break
			}
			if detect.Analyze(bl, res.Status, res.Body, res.Duration, markers, cfg.lenPct, "", nil).Interesting {
				live = true
				break
			}
		}
		if live {
			allow[h] = true
			kept++
		} else {
			skipped++
		}
	}
	fmt.Printf("[*] probe: kept %d headers, skipped %d (core always kept)\n", kept, skipped)
	return allow
}

func randToken() string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = cs[rand.Intn(len(cs))]
	}
	return "c" + string(b)
}

func buildRequest(base *rawreq.Request, c gen.Case, param string, useTLS bool, legitHost string) (*rawreq.Request, error) {
	if c.Mode == "ssrf" {
		p := c.Param
		if p == "" {
			p = param
		}
		if p != "" {
			return base.InjectParam(p, c.Payload)
		}
		return base.InjectMarker(c.Payload), nil
	}
	var r *rawreq.Request
	switch c.Variant {
	case "replace":
		r = base.WithHostReplaced(c.Payload)
	case "dup":
		r = base.WithDupHost(c.Payload)
	case "add":
		r = base.WithAddedHeader(c.Header, c.Payload)
	case "absolute":
		r = base.WithHostReplaced(c.Payload)
	default:
		r = base.Clone()
	}
	if c.Path != "" {
		r.Target = c.Path
	}
	if c.Variant == "absolute" && !strings.HasPrefix(r.Target, "http://") && !strings.HasPrefix(r.Target, "https://") {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		r.Target = scheme + "://" + legitHost + r.Target
	}
	return r, nil
}

func resolvePaths(cfg *config) ([]string, error) {
	if cfg.paths != "" {
		var path string
		switch strings.ToLower(cfg.paths) {
		case "default", "all":
			path = filepath.Join(cfg.payloads, "paths.txt")
		default:
			path = cfg.paths
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read -paths: %w", err)
		}
		var out []string
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			out = append(out, ln)
		}
		return out, nil
	}
	if cfg.path != "" {
		return []string{cfg.path}, nil
	}
	return nil, nil
}

func writeJSON(f *os.File, mu *sync.Mutex, c gen.Case, res sender.Result, sig detect.Signal, buildErr error) {
	if f == nil {
		return
	}
	rec := map[string]interface{}{
		"id": c.ID, "mode": c.Mode, "source": c.Source,
		"payload": c.Payload, "header": c.Header, "variant": c.Variant,
		"oob": c.OOB, "status": res.Status, "len": res.BodyLen,
		"dur_ms":      res.Duration.Milliseconds(),
		"interesting": sig.Interesting, "strong": sig.Strong,
		"reasons": sig.Reasons,
	}
	if res.Err != nil {
		rec["error"] = res.Err.Error()
	}
	if buildErr != nil {
		rec["build_error"] = buildErr.Error()
	}
	b, _ := json.Marshal(rec)
	mu.Lock()
	f.Write(append(b, '\n'))
	mu.Unlock()
}

func resolveTarget(r *rawreq.Request, urlFlag string, tlsFlag bool) (dialAddr, targetHost, sni string, useTLS bool, err error) {
	if urlFlag != "" {
		u, e := url.Parse(urlFlag)
		if e != nil {
			return "", "", "", false, fmt.Errorf("parse -url: %w", e)
		}
		useTLS = u.Scheme == "https"
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if useTLS {
				port = "443"
			} else {
				port = "80"
			}
		}
		return net.JoinHostPort(host, port), u.Host, host, useTLS, nil
	}

	useTLS = tlsFlag
	hh := r.HeaderValue("Host")
	if hh == "" {
		return "", "", "", false, fmt.Errorf("no Host header and no -url")
	}
	host, port, e := net.SplitHostPort(hh)
	if e != nil {
		host = hh
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), hh, host, useTLS, nil
}

func parseSweep(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	switch strings.ToLower(s) {
	case "private", "default", "all":
		return []string{"192.168.0", "10.0.0", "172.16.0", "127.0.0"}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadMarkers(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out, nil
}

func short(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
