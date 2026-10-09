package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dripentest/postern/internal/detect"
	"github.com/dripentest/postern/internal/gen"
	"github.com/dripentest/postern/internal/oob"
	"github.com/dripentest/postern/internal/rawreq"
	"github.com/dripentest/postern/internal/sender"
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type config struct {
	reqFile          string
	mode             string
	param            string
	urlFlag          string
	tls              bool
	proxy            string
	conc             int
	rate             float64
	delay            time.Duration
	jitter           time.Duration
	timeout          time.Duration
	insecure         bool
	oobBase          string
	oobMap           string
	interactsh       bool
	interactshServer string
	interactshToken  string
	oobWait          time.Duration
	lhost            string
	evil             string
	itarget          string
	sweep            string
	rebind           string
	ports            string
	scanHost         string
	path             string
	paths            string
	payloads         string
	out              string
	verbose          bool
	lenPct           int
	match            string
	probe            bool
	max              int
	maxErrors        int
	retries          int
	listParams       bool
	silent           bool
	extraHdrs        headerList
}

//go:embed payloads
var embeddedPayloads embed.FS

func payloadFS(dir string) (fs.FS, string, error) {
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return os.DirFS(dir), dir, nil
	}
	sub, err := fs.Sub(embeddedPayloads, "payloads")
	if err != nil {
		return nil, "", err
	}
	return sub, "embedded", nil
}

func printBanner(w io.Writer) {
	var door, name, dim, x string
	if bannerColor(w) {
		door = "\033[90m"   // door: dim gray
		name = "\033[1;96m" // name: bold cyan
		dim = "\033[90m"    // taglines: dim gray
		x = "\033[0m"
	}
	D := func(s string) string { return door + s + x }
	T := func(c, s string) string { return c + s + x }
	fmt.Fprintln(w)
	fmt.Fprintf(w, "    %s\n", D(".--------."))
	fmt.Fprintf(w, "    %s\n", D("|  .--.  |"))
	fmt.Fprintf(w, "    %s      %s\n", D("|  |  |  |"), T(name, "p o s t e r n"))
	fmt.Fprintf(w, "    %s\n", D("|  '--'  |"))
	fmt.Fprintf(w, "    %s      %s\n", D("|  .--. o|"), T(dim, "SSRF & Host-Header recon"))
	fmt.Fprintf(w, "    %s\n", D("|  |  |  |"))
	fmt.Fprintf(w, "    %s      %s\n", D("|  '--'  |"), T(dim, "slip in through the side gate"))
	fmt.Fprintf(w, "    %s      %s\n", D("'--------'"), T(dim, "authorized use only"))
	fmt.Fprintln(w)
}

func bannerColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
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

const usageText = `postern - SSRF and Host-Header fuzzer (authorized testing only)

USAGE:
  postern -r <request> -mode <ssrf|host|both> [options]

MODES:
  ssrf   inject SSRF payloads at a parameter or FUZZ marker
  host   Host-Header attacks (override headers x values, routing SSRF)
  both   run ssrf then host


TARGET:
  -r <file>               raw HTTP request file (Burp "Copy to file")  [required]
  -mode <ssrf|host|both>  attack mode  (default ssrf)
  -url <scheme://h[:p]>   connect override (else taken from Host header)
  -tls                    use TLS when -url is not given
  -proxy <host:port>      route every request through an HTTP proxy (Burp)
  -H <"Name: Value">      add a header to every request  (repeatable)

INJECTION:
  -p <name|auto|all>      parameter to fuzz, or auto / all; else FUZZ marker
  -list-params            list request parameters (candidates marked *), then exit

SSRF:
  -sweep <spec>           /24 last-octet sweep: "private" or "10.10.10,192.168.56"
  -rebind <ext:int>       DNS-rebinding hosts (1u.ms, rbndr.us) for TOCTOU filters
  -ports <spec>           port-scan via SSRF: top | all | CSV | range (80,6379|1-1024)
  -scan-host <host>       host to port-scan  (default 127.0.0.1)

HOST-HEADER:
  -probe                  probe headers first, drop the ineffective ones (keep core)
  -path <path>            replace the request path (e.g. /admin)
  -paths <default|file>   replay each host case across a path list

PLACEHOLDERS:
  -lhost <addr>           {{LHOST}}  - your server for redirect tricks
  -evil <host>            {{EVIL}}   - attacker host for poisoning (else OOB)
  -itarget <addr>         {{TARGET}} - internal address to wrap  (default 127.0.0.1)
  -payloads <dir>         payload dir to override the embedded lists

DETECTION:
  -match <list>           extra body signatures (comma-separated) = strong hit
  -lenpct <n>             body-length delta percent to flag  (default 25)
  -interactsh             built-in interactsh client for blind OOB (auto-confirm)
  -interactsh-server <u>  self-hosted interactsh server  (default public)
  -interactsh-token <t>   server auth token (or env POSTERN_INTERACTSH_TOKEN)
  -oob-wait <dur>         keep polling for callbacks after the run  (default 30s)
  -oob <domain>           manual OOB: your interactsh domain + correlation map
  -oobmap <file>          OOB map file  (default oob-map-<ts>.txt)

RATE / SAFETY:
  -rate <n>               global requests/sec, 0 = unlimited  (default 25)
  -c <n>                  concurrent workers  (default 10)
  -delay <dur>            fixed pause before each request
  -jitter <dur>           random extra pause up to this value
  -timeout <dur>          per-request timeout  (default 10s)
  -retries <n>            network-error retries before recording  (default 1)
  -max <n>                abort before start if cases exceed n  (0 = no cap)
  -max-errors <n>         circuit-breaker threshold  (default 25)

OUTPUT:
  -o <file>               write results as JSON Lines
  -v                      print every result, not just interesting ones
  -silent                 suppress the startup banner
  -k                      skip TLS certificate verification  (default true)
EXAMPLES:
  # recon: what parameters are in the request
  postern -r req.txt -list-params

  # SSRF on one parameter, confirm blind hits with the built-in interactsh
  postern -r req.txt -mode ssrf -p imageUrl -interactsh

  # SSRF: let postern pick the candidate parameters
  postern -r req.txt -mode ssrf -p auto -interactsh

  # SSRF to cloud metadata via DNS rebinding (TOCTOU bypass)
  postern -r req.txt -mode ssrf -p url -rebind 1.2.3.4:169.254.169.254

  # Host-Header: prune dead headers, match an app-specific indicator
  postern -r req.txt -mode host -probe -match "ADMIN PANEL"

  # routing-based SSRF: internal ranges x internal paths
  postern -r req.txt -mode host -probe -sweep private -paths default

  # port-scan localhost through a confirmed SSRF
  postern -r req.txt -mode ssrf -p url -ports top

  # network scan: every private host x common ports, go gently
  postern -r req.txt -mode ssrf -p url -sweep private -ports 80,443,6379 -rate 10

  # run everything through Burp and print all results
  postern -r req.txt -mode both -proxy 127.0.0.1:8080 -v
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
	flag.BoolVar(&cfg.silent, "silent", false, "suppress the startup banner")
	flag.StringVar(&cfg.urlFlag, "url", "", "override target: scheme://host[:port]")
	flag.BoolVar(&cfg.tls, "tls", false, "target over TLS (when -url not given)")
	flag.StringVar(&cfg.proxy, "proxy", "", "HTTP proxy host:port (e.g. Burp 127.0.0.1:8080)")
	flag.IntVar(&cfg.conc, "c", 10, "concurrent workers")
	flag.Float64Var(&cfg.rate, "rate", 25, "global requests/sec (0 = unlimited, use with care)")
	flag.DurationVar(&cfg.delay, "delay", 0, "delay before each request (e.g. 200ms)")
	flag.DurationVar(&cfg.jitter, "jitter", 0, "random extra delay up to this value")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.insecure, "k", true, "skip TLS certificate verification")
	flag.StringVar(&cfg.oobBase, "oob", "", "interactsh base domain for blind detection (external client + map)")
	flag.StringVar(&cfg.oobMap, "oobmap", "", "file for the OOB correlation map")
	flag.BoolVar(&cfg.interactsh, "interactsh", false, "built-in interactsh client: register, poll, and auto-confirm blind hits")
	flag.StringVar(&cfg.interactshServer, "interactsh-server", "", "self-hosted interactsh server URL (default: public servers)")
	flag.StringVar(&cfg.interactshToken, "interactsh-token", "", "auth token for a self-hosted interactsh server (or env POSTERN_INTERACTSH_TOKEN)")
	flag.DurationVar(&cfg.oobWait, "oob-wait", 30*time.Second, "after the run, keep polling interactsh this long for delayed callbacks")
	flag.StringVar(&cfg.lhost, "lhost", "", "value for {{LHOST}}")
	flag.StringVar(&cfg.evil, "evil", "", "value for {{EVIL}} host poisoning (else OOB)")
	flag.StringVar(&cfg.itarget, "itarget", "127.0.0.1", "value for {{TARGET}} internal address")
	flag.StringVar(&cfg.sweep, "sweep", "", "last-octet /24 sweep: 'private' or custom list like '10.10.10,192.168.56'")
	flag.StringVar(&cfg.rebind, "rebind", "", "DNS rebinding bypass: 'ext:int' IPs, or 'int' (ext defaults 1.2.3.4); builds 1u.ms/rbndr.us hosts")
	flag.StringVar(&cfg.ports, "ports", "", "post-SSRF scan: port spec 'top', CSV '80,6379', or range '1-1024' (ssrf mode)")
	flag.StringVar(&cfg.scanHost, "scan-host", "", "post-SSRF scan: host to port-scan (default 127.0.0.1; or use -sweep for a network scan)")
	flag.StringVar(&cfg.path, "path", "", "host mode: single request path to use (e.g. /admin), overrides the request path")
	flag.StringVar(&cfg.paths, "paths", "", "host mode: path list - 'default' (built-in paths.txt) or a file; multiplies the host matrix")
	flag.StringVar(&cfg.payloads, "payloads", "payloads", "payload directory to override the embedded lists")
	flag.StringVar(&cfg.out, "o", "", "write results as JSONL to this file")
	flag.BoolVar(&cfg.verbose, "v", false, "print all results, not only interesting")
	flag.IntVar(&cfg.lenPct, "lenpct", 25, "body-length delta threshold (%) to flag")
	flag.StringVar(&cfg.match, "match", "", "extra body signatures (comma-separated), treated as strong hits")
	flag.BoolVar(&cfg.probe, "probe", false, "host mode: probe each header first, skip the ones with no visible effect (keeps core headers)")
	flag.IntVar(&cfg.max, "max", 0, "abort before start if case count exceeds this (0 = no cap)")
	flag.IntVar(&cfg.maxErrors, "max-errors", 25, "circuit breaker: consecutive errors / sustained slow responses before auto-stop")
	flag.IntVar(&cfg.retries, "retries", 1, "retries on network error before recording a result (a transient reset != closed port)")
	flag.Var(&cfg.extraHdrs, "H", "extra header for every request (repeatable): -H 'Name: Value'")
	flag.Parse()
	return cfg
}

func run(cfg *config) error {
	if !cfg.silent {
		printBanner(os.Stderr)
	}
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

	pfs, payloadSrc, err := payloadFS(cfg.payloads)
	if err != nil {
		return fmt.Errorf("payloads: %w", err)
	}
	_ = payloadSrc

	markers, _ := loadMarkers(pfs)
	for _, m := range strings.Split(cfg.match, ",") {
		if m = strings.TrimSpace(m); m != "" {
			markers = append(markers, m)
		}
	}

	var printMu sync.Mutex

	var oobProvider gen.OOB
	var oobClient *oob.Client
	var staticMapper *oob.Mapper
	oobMapPath := cfg.oobMap
	if cfg.interactsh {
		token := cfg.interactshToken
		if token == "" {
			token = os.Getenv("POSTERN_INTERACTSH_TOKEN")
		}
		cl, err := oob.NewClient(cfg.interactshServer, token, func(h oob.Hit) {
			printMu.Lock()
			fmt.Printf("[OOB   ] %-28s via %-4s from %s\n", short(h.Label, 28), h.Protocol, h.Remote)
			printMu.Unlock()
		})
		if err != nil {
			return fmt.Errorf("interactsh client: %w", err)
		}
		oobClient = cl
		oobProvider = cl
		defer cl.Close()
	} else {
		if cfg.oobBase != "" && oobMapPath == "" {
			oobMapPath = fmt.Sprintf("oob-map-%d.txt", time.Now().Unix())
		}
		m, err := oob.New(cfg.oobBase, oobMapPath)
		if err != nil {
			return fmt.Errorf("oob map: %w", err)
		}
		staticMapper = m
		oobProvider = m
		defer m.Close()
	}

	ports, err := parsePorts(cfg.ports)
	if err != nil {
		return err
	}
	var scanHosts []string
	if len(ports) > 0 {
		switch {
		case cfg.scanHost != "":
			scanHosts = []string{cfg.scanHost}
		case cfg.sweep != "":
			for _, base := range parseSweep(cfg.sweep) {
				base = strings.TrimSuffix(base, ".")
				for i := 0; i <= 255; i++ {
					scanHosts = append(scanHosts, fmt.Sprintf("%s.%d", base, i))
				}
			}
		default:
			scanHosts = []string{"127.0.0.1"}
		}
	}
	rebindHosts, err := parseRebind(cfg.rebind, cfg.itarget)
	if err != nil {
		return err
	}
	params := gen.Params{LHOST: cfg.lhost, TARGET: cfg.itarget, EVIL: cfg.evil, HOST: sni, Sweep: parseSweep(cfg.sweep), ScanHosts: scanHosts, Ports: ports, Rebind: rebindHosts}

	sopts := sender.Options{
		DialAddr: dialAddr, TLS: useTLS, Proxy: cfg.proxy, TargetHost: targetHost,
		Method: base.Method, SNI: sni, Insecure: cfg.insecure, Timeout: cfg.timeout, Retries: cfg.retries,
	}

	fmt.Printf("[*] target: %s  TLS=%v  proxy=%q  method=%s\n", targetHost, useTLS, cfg.proxy, base.Method)
	var durs []time.Duration
	var lastOK sender.Result
	var lastErr error
	for i := 0; i < 5; i++ {
		r := sender.Send(sopts, base.Bytes())
		if r.Err == nil {
			durs = append(durs, r.Duration)
			lastOK = r
		} else {
			lastErr = r.Err
		}
	}
	var bl detect.Baseline
	if len(durs) == 0 {
		fmt.Printf("[!] baseline failed: %v - diff will be coarser\n", lastErr)
		bl = detect.NewBaseline(0, nil, 0, 0, markers)
	} else {
		mean, std := meanStd(durs)
		bl = detect.NewBaseline(lastOK.Status, lastOK.Body, mean, std, markers)
		fmt.Printf("[*] baseline: status=%d len=%d hash=%s timing=%s±%s (n=%d)\n",
			lastOK.Status, lastOK.BodyLen, detect.HashBody(lastOK.Body),
			mean.Round(time.Millisecond), std.Round(time.Millisecond), len(durs))
	}

	var cases []gen.Case
	if cfg.mode == "ssrf" || cfg.mode == "both" {
		sc, err := gen.SSRF(pfs, params, oobProvider)
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
			allow = probeHeaders(cfg, pfs, base, sopts, bl, markers)
		}
		pathList, err := resolvePaths(cfg, pfs)
		if err != nil {
			return err
		}
		hc, err := gen.Host(pfs, params, oobProvider, allow, pathList)
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
	if oobClient != nil {
		fmt.Printf(" | OOB: interactsh %s (live)", oobClient.Domain())
	} else if staticMapper.Enabled() {
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

	slowCut := bl.SlowThreshold() * 3
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
		if bl.Mean > 0 && res.Duration > slowCut {
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

	if oobClient != nil {
		if nOOB > 0 && ctx.Err() == nil && cfg.oobWait > 0 {
			fmt.Printf("[*] waiting %s for delayed OOB callbacks (Ctrl-C to skip)...\n", cfg.oobWait)
			waitInterruptible(ctx, cfg.oobWait)
		}
		hits := oobClient.Hits()
		fmt.Printf("[*] OOB (interactsh %s): %d confirmed callback(s)\n", oobClient.Domain(), len(hits))
		for _, h := range hits {
			fmt.Printf("    [%s] %s  from %s\n", h.Protocol, h.Label, h.Remote)
		}
	} else if staticMapper.Enabled() {
		fmt.Printf("[*] check interactsh-client for callbacks; payload mapping in %s\n", oobMapPath)
	}
	return nil
}

func waitInterruptible(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
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

var (
	reIPv4    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reB64Like = regexp.MustCompile(`^[A-Za-z0-9+/_-]{12,}={0,2}$`)
)

func isCandidate(p rawreq.Param) bool {
	name := strings.ToLower(p.Name)
	for _, kw := range ssrfParamKeywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	raw := strings.TrimSpace(p.Value)
	v := strings.ToLower(raw)
	switch {
	case strings.Contains(v, "://"), strings.HasPrefix(v, "http"), strings.HasPrefix(v, "//"), strings.HasPrefix(v, "/"):
		return true
	case reIPv4.MatchString(v):
		return true
	case strings.Contains(v, "../") || strings.Contains(v, "..%2f") || strings.Contains(v, "%2e%2e"):
		return true
	case reB64Like.MatchString(raw) && decodedLooksURL(raw):
		return true
	}
	return false
}

func decodedLooksURL(s string) bool {
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := dec.DecodeString(s); err == nil {
			if d := strings.ToLower(string(b)); strings.Contains(d, "://") || strings.HasPrefix(d, "http") {
				return true
			}
		}
	}
	return false
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

func probeHeaders(cfg *config, pfs fs.FS, base *rawreq.Request, sopts sender.Options, bl detect.Baseline, markers []string) map[string]bool {
	headers, err := gen.LoadHostHeaders(pfs)
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

func resolvePaths(cfg *config, pfs fs.FS) ([]string, error) {
	if cfg.paths != "" {
		var b []byte
		var err error
		switch strings.ToLower(cfg.paths) {
		case "default", "all":
			b, err = fs.ReadFile(pfs, "paths.txt")
		default:
			b, err = os.ReadFile(cfg.paths)
		}
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

// topPorts is ordered by likelihood: web first, then DBs/stores, services,
// container/k8s, message/queues, remote access, then round "dev app" ports.
var topPorts = []int{
	80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8082,
	3306, 5432, 6379, 27017, 1433, 1521, 9200, 9300, 11211, 5984, 9042, 2181,
	22, 21, 23, 25, 53, 110, 135, 139, 143, 389, 445, 465, 587, 993, 995, 2049,
	2375, 2379, 6443, 10250, 10255,
	5601, 5672, 15672, 9092, 8086, 8500, 7001, 4444,
	3389, 5900,
	3000, 5000, 9000, 1000, 2000, 4000, 6000, 7000, 10000, 3001, 4200, 5173, 9001, 9999,
}

// priorityPorts defines the front-loaded order used when expanding ranges.
var priorityPorts = topPorts

func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch strings.ToLower(s) {
	case "top", "common", "default":
		return topPorts, nil
	case "all":
		set := map[int]bool{}
		for i := 1; i <= 65535; i++ {
			set[i] = true
		}
		return orderByPriority(set), nil
	}

	set := map[int]bool{}
	var order []int
	hasRange := false
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			hasRange = true
			se := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(se[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(se[1]))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for i := a; i <= b; i++ {
				set[i] = true
			}
		} else {
			v, err := strconv.Atoi(part)
			if err != nil || v < 1 || v > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			if !set[v] {
				order = append(order, v)
				set[v] = true
			}
		}
	}
	if hasRange {
		return orderByPriority(set), nil
	}
	return order, nil
}

func orderByPriority(set map[int]bool) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range priorityPorts {
		if set[p] && !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	rest := make([]int, 0, len(set))
	for p := range set {
		if !seen[p] {
			rest = append(rest, p)
		}
	}
	sort.Ints(rest)
	return append(out, rest...)
}

func meanStd(ds []time.Duration) (mean, std time.Duration) {
	if len(ds) == 0 {
		return 0, 0
	}
	var sum float64
	for _, d := range ds {
		sum += float64(d)
	}
	m := sum / float64(len(ds))
	var variance float64
	for _, d := range ds {
		diff := float64(d) - m
		variance += diff * diff
	}
	variance /= float64(len(ds))
	return time.Duration(m), time.Duration(math.Sqrt(variance))
}

func parseRebind(s, itarget string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	ext, intip := "1.2.3.4", itarget
	if s != "default" && s != "on" {
		if i := strings.IndexByte(s, ':'); i >= 0 {
			ext, intip = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
		} else {
			intip = s
		}
	}
	if net.ParseIP(ext).To4() == nil || net.ParseIP(intip).To4() == nil {
		return nil, fmt.Errorf("-rebind needs IPv4 addresses (got ext=%q int=%q)", ext, intip)
	}
	hosts := []string{fmt.Sprintf("make-%s-rebind-%s-rr.1u.ms", ext, intip)}
	if he, ok1 := ipv4Hex(ext); ok1 {
		if hi, ok2 := ipv4Hex(intip); ok2 {
			hosts = append(hosts, he+"."+hi+".rbndr.us")
		}
	}
	return hosts, nil
}

func ipv4Hex(s string) (string, bool) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return "", false
	}
	return fmt.Sprintf("%02x%02x%02x%02x", ip[0], ip[1], ip[2], ip[3]), true
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

func loadMarkers(pfs fs.FS) ([]string, error) {
	b, err := fs.ReadFile(pfs, "markers.txt")
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
