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
	sweepEnc         string
	rebind           string
	rebindOnly       bool
	repeat           int
	ports            string
	scanHost         string
	scanEnc          string
	followRedirects  int
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
	timing           bool
	listParams       bool
	silent           bool
	cloud            string
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

WORKFLOW (typical staged run):
  1. postern -r req.txt -list-params                      # what's injectable
  2. postern -r req.txt -mode ssrf -p auto -interactsh    # find SSRF (in-band + blind)
  3. postern -r req.txt -mode host -probe -match "Admin"  # host-header / admin bypass
  4. ... -scan-host 10.0.0.5 -ports top                   # scan one internal host
  5. ... -sweep private -ports 80,6379 -rate 10           # map the internal network
  Confirmed a bypass on one host? Re-run the sweep with just that encoding
  (-sweep-encode decimal) to keep the volume sane.

TARGET:
  -r <file>               raw HTTP request file (Burp "Copy to file")  [required]
  -mode <ssrf|host|both>  attack mode  (default ssrf)
  -url <scheme://h[:p]>   connect override (else taken from Host header)
  -tls                    use TLS when -url is not given
  -proxy <host:port>      route every request through an HTTP proxy (Burp)
  -H <"Name: Value">      add a header to every request  (repeatable)
  -cloud <preset>         metadata preset, sets the required header:
                          gcp|yandex (Metadata-Flavor: Google), azure, all

INJECTION:
  -p <name|auto|all>      parameter to fuzz, or auto / all; else FUZZ marker
  -list-params            list request parameters (candidates marked *), then exit

SSRF:
  -sweep <spec>           /24 last-octet sweep: "private" or "10.10.10,192.168.56"
  -sweep-encode <spec>    encode swept IPs to bypass filters: "all" or "decimal,hex"
  -rebind <ext:int>       DNS-rebinding hosts (1u.ms, rbndr.us) for TOCTOU filters
  -rebind-only            generate only -rebind cases (pair with -repeat)
  -repeat <n>             send each case n times (race / rebind retries)
  -ports <spec>           port-scan via SSRF: top | all | CSV | range (80,6379|1-1024)
  -scan-host <host>       host to port-scan  (default 127.0.0.1)
  -scan-encode <spec>     encode the -scan-host host: "all" or "decimal,hex"

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
  -follow-redirects <n>   follow up to n 3xx hops to the final response (off)
  -timing                 flag slow responses as hits (off; noisy on VPN/THM)
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

  # Yandex Cloud / GCP metadata (token needs the Metadata-Flavor header)
  postern -r req.txt -mode ssrf -p url -cloud yandex

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

  # scan behind a filter that blocks plain IPs but resolves decimal
  postern -r req.txt -mode ssrf -p url -scan-host 172.28.0.20 -scan-encode decimal -ports 5000,5432

  # hammer only the rebinding payloads to win a TOCTOU race
  postern -r req.txt -mode ssrf -p url -rebind-only -rebind 1.2.3.4:169.254.169.254 -repeat 50 -follow-redirects 3

  # JSON body with a list of URLs ({"urls":["..."]}) - fuzz the array
  postern -r req.txt -mode ssrf -p urls -interactsh

  # follow a redirect chain while keeping an injected Host (admin bypass)
  postern -r req.txt -mode host -path /redir1 -follow-redirects 3 -match "Dashboard"

  # run everything through Burp and print all results
  postern -r req.txt -mode both -proxy 127.0.0.1:8080 -v

WHERE POSTERN FITS (it is not a dirbuster or a port scanner):
  ffuf / feroxbuster   discover parameters and paths. Use them to find the
                       injectable param, then postern to fuzz SSRF/host bypasses
                       into that known request.
  nmap                 scans a host from the outside. postern port-scans INTERNAL
                       hosts THROUGH a confirmed SSRF - the target scans for you,
                       reaching services nmap can't see from outside.
  SSRFmap              weaponizes an SSRF (RCE, pivot, file read). postern finds
                       and confirms the bypass first; its -r/-p input is
                       compatible, so hand the finding straight over.
  ReSSRF / nuclei      also fuzz params/headers for SSRF callbacks (OOB). postern
                       adds a raw-request input, generated/tagged IP encodings,
                       real Host-Header attacks, scan-through-bypass and rebind.

SELECTED FLAGS:
  -p auto              fuzz only parameters that look SSRF-capable (url/host-like
                       names, URL/IP/base64 values); -p all fuzzes every param.
  -sweep-encode <k>    apply an IP encoding to each swept host - use the one you
                       already confirmed bypasses the filter, not "all".
  -probe               in host mode, send each header once and keep only the ones
                       that change the response (core headers always kept).
  -follow-redirects n  chase 3xx to the final response; an injected Host survives
                       relative redirects (redirect-chain host-header attacks).
  -interactsh          built-in blind/OOB confirmation - the only way to see a
                       blind SSRF (one with no visible response difference).
  -rate / -max         stay safe on live targets: cap requests/sec and total cases.
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
	flag.StringVar(&cfg.sweepEnc, "sweep-encode", "", "encode swept IPs to bypass filters: 'all' or CSV 'decimal,hex,octal' (use after a bypass is found)")
	flag.StringVar(&cfg.rebind, "rebind", "", "DNS rebinding bypass: 'ext:int' IPs, or 'int' (ext defaults 1.2.3.4); builds 1u.ms/rbndr.us hosts")
	flag.BoolVar(&cfg.rebindOnly, "rebind-only", false, "generate only -rebind cases (skip the standard SSRF set); pair with -repeat to win TOCTOU races")
	flag.IntVar(&cfg.repeat, "repeat", 1, "send each case this many times (race conditions / DNS-rebinding retries)")
	flag.StringVar(&cfg.ports, "ports", "", "post-SSRF scan: port spec 'top', CSV '80,6379', or range '1-1024' (ssrf mode)")
	flag.StringVar(&cfg.scanHost, "scan-host", "", "post-SSRF scan: host to port-scan (default 127.0.0.1; or use -sweep for a network scan)")
	flag.StringVar(&cfg.scanEnc, "scan-encode", "", "encode the -scan-host host to bypass filters: 'all' or CSV 'decimal,hex,octal' (backend must resolve it)")
	flag.IntVar(&cfg.followRedirects, "follow-redirects", 0, "follow up to N 3xx hops to the final response (0 = off; useful for redirect/rebind chains)")
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
	flag.BoolVar(&cfg.timing, "timing", false, "flag slow responses as hits (blind-timing signal; off by default - noisy on jittery links)")
	flag.StringVar(&cfg.cloud, "cloud", "", "metadata preset - adds the provider's required header: gcp|yandex|azure|all")
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
	// -cloud preset: GCP-style metadata (incl. Yandex Cloud) needs
	// "Metadata-Flavor: Google"; Azure needs "Metadata: true". Without the header
	// those endpoints refuse the IAM token, so set it for the whole run.
	switch strings.ToLower(strings.TrimSpace(cfg.cloud)) {
	case "":
	case "gcp", "gce", "yandex":
		cfg.extraHdrs = append(cfg.extraHdrs, "Metadata-Flavor: Google")
	case "azure":
		cfg.extraHdrs = append(cfg.extraHdrs, "Metadata: true")
	case "all":
		cfg.extraHdrs = append(cfg.extraHdrs, "Metadata-Flavor: Google", "Metadata: true")
	default:
		return fmt.Errorf("unknown -cloud preset %q (use gcp|yandex|azure|all)", cfg.cloud)
	}
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
	// {{HOST}} is the whitelisted domain the app sees (Host header), not the dial
	// target: with -url pointing at a lab IP, the Host header still carries the domain.
	hostHdr := sni
	if base.Host != "" {
		h := base.Host
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		hostHdr = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	if cfg.rebindOnly && len(rebindHosts) == 0 {
		return fmt.Errorf("-rebind-only requires -rebind")
	}
	params := gen.Params{LHOST: cfg.lhost, TARGET: cfg.itarget, EVIL: cfg.evil, HOST: hostHdr, Sweep: parseSweep(cfg.sweep), SweepEnc: parseSweepEnc(cfg.sweepEnc), ScanEnc: parseSweepEnc(cfg.scanEnc), ScanHosts: scanHosts, Ports: ports, Rebind: rebindHosts, RebindOnly: cfg.rebindOnly}

	sopts := sender.Options{
		DialAddr: dialAddr, TLS: useTLS, Proxy: cfg.proxy, TargetHost: targetHost,
		Method: base.Method, SNI: sni, Insecure: cfg.insecure, Timeout: cfg.timeout, Retries: cfg.retries,
		FollowRedirects: cfg.followRedirects,
	}

	clean := !cfg.verbose
	if clean {
		fmt.Printf("  Target:  %s  (%s)\n", targetHost, base.Method)
	} else {
		fmt.Printf("[*] target: %s  TLS=%v  proxy=%q  method=%s\n", targetHost, useTLS, cfg.proxy, base.Method)
	}
	encPfx, redPfx := "  Encoding: ", "  Redirects: "
	if !clean {
		encPfx, redPfx = "[*] encode: ", "[*] follow-redirects: "
	}
	if enc := parseSweepEnc(cfg.scanEnc); len(ports) > 0 && len(enc) > 0 {
		fmt.Printf("%shost as %s\n", encPfx, strings.Join(enc, ", "))
	} else if enc := parseSweepEnc(cfg.sweepEnc); len(enc) > 0 {
		fmt.Printf("%sinternal IPs as %s\n", encPfx, strings.Join(enc, ", "))
	}
	if cfg.followRedirects > 0 {
		fmt.Printf("%sup to %d hop(s)\n", redPfx, cfg.followRedirects)
	}
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
		fmt.Printf("[!] no baseline response (%v) - flagging only signature/reflection/OOB hits;\n    raise -timeout or lower -rate on a slow target to get a baseline\n", lastErr)
		bl = detect.NewBaseline(0, nil, 0, 0, markers)
	} else {
		mean, std := meanStd(durs)
		bl = detect.NewBaseline(lastOK.Status, lastOK.Body, mean, std, markers)
		if !clean {
			fmt.Printf("[*] baseline: status=%d len=%d hash=%s timing=%s±%s (n=%d)\n",
				lastOK.Status, lastOK.BodyLen, detect.HashBody(lastOK.Body),
				mean.Round(time.Millisecond), std.Round(time.Millisecond), len(durs))
		}
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

	if cfg.repeat > 1 {
		orig := cases
		cases = make([]gen.Case, 0, len(orig)*cfg.repeat)
		for r := 0; r < cfg.repeat; r++ {
			for _, c := range orig {
				if r > 0 {
					c.ID = fmt.Sprintf("%s.%d", c.ID, r)
				}
				cases = append(cases, c)
			}
		}
	}

	if cfg.max > 0 && len(cases) > cfg.max {
		return fmt.Errorf("case count %d exceeds -max %d; narrow scope (-probe, smaller -sweep/-paths) or raise -max", len(cases), cfg.max)
	}

	oobNote := ""
	if oobClient != nil {
		oobNote = ", blind check via interactsh"
	}
	if clean {
		eta := ""
		if cfg.rate > 0 {
			eta = fmt.Sprintf(", ~%s", time.Duration(float64(len(cases))/cfg.rate*float64(time.Second)).Round(time.Second))
		}
		fmt.Printf("  Sending: %d payloads%s%s\n", len(cases), eta, oobNote)
		if cfg.rate == 0 {
			fmt.Printf("  %s\n", "Note: rate is unlimited (-rate 0) - this can overwhelm the target; Ctrl-C to abort")
		}
		fmt.Println()
	} else {
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
	}

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
		nStood        int64
		consecErr     int64
		slowStreak    int64
		tripped       int32
		clMu          sync.Mutex
		clusters      = map[string]*cluster{}
		notable       = map[string]*noteCat{} // category -> count+examples (differs from baseline)
		findMu        sync.Mutex
		findings      []finding
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

	// Clean mode on a TTY shows a single self-updating progress line (declared
	// here so process can clear it before printing a live finding above it).
	showProgress := clean && !cfg.silent && isTTY(os.Stdout)
	var liveGrn, liveRst string
	var cGrn, cYel, cDim, cRst string
	if bannerColor(os.Stdout) {
		liveGrn, liveRst = "\033[32m", "\033[0m"
		cGrn, cYel, cDim, cRst = "\033[32m", "\033[33m", "\033[90m", "\033[0m"
	}
	var nLive int64
	const liveCap = 25
	// emitLive surfaces a high-value hit the instant it happens (above the progress
	// line), so the user can act or Ctrl-C mid-scan. Capped to avoid flooding.
	emitLive := func(msg, label string) {
		if !clean {
			return
		}
		n := atomic.AddInt64(&nLive, 1)
		if n > liveCap {
			return
		}
		printMu.Lock()
		if showProgress {
			fmt.Print("\r\033[K")
		}
		fmt.Printf("  %s✓ %s%s  %s\n", liveGrn, msg, liveRst, label)
		if n == liveCap {
			fmt.Printf("  %s… more below in the summary%s\n", liveGrn, liveRst)
		}
		printMu.Unlock()
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
			// In port-scan mode a non-dial error (timeout/reset while the app
			// fetches a closed internal port) is scan feedback, not a sign the
			// target is dying - only count dial failures toward the breaker.
			countErr := cfg.ports == "" || res.Kind == "dial"
			if countErr && atomic.AddInt64(&consecErr, 1) >= int64(cfg.maxErrors) {
				trip(fmt.Sprintf("%d consecutive request errors", cfg.maxErrors))
			}
			if cfg.verbose {
				printMu.Lock()
				fmt.Printf("[err] %-6s %-40s %v\n", c.ID, short(labelTag(c), 40), res.Err)
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

		recordCluster(fmt.Sprintf("%d/%d", res.Status, res.BodyLen), short(labelTag(c), 60))
		sig := detect.Analyze(bl, res.Status, res.Body, res.Duration, markers, cfg.lenPct, c.Payload, res.Header, cfg.timing)
		if res.Redirects > 0 {
			sig.Interesting = true
			sig.Reasons = append(sig.Reasons, fmt.Sprintf("followed %dr", res.Redirects))
		}
		if sig.Strong {
			atomic.AddInt64(&nStrong, 1)
			what := humanizeStrong(sig.Reasons)
			findMu.Lock()
			if len(findings) < 50 {
				findings = append(findings, finding{what: what, label: short(labelTag(c), 60)})
			}
			findMu.Unlock()
			emitLive(what, short(labelTag(c), 60))
		}
		if sig.Interesting {
			atomic.AddInt64(&nInt, 1)
			atomic.AddInt64(&nStood, 1)
			cat := statusClass(res.Status)
			clMu.Lock()
			nb := notable[cat]
			if nb == nil {
				nb = &noteCat{}
				notable[cat] = nb
			}
			nb.count++
			if len(nb.ex) < 3 {
				nb.ex = append(nb.ex, short(labelTag(c), 60))
			}
			clMu.Unlock()
			// A 2xx that differs from the baseline = reached the backend / got into
			// an admin panel: the key host-mode win, so stream it live too (5xx/4xx
			// stay quiet to avoid noise).
			if !sig.Strong && cat == "BYPASS" {
				emitLive(fmt.Sprintf("reached the backend (HTTP %d)", res.Status), short(labelTag(c), 60))
			}
		}

		// Verbose mode prints every noteworthy request; clean mode stays quiet and
		// lets the live progress line + the final summary do the talking.
		if cfg.verbose && (sig.Interesting || c.OOB != "") {
			tag, col := "other ", cDim
			switch {
			case sig.Strong:
				tag, col = "found ", cGrn
			case c.OOB != "":
				tag, col = "oob   ", cGrn
			case res.Status >= 200 && res.Status < 300:
				tag, col = "bypass", cGrn
			case res.Status >= 500:
				tag, col = "error ", cYel
			case res.Status >= 400:
				tag, col = "blocked", cDim
			}
			reason := prettyReasons(sig.Reasons)
			if c.OOB != "" {
				reason = strings.TrimSpace(reason + " OOB:" + c.OOB)
			}
			line := fmt.Sprintf("  %s%-7s%s %3d %6dB  %-52s %s%s%s",
				col, tag, cRst, res.Status, res.BodyLen, short(labelTag(c), 52), cDim, reason, cRst)
			printMu.Lock()
			fmt.Println(line)
			printMu.Unlock()
		}
		writeJSON(outFile, &printMu, c, res, sig, nil)
	}

	progDone := make(chan struct{})
	if showProgress {
		go func() {
			t := time.NewTicker(150 * time.Millisecond)
			defer t.Stop()
			total := int64(len(cases))
			draw := func() {
				sent := atomic.LoadInt64(&nSent)
				pct := int64(0)
				if total > 0 {
					pct = sent * 100 / total
				}
				printMu.Lock()
				fmt.Printf("\r\033[K  scanning... %d/%d (%d%%)   stood out: %d", sent, total, pct, atomic.LoadInt64(&nStood))
				printMu.Unlock()
			}
			for {
				select {
				case <-progDone:
					return
				case <-t.C:
					draw()
				}
			}
		}()
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
	if showProgress {
		close(progDone)
		printMu.Lock()
		fmt.Print("\r\033[K")
		printMu.Unlock()
	}

	aborted := ctx.Err() != nil && atomic.LoadInt32(&tripped) == 0

	// Wait for delayed OOB callbacks before the summary so confirmed hits are
	// counted in it.
	var oobHits int
	if oobClient != nil {
		if nOOB > 0 && ctx.Err() == nil && cfg.oobWait > 0 {
			if clean {
				fmt.Printf("  Waiting %s for out-of-band callbacks (Ctrl-C to skip)...\n", cfg.oobWait)
			} else {
				fmt.Printf("[*] waiting %s for delayed OOB callbacks (Ctrl-C to skip)...\n", cfg.oobWait)
			}
			waitInterruptible(ctx, cfg.oobWait)
		}
		hits := oobClient.Hits()
		oobHits = len(hits)
		for _, h := range hits {
			findMu.Lock()
			if len(findings) < 50 {
				findings = append(findings, finding{what: "out-of-band callback (" + h.Protocol + ")", label: short(h.Label, 60)})
			}
			findMu.Unlock()
		}
	}

	if clean {
		oobUsed := oobClient != nil || staticMapper.Enabled()
		printSummaryClean(os.Stdout, notable, findings, nSent, nErr, bl.Status, aborted, cfg.out, oobUsed)
	} else {
		fmt.Println(strings.Repeat("-", 72))
		if aborted {
			fmt.Printf("[!] aborted by user (Ctrl-C)\n")
		}
		fmt.Printf("[*] done: sent=%d interesting=%d strong=%d errors=%d oob-sent=%d\n",
			nSent, nInt, nStrong, nErr, nOOB)
		printClusters(clusters)
		if oobClient != nil {
			fmt.Printf("[*] OOB (interactsh %s): %d confirmed callback(s)\n", oobClient.Domain(), oobHits)
			for _, h := range oobClient.Hits() {
				fmt.Printf("    [%s] %s  from %s\n", h.Protocol, h.Label, h.Remote)
			}
		} else if staticMapper.Enabled() {
			fmt.Printf("[*] check interactsh-client for callbacks; payload mapping in %s\n", oobMapPath)
		}
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

// clusterCategory maps a cluster signature ("status/len" or "ERR") to a semantic
// outcome class so the summary reads as BLOCKED / ERROR / BYPASS at a glance.
func clusterCategory(sig string) string {
	if sig == "ERR" {
		return "NORESP"
	}
	slash := strings.IndexByte(sig, '/')
	if slash < 0 {
		return "OTHER"
	}
	status, err := strconv.Atoi(sig[:slash])
	if err != nil {
		return "OTHER"
	}
	switch {
	case status >= 200 && status < 300:
		return "BYPASS"
	case status >= 400 && status < 500:
		return "BLOCKED"
	case status >= 500:
		return "ERROR"
	default:
		return "OTHER"
	}
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

	// Semantic rollup: what actually happened, by response class.
	var bypass, errored, blocked, other, noResp int
	var bypassEx, errEx string
	for _, e := range all {
		switch clusterCategory(e.sig) {
		case "BYPASS":
			bypass += e.c.count
			if bypassEx == "" {
				bypassEx = e.c.example
			}
		case "ERROR":
			errored += e.c.count
			if errEx == "" {
				errEx = e.c.example
			}
		case "BLOCKED":
			blocked += e.c.count
		case "NORESP":
			noResp += e.c.count
		default:
			other += e.c.count
		}
	}
	fmt.Println("[*] outcome summary:")
	fmt.Printf("      BYPASS  (2xx, filter passed + backend served): %d", bypass)
	if bypassEx != "" {
		fmt.Printf("   e.g. %s", short(bypassEx, 45))
	}
	fmt.Println()
	fmt.Printf("      ERROR   (5xx, filter passed + backend broke) : %d", errored)
	if errEx != "" {
		fmt.Printf("   e.g. %s", short(errEx, 45))
	}
	fmt.Println()
	fmt.Printf("      BLOCKED (4xx, filter caught it)              : %d\n", blocked)
	fmt.Printf("      OTHER   (1xx/3xx)                            : %d\n", other)
	fmt.Printf("      NO-RESP (network error / no reply)           : %d\n", noResp)

	fmt.Printf("[*] response clusters (status/len, rare first) - %d unique:\n", len(all))
	limit := len(all)
	if limit > 20 {
		limit = 20
	}
	for _, e := range all[:limit] {
		fmt.Printf("    %6dx  %-14s  e.g. %s\n", e.c.count, e.sig, short(e.c.example, 50))
	}
}

type finding struct {
	what  string // human-readable description of the evidence
	label string // the payload / case that produced it
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// humanizeStrong turns detection reasons ("marker:root:x:0:0", "reflected-body")
// into a plain phrase a non-expert can act on.
func humanizeStrong(reasons []string) string {
	for _, r := range reasons {
		switch {
		case strings.HasPrefix(r, "marker:"):
			m := strings.ToLower(strings.TrimPrefix(r, "marker:"))
			switch {
			case strings.Contains(m, "root:x:0:0"), strings.Contains(m, "nologin"), strings.Contains(m, "/bin/bash"), strings.Contains(m, "daemon:"):
				return "read /etc/passwd"
			case strings.Contains(m, "localhost"):
				return "read /etc/hosts"
			case strings.Contains(m, "refcnt"), strings.Contains(m, "hw address"), strings.Contains(m, "nameserver"):
				return "read host network config (routes/ARP/DNS)"
			case strings.Contains(m, "kubepods"):
				return "read cgroup (Kubernetes pod)"
			case strings.Contains(m, "database_url"), strings.Contains(m, "db_password"), strings.Contains(m, "app_key"), strings.Contains(m, "secret_key"):
				return "read app config / secrets (.env)"
			case strings.Contains(m, "ami-id"), strings.Contains(m, "instance-id"), strings.Contains(m, "iam/security"), strings.Contains(m, "accesskeyid"), strings.Contains(m, "secretaccesskey"), strings.Contains(m, "security-credentials"):
				return "reached AWS metadata / credentials"
			case strings.Contains(m, "computemetadata"), strings.Contains(m, "access_token"), strings.Contains(m, "service-account"), strings.Contains(m, "oauth2"):
				return "reached GCP metadata / token"
			case strings.Contains(m, "vmid"), strings.Contains(m, "subscriptionid"), strings.Contains(m, "\"compute\":"):
				return "reached Azure metadata"
			case strings.Contains(m, "availability_zone"), strings.Contains(m, "random_seed"), strings.Contains(m, "securitytoken"):
				return "reached OpenStack metadata (VK/SberCloud/Selectel)"
			case strings.Contains(m, "redis_version"), strings.Contains(m, "+pong"), strings.Contains(m, "stat pid"):
				return "reached an internal service (Redis/Memcached)"
			case strings.Contains(m, "ssh-2.0"), strings.Contains(m, "ssh-1.99"), strings.Contains(m, "vsftpd"), strings.Contains(m, "proftpd"), strings.Contains(m, "esmtp"):
				return "reached an internal service (banner leaked)"
			case strings.Contains(m, "phpmyadmin"), strings.Contains(m, "index of"), strings.Contains(m, "directory listing"):
				return "reached an internal web page"
			default:
				return "matched a known response signature"
			}
		case strings.HasPrefix(r, "reflected"):
			return "server fetched our URL (reflected back)"
		}
	}
	if len(reasons) > 0 && reasons[0] != "-" {
		return reasons[0]
	}
	return "notable response"
}

type noteCat struct {
	count int
	ex    []string
}

// prettyReasons rewrites detection reasons for the verbose per-line view: status
// and length deltas get arrows, markers/reflection get their plain phrasing.
func prettyReasons(reasons []string) string {
	var out []string
	for _, r := range reasons {
		switch {
		case r == "-":
			continue
		case strings.HasPrefix(r, "status "):
			out = append(out, strings.ReplaceAll(strings.TrimPrefix(r, "status "), "->", "→"))
		case strings.HasPrefix(r, "len "):
			out = append(out, strings.ReplaceAll(r, "->", "→"))
		case strings.HasPrefix(r, "marker:"), strings.HasPrefix(r, "reflected"):
			out = append(out, humanizeStrong([]string{r}))
		default:
			out = append(out, r)
		}
	}
	return strings.Join(out, ", ")
}

func statusClass(s int) string {
	switch {
	case s == 0:
		return "NORESP"
	case s >= 200 && s < 300:
		return "BYPASS"
	case s >= 300 && s < 400:
		return "OTHER"
	case s >= 500:
		return "ERROR"
	case s >= 400 && s < 500:
		return "BLOCKED"
	default:
		return "OTHER"
	}
}

func describeStatus(status int) string {
	switch {
	case status == 0:
		return "no response"
	case status >= 200 && status < 300:
		return fmt.Sprintf("HTTP %d - OK", status)
	case status >= 300 && status < 400:
		return fmt.Sprintf("HTTP %d - redirect", status)
	case status == 401 || status == 403:
		return fmt.Sprintf("HTTP %d - blocked", status)
	case status == 404:
		return fmt.Sprintf("HTTP %d - not found", status)
	case status >= 400 && status < 500:
		return fmt.Sprintf("HTTP %d", status)
	case status >= 500:
		return fmt.Sprintf("HTTP %d - server error", status)
	default:
		return fmt.Sprintf("HTTP %d", status)
	}
}

// printSummaryClean is the human-facing wrap-up: confirmed findings, the response
// classes that differed from the baseline, a one-line verdict, and where to dig in.
// Only responses that differ from the baseline count as "notable"; everything that
// looked like the baseline is reported as a single typical-response total.
func printSummaryClean(w io.Writer, notable map[string]*noteCat, findings []finding, sent, nErr int64, baselineStatus int, aborted bool, outPath string, oobUsed bool) {
	color := bannerColor(w)
	var grn, yel, dim, bold, rst string
	if color {
		grn, yel, dim, bold, rst = "\033[32m", "\033[33m", "\033[90m", "\033[1m", "\033[0m"
	}

	fmt.Fprintln(w)
	if aborted {
		fmt.Fprintf(w, "  %sStopped early (Ctrl-C / circuit breaker).%s\n", yel, rst)
	}
	fmt.Fprintf(w, "  %sResults%s\n\n", bold, rst)

	if len(findings) > 0 {
		fmt.Fprintf(w, "  %s✓ Confirmed SSRF: %d%s\n", grn, len(findings), rst)
		shown, extra := findings, 0
		if len(shown) > 10 {
			extra, shown = len(shown)-10, shown[:10]
		}
		for _, f := range shown {
			fmt.Fprintf(w, "       %s%s%s  —  %s\n", grn, f.what, rst, f.label)
		}
		if extra > 0 {
			fmt.Fprintf(w, "       %s+%d more%s\n", dim, extra, rst)
		}
		fmt.Fprintln(w)
	}

	notableTotal := 0
	for _, b := range notable {
		notableTotal += b.count
	}

	labels := map[string]string{
		"BYPASS": grn + "● reached the backend (HTTP 2xx)" + rst,
		"ERROR":  yel + "● got past the filter, backend errored (HTTP 5xx)" + rst,
		"BLOCKED": "● blocked by the filter (HTTP 4xx)",
		"OTHER":   "● redirect / other response",
	}

	fmt.Fprintf(w, "  %d payloads sent.\n", sent)
	if notableTotal == 0 && len(findings) == 0 {
		fmt.Fprintf(w, "  %sEvery payload got the same response as the baseline (%s) - nothing stood out.%s\n\n",
			dim, describeStatus(baselineStatus), rst)
	} else {
		fmt.Fprintf(w, "  Responses that differed from the baseline (%s):\n\n", describeStatus(baselineStatus))
		for _, cat := range []string{"BYPASS", "ERROR", "BLOCKED", "OTHER"} {
			b := notable[cat]
			if b == nil {
				continue
			}
			fmt.Fprintf(w, "  %s  ×%d\n", labels[cat], b.count)
			for _, e := range b.ex {
				fmt.Fprintf(w, "       %s\n", e)
			}
		}
		if typical := sent - int64(notableTotal); typical > 0 {
			fmt.Fprintf(w, "  %s○ looked like the baseline (%s)  ×%d%s\n", dim, describeStatus(baselineStatus), typical, rst)
		}
		fmt.Fprintln(w)
	}
	if nErr > 0 {
		fmt.Fprintf(w, "  %s○ no response / network error  ×%d%s\n\n", dim, nErr, rst)
	}

	switch {
	case len(findings) > 0:
		fmt.Fprintf(w, "  → SSRF confirmed (above). Start there.\n")
	case notable["BYPASS"] != nil:
		fmt.Fprintf(w, "  → Some payloads reached the backend - inspect their responses (-v or -o).\n")
	case notable["ERROR"] != nil:
		fmt.Fprintf(w, "  → The filter let some payloads through (the backend errored on them).\n")
		fmt.Fprintf(w, "    The filter is bypassable; retry against a target whose fetcher resolves these forms.\n")
	case notable["BLOCKED"] != nil:
		fmt.Fprintf(w, "  → These payloads were blocked by the filter - nothing got through.\n")
		fmt.Fprintf(w, "    Try other encodings, or a blind out-of-band check with -interactsh.\n")
	case notableTotal > 0:
		fmt.Fprintf(w, "  → Some responses differed from the baseline - worth a manual look.\n")
	default:
		fmt.Fprintf(w, "  → Nothing stood out; the target handled every payload the same way.\n")
	}
	// Blind SSRF (the app fetches but the response never changes) is invisible to
	// response diffing - point the user at the out-of-band check when they aren't
	// already using it and nothing surfaced in-band.
	if !oobUsed && len(findings) == 0 && notable["BYPASS"] == nil {
		fmt.Fprintf(w, "    For blind SSRF (no visible change), re-run with -interactsh.\n")
	}

	tip := "  More detail: -v"
	if outPath == "" {
		tip += "   ·   save everything: -o results.jsonl"
	} else {
		tip += "   ·   full data saved to " + outPath
	}
	fmt.Fprintf(w, "%s%s%s\n", dim, tip, rst)
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
			if detect.Analyze(bl, res.Status, res.Body, res.Duration, markers, cfg.lenPct, "", nil, false).Interesting {
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
		"payload": c.Payload, "header": c.Header, "variant": c.Variant, "tag": c.Tag,
		"oob": c.OOB, "status": res.Status, "len": res.BodyLen,
		"dur_ms": res.Duration.Milliseconds(), "redirects": res.Redirects,
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

func parseSweepEnc(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.EqualFold(s, "all") {
		return []string{"decimal", "hex", "octal", "mixed", "dotless", "ipv6"}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

func labelTag(c gen.Case) string {
	if c.Tag == "" {
		return c.Label
	}
	return c.Label + " [" + c.Tag + "]"
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
