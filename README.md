# postern

[![ci](https://github.com/dripentest/postern/actions/workflows/ci.yml/badge.svg)](https://github.com/dripentest/postern/actions/workflows/ci.yml)

**SSRF and Host-Header reconnaissance fuzzer.** It takes one raw HTTP request,
injects a bypass arsenal into a chosen parameter or header, and tells you — in
plain language — which payloads got past the filter, reached an internal host,
or leaked data. Blind cases are confirmed out-of-band via a built-in interactsh
client.

postern *finds and confirms* the bypass. It is deliberately not an exploitation
framework — hand a confirmed finding to [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
to weaponize it.

> For authorized security testing only. See the [disclaimer](#disclaimer).

## Why

A raw socket, not `net/http`, so duplicate/cased Host headers and odd request
shapes are sent exactly as written. IP-encoding bypasses are **generated per
target address** (a faithful set of `inet_aton` forms) rather than shipped as a
static list, so the dictionary adapts to any host instead of bloating. Detection
is baseline-relative, and the default output is built for humans: a live progress
line, confirmed findings streamed the moment they happen, and a short verdict at
the end — with `-v` for the full per-request detail.

## Features

- **SSRF, Host-Header, or both** from a single raw request (`-mode`).
- **Inject anywhere:** a named parameter, auto-discovered candidates (`-p auto`),
  every parameter (`-p all`), or a `FUZZ` marker — in query, form, JSON (including
  nested keys and arrays of strings), and multipart, with Content-Length recalculated.
- **Generated IP encodings:** decimal, hex, hex-dotted, octal, octal-padded,
  mixed-base, dotless, and IPv6-mapped forms — each tagged so you see which one
  worked and can reuse it.
- **Bypass arsenal:** localhost tricks, cloud metadata (AWS/GCP/Azure/DO/Alibaba/
  OCI/k8s), schemes (`file`/`gopher`/`dict`/PHP wrappers), redirect and parser-
  discrepancy payloads, `@`-trick and domain-confusion.
- **DNS rebinding** against TOCTOU filters (`-rebind` → 1u.ms / rbndr.us), with a
  `-rebind-only` / `-repeat` mode to win the race.
- **Host-Header attacks:** replace / duplicate / absolute-URI / override headers,
  routing sweeps over private /24 ranges, internal path replay, and `-probe` to
  drop headers with no effect.
- **Internal recon through a confirmed SSRF:** port scan (`-ports top|all|CSV|range`,
  likelihood-ordered) and network sweep, with `-scan-encode` / `-sweep-encode` to
  tunnel the scan through a filter bypass.
- **Follow redirects** (`-follow-redirects`) keeping an injected Host across the
  chain — the redirect-chain host-header attack.
- **Detection:** baseline diff (status/length), body signatures, payload reflection
  (numeric and hostname forms), and **blind confirmation via a built-in interactsh
  client** (`-interactsh`).
- **Safe on live targets:** rate limit, circuit breaker, case cap, graceful Ctrl-C,
  ETA before the run.
- Burp proxy support and JSONL output (`-o`).

## Install

```bash
go install github.com/dripentest/postern@latest
```

From source:

```bash
git clone https://github.com/dripentest/postern
cd postern && go build -o postern .
```

Payload lists are embedded, so `go install` gives a self-contained binary. To
customize them, drop a `payloads/` directory next to where you run it (it takes
precedence) or point at one with `-payloads`.

## Usage

```bash
postern -r <request-file> -mode <ssrf|host|both> [options]
```

Capture a request in Burp (right-click → *Copy to file*) and point `-r` at it.
Run `postern -h` for every flag, a staged workflow, and tool positioning.

### Typical workflow

```bash
# 1. what is injectable?
postern -r req.txt -list-params

# 2. find SSRF (in-band + blind) on the candidate parameters
postern -r req.txt -mode ssrf -p auto -interactsh

# 3. host-header / admin-panel bypass (prune dead headers, match an indicator)
postern -r req.txt -mode host -probe -match "Dashboard"

# 4. scan an internal host through the SSRF
postern -r req.txt -mode ssrf -p url -scan-host 10.0.0.5 -ports top

# 5. map the internal network (go gently)
postern -r req.txt -mode ssrf -p url -sweep private -ports 80,443,6379 -rate 10
```

### More examples

```bash
# SSRF to cloud metadata via DNS rebinding (TOCTOU bypass)
postern -r req.txt -mode ssrf -p url -rebind 1.2.3.4:169.254.169.254

# scan behind a filter that blocks plain IPs but resolves decimal
postern -r req.txt -mode ssrf -p url -scan-host 172.28.0.20 -scan-encode decimal -ports 5000,5432

# hammer only the rebinding payloads to win a TOCTOU race
postern -r req.txt -mode ssrf -p url -rebind-only -rebind 1.2.3.4:169.254.169.254 -repeat 50

# follow a redirect chain while keeping an injected Host
postern -r req.txt -mode host -path /redir1 -follow-redirects 3 -match "Dashboard"

# JSON body with a list of URLs: {"urls":["..."]}
postern -r req.txt -mode ssrf -p urls -interactsh

# everything through Burp, every result printed
postern -r req.txt -mode both -proxy 127.0.0.1:8080 -v
```

## Output

By default postern stays quiet while it runs (a single live progress line),
streams **confirmed findings the instant they happen**, and prints a human
summary at the end:

```
  ✓ reached AWS metadata / credentials   url=http://2852039166/latest/meta-data/
  ✓ reached the backend (HTTP 200)        Host: admin.local [replace]

  Results

  768 payloads sent.
  Responses that differed from the baseline (HTTP 403 - blocked):

  ● got past the filter, backend errored (HTTP 5xx)  ×12
       url=http://2887516160:5000 [decimal]
  ○ looked like the baseline (HTTP 403 - blocked)  ×754

  → The filter let some payloads through (the backend errored on them).
  More detail: -v   ·   save everything: -o results.jsonl
```

Only responses that differ from the baseline count as notable, so a target whose
baseline is itself an error page doesn't flag every request. Use `-v` for the
full per-request view and the raw status/length clusters, and `-o out.jsonl` to
save everything for `jq`/grep.

## Where postern fits

It is **not** a dirbuster or a port scanner — it complements them:

| Tool | Does | postern |
|---|---|---|
| **ffuf / feroxbuster** | discover parameters and paths | fuzzes SSRF/host bypasses into a *known* request |
| **nmap** | scan a host from the outside | port-scans *internal* hosts **through** an SSRF |
| **SSRFmap** | weaponize an SSRF (RCE, pivot, read) | finds and confirms the bypass first (`-r`/`-p` compatible) |

## Blind detection (interactsh)

Pass `-interactsh` and postern runs its own interactsh client: it registers with
the public servers, gives each payload a unique subdomain, polls in the
background, and prints confirmed blind callbacks live and in the summary — no
separate client needed. When nothing surfaces in-band, the summary points you
here, because a blind SSRF has no visible response difference.

```bash
postern -r req.txt -mode ssrf -p url -interactsh
```

The public servers mean the target's out-of-band interactions transit a third
party. For sensitive engagements, use your own with `-interactsh-server` /
`-interactsh-token`, or run `interactsh-client` yourself and pass its domain with
`-oob abc.oast.fun` (postern writes a `subdomain → payload` map for correlation).

## Payloads

Payload files live in `payloads/` and are editable without rebuilding.
Placeholders are expanded at runtime:

| Placeholder  | Meaning                         | Flag       |
|--------------|---------------------------------|------------|
| `{{OOB}}`    | interactsh subdomain            | `-oob`     |
| `{{EVIL}}`   | your server for host poisoning  | `-evil`    |
| `{{LHOST}}`  | your host for redirect tricks   | `-lhost`   |
| `{{TARGET}}` | internal address to wrap        | `-itarget` |
| `{{HOST}}`   | the target host (auto)          | —          |

## Development

```bash
go build ./...
go test -race ./...
```

CI runs `go vet`, `go build` and the race-enabled test suite on every push.

## Disclaimer

postern is intended **only** for authorized security testing and educational
purposes. Use it exclusively against systems that you own or for which you have
explicit, prior, written permission to test (for example a signed penetration-test
engagement, a bug-bounty program whose scope covers the target, or your own lab).

Using this tool against systems without authorization is illegal in most
jurisdictions and may violate computer-misuse, privacy, and other laws. Sending
traffic at a target can also disrupt it — you are responsible for staying within
your scope and rules of engagement.

**You are solely responsible for your own actions.** The authors and contributors
accept no liability and are not responsible for any misuse, damage, or other
consequences arising from the use of this tool. By downloading, compiling, or
running postern you agree to these terms and accept full responsibility for how
you use it. If you do not agree, do not use it.
