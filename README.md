# ssrfuzz

A Go fuzzing toolkit for **SSRF** and **Host-Header** attacks, driven by a raw
HTTP request.

> ⚠️ **Authorized testing only.** Use exclusively against systems you have
> explicit permission to test (signed scope, a bug-bounty program in scope, your
> own infrastructure, or training labs). You are responsible for how you use it.

## Why Go

The bottleneck here is network I/O, not CPU. Goroutines let the tool keep many
requests in flight cheaply, it compiles to a single static binary (drop it on any
jump box, no runtime deps), and raw TCP/TLS gives full control over duplicated
and non-standard request headers — which `net/http` would normalize away.

## Features

- Raw HTTP request as input (saved from Burp "Copy to file")
- Modes: `ssrf`, `host`, `both`
- Fuzz a parameter by name (`-p imageUrl`), auto-discover SSRF candidates
  (`-p auto`), fuzz every parameter (`-p all`), or use a `FUZZ` marker —
  across query / form-urlencoded / JSON / **multipart** bodies
- `-list-params` to enumerate request parameters (candidates marked) for recon
- Comprehensive payloads: localhost bypasses, IP encodings (dec/oct/hex/IPv6),
  cloud metadata (AWS/GCP/Azure/DO/Alibaba/OCI/k8s), dangerous schemes
  (`file`/`gopher`/`dict`/PHP wrappers), redirect + DNS rebinding
- Host-Header techniques: replace Host, duplicate Host, absolute-URI, and
  override headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, …)
- Detection: baseline diff (status/length/body) + body signatures + custom
  `-match` strings + **payload reflection** (body and response headers like
  `Location`) + blind confirmation via interactsh (OOB)
- Response clustering (rare-first) to triage huge runs at a glance
- Built-in anti-DoS: default rate cap, volume/ETA preview, circuit breaker,
  graceful Ctrl-C
- `-probe`: skip headers with no visible effect, keep core SSRF headers
- `-sweep`: last-octet sweep of private /24 ranges (routing-based SSRF)
- `-path`/`-paths`: replay routing-based SSRF across internal paths (`/admin`,
  `/internal`, `/dashboard`, … or your own list)
- Rate control: `-rate` (req/s), `-c` (workers), `-delay`/`-jitter`
- Proxy through Burp (`-proxy`)
- JSONL output (`-o`)

## Build

```bash
go build -o ssrfuzz .
```

## Usage

```
ssrfuzz -r <raw-request-file> -mode <ssrf|host|both> [options]
```

Run `ssrfuzz -h` for the full option list.

### Examples

```bash
# SSRF: fuzz the "imageUrl" parameter, confirm blind via interactsh
ssrfuzz -r req.txt -mode ssrf -p imageUrl -oob abc.oast.fun -rate 15

# Host-Header: poison with your server, match the admin indicator
ssrfuzz -r req.txt -mode host -evil evil.attacker.com -match "ADMIN PANEL" -rate 20

# Host-Header with header probing (skip useless headers) and routing sweep
ssrfuzz -r req.txt -mode host -probe -sweep private -rate 10 -c 5

# Routing-based SSRF: internal IPs x internal paths
ssrfuzz -r req.txt -mode host -probe -sweep private -paths default -rate 10

# Everything, piped through Burp for manual review
ssrfuzz -r req.txt -mode both -proxy 127.0.0.1:8080 -v
```

## Typical workflow

```bash
# 1. Host-Header attacks on the landing page
ssrfuzz -r get-root.txt -mode host -probe

# 2. If there's an admin area, check Host-based auth bypass there
ssrfuzz -r get-admin.txt -mode host -match "ADMIN"

# 3. Found an interesting parameter? Copy the full request from Burp,
#    point -p at it, and let the SSRF dictionary run (no manual ffuf edits)
ssrfuzz -r upload.txt -mode ssrf -p imageUrl -oob abc.oast.fun

# ...or let the tool find the SSRF-candidate params itself
ssrfuzz -r req.txt -list-params            # recon: what's in the request
ssrfuzz -r req.txt -mode ssrf -p auto      # fuzz the candidates
```

## Safety / not a DoS tool

Against a target you were contracted to test, hammering it into the ground is the
worst outcome. Guardrails are built in:

- `-rate` defaults to 25 req/s (set `-rate 0` for unlimited — with a warning)
- the estimated request count and duration print before the run starts
- `-max` aborts before start if the case count is too large
- a circuit breaker auto-stops on sustained errors or latency blowup
  (`-max-errors`), i.e. when the target starts to degrade
- Ctrl-C stops gracefully with a partial summary

## Payload files

Live in `payloads/`, editable without rebuilding. Placeholders expanded at runtime:

| Placeholder   | Meaning                                   | Flag        |
|---------------|-------------------------------------------|-------------|
| `{{OOB}}`     | interactsh subdomain (unique per payload) | `-oob`      |
| `{{EVIL}}`    | your server for host poisoning            | `-evil`     |
| `{{LHOST}}`   | your IP/domain for redirect tricks        | `-lhost`    |
| `{{TARGET}}`  | internal address to wrap                  | `-itarget`  |
| `{{HOST}}`    | legitimate target host (auto)             | from target |

## Blind detection (interactsh)

Run `interactsh-client` in a separate terminal, take your domain (e.g.
`abc.oast.fun`), and pass it with `-oob abc.oast.fun`. The tool gives each payload
a unique subdomain (`<id>.abc.oast.fun`) and writes an `<subdomain> → payload` map
to `oob-map-*.txt`. When a callback lands in interactsh-client, look the subdomain
up in that map to see exactly which payload fired.

## Detection output

Each flagged result prints a tag, case id, status, body length, the reasons, and
the payload:

```
[STRONG] s0095 200   49  marker:ami-id,...  | http://169.254.169.254/latest/meta-data/
[hit   ] h0013 400   15  status 200->400    | Host: localhost [dup]
```

`STRONG` = a body signature or `-match` string hit (or an OOB payload sent);
`hit` = an anomaly vs baseline. The tool flags candidates — you confirm.
