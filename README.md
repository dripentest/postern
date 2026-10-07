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
- Fuzz a parameter by name (`-p imageUrl`) or by a `FUZZ` marker
- Comprehensive payloads: localhost bypasses, IP encodings (dec/oct/hex/IPv6),
  cloud metadata (AWS/GCP/Azure/DO/Alibaba/OCI/k8s), dangerous schemes
  (`file`/`gopher`/`dict`/PHP wrappers), redirect + DNS rebinding
- Host-Header techniques: replace Host, duplicate Host, absolute-URI, and
  override headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, …)
- Detection: baseline diff (status/length/body) + body signatures + custom
  `-match` strings + blind confirmation via interactsh (OOB)
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
