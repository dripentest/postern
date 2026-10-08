# ssrfuzz

SSRF and Host-Header fuzzer. It takes a raw HTTP request, injects a large bypass
dictionary into a chosen parameter or header, and flags responses that differ
from the baseline — with blind confirmation over OOB (interactsh).

For authorized security testing only.

## Features

- SSRF, Host-Header, or both modes from a single raw request
- Inject into a named parameter, auto-discovered candidates (`-p auto`), every
  parameter (`-p all`), or a `FUZZ` marker — in query, form, JSON and multipart
- Bypass dictionary: localhost tricks, IP encodings (dec/oct/hex/IPv6), cloud
  metadata (AWS/GCP/Azure/DO/Alibaba/OCI/k8s), schemes (file/gopher/dict/PHP),
  redirect and DNS-rebind payloads
- Host-Header: replace / duplicate / absolute-URI / override headers, routing
  sweeps over private /24 ranges, and internal path replay
- Port and network scan through a confirmed SSRF
- Detection: baseline diff, body signatures, payload reflection, interactsh OOB
- Response clustering to triage large runs
- Rate limiting, circuit breaker and a request cap to stay safe on live targets
- Burp proxy support and JSONL output

## Install

```bash
git clone https://github.com/dripentest/ssrfuzz
cd ssrfuzz && go build -o ssrfuzz .
```

## Usage

```bash
ssrfuzz -r <request-file> -mode <ssrf|host|both> [options]
```

Run `ssrfuzz -h` for all options.

## Examples

```bash
# SSRF on a parameter, blind confirmation via interactsh
ssrfuzz -r req.txt -mode ssrf -p imageUrl -oob abc.oast.fun

# auto-discover and fuzz SSRF-candidate parameters
ssrfuzz -r req.txt -list-params
ssrfuzz -r req.txt -mode ssrf -p auto

# Host-Header attacks, skipping headers with no effect
ssrfuzz -r req.txt -mode host -probe

# routing-based SSRF: internal ranges x internal paths
ssrfuzz -r req.txt -mode host -probe -sweep private -paths default

# port-scan localhost through a confirmed SSRF
ssrfuzz -r req.txt -mode ssrf -p url -ports top

# through Burp, print every result
ssrfuzz -r req.txt -mode both -proxy 127.0.0.1:8080 -v
```

## Output

Flagged results print a tag, id, status, length, reasons and the payload.
`STRONG` is a signature/reflection/OOB hit; `hit` is an anomaly vs baseline:

```
[STRONG] s0095 200   49  marker:ami-id,...  | http://169.254.169.254/latest/meta-data/
[hit   ] h0013 400   15  status 200->400    | Host: localhost [dup]
```

A rare-first response-cluster summary prints at the end so outliers (open ports,
distinct responses) stand out without scrolling.

## Blind detection (interactsh)

Run `interactsh-client` in another terminal and pass its domain with
`-oob abc.oast.fun`. Each payload gets a unique subdomain and the
`subdomain → payload` map is written to `oob-map-*.txt`, so a callback tells you
exactly which payload fired.

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

## Exploitation

ssrfuzz finds the SSRF/bypass; it does not weaponize it. Hand a confirmed finding
to [SSRFmap](https://github.com/swisskyrepo/SSRFmap) for RCE and pivoting — the
`-r`/`-p` input format is compatible.
