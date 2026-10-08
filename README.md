# postern

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
- Detection: baseline diff, body signatures, payload reflection, and blind
  confirmation via a built-in interactsh client (`-interactsh`)
- Response clustering to triage large runs
- Rate limiting, circuit breaker and a request cap to stay safe on live targets
- Burp proxy support and JSONL output

## Install

```bash
go install github.com/dripentest/postern@latest
```

Or from source:

```bash
git clone https://github.com/dripentest/postern
cd postern && go build -o postern .
```

The payload lists are embedded in the binary, so `go install` gives a
self-contained tool. To customize them, drop a `payloads/` directory next to
where you run it (it takes precedence) or point at one with `-payloads`.

## Usage

```bash
postern -r <request-file> -mode <ssrf|host|both> [options]
```

Run `postern -h` for all options.

## Examples

```bash
# SSRF on a parameter, blind confirmation via interactsh
postern -r req.txt -mode ssrf -p imageUrl -oob abc.oast.fun

# auto-discover and fuzz SSRF-candidate parameters
postern -r req.txt -list-params
postern -r req.txt -mode ssrf -p auto

# Host-Header attacks, skipping headers with no effect
postern -r req.txt -mode host -probe

# routing-based SSRF: internal ranges x internal paths
postern -r req.txt -mode host -probe -sweep private -paths default

# port-scan localhost through a confirmed SSRF
postern -r req.txt -mode ssrf -p url -ports top

# through Burp, print every result
postern -r req.txt -mode both -proxy 127.0.0.1:8080 -v
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

Pass `-interactsh` and the tool runs its own interactsh client: it registers with
the public servers, gives each payload a unique subdomain, polls in the
background, and prints confirmed blind callbacks live and in the summary — no
separate client needed.

```bash
postern -r req.txt -mode ssrf -p url -interactsh
```

By default this uses the public interactsh servers, so the target's out-of-band
interactions (and the fact you are testing it) transit a third party. For
sensitive engagements, point at your own server with `-interactsh-server` /
`-interactsh-token`.

For a manual workflow instead, run `interactsh-client` yourself and pass its
domain with `-oob abc.oast.fun`; the tool writes a `subdomain → payload` map to
`oob-map-*.txt` for correlation by hand.

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

postern finds the SSRF/bypass; it does not weaponize it. Hand a confirmed finding
to [SSRFmap](https://github.com/swisskyrepo/SSRFmap) for RCE and pivoting — the
`-r`/`-p` input format is compatible.

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
