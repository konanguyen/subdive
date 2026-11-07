# subdive

Deep subdomain enumeration using free, public data sources and DNS. Self-hosted
replacement for the "Deep" tier of commercial subdomain finders: no API keys, no
paid services, no external account.

## Features

| Technique | Supported | Implementation |
|---|---|---|
| Passive detection | Yes | crt.sh, Cert Spotter, HackerTarget, RapidDNS, OTX, urlscan, subdomain.center, Anubis, ThreatMiner, DNSDumpster, Wayback, Common Crawl |
| Certificate Transparency | Yes | crt.sh and Cert Spotter |
| DNS records | Yes | NS, MX, TXT, SOA, CAA via UDP DNS with DoH fallback |
| Zone transfer | Yes | AXFR attempt against every authoritative NS |
| DNS brute force | Yes | SecLists wordlist, 20,000 entries by default |
| Alteration search | Yes | Prefix/suffix variants and separator changes |
| Reverse DNS | Yes | PTR lookups plus a /24 sweep around discovered IPs |
| TLS certificate SAN | Yes | TLS handshake against resolved hosts |
| HTML link extraction | Yes | Fetches resolved hosts and extracts hostnames |
| Search engines | Yes | DuckDuckGo, Bing, Google (`site:` queries) |
| CNAME analysis | Yes | Full CNAME chain plus dangling-CNAME takeover hints |
| HTTP fingerprinting | Yes | Status code, page title, Server header |
| Baseline diff | Yes | Compares against a previous report (PDF or TXT) |

## Pipeline

1. **Passive discovery** - queries 12 public sources over HTTPS. This is where
   most names come from.
2. **Name generation** - brute force from a wordlist and alteration of names
   already discovered.
3. **Resolution** - A, CNAME and optional AAAA lookups. Starts with the system
   resolver and switches to DNS-over-HTTPS when the resolver is rate limited.
4. **Expansion** - reverse DNS, TLS SAN, HTML links and search engines feed new
   candidates back into the resolver.
5. **Enrichment** - HTTP status, title and Server header for every live host.
6. **Reporting** - TXT, CSV and JSON output, with an optional diff against a
   previous report.

DNS is used to verify names, not to discover them. The only ways DNS itself can
reveal a name are brute force, AXFR and PTR, and all three are implemented.

## Requirements

- Python 3.9 or newer
- Outbound HTTPS and DNS access
- No root privileges

## Installation

Using a virtualenv:

```bash
git clone <repo-url> subdive
cd subdive
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Or install as a package, which adds the `subdive` command:

```bash
python3 -m pip install -e .
subdive --version
```

The SecLists wordlist is not stored in the repository. It is downloaded from
GitHub on first use and can be refreshed at any time:

```bash
subdive -d example.com --update-wordlist
```

## Usage

Activate the virtualenv once per shell:

```bash
source .venv/bin/activate
```

Then run the script directly:

```bash
python subdive.py -d example.com
```

If you installed the package with `pip install -e .`, the `subdive` command is
available on your PATH and no script path is needed:

```bash
subdive -d example.com
```

Deep scan with a baseline report for diffing:

```bash
subdive -d example.com --baseline baseline-report.pdf
```

Fast scan, passive sources plus DNS brute force only:

```bash
subdive -d example.com --light
```

Force DNS-over-HTTPS from the start:

```bash
subdive -d example.com --resolver doh
```

With tuning:

```bash
subdive -d example.com --concurrency 200 --threads 50
```

Without activating the virtualenv:

```bash
.venv/bin/python subdive.py -d example.com
```

## Options

| Option | Default | Description |
|---|---|---|
| `-d, --domain` | required | Target domain |
| `--light` | off | Passive sources and DNS brute force only |
| `--sources` | all | Comma-separated list of passive sources |
| `--wordlist` | SecLists 20k | Custom wordlist path |
| `--update-wordlist` | off | Re-download the default wordlist |
| `--wordlist-limit` | 20000 | Maximum number of words to use |
| `--no-brute` | off | Disable brute force |
| `--no-alter` | off | Disable alteration search |
| `--no-tls` | off | Disable TLS SAN harvesting |
| `--no-links` | off | Disable HTML link extraction |
| `--no-search` | off | Disable search engine queries |
| `--no-revdns` | off | Disable reverse DNS |
| `--no-axfr` | off | Disable zone transfer attempts |
| `--ipv6` | off | Also resolve AAAA records |
| `--concurrency` | 150 | Concurrent DNS queries |
| `--dns-rate` | 300 | DNS queries per second, 0 for unlimited |
| `--resolver` | auto | `auto`, `udp` or `doh` |
| `--threads` | 40 | Threads for HTTP and TLS work |
| `--timeout` | 5.0 | DNS timeout in seconds |
| `--alter-limit` | 30000 | Maximum number of alteration candidates |
| `--revdns-limit` | 3000 | Maximum number of neighbours in the /24 sweep |
| `--outdir` | results | Output directory |
| `--baseline` | none | Previous report (PDF or TXT) for diffing |
| `--include-unresolved` | off | Include unresolved names in the TXT output |
| `--print-limit` | 0 | Maximum number of rows printed to the terminal |
| `-q, --quiet` | off | Suppress progress output |

## Output

The scan writes three files to the output directory:

| File | Content |
|---|---|
| `<domain>.txt` | Resolved subdomains, one per line |
| `<domain>.csv` | All tested names with status, IPs, CNAME, HTTP status, title, sources |
| `<domain>.json` | Same data plus DNS records and baseline diff |

Generate a Markdown report from the JSON:

```bash
.venv/bin/python make_report.py results/example.com.json
```

## Baseline diff

`--baseline` accepts either a PDF report or a plain text file. Names from the
baseline are re-resolved and compared with the new results, so the output shows:

- names that were in the baseline and still resolve
- names that were in the baseline and are now dead
- names that are new

## Comparison with Kali tools

Single test on a real target, same machine, same network, default settings.

| Tool | Time | Raw names | Live names |
|---|---:|---:|---:|
| subdive | 13 min | 49,239 | 113 |
| subfinder `-all` | 87 s | 89 | 82 |
| gobuster dns, 20k wordlist | 8 min 17 s | 33 | 33 |
| sublist3r | 60 s | 1 | 1 |
| amass `-passive` | 100 s | 0 | 0 |

The union of the four Kali tools produced 99 live names, all of which are also
found by subdive. The seven names that only subfinder returned are NXDOMAIN and
are listed as dead by both tools.

The amass package in Kali ships an empty `datasources.yaml` and its wrapper
script requires sudo, so it returns nothing out of the box. It needs manual
configuration and API keys to be useful.

## How it handles rate limits

The local resolver used during development started dropping queries after about
9,000 lookups. subdive detects this by probing the resolver before the main run
and switches to DNS-over-HTTPS (Cloudflare, then Google) when the resolver is
degraded. Names that still fail are retried twice with lower concurrency.
Without this, brute force against large wordlists silently returns a fraction of
the real results.

## Limitations

- 12 passive sources. Sources that require API keys, such as Shodan, Censys,
  SecurityTrails, VirusTotal and BinaryEdge, are not included.
- No ASN or netblock expansion and no reverse WHOIS.
- No NSEC zone walking and no recursive name expansion beyond alteration.
- Throughput over DoH is about 60 names per second, limited by HTTP overhead.
- HTTP fingerprinting covers resolved hosts only.

## Legal

Use this tool only against domains you own or have written permission to test.
Passive sources return public data, but brute force and HTTP probing generate
traffic against the target.

## License

MIT
