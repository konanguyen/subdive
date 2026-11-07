#!/usr/bin/env python3
"""
subdive.py - Deep subdomain enumeration (free, self-hosted)

Replicates the "Deep scan" of commercial subdomain finders using only free,
public data sources plus DNS resolution:

  * Certificate Transparency (crt.sh, Cert Spotter)
  * Passive DNS / threat-intel APIs (HackerTarget, RapidDNS, OTX, urlscan,
    subdomain.center, Anubis, ThreatMiner, DNSDumpster)
  * Web archives (Wayback CDX, Common Crawl)
  * DNS records (NS/MX/TXT/SOA/CAA) + AXFR attempt
  * DNS brute force with a wordlist
  * Alteration / permutation search
  * Reverse DNS (PTR) enumeration
  * TLS certificate SAN harvesting
  * HTML link extraction
  * Search engine scraping (DuckDuckGo / Bing / Google)
  * CNAME chain + dangling-CNAME (subdomain takeover) hints
  * HTTP status / title probing
  * Diff against a previous report (e.g. the free Pentest-Tools PDF)

Usage:
    subdive -d example.com
    subdive -d example.com --light
    subdive -d example.com --baseline previous-report.pdf

Only scan domains you own or have written permission to test.
"""

import argparse
import asyncio
import csv
import json
import random
import re
import socket
import ssl
import string
import sys
import time
import warnings
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.reversename
import dns.zone
import requests
from cryptography import x509

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
HERE = Path(__file__).resolve().parent
__version__ = "1.0.0"
DEFAULT_WORDLIST = HERE / "wordlists" / "subdomains-top1million-20000.txt"
WORDLIST_URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
                "master/Discovery/DNS/subdomains-top1million-20000.txt")
WORDLIST_MIRROR = ("https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/"
                   "Discovery/DNS/subdomains-top1million-20000.txt")

PREFIXES = [
    "dev", "test", "testing", "staging", "stage", "prod", "production", "beta",
    "alpha", "demo", "old", "new", "backup", "bak", "admin", "administrator",
    "api", "app", "web", "www2", "mail", "mail2", "webmail", "smtp", "imap",
    "pop", "vpn", "vpn2", "portal", "internal", "intranet", "extranet", "qa",
    "uat", "preprod", "sandbox", "temp", "tmp", "v2", "v3", "mobile", "m",
    "static", "cdn", "assets", "img", "images", "files", "docs", "git",
    "gitlab", "jenkins", "ci", "cd", "monitor", "grafana", "kibana", "db",
    "sql", "mysql", "postgres", "redis", "mongo", "ns1", "ns2", "ns3",
    "autodiscover", "autoconfig", "owa", "exchange", "remote", "secure",
    "sso", "auth", "login", "id", "accounts", "pay", "payment", "shop",
    "store", "blog", "news", "support", "help", "status", "download",
    "upload", "ftp", "sftp", "ssh", "proxy", "gateway", "gw", "lb", "edge",
    "cache", "search", "solr", "elastic", "k8s", "kube", "docker",
    "registry", "harbor", "nexus", "artifactory", "jira", "confluence",
    "wiki", "crm", "erp", "hrm", "lms", "elearning", "learn", "training",
    "edu", "student", "students", "teacher", "staff", "hr", "finance",
    "accounting", "library", "thuvien", "exam", "thi", "tuyensinh",
    "admission", "alumni", "event", "media", "video", "stream", "live",
    "chat", "forum", "helpdesk", "ticket", "cms", "wp", "wordpress",
    "drupal", "joomla", "laravel", "node", "python", "java", "php", "go",
]
SUFFIXES = [
    "dev", "test", "staging", "prod", "beta", "old", "new", "backup", "bak",
    "admin", "api", "app", "web", "v2", "v3", "1", "2", "3", "01", "02",
    "internal", "external", "temp", "tmp", "demo", "sandbox", "qa", "uat",
    "preprod", "prod2", "test2", "dev2", "old2", "new2", "db", "sql",
    "mail", "smtp", "cdn", "static", "assets", "files", "docs", "git",
    "jenkins", "ci", "monitor", "grafana", "kibana", "vpn", "portal",
    "sso", "auth", "login", "pay", "shop", "store", "blog", "news",
    "support", "help", "status", "ftp", "proxy", "gw", "lb", "edge",
    "cache", "search", "k8s", "docker", "registry", "wiki", "crm", "erp",
    "hrm", "lms", "elearning", "learn", "student", "staff", "hr",
    "library", "exam", "tuyensinh", "media", "chat", "forum", "cms",
]
TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "cloudfront.net": "CloudFront", "azurewebsites.net": "Azure",
    "blob.core.windows.net": "Azure Blob", "trafficmanager.net": "Azure TM",
    "s3.amazonaws.com": "S3", "elasticbeanstalk.com": "Elastic Beanstalk",
    "netlify.app": "Netlify", "netlify.com": "Netlify",
    "vercel.app": "Vercel", "now.sh": "Vercel", "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket", "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers", "web.app": "Firebase",
    "firebaseapp.com": "Firebase", "readthedocs.io": "ReadTheDocs",
    "ghost.io": "Ghost", "myshopify.com": "Shopify", "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress", "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage", "pantheonsite.io": "Pantheon",
    "fastly.net": "Fastly", "unbouncepages.com": "Unbounce",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def log(msg, quiet=False):
    if not quiet:
        print(msg, flush=True)


def http_get(url, timeout=30, retries=2, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    headers.setdefault("Accept", "*/*")
    last = None
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=timeout, headers=headers,
                             allow_redirects=True, **kwargs)
            if r.status_code == 200:
                return r
            last = r
            if r.status_code in (403, 404):
                return r
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(1.5 * (attempt + 1))
                continue
            return r
        except requests.RequestException as exc:
            last = exc
            time.sleep(1.2 * (attempt + 1))
    return last if isinstance(last, requests.Response) else None


def normalize_name(name, domain):
    if not name:
        return None
    name = name.strip().lower().strip(".")
    if name.startswith("*."):
        name = name[2:]
    if name.startswith("."):
        name = name[1:]
    name = name.rstrip(".")
    if name != domain and not name.endswith("." + domain):
        return None
    if not re.fullmatch(r"[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?", name):
        return None
    if ".." in name or len(name) > 253:
        return None
    return name


def clean_names(raw, domain):
    out = set()
    for item in raw:
        n = normalize_name(item, domain)
        if n:
            out.add(n)
    return out


def ensure_wordlist(path=DEFAULT_WORDLIST, update=False, quiet=False):
    """Fetch the latest SecLists wordlist when it is missing (or on demand).

    Returns the path on success, or None when the download failed and no local
    copy exists. An existing file is kept when refreshing fails.
    """
    path = Path(path)
    if path.exists() and not update:
        return path

    log(f"[*] {'Refreshing' if path.exists() else 'Downloading'} wordlist "
        f"from GitHub ...", quiet)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")

    for url in (WORDLIST_URL, WORDLIST_MIRROR):
        host = urlparse(url).netloc
        try:
            with requests.get(url, timeout=60, stream=True,
                              headers={"User-Agent": UA}) as r:
                r.raise_for_status()
                size = 0
                with tmp.open("wb") as fh:
                    for chunk in r.iter_content(65536):
                        if chunk:
                            fh.write(chunk)
                            size += len(chunk)
            if size < 10_000:
                raise ValueError(f"response too small ({size} bytes)")
            head = tmp.read_bytes()[:200].lstrip()
            if head.startswith(b"<"):
                raise ValueError("got HTML instead of a wordlist")
            tmp.replace(path)
            lines = sum(1 for _ in path.open("rb"))
            log(f"    [+] {path} ({size // 1024} KB, {lines} lines)", quiet)
            return path
        except Exception as exc:  # noqa: BLE001 - any failure -> try mirror
            tmp.unlink(missing_ok=True)
            log(f"    [-] {host}: {exc}", quiet)

    if path.exists():
        log(f"    [!] download failed, using existing {path}", quiet)
        return path
    log("[!] Could not download a wordlist; brute force will be skipped.", quiet)
    return None


def load_wordlist(path, limit=None):
    p = Path(path)
    if not p.exists():
        return []
    words = []
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().lower()
            if not w or w.startswith("#"):
                continue
            if re.fullmatch(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?", w):
                words.append(w)
    # de-dup, keep order
    seen = set()
    words = [w for w in words if not (w in seen or seen.add(w))]
    return words[:limit] if limit else words


# --------------------------------------------------------------------------
# passive sources
# --------------------------------------------------------------------------
def src_crtsh(domain, _session=None):
    names = set()
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?Identity=%25.{domain}&output=json",
    ]
    for url in urls:
        r = http_get(url, timeout=30, retries=1)
        if r is None or not hasattr(r, "status_code") or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            for value in str(entry.get("name_value", "")).split("\n"):
                names.add(value)
            names.add(str(entry.get("common_name", "")))
        if names:
            break
    if not names:
        raise RuntimeError("crt.sh unavailable (502/HTML response)")
    return names


def src_certspotter(domain, _session=None):
    url = ("https://api.certspotter.com/v1/issuances"
           f"?domain={domain}&include_subdomains=true&expand=dns_names")
    r = http_get(url, timeout=30)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    names = set()
    for entry in r.json():
        names.update(entry.get("dns_names", []))
    return names


def src_hackertarget(domain, _session=None):
    r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    names = set()
    for line in r.text.splitlines():
        host = line.split(",")[0].strip()
        if host and "." in host:
            names.add(host)
    return names


def src_rapiddns(domain, _session=None):
    r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=40)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    return set(re.findall(
        r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b", r.text))


def src_otx(domain, _session=None):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=30, retries=2)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    return {e.get("hostname", "") for e in r.json().get("passive_dns", [])}


def src_urlscan(domain, _session=None):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    r = http_get(url, timeout=40)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    names = set()
    for res in r.json().get("results", []):
        names.add(res.get("page", {}).get("domain", ""))
        u = res.get("task", {}).get("url", "")
        if u:
            names.add(urlparse(u).hostname or "")
    return names


def src_subdomain_center(domain, _session=None):
    r = http_get(f"https://api.subdomain.center/?domain={domain}", timeout=40)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    data = r.json()
    return set(data) if isinstance(data, list) else set()


def src_anubis(domain, _session=None):
    r = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=25)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    return set(r.json())


def src_threatminer(domain, _session=None):
    r = http_get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=25)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    return set(r.json().get("results", []))


def src_wayback(domain, _session=None):
    url = ("http://web.archive.org/cdx/search/cdx?url=*." + domain +
           "&output=json&collapse=urlkey&fl=original&limit=200000")
    r = http_get(url, timeout=60, retries=1)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r, 'status_code', 'error')}")
    try:
        rows = r.json()
    except Exception:
        raise RuntimeError("non-JSON response")
    names = set()
    for row in rows[1:] if rows and isinstance(rows[0], list) else rows:
        value = row[0] if isinstance(row, list) else row
        host = urlparse(value if "://" in value else "http://" + value).hostname
        if host:
            names.add(host)
    return names


def src_commoncrawl(domain, _session=None):
    r = http_get("https://index.commoncrawl.org/collinfo.json", timeout=30)
    if r is None or r.status_code != 200:
        raise RuntimeError("collinfo failed")
    index = r.json()[0]["id"]
    url = (f"https://index.commoncrawl.org/{index}-index?url=*." + domain +
           "&output=json&fl=url&collapse=urlkey&limit=50000")
    r2 = http_get(url, timeout=60, retries=1)
    if r2 is None or r2.status_code != 200:
        raise RuntimeError(f"HTTP {getattr(r2, 'status_code', 'error')}")
    names = set()
    for line in r2.text.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = urlparse(obj.get("url", "")).hostname
        if host:
            names.add(host)
    return names


def src_dnsdumpster(domain, _session=None):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    r = s.get("https://dnsdumpster.com/", timeout=30)
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("CSRF token not found")
    r2 = s.post("https://dnsdumpster.com/",
                data={"csrfmiddlewaretoken": m.group(1), "targetip": domain,
                      "user": "free"},
                headers={"Referer": "https://dnsdumpster.com/"}, timeout=40)
    if r2.status_code != 200:
        raise RuntimeError(f"HTTP {r2.status_code}")
    return set(re.findall(
        r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b", r2.text))


SOURCES = {
    "crtsh": src_crtsh,
    "certspotter": src_certspotter,
    "hackertarget": src_hackertarget,
    "rapiddns": src_rapiddns,
    "otx": src_otx,
    "urlscan": src_urlscan,
    "subdomain.center": src_subdomain_center,
    "anubis": src_anubis,
    "threatminer": src_threatminer,
    "wayback": src_wayback,
    "commoncrawl": src_commoncrawl,
    "dnsdumpster": src_dnsdumpster,
}


def run_passive(domain, enabled, quiet=False):
    names = set()
    source_map = defaultdict(set)
    errors = {}
    log(f"[*] Querying {len(enabled)} passive sources ...", quiet)

    def task(key):
        t = time.time()
        try:
            raw = SOURCES[key](domain)
            got = clean_names(raw, domain)
            return key, got, None, time.time() - t
        except Exception as exc:
            return key, set(), f"{type(exc).__name__}: {exc}", time.time() - t

    with ThreadPoolExecutor(max_workers=min(12, len(enabled))) as pool:
        futures = [pool.submit(task, k) for k in enabled]
        for fut in as_completed(futures):
            key, got, err, elapsed = fut.result()
            if err:
                errors[key] = err
                log(f"    [-] {key:<16} {err} ({elapsed:.1f}s)", quiet)
            else:
                names |= got
                source_map[key] |= got
                log(f"    [+] {key:<16} {len(got):>5} names ({elapsed:.1f}s)", quiet)
    return names, source_map, errors


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def make_resolver(timeout):
    r = dns.asyncresolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    r.retry_attempts = 2
    return r


class RateLimiter:
    """Simple async token bucket to avoid hammering the local resolver."""

    def __init__(self, rate):
        self.rate = float(rate)
        self.tokens = float(rate)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(self.rate,
                                  self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait)


async def resolve_one(name, resolver, sem, ipv6=False, limiter=None):
    rec = {"a": set(), "aaaa": set(), "cname": set(),
           "status": "unresolved", "error": None}

    async def query(rdtype):
        if limiter is not None:
            await limiter.acquire()
        return await resolver.resolve(name, rdtype, raise_on_no_answer=False)

    async with sem:
        try:
            ans = await query("A")
            if ans.rrset:
                rec["a"] = {r.address for r in ans.rrset}
                rec["status"] = "resolved"
            cn = str(ans.canonical_name).rstrip(".").lower()
            if cn and cn != name:
                rec["cname"].add(cn)
        except dns.resolver.NXDOMAIN:
            rec["status"] = "nxdomain"
        except dns.exception.DNSException as exc:
            rec["status"] = "error"
            rec["error"] = type(exc).__name__

        if rec["status"] == "unresolved":
            try:
                ans = await query("CNAME")
                if ans.rrset:
                    rec["cname"] = {str(r.target).rstrip(".").lower() for r in ans.rrset}
                    rec["status"] = "cname-only"
            except dns.exception.DNSException:
                pass

        if ipv6:
            try:
                ans = await query("AAAA")
                if ans.rrset:
                    rec["aaaa"] = {r.address for r in ans.rrset}
                    rec["status"] = "resolved"
            except dns.exception.DNSException:
                pass
    return name, rec


async def resolve_many(names, resolver, concurrency, ipv6=False, quiet=False,
                       batch_size=4000, rate=None):
    names = list(dict.fromkeys(names))
    results = {}
    done = 0
    total = len(names)
    limiter = RateLimiter(rate) if rate else None
    for start in range(0, total, batch_size):
        batch = names[start:start + batch_size]
        sem = asyncio.Semaphore(concurrency)
        tasks = [asyncio.create_task(resolve_one(n, resolver, sem, ipv6, limiter))
                 for n in batch]
        for fut in asyncio.as_completed(tasks):
            name, rec = await fut
            results[name] = rec
            done += 1
            if not quiet and (done % 500 == 0 or done == total):
                print(f"\r    resolved {done}/{total}", end="", flush=True)
        if start + batch_size < total:
            await asyncio.sleep(0.25)
    if not quiet and total:
        print()
    return results


DOH_ENDPOINTS = ("https://cloudflare-dns.com/dns-query",
                 "https://dns.google/resolve")


def doh_query(name, rdtype="A", timeout=10):
    """Return (status, answers) from DoH, or (None, []) on transport failure."""
    for base in DOH_ENDPOINTS:
        r = http_get(base, params={"name": name, "type": rdtype},
                     headers={"Accept": "application/dns-json"},
                     timeout=timeout, retries=1)
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        return data.get("Status", 2), data.get("Answer") or []
    return None, []


def doh_lookup(name, ipv6=False, timeout=10):
    """Resolve a name over DNS-over-HTTPS (Cloudflare, then Google)."""
    rec = {"a": set(), "aaaa": set(), "cname": set(),
           "status": "unresolved", "error": None}
    status, answers = doh_query(name, "A", timeout)
    if status is None:
        rec["status"] = "error"
        rec["error"] = "DoH failed"
        return rec
    got_any = False
    for ans in answers:
        atype = ans.get("type")
        value = str(ans.get("data", "")).rstrip(".")
        if atype == 1:
            rec["a"].add(value)
            got_any = True
        elif atype == 5:
            rec["cname"].add(value.lower())
    if got_any:
        rec["status"] = "resolved"
    elif rec["cname"]:
        rec["status"] = "cname-only"
    elif status == 3:
        rec["status"] = "nxdomain"
    elif status not in (0, 3):
        rec["status"] = "error"
        rec["error"] = f"DoH status {status}"
    if ipv6:
        _, answers6 = doh_query(name, "AAAA", timeout)
        for ans in answers6:
            if ans.get("type") == 28:
                rec["aaaa"].add(str(ans.get("data", "")).rstrip("."))
                rec["status"] = "resolved"
    return rec


def doh_ptr(ip, timeout=10):
    """PTR lookup over DoH."""
    rev = str(dns.reversename.from_address(ip))
    status, answers = doh_query(rev, "PTR", timeout)
    if status is None:
        return set()
    return {str(a.get("data", "")).rstrip(".").lower()
            for a in answers if a.get("type") == 12}


async def doh_resolve_many(names, concurrency=60, ipv6=False, quiet=False):
    names = list(dict.fromkeys(names))
    results = {}
    done = 0
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    with ThreadPoolExecutor(max_workers=max(8, concurrency)) as pool:
        async def one(n):
            nonlocal done
            async with sem:
                rec = await loop.run_in_executor(pool, doh_lookup, n, ipv6)
            done += 1
            if not quiet and done % 500 == 0:
                print(f"\r    DoH {done}/{len(names)}", end="", flush=True)
            return n, rec

        tasks = [asyncio.create_task(one(n)) for n in names]
        for fut in asyncio.as_completed(tasks):
            n, rec = await fut
            results[n] = rec
    if not quiet and names:
        print()
    return results


async def udp_healthy(resolver, domain, quiet=True):
    labels = ["".join(random.choices(string.ascii_lowercase + string.digits, k=12))
              for _ in range(6)]
    sem = asyncio.Semaphore(6)
    started = time.time()
    recs = await asyncio.gather(
        *(resolve_one(f"{label}.{domain}", resolver, sem) for label in labels))
    errors = sum(1 for _, rec in recs if rec["status"] == "error")
    elapsed = time.time() - started
    return errors <= 2 and elapsed < 6


async def resolve_with_retry(names, resolver, concurrency, ipv6=False, quiet=False,
                             rate=None, use_doh=False):
    """Resolve names; fall back to DoH when the UDP resolver is degraded."""
    names = list(dict.fromkeys(names))
    if use_doh:
        records = await doh_resolve_many(
            names, max(30, concurrency), ipv6, quiet)
    else:
        records = await resolve_many(names, resolver, concurrency, ipv6, quiet,
                                     rate=rate)
        failed = [n for n, r in records.items() if r["status"] == "error"]
        if failed:
            if len(failed) > max(50, len(records) // 10):
                log(f"    [!] {len(failed)} DNS errors -> redoing batch over DoH",
                    quiet)
                more = await doh_resolve_many(
                    list(records), max(30, concurrency), ipv6, quiet)
            else:
                log(f"    [!] {len(failed)} DNS errors -> retrying over DoH", quiet)
                more = await doh_resolve_many(
                    failed, max(30, concurrency // 2), ipv6, quiet)
            for n, rec in more.items():
                if rec["status"] != "error":
                    records[n] = rec

    # up to two extra DoH passes for anything still failing
    for attempt in range(2):
        failed = [n for n, r in records.items() if r["status"] == "error"]
        if not failed:
            break
        log(f"    [!] {len(failed)} names still failed -> DoH retry {attempt + 1}",
            quiet)
        more = await doh_resolve_many(
            failed, max(16, concurrency // (2 * (attempt + 1))), ipv6, quiet)
        for n, rec in more.items():
            if rec["status"] != "error":
                records[n] = rec
    still = sum(1 for r in records.values() if r["status"] == "error")
    if still:
        log(f"    [!] {still} names could not be resolved", quiet)
    return records


async def detect_wildcard(domain, resolver, concurrency, use_doh=False):
    labels = ["".join(random.choices(string.ascii_lowercase + string.digits, k=14))
              for _ in range(3)]
    ips = set()
    if use_doh:
        recs = await doh_resolve_many(
            [f"{label}.{domain}" for label in labels],
            concurrency=3, quiet=True)
        for rec in recs.values():
            ips |= rec["a"]
    else:
        sem = asyncio.Semaphore(concurrency)
        for label in labels:
            _, rec = await resolve_one(f"{label}.{domain}", resolver, sem)
            ips |= rec["a"]
    return ips


async def reverse_dns(ips, domain, resolver, concurrency, limit=3000, quiet=False,
                      use_doh=False):
    ips = {ip for ip in ips if not ip.startswith(("10.", "127.", "192.168.", "169.254."))}
    sweep = []
    for ip in ips:
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        net = ".".join(parts[:3])
        for i in range(1, 255):
            candidate = f"{net}.{i}"
            if candidate not in ips:
                sweep.append(candidate)
    random.shuffle(sweep)
    targets = list(ips) + sweep[:limit]
    log(f"[*] Reverse DNS on {len(ips)} IPs + {len(targets) - len(ips)} neighbours ...",
        quiet)

    if use_doh:
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(concurrency)

        with ThreadPoolExecutor(max_workers=max(8, concurrency)) as pool:
            async def ptr(ip):
                async with sem:
                    return ip, await loop.run_in_executor(pool, doh_ptr, ip)

            results = await asyncio.gather(*(ptr(ip) for ip in targets))
    else:
        sem = asyncio.Semaphore(concurrency)

        async def ptr(ip):
            try:
                rev = dns.reversename.from_address(ip)
                async with sem:
                    ans = await resolver.resolve(rev, "PTR", raise_on_no_answer=False)
                if ans.rrset:
                    return ip, {str(r.target).rstrip(".").lower() for r in ans.rrset}
            except dns.exception.DNSException:
                pass
            return ip, set()

        results = await asyncio.gather(*(ptr(ip) for ip in targets))

    found = set()
    ptr_map = {}
    for ip, names in results:
        ptr_map[ip] = names
        for n in names:
            if n == domain or n.endswith("." + domain):
                found.add(n)
    log(f"    [+] {len(found)} names from PTR", quiet)
    return found, ptr_map


DOH_TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
                  "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


def get_dns_records(domain, timeout=6):
    records = {}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    for rdtype in ("NS", "MX", "TXT", "SOA", "CAA"):
        values = []
        try:
            ans = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            if ans.rrset:
                for r in ans.rrset:
                    values.append(r.to_text().strip('"'))
        except dns.exception.DNSException:
            pass
        if not values:  # UDP resolver may be rate-limited; ask DoH
            status, answers = doh_query(domain, rdtype, timeout)
            code = DOH_TYPE_CODES[rdtype]
            for ans in answers:
                if ans.get("type") == code:
                    values.append(str(ans.get("data", "")).strip('"'))
        records[rdtype] = values
    return records


def try_axfr(domain, nameservers, timeout=8):
    found = set()
    for ns in nameservers:
        try:
            xfr = dns.query.xfr(ns, domain, timeout=timeout, lifetime=timeout)
            zone = dns.zone.from_xfr(xfr)
            for name in zone.nodes.keys():
                text = str(name)
                full = domain if text == "@" else f"{text}.{domain}"
                found.add(full)
        except Exception:
            continue
    return found


# --------------------------------------------------------------------------
# active / enrichment techniques
# --------------------------------------------------------------------------
def tls_names(host, timeout=7):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        return set()
    cert = x509.load_der_x509_certificate(der)
    names = set()
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names |= set(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
            names.add(attr.value)
    except Exception:
        pass
    return names


def probe_host(host, timeout=7):
    """Return dict with http info and any hostnames found in the HTML."""
    info = {"http": None, "title": "", "server": "", "final_url": "",
            "links": set()}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}/", timeout=timeout,
                             verify=False, allow_redirects=True,
                             headers={"User-Agent": UA})
            info["http"] = r.status_code
            info["final_url"] = r.url
            info["server"] = r.headers.get("Server", "")
            if not r.encoding or r.encoding.lower() in ("iso-8859-1", "latin-1"):
                r.encoding = r.apparent_encoding or "utf-8"
            text = r.text[:2_000_000]
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            info["links"] = set(re.findall(
                r"(?i)\b([a-z0-9_][a-z0-9._-]*\.[a-z]{2,})\b", text))
            break
        except requests.RequestException:
            continue
    return info


def search_engine(domain, engine, pages=2, timeout=20):
    found = set()
    if engine == "ddg":
        base = "https://html.duckduckgo.com/html/"
        for page in range(pages):
            r = http_get(base, params={"q": f"site:{domain}", "s": page * 30},
                         timeout=timeout, retries=2)
            if r is None or r.status_code != 200:
                break
            found |= set(re.findall(
                r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b",
                r.text))
    elif engine == "bing":
        for page in range(pages):
            r = http_get("https://www.bing.com/search",
                         params={"q": f"site:{domain}", "count": 50,
                                 "first": page * 50},
                         timeout=timeout, retries=2)
            if r is None or r.status_code != 200:
                break
            found |= set(re.findall(
                r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b",
                r.text))
    elif engine == "google":
        for page in range(pages):
            r = http_get("https://www.google.com/search",
                         params={"q": f"site:{domain}", "num": 100,
                                 "start": page * 100},
                         timeout=timeout, retries=2)
            if r is None or r.status_code != 200:
                break
            found |= set(re.findall(
                r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b",
                r.text))
    return found


def alterations(names, domain, limit=15000):
    out = set()
    for name in names:
        label = name[: -len(domain) - 1] if name.endswith("." + domain) else ""
        if not label or "." in label:
            continue
        for p in PREFIXES:
            out.add(f"{p}-{label}.{domain}")
            out.add(f"{p}{label}.{domain}")
        for s in SUFFIXES:
            out.add(f"{label}-{s}.{domain}")
            out.add(f"{label}{s}.{domain}")
        if "-" in label:
            out.add(label.replace("-", "") + "." + domain)
            out.add(label.replace("-", ".") + "." + domain)
    out -= set(names)
    out = sorted(out)
    return out[:limit]


def dangling_cname(cname_targets):
    hits = []
    for target in cname_targets:
        for suffix, service in TAKEOVER_FINGERPRINTS.items():
            if target == suffix or target.endswith("." + suffix):
                hits.append((target, service))
                break
    return hits


# --------------------------------------------------------------------------
# baseline / diff
# --------------------------------------------------------------------------
def load_baseline(path, domain):
    p = Path(path)
    if not p.exists():
        return set()
    if p.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            log("[!] pypdf not installed, cannot read PDF baseline")
            return set()
        text = "\n".join((pg.extract_text() or "") for pg in PdfReader(str(p)).pages)
        return set(re.findall(
            r"(?i)\b([a-z0-9_][a-z0-9._-]*\." + re.escape(domain) + r")\b", text))
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        return clean_names((line.strip() for line in fh), domain)


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------
def write_outputs(domain, records, sources, dns_records, outdir, baseline,
                  ptr_map, quiet=False, include_unresolved=False):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    txt_path = outdir / f"{domain}.txt"
    csv_path = outdir / f"{domain}.csv"
    json_path = outdir / f"{domain}.json"
    name_sources = defaultdict(set)
    for src, src_names in sources.items():
        for n in src_names:
            name_sources[n].add(src)
    resolved = {n: r for n, r in records.items() if r["status"] == "resolved"}
    rows = []
    for name in sorted(records):
        rec = records[name]
        rows.append({
            "subdomain": name,
            "status": rec["status"],
            "ipv4": ",".join(sorted(rec["a"])),
            "ipv6": ",".join(sorted(rec["aaaa"])),
            "cname": ",".join(sorted(rec["cname"])),
            "http_status": rec.get("http") or "",
            "title": rec.get("title") or "",
            "server": rec.get("server") or "",
            "sources": ",".join(sorted(name_sources.get(name, []))),
            "new_vs_baseline": "yes" if baseline and name not in baseline else "",
            "ptr": ",".join(sorted(ptr_map.get(next(iter(rec["a"]), ""), set()))),
        })

    with txt_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# {domain} - {len(resolved)} resolved / {len(records)} tested\n")
        for row in rows:
            if row["status"] == "resolved":
                fh.write(row["subdomain"] + "\n")
        if include_unresolved and any(r["status"] != "resolved" for r in rows):
            fh.write("\n# unresolved\n")
            for row in rows:
                if row["status"] != "resolved":
                    fh.write(row["subdomain"] + "\n")

    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["subdomain"])
        writer.writeheader()
        writer.writerows(rows)

    with json_path.open("w", encoding="utf-8") as fh:
        json.dump({
            "domain": domain,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "dns_records": dns_records,
            "total": len(records),
            "resolved": len(resolved),
            "baseline_new": sorted(
                n for n in records
                if baseline and n not in baseline
                and records[n]["status"] == "resolved"),
            "records": rows,
        }, fh, ensure_ascii=False, indent=2)

    log(f"[*] Written: {txt_path} / {csv_path.name} / {json_path.name}", quiet)
    return rows, resolved


def print_table(rows, include_unresolved, limit=None):
    shown = [r for r in rows if include_unresolved or r["status"] == "resolved"]
    if limit:
        shown = shown[:limit]
    if not shown:
        return
    w = max(len(r["subdomain"]) for r in shown)
    w = min(max(w, 20), 55)
    print()
    print(f"{'SUBDOMAIN':<{w}}  {'IP ADDRESS':<16} {'HTTP':<5} {'SOURCE':<28} TITLE")
    print("-" * (w + 2 + 16 + 1 + 5 + 1 + 28 + 1 + 30))
    for r in shown:
        ip = r["ipv4"].split(",")[0] if r["ipv4"] else "-"
        http = str(r["http_status"]) if r["http_status"] else "-"
        src = r["sources"].replace(",", " ")[:28]
        title = r["title"][:30]
        print(f"{r['subdomain']:<{w}}  {ip:<16} {http:<5} {src:<28} {title}")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
async def main_async(args):
    domain = args.domain.strip().lower().strip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        print(f"[!] Invalid domain: {domain}")
        return 1
    t0 = time.time()
    quiet = args.quiet
    print(f"""
  subdive.py - deep subdomain enumeration
  target : {domain}
  mode   : {'LIGHT' if args.light else 'DEEP'}
  notice : only scan domains you own or have permission to test.
""", flush=True)

    enabled = list(SOURCES)
    if args.light:
        enabled = [s for s in enabled if s not in
                   ("wayback", "commoncrawl", "dnsdumpster", "anubis", "threatminer")]
    if args.sources:
        wanted = {s.strip() for s in args.sources.split(",") if s.strip()}
        enabled = [s for s in enabled if s in wanted]

    # 1. passive
    names, source_map, source_errors = run_passive(domain, enabled, quiet)

    # seed with names from a previous report (e.g. the free Pentest-Tools PDF)
    baseline = load_baseline(args.baseline, domain) if args.baseline else set()
    if baseline:
        names |= baseline
        source_map["baseline"] |= baseline
        log(f"[*] Baseline: {len(baseline)} names from {Path(args.baseline).name}",
            quiet)

    # 2. DNS records + AXFR
    dns_records = get_dns_records(domain)
    log("[*] DNS records:", quiet)
    for rtype, values in dns_records.items():
        if values:
            log(f"    {rtype:<4} {', '.join(values[:4])}", quiet)
    if args.axfr and dns_records.get("NS"):
        log("[*] Trying AXFR ...", quiet)
        axfr = try_axfr(domain, dns_records["NS"])
        if axfr:
            axfr = clean_names(axfr, domain)
            log(f"    [+] AXFR leaked {len(axfr)} names", quiet)
            for n in axfr:
                source_map["axfr"].add(n)
            names |= axfr
        else:
            log("    [-] AXFR refused", quiet)

    # 3. brute force
    brute_set = set()
    if args.brute:
        wl_path = args.wordlist or DEFAULT_WORDLIST
        if not args.wordlist:
            wl_path = ensure_wordlist(wl_path, args.update_wordlist, quiet) or wl_path
        words = load_wordlist(wl_path, args.wordlist_limit)
        if not words:
            log(f"[!] Wordlist not found/empty: {wl_path}", quiet)
        else:
            brute_set = {f"{w}.{domain}" for w in words}
            names |= brute_set
            log(f"[*] Brute force: {len(words)} words from {Path(wl_path).name}", quiet)

    # 4. alteration (only mutate names that actually came from passive sources,
    #    not every brute-force candidate)
    alter_set = set()
    if args.alter and not args.light:
        seed_names = set()
        for got in source_map.values():
            seed_names |= got
        alter_set = set(alterations(seed_names, domain, args.alter_limit))
        names |= alter_set
        log(f"[*] Alteration search: {len(alter_set)} candidates", quiet)

    # 5. resolve
    resolver = make_resolver(args.timeout)
    use_doh = False
    if args.resolver == "doh":
        use_doh = True
    elif args.resolver == "auto":
        use_doh = not await udp_healthy(resolver, domain)
    if use_doh:
        log("[*] UDP resolver degraded -> using DNS-over-HTTPS", quiet)
    wildcard_ips = set()
    if args.brute or args.alter:
        wildcard_ips = await detect_wildcard(
            domain, resolver, args.concurrency, use_doh)
        if wildcard_ips:
            log(f"[!] Wildcard DNS detected -> {', '.join(sorted(wildcard_ips)[:4])}",
                quiet)
            log("    Brute-force hits pointing only at the wildcard will be dropped.",
                quiet)

    log(f"[*] Resolving {len(names)} unique names ...", quiet)
    records = await resolve_with_retry(names, resolver, args.concurrency,
                                       args.ipv6, quiet, rate=args.dns_rate,
                                       use_doh=use_doh)

    # drop wildcard-only brute hits
    if wildcard_ips:
        dropped = 0
        for n in list(records):
            rec = records[n]
            if (n in brute_set or n in alter_set) and rec["a"]:
                if rec["a"] <= wildcard_ips:
                    del records[n]
                    dropped += 1
        if dropped:
            log(f"    [-] dropped {dropped} wildcard hits", quiet)

    # 6. enrichment rounds (TLS SAN, HTML links, search engines)
    for round_no in range(2):
        extra = set()
        resolved_hosts = [n for n, r in records.items() if r["status"] == "resolved"]

        if args.tls and not args.light:
            log(f"[*] TLS certificate SAN harvest on {len(resolved_hosts)} hosts ...",
                quiet)
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futs = {pool.submit(tls_names, h): h for h in resolved_hosts}
                for fut in as_completed(futs):
                    try:
                        got = fut.result()
                    except Exception:
                        continue
                    extra |= clean_names(got, domain)
            log(f"    [+] {len(extra)} names so far", quiet)

        if args.links and not args.light:
            log(f"[*] HTML link harvest on {len(resolved_hosts)} hosts ...", quiet)
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futs = {pool.submit(probe_host, h): h for h in resolved_hosts}
                for fut in as_completed(futs):
                    host = futs[fut]
                    try:
                        info = fut.result()
                    except Exception:
                        continue
                    rec = records.get(host)
                    if rec is not None:
                        rec["http"] = info["http"]
                        rec["title"] = info["title"]
                        rec["server"] = info["server"]
                        rec["final_url"] = info["final_url"]
                    extra |= clean_names(info["links"], domain)

        if args.search and not args.light:
            log("[*] Search engine scraping ...", quiet)
            for engine in ("ddg", "bing", "google"):
                try:
                    got = search_engine(domain, engine)
                    got = clean_names(got, domain)
                    extra |= got
                    log(f"    [+] {engine:<7} {len(got)} names", quiet)
                except Exception as exc:
                    log(f"    [-] {engine:<7} {type(exc).__name__}", quiet)

        new = extra - set(records)
        if not new:
            break
        log(f"[*] Resolving {len(new)} new names from enrichment round {round_no + 1} ...",
            quiet)
        more = await resolve_with_retry(new, resolver, args.concurrency,
                                        args.ipv6, quiet, rate=args.dns_rate)
        if wildcard_ips:
            for n in list(more):
                if more[n]["a"] and more[n]["a"] <= wildcard_ips:
                    del more[n]
        if not more:
            break
        records.update(more)

    # 7. reverse DNS (uses resolved IPs)
    ptr_map = {}
    if args.revdns and not args.light:
        ips = set()
        for rec in records.values():
            ips |= rec["a"]
        rev_names, ptr_map = await reverse_dns(
            ips, domain, resolver, args.concurrency, args.revdns_limit, quiet,
            use_doh=use_doh)
        new = rev_names - set(records)
        if new:
            more = await resolve_with_retry(new, resolver, args.concurrency,
                                            args.ipv6, quiet, rate=args.dns_rate,
                                            use_doh=use_doh)
            records.update(more)

    # 8. CNAME / takeover hints
    all_cnames = set()
    for rec in records.values():
        all_cnames |= rec["cname"]
    takeover = dangling_cname(all_cnames)
    if takeover:
        log("[!] Potential subdomain-takeover CNAMEs:", quiet)
        for target, service in takeover:
            log(f"    {target}  ({service})", quiet)

    # 9. write + report
    rows, resolved = write_outputs(domain, records, source_map, dns_records,
                                   args.outdir, baseline, ptr_map, quiet,
                                   args.include_unresolved)

    print_table(rows, args.include_unresolved, args.print_limit)

    new_names = sorted(
        n for n in records
        if baseline and n not in baseline and records[n]["status"] == "resolved")
    if baseline:
        print(f"\n[+] {len(new_names)} RESOLVED subdomains NOT in the baseline report:")
        shown = new_names[:args.print_limit] if args.print_limit else new_names
        for n in shown:
            rec = records[n]
            ip = ",".join(sorted(rec["a"])) or "-"
            print(f"    {n:<50} {ip}")
        if len(shown) < len(new_names):
            print(f"    ... and {len(new_names) - len(shown)} more (see CSV/JSON)")

    print(f"""
================ SUMMARY ================
unique names     : {len(records)}
resolved         : {len(resolved)}
unresolved/error : {len(records) - len(resolved)}
wildcard IPs     : {len(wildcard_ips)}
dangling CNAMEs  : {len(takeover)}
new vs baseline  : {len(new_names) if baseline else 'n/a'}
elapsed          : {time.time() - t0:.1f}s
output           : {Path(args.outdir).resolve()}/{domain}.{{txt,csv,json}}
=========================================
""")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Deep subdomain enumeration using free public sources.")
    p.add_argument("--version", action="version",
                   version=f"subdive {__version__}")
    p.add_argument("-d", "--domain", required=True, help="target domain")
    p.add_argument("--light", action="store_true",
                   help="passive + DNS brute force only (like the free scan)")
    p.add_argument("--sources", help="comma separated passive sources")
    p.add_argument("--wordlist", help="wordlist path (default: SecLists 20k, "
                                      "downloaded automatically when missing)")
    p.add_argument("--update-wordlist", action="store_true",
                   help="re-download the default wordlist from GitHub")
    p.add_argument("--wordlist-limit", type=int, default=20000)
    p.add_argument("--no-brute", dest="brute", action="store_false",
                   help="disable DNS brute force")
    p.add_argument("--no-alter", dest="alter", action="store_false",
                   help="disable alteration search")
    p.add_argument("--no-tls", dest="tls", action="store_false",
                   help="disable TLS SAN harvesting")
    p.add_argument("--no-links", dest="links", action="store_false",
                   help="disable HTML link harvesting")
    p.add_argument("--no-search", dest="search", action="store_false",
                   help="disable search engine scraping")
    p.add_argument("--no-revdns", dest="revdns", action="store_false",
                   help="disable reverse DNS")
    p.add_argument("--no-axfr", dest="axfr", action="store_false",
                   help="disable AXFR attempt")
    p.add_argument("--ipv6", action="store_true", help="also resolve AAAA")
    p.add_argument("--concurrency", type=int, default=150, help="DNS concurrency")
    p.add_argument("--dns-rate", type=float, default=300.0,
                   help="max DNS queries/second (0 = unlimited)")
    p.add_argument("--resolver", choices=("auto", "udp", "doh"), default="auto",
                   help="DNS transport: auto (probe), udp, or DoH")
    p.add_argument("--threads", type=int, default=40, help="HTTP/TLS threads")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout")
    p.add_argument("--alter-limit", type=int, default=30000)
    p.add_argument("--revdns-limit", type=int, default=3000)
    p.add_argument("--outdir", default="results")
    p.add_argument("--baseline", help="previous report (.pdf or .txt) for diffing")
    p.add_argument("--include-unresolved", action="store_true",
                   help="show unresolved names in the table")
    p.add_argument("--print-limit", type=int, default=0,
                   help="limit rows printed to console (0 = all)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(brute=True, alter=True, tls=True, links=True, search=True,
                   revdns=True, axfr=True)
    return p


def main():
    args = build_parser().parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
