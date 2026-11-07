#!/usr/bin/env python3
"""Render a Markdown report from a subdive JSON result."""
import json
import sys
from pathlib import Path


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "results/example.com.json")
    data = json.load(src.open())
    rows = data["records"]
    resolved = [r for r in rows if r["status"] == "resolved"]
    new = data.get("baseline_new", [])
    out = src.with_suffix(".md")

    lines = [
        f"# Subdomain report — {data['domain']}",
        "",
        f"- Generated: {data.get('generated', '')}",
        f"- Unique names tested: **{data['total']}**",
        f"- Resolved: **{data['resolved']}**",
        f"- New vs baseline: **{len(new)}**",
        "",
        "## DNS records",
        "",
    ]
    for rtype, values in data.get("dns_records", {}).items():
        if values:
            lines.append(f"- **{rtype}**: {', '.join(values)}")

    lines += ["", "## New subdomains (not in the baseline report)", "",
              "| Subdomain | IP | HTTP | Sources |", "|---|---|---|---|"]
    by = {r["subdomain"]: r for r in rows}
    for name in new:
        r = by.get(name, {})
        lines.append(f"| `{name}` | {r.get('ipv4', '')} | "
                     f"{r.get('http_status', '')} | {r.get('sources', '')} |")

    lines += ["", f"## All resolved subdomains ({len(resolved)})", "",
              "| Subdomain | IP | HTTP | Title |", "|---|---|---|---|"]
    for r in sorted(resolved, key=lambda x: x["subdomain"]):
        title = (r.get("title") or "").replace("|", "\\|")[:80]
        lines.append(f"| `{r['subdomain']}` | {r.get('ipv4', '')} | "
                     f"{r.get('http_status', '')} | {title} |")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"written {out}")


if __name__ == "__main__":
    main()
