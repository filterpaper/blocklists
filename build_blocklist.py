#!/usr/bin/env python3
"""Build blocklist by downloading sources, extracting and validating domains."""

import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen

URL_SOURCE = "https://github.com/filterpaper/blocklists/raw/main/src.txt"
DOMAIN_RE = re.compile(r'(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})')
MAX_ENTRIES = 330000
URL_WORKERS = 8
DNS_WORKERS = 100
DNS_TIMEOUT = 3.0

def fetch_url(url: str) -> str:
    """Fetch content from URL."""
    try:
        with urlopen(url, timeout=30) as r:
            return r.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

def extract_domains(text: str) -> set[str]:
    """Extract valid domain patterns from text."""
    domains = set()
    for line in text.splitlines():
        # Allow lines starting with alphanumeric or * (for RPZ wildcards)
        if line and (line[0].isalnum() or line[0] == '*'):
            if match := DOMAIN_RE.search(line):
                domains.add(match.group(0).lower())
    return domains

def resolve_domain(domain: str) -> str | None:
    """Return domain if it resolves to IPv4 or IPv6, None otherwise."""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        socket.getaddrinfo(domain, None)
        return domain
    except (socket.gaierror, socket.timeout):
        return None

def main():
    # Fetch source list
    sources = fetch_url(URL_SOURCE)
    src_url = [u.strip() for u in sources.splitlines() if u.strip()]

    # Download all sources in parallel and extract domains
    domains = set()
    with ThreadPoolExecutor(max_workers=URL_WORKERS) as pool:
        for url_content in pool.map(fetch_url, src_url):
            domains.update(extract_domains(url_content))

    total = len(domains)
    print(f"Extracted {total} unique domains", file=sys.stderr)

    # Validate domains in parallel (removing invalid ones)
    completed = 0
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futures = {pool.submit(resolve_domain, d): d for d in domains}
        for future in as_completed(futures):
            if not future.result():
                domains.discard(futures[future])
            completed += 1
            if completed % 10000 == 0:
                print(f"Validated {completed}/{total} ({completed*100//total}%)", file=sys.stderr)

    count = len(domains)
    if count > MAX_ENTRIES:
        print(f"Too many valid entries: {count}", file=sys.stderr)
        sys.exit(0)
    else:
        print(f"Valid entries: {count}", file=sys.stderr)

    # Output unbound format
    for entry in domains:
        print(f'local-zone: "{entry}" always_null')

if __name__ == "__main__":
    main()
