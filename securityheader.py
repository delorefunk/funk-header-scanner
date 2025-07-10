import argparse
import requests
from urllib.parse import urlparse

# List of headers to check, with expected substrings (None means just check existence)
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age',
    'Content-Security-Policy': None,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
    'Referrer-Policy': None,
    'Permissions-Policy': None
}

def check_headers(response):
    results = {}
    for header, expect in SECURITY_HEADERS.items():
        actual = response.header.get(header)
        if actual is None:
            results[header] = (False, None)
        else:
            # Allow expect to be a list of acceptable values or a single string
            if isinstance(expect, list):
                ok = any(e.lower() in actual.lower() for e in expect)
            else:
                ok = expect.lower() in actual.lower()
            results[header] = (ok, actual)

    return results

def scan_url(url):
    print(f"\nScanning {url}")
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"    [ERROR] Could not fetch: {e}")
        return
    
    for hdr, (ok, val) in check_headers(resp).items():
        if val is None:
            print(f"    [MISSING] {hdr}")
        elif ok:
            print(f"    [OK] {hdr}: {val}")
        else:
            print(f"    [WARN] {hdr}: {val!r} (unexpectede value)")

def main():
    p = argparse.ArgumentParser(
        description="Scan HTTP response headers in accordance with OWASP and Mozilla Dev."
    )
    p.add_argument('urls', nargs='+', help="One or more URLs to scan")
    args = p.parse_args()

    for u in args.urls:
        # Ensure scheme
        if not urlparse(u).scheme:
            u = 'https://' + u
        scan_url(u)

if __name__ == "__main__":
    main()
