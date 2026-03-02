#!/usr/bin/env python3
"""
Google Cloud API Key Scanner
Extracts exposed AIza API keys from web pages (Maps, Analytics, etc.).
Keys embedded in client-side code may have unintended Gemini access if the API is enabled.
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Google API key format: AIza + 35 alphanumeric/dash/underscore
API_KEY_PATTERN = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

# Alternative: broader match for keys that might be truncated
API_KEY_PATTERN_LOOSE = re.compile(r'AIza[0-9A-Za-z\-_]{20,}')

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ANSI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Unicode symbols (fallback for narrow terminals)
CHECK = "✓"
CROSS = "✗"
WARN = "∿"

print_lock = Lock()


def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def c(text, color):
    return f"{color}{text}{RESET}" if supports_color() else text


def _sym(check=True):
    """Return symbol for status; use ASCII if not TTY."""
    if supports_color():
        return CHECK if check else CROSS
    return "+" if check else "-"


def banner():
    """Print tool banner."""
    art = """
  ██   ██ ███████ ██    ██ ██████  ███████  █████  ██████  ███████ ██████  
  ██  ██  ██       ██  ██  ██   ██ ██      ██   ██ ██   ██ ██      ██   ██ 
  █████   █████     ████   ██████  █████   ███████ ██████  █████   ██████  
  ██  ██  ██         ██    ██   ██ ██      ██   ██ ██      ██      ██   ██ 
  ██   ██ ███████    ██    ██   ██ ███████ ██   ██ ██      ███████ ██   ██ 

  GCP API Key Scanner  •  Extract & assess exposed AIza keys  •  by c0d3Ninja
"""
    if supports_color():
        print(c(art, CYAN))
    else:
        print(art)


def _fmt_key_card(key, source, impact_results, accessible):
    """Format a single key's impact."""
    lines = []
    sym_ok = c(CHECK, GREEN) if supports_color() else "[+]"
    sym_fail = c(CROSS, RED) if supports_color() else "[-]"
    sym_warn = c(WARN, YELLOW) if supports_color() else "[~]"

    lines.append("")
    lines.append(f"  {key[:16]}...  {c('from', DIM) if supports_color() else 'from'} {source}")
    for name, impact_desc, ok, err in impact_results:
        if ok:
            lines.append(f"    {sym_ok}  {name:<18} {c(impact_desc, DIM) if supports_color() else impact_desc}")
        elif err == "referrer_blocked":
            lines.append(f"    {sym_warn}  {name:<18} referrer blocked")
        else:
            err_txt = err or "no access"
            lines.append(f"    {sym_fail}  {name:<18} {c(err_txt, DIM) if supports_color() else err_txt}")
    if accessible:
        impacts = [d for n, d, ok, _ in impact_results if ok]
        lines.append(f"    {c('Impact:', YELLOW) + ' ' if supports_color() else 'Impact: '}{'; '.join(impacts)}")
    return "\n".join(lines)


def _fmt_summary(impact_by_key):
    """Format impact summary for report copy-paste."""
    lines = []
    lines.append("")
    lines.append(c("  Impact summary (for report)", BOLD) if supports_color() else "  Impact summary (for report)")
    for key, (url, impact_results) in impact_by_key.items():
        accessible = [(n, d) for n, d, ok, _ in impact_results if ok]
        if accessible:
            src = url if url not in ("-", "unknown") else "keys file"
            lines.append(f"\n  {key[:16]}... from {src}")
            lines.append(f"    APIs: {', '.join(n for n, _ in accessible)}")
            lines.append(f"    Impact: {'; '.join(d for _, d in accessible)}")
    return "\n".join(lines) if lines else ""


def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_url(url, timeout=15):
    """Fetch URL content."""
    headers = {"User-Agent": "Mozilla/5.0 (Google API Key Scanner)"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            return resp.read().decode("utf-8", errors="ignore"), resp.geturl(), None
    except urllib.error.HTTPError as e:
        return None, url, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, url, str(e.reason)
    except Exception as e:
        return None, url, str(e)


def extract_keys(content, url, loose=False):
    """Extract unique AIza keys from content."""
    pattern = API_KEY_PATTERN_LOOSE if loose else API_KEY_PATTERN
    keys = set()
    for m in pattern.finditer(content):
        key = m.group(0)
        if len(key) == 39:  # Full-length keys
            keys.add(key)
        elif loose and len(key) >= 20:
            keys.add(key)
    return list(keys)


def get_script_urls(html, base_url):
    """Extract script src URLs from HTML for follow-up fetching."""
    script_src = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    urls = []
    for m in script_src.finditer(html):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            src = f"{parsed.scheme}://{parsed.netloc}{src}"
        elif not src.startswith("http"):
            src = urllib.parse.urljoin(base_url, src)
        if src.startswith("http"):
            urls.append(src)
    return urls


def scan_url(url, timeout=15, loose=False, follow_scripts=False):
    """Scan a single URL for API keys. Optionally fetch referenced script URLs."""
    url = normalize_url(url)
    if not url:
        return url, [], "Invalid URL"

    content, final_url, error = fetch_url(url, timeout)
    if error:
        return url, [], error

    keys = extract_keys(content, url, loose)
    urls_to_scan = [url]

    if follow_scripts and content:
        script_urls = get_script_urls(content, final_url)
        urls_to_scan.extend(script_urls[:20])  # Limit to 20 scripts per page

    for u in urls_to_scan[1:]:  # Skip first (already scanned)
        c2, _, err = fetch_url(u, timeout)
        if not err and c2:
            keys.extend(extract_keys(c2, u, loose))

    return url, list(set(keys)), None


def validate_key_gemini(key, referer=None):
    """Check if key has Gemini API access (minimal request). Uses victim quota."""
    api_url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + key
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(api_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
            if "models" in data:
                return True, None
            return False, None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        if e.code == 403:
            if "API_KEY_HTTP_REFERRER_BLOCKED" in body:
                return None, "referrer_blocked"
            if "API_KEY_INVALID" in body or "invalid" in body.lower():
                return False, None
            return False, None
        return None, str(e.code)
    except Exception as ex:
        return None, str(ex)


def get_referer_from_url(url):
    """Derive Referer header from source URL (origin + /)."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


# API probes for impact assessment: (name, impact_desc, url_or_callable)
# callable(key) -> (url, data=None, method='GET')
def _gemini_probe(key):
    return ("https://generativelanguage.googleapis.com/v1beta/models?key=" + key, None, "GET")


def _maps_geocode_probe(key):
    return ("https://maps.googleapis.com/maps/api/geocode/json?address=test&key=" + key, None, "GET")


def _maps_places_probe(key):
    return ("https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&key=" + key, None, "GET")


def _vision_probe(key):
    # Minimal 1x1 PNG base64
    b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    body = json.dumps({
        "requests": [{"image": {"content": b64}, "features": [{"type": "LABEL_DETECTION"}]}]
    }).encode()
    return ("https://vision.googleapis.com/v1/images:annotate?key=" + key, body, "POST")


def _translate_probe(key):
    return ("https://translation.googleapis.com/language/translate/v2?key=" + key + "&q=hello&target=es", None, "GET")


def _youtube_probe(key):
    return ("https://www.googleapis.com/youtube/v3/videos?part=snippet&id=dQw4w9WgXcQ&key=" + key, None, "GET")


def _maps_directions_probe(key):
    return ("https://maps.googleapis.com/maps/api/directions/json?origin=Boston&destination=Cambridge&key=" + key, None, "GET")


def _maps_distance_probe(key):
    return ("https://maps.googleapis.com/maps/api/distancematrix/json?origins=Boston&destinations=Cambridge&key=" + key, None, "GET")


def _maps_elevation_probe(key):
    return ("https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + key, None, "GET")


def _maps_timezone_probe(key):
    return ("https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + key, None, "GET")


def _maps_autocomplete_probe(key):
    return ("https://maps.googleapis.com/maps/api/place/autocomplete/json?input=pizza&key=" + key, None, "GET")


def _books_probe(key):
    return ("https://www.googleapis.com/books/v1/volumes?q=test&maxResults=1&key=" + key, None, "GET")


def _kg_probe(key):
    return ("https://kgsearch.googleapis.com/v1/entities:search?query=google&key=" + key + "&limit=1", None, "GET")


def _pagespeed_probe(key):
    return ("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://example.com&key=" + key, None, "GET")


def _customsearch_probe(key):
    return ("https://www.googleapis.com/customsearch/v1?key=" + key + "&cx=017576662512468239146:omuauf_lfve&q=test", None, "GET")


API_PROBES = [
    ("Gemini", "LLM access, content generation, image analysis", _gemini_probe, lambda r: "models" in r),
    ("Maps Geocoding", "Location data, address lookup", _maps_geocode_probe, lambda r: "results" in r and r.get("status") in ("OK", "ZERO_RESULTS")),
    ("Maps Places", "Place details, business info", _maps_places_probe, lambda r: "result" in r and r.get("status") == "OK"),
    ("Maps Directions", "Routing, turn-by-turn directions", _maps_directions_probe, lambda r: "routes" in r and r.get("status") == "OK"),
    ("Maps Distance Matrix", "Travel time, distance between points", _maps_distance_probe, lambda r: "rows" in r and r.get("status") == "OK"),
    ("Maps Elevation", "Elevation data for coordinates", _maps_elevation_probe, lambda r: "results" in r and r.get("status") == "OK"),
    ("Maps Timezone", "Timezone for coordinates", _maps_timezone_probe, lambda r: "timeZoneId" in r and r.get("status") == "OK"),
    ("Maps Autocomplete", "Place search predictions", _maps_autocomplete_probe, lambda r: "predictions" in r and r.get("status") == "OK"),
    ("Cloud Vision", "Image analysis, OCR, labels", _vision_probe, lambda r: "responses" in r),
    ("Translation", "Text translation", _translate_probe, lambda r: "data" in r),
    ("YouTube Data", "Video/channel metadata", _youtube_probe, lambda r: "items" in r),
    ("Books API", "Book metadata, search", _books_probe, lambda r: "items" in r or "totalItems" in r),
    ("Knowledge Graph", "Entity search, facts", _kg_probe, lambda r: "itemListElement" in r or "error" not in r),
    ("PageSpeed Insights", "Site performance data", _pagespeed_probe, lambda r: "lighthouseResult" in r or "loadingExperience" in r),
    ("Custom Search", "Web search results", _customsearch_probe, lambda r: "queries" in r or "items" in r),
]


def probe_api(url, headers, data=None, method="GET", timeout=10):
    """Probe a single API endpoint. Returns (json_response, error_msg)."""
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        if data and method == "POST":
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            try:
                j = json.loads(body)
                return j, None
            except json.JSONDecodeError:
                return None, "invalid json"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        if e.code == 403 and "API_KEY_HTTP_REFERRER_BLOCKED" in body:
            return None, "referrer_blocked"
        if e.code == 403 and ("API_KEY_INVALID" in body or "invalid" in body.lower()):
            return None, "invalid_key"
        return None, f"HTTP {e.code}"
    except Exception as ex:
        return None, str(ex)


def assess_impact(key, referer=None):
    """Probe multiple Google APIs and return which ones the key can access."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    if referer:
        headers["Referer"] = referer

    results = []
    for name, impact_desc, probe_fn, check_fn in API_PROBES:
        url, data, method = probe_fn(key)
        resp, err = probe_api(url, headers, data, method)
        if err:
            results.append((name, impact_desc, False, err))
        elif resp and check_fn(resp):
            results.append((name, impact_desc, True, None))
        else:
            results.append((name, impact_desc, False, "no access"))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan web pages for exposed Google Cloud API keys (AIza)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l urls.txt -o keys.txt
  %(prog)s -l urls.txt -w 20 --follow-scripts
  %(prog)s -l urls.txt -o keys.txt -r results.tsv
  %(prog)s -u https://example.com --loose --validate
  %(prog)s -l urls.txt --validate --referer https://example.com/
  %(prog)s -u https://example.com --impact -r impact.tsv
  %(prog)s -k keys.txt --impact --referer https://example.com/
        """,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single URL to scan")
    target_group.add_argument("-l", "--list", help="File with URLs (one per line)")
    target_group.add_argument("-k", "--keys", help="File with API keys (one per line, for --impact only)")

    parser.add_argument("-o", "--output", help="Output file for extracted keys")
    parser.add_argument("-r", "--results", help="Output file for full results (url,key)")
    parser.add_argument("-w", "--workers", type=int, default=10,
                        help="Concurrent workers (default: 10)")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                        help="Request timeout (default: 15)")
    parser.add_argument("--loose", action="store_true",
                        help="Use loose regex (shorter keys, partial matches)")
    parser.add_argument("--follow-scripts", action="store_true",
                        help="Also fetch and scan externally referenced JS files")
    parser.add_argument("--validate", action="store_true",
                        help="Validate keys against Gemini API (WARNING: uses victim's quota)")
    parser.add_argument("--impact", action="store_true",
                        help="Probe all APIs (Gemini, Maps, Vision, etc.) and report impact (implies --validate)")
    parser.add_argument("--referer", metavar="URL",
                        help="Referer header for validation (default: derived from source URL)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only output keys, no status messages")

    banner()  # show before parse so it appears with -h too
    args = parser.parse_args()

    if args.quiet:
        pass  # quiet suppresses scan/impact output, not banner

    keys_from_file = None
    if args.keys:
        if not args.impact and not args.validate:
            print("--keys requires --impact or --validate", file=sys.stderr)
            sys.exit(1)
        with open(args.keys, "r", errors="ignore") as f:
            keys_from_file = [line.strip() for line in f if line.strip() and "AIza" in line]
        if not keys_from_file:
            print("No valid keys in file.", file=sys.stderr)
            sys.exit(1)
        all_keys = set(keys_from_file)
        results = [("-", k, None) for k in all_keys]
        urls = []
    else:
        if args.url:
            urls = [normalize_url(args.url)]
        else:
            with open(args.list, "r", errors="ignore") as f:
                urls = [normalize_url(line) for line in f if line.strip()]
        urls = [u for u in urls if u]

        if not urls:
            print("No valid URLs.", file=sys.stderr)
            sys.exit(1)

        all_keys = set()
        results = []  # (url, key, validated?)

        if not args.quiet:
            print(f"Scanning {len(urls)} URL(s)...\n")

    if not args.keys:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(scan_url, u, args.timeout, args.loose, args.follow_scripts): u
                for u in urls
            }

            for future in as_completed(futures):
                url, keys, error = future.result()
                if error and not args.quiet:
                    with print_lock:
                        sym = c(CROSS, RED) if supports_color() else "[-]"
                        print(f"  {sym} {url}" + (c(f" — {error}", DIM) if supports_color() else f": {error}"))
                if keys:
                    for key in keys:
                        all_keys.add(key)
                        results.append((url, key, None))
                    if not args.quiet:
                        with print_lock:
                            sym = c(CHECK, GREEN) if supports_color() else "[+]"
                            print(f"  {sym} {url}" + (c(f" — {len(keys)} key(s)", DIM) if supports_color() else f": {len(keys)} key(s)"))

    # Impact assessment (probes all APIs)
    if args.impact and all_keys:
        if not args.quiet:
            print(c("\n  [!] ", YELLOW) + "Impact assessment uses the key owner's API quota.")
            print(c("  Probing ", DIM) + f"{len(all_keys)} key(s)" + c(f" across {len(API_PROBES)} APIs", DIM) + c(" ...", DIM))
        referer_override = normalize_url(args.referer) if args.referer else None
        impact_by_key = {}  # key -> (source_url, impact_results)
        for url, key in [(r[0], r[1]) for r in results]:
            if key in impact_by_key:
                continue
            referer = referer_override or (get_referer_from_url(url) if url not in ("-", "unknown") else None)
            impact_results = assess_impact(key, referer=referer)
            impact_by_key[key] = (url, impact_results)
        results = []
        for key, (url, impact_results) in impact_by_key.items():
            accessible = [name for name, _, ok, _ in impact_results if ok]
            results.append((url, key, accessible))
            if not args.quiet:
                with print_lock:
                    src = url if url not in ("-", "unknown") else "keys file"
                    print(_fmt_key_card(key, src, impact_results, accessible))
        if not args.quiet and impact_by_key:
            summary = _fmt_summary(impact_by_key)
            if summary:
                with print_lock:
                    print(summary)

    # Validate only (Gemini) if requested and not already doing impact
    elif args.validate and all_keys:
        if not args.quiet:
            print(c("\n[!] WARNING: Validation uses the key owner's API quota.", YELLOW))
            print(f"Validating {len(all_keys)} key(s) against Gemini API...")
        validated_results = []
        referer_override = normalize_url(args.referer) if args.referer else None
        for url, key in [(r[0], r[1]) for r in results]:
            referer = referer_override or get_referer_from_url(url)
            v, err = validate_key_gemini(key, referer=referer)
            validated_results.append((url, key, v))
            if v is True and not args.quiet:
                with print_lock:
                    print(c(f"[!] Gemini access: ", YELLOW) + f"{key[:20]}...")
            elif err == "referrer_blocked" and not args.quiet:
                with print_lock:
                    print(c(f"[~] Referrer blocked: ", CYAN) + f"{key[:20]}... (try --referer <url>)")
        results = [(r[0], r[1], r[2]) for r in validated_results]

    # Output
    keys_list = sorted(all_keys)

    if args.output:
        with open(args.output, "w") as f:
            for k in keys_list:
                f.write(k + "\n")
        if not args.quiet:
            print(f"\n[+] Saved {len(keys_list)} keys to {args.output}")

    if args.results:
        with open(args.results, "w") as f:
            for url, key, valid in results:
                v = ",".join(valid) if isinstance(valid, list) else valid
                f.write(f"{url}\t{key}\t{v}\n")
        if not args.quiet:
            print(f"[+] Saved full results to {args.results}")

    if not args.output and not args.quiet:
        if keys_list:
            print(f"\n  {c('Extracted', BOLD) if supports_color() else 'Extracted'} {len(keys_list)} unique key(s)")
            for k in keys_list:
                print(f"    {k}")

    if args.quiet and not args.output:
        for k in keys_list:
            print(k)

    sys.exit(0 if keys_list else 1)


if __name__ == "__main__":
    main()
