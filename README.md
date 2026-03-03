# KeyReaper

**GCP API Key Scanner** — Extract and access exposed Google Cloud (AIza) API keys from web pages. Built for bug bounty hunters and security researchers.

Keys embedded in client-side code can be scraped by anyone and used for quota theft, unauthorized API access, and billing abuse. KeyReaper finds them and reports which APIs each key can access.

---

## Features

- **Extract** AIza keys from URLs or URL lists
- **Follow scripts** — optionally fetch and scan externally referenced JS files
- **Validate** — test keys against Gemini API
- **Impact assessment** — probe 15 Google APIs and report accessible endpoints
- **Referer support** — test keys restricted by HTTP referrer
- **Key file input** — assess keys from a file (no URL scan)

---

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)

---

## Usage

```bash
# Scan single URL
python keyreaper.py -u https://example.com

# Scan URL list, save keys
python keyreaper.py -l urls.txt -o keys.txt

# Scan with script following (fetch external JS)
python keyreaper.py -l urls.txt --follow-scripts -w 20

# Validate keys against Gemini
python keyreaper.py -u https://example.com --validate

# Full impact assessment (probe all APIs)
python keyreaper.py -u https://example.com --impact

# Use referer for keys with HTTP referrer restrictions
python keyreaper.py -l urls.txt --impact --referer https://example.com/

# Assess keys from file (e.g. from prior scan)
python keyreaper.py -k keys.txt --impact --referer https://example.com/

# Save full results (url, key, accessible APIs)
python keyreaper.py -l urls.txt --impact -r impact.tsv
```

---

## Options

| Flag | Description |
|------|-------------|
| `-u URL` | Single URL to scan |
| `-l FILE` | File with URLs (one per line) |
| `-k FILE` | File with API keys (for `--impact` only) |
| `-o FILE` | Output file for extracted keys |
| `-r FILE` | Output file for full results (TSV: url, key, accessible APIs) |
| `-w N` | Concurrent workers (default: 10) |
| `-t N` | Request timeout in seconds (default: 15) |
| `--loose` | Use loose regex (shorter/partial keys) |
| `--follow-scripts` | Fetch and scan externally referenced JS files |
| `--validate` | Validate keys against Gemini API |
| `--impact` | Probe all APIs and report impact |
| `--referer URL` | Referer header for validation (default: derived from source URL) |
| `-q` | Quiet mode — keys only, minimal output |

---

## APIs Probed (Impact Mode)

| API | Impact |
|-----|--------|
| **Gemini** | LLM access, content generation, image analysis |
| **Maps Geocoding** | Location data, address lookup |
| **Maps Places** | Place details, business info |
| **Maps Directions** | Routing, turn-by-turn directions |
| **Maps Distance Matrix** | Travel time, distance between points |
| **Maps Elevation** | Elevation data for coordinates |
| **Maps Timezone** | Timezone for coordinates |
| **Maps Autocomplete** | Place search predictions |
| **Cloud Vision** | Image analysis, OCR, labels |
| **Translation** | Text translation |
| **YouTube Data** | Video/channel metadata |
| **Books API** | Book metadata, search |
| **Knowledge Graph** | Entity search, facts |
| **PageSpeed Insights** | Site performance data |
| **Custom Search** | Web search results |

---

## Output

**Scan mode:**
```
  ✓ https://example.com — 2 key(s)
  Extracted 2 unique key(s)
    AIzaSyB...
    AIzaSyC...
```

**Impact mode:**
```
  AIzaSyB...  from https://example.com
    ✓  Maps Geocoding     Location data, address lookup
    ✓  Maps Places        Place details, business info
    ✗  Gemini             no access
    ...
    Impact: Location data, address lookup; Place details, business info
```

---

## Bug Bounty Notes

- **Validation uses the victim's quota** — use sparingly; document in reports
- Keys with `referrer_blocked` may work with `--referer` set to the source domain
- `REQUEST_DENIED` = API not enabled on project; key may still be valid for other APIs
- Report: exposed credential + which APIs are accessible + cost/quota impact

---

## Resources

### Google API Documentation
- [Google Cloud API Keys](https://cloud.google.com/docs/authentication/api-keys)
- [Maps APIs Overview](https://developers.google.com/maps/documentation)
- [Geocoding API](https://developers.google.com/maps/documentation/geocoding)
- [Places API](https://developers.google.com/maps/documentation/places/web-service)
- [Gemini API](https://ai.google.dev/gemini-api/docs)
- [Cloud Vision API](https://cloud.google.com/vision/docs)

### Security Research
- [Truffle Security — Exposed Google API Keys](https://trufflesecurity.com/blog/) — Research on default unrestricted keys and Gemini access
- [OWASP — Sensitive Data Exposure](https://owasp.org/www-project-top-ten/)

### Manual Testing (curl)
```bash
# Geocoding
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=KEY"

# Place details
curl "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&key=KEY"

# Gemini models
curl "https://generativelanguage.googleapis.com/v1beta/models?key=KEY"
```

### Best Practices (for remediation)
- [Restrict API keys](https://cloud.google.com/docs/authentication/api-keys#adding_api_restrictions)
- [Restrict by HTTP referrer](https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions)
- Rotate keys immediately after exposure

---

## Author

c0d3Ninja
