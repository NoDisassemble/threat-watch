# Threat Watch

Current release: **v2.0.0**

Threat Watch is a live security intelligence dashboard for exploring software weakness patterns (CWEs), individual vulnerabilities (CVEs), and community honeypot observations.

The dashboard includes separate top-ten watchlists and data-chart views for CWE and CVE intelligence. It combines CISA Known Exploited Vulnerabilities (KEV) data with FIRST EPSS likelihood data, MITRE CWE records, and NVD CVE enrichment.

## Features

- Opens on a unified dashboard with live 60/40 data-and-chart summaries for CWE, CVE, and honeypot intelligence
- Displays the current CWE catalog version and catalog totals
- Ranks ten high-priority weaknesses using CISA KEV, ransomware, recency, and EPSS signals
- Ranks ten recently exploited CVEs using KEV, ransomware, recency, EPSS, and CVSS signals
- Provides separate CWE and CVE chart views through a persistent side navigation
- Charts cumulative CISA KEV catalog additions over the rolling 365-day window
- Shows threat scores and full descriptions for watchlist entries
- Identifies mappings to ranked OWASP Top 10:2025 risk categories
- Looks up individual weaknesses by CWE number
- Looks up individual vulnerabilities by CVE identifier
- Exports the current top-ten CWE watchlist as a PDF report
- Supports light and dark themes
- Caches the generated watchlist for 24 hours to reduce external API requests
- Displays current DShield attacker IPs, targeted ports, SSH usernames, and honeypot-derived indicators
- Provides a dedicated DShield chart view for attacker volume and breadth, port activity and source diversity, SSH usernames, and indicator composition
- Looks up public IP reputation through the DShield API
- Caches DShield telemetry for one hour in accordance with the provider's feed guidance
- Uses independent single-flight refresh locks so concurrent cache misses produce only one upstream refresh per feed

## Data sources

- [MITRE CWE REST API](https://github.com/CWE-CAPEC/REST-API-wg) for CWE catalog metadata and weakness records
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for evidence of exploitation in the wild
- [FIRST EPSS](https://www.first.org/epss/) for exploit-probability percentiles
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for CVE descriptions, CVSS scores, status, references, and CWE mappings
- [OWASP Top 10:2025](https://owasp.org/Top10/) and [MITRE CWE View 1450](https://cwe.mitre.org/data/definitions/1450.html) for CWE-to-OWASP category mappings
- [SANS Internet Storm Center / DShield](https://isc.sans.edu/feeds_doc.html) for community firewall, Cowrie SSH/Telnet, web-scanner, targeted-port, and IP reputation telemetry

DShield data is used with attribution to SANS Technology Institute, Internet Storm Center. Its published terms permit use with attribution but prohibit resale. The public feeds are observational and should not be treated as a definitive blocklist.

An internet connection is required when the server retrieves fresh data. Threat Watch is an informational dashboard; its threat scores are project-specific rankings and should not be treated as official risk ratings.

## Run locally

### Requirements

- Python 3.10 or newer
- A modern web browser
- An internet connection for live API data

Install the FastAPI and Uvicorn dependencies with:

```bash
python -m pip install -r requirements.txt
```

### Start the app

1. Clone the repository and enter its directory:

   ```bash
   git clone https://github.com/NoDisassemble/threat-watch.git
   cd threat-watch
   ```

2. Install the Python dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Start the local server:

   ```bash
   python server.py
   ```

   On Windows, if `python` is not recognized, use:

   ```powershell
   py server.py
   ```

4. Open [http://localhost:8000](http://localhost:8000) in your browser.

5. Press `Ctrl+C` in the terminal to stop the server.

Do not open `index.html` directly. FastAPI serves the SPA and proxies requests to the external APIs.

## API documentation

FastAPI generates the API schema and interactive documentation automatically:

- ReDoc: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- Swagger UI: [http://localhost:8000/api/swagger](http://localhost:8000/api/swagger)
- OpenAPI JSON: [http://localhost:8000/api/openapi.json](http://localhost:8000/api/openapi.json)

The documented API covers the CWE and CVE watchlists, CVE lookup, DShield activity and IP lookup, and the read-only MITRE CWE proxy.

### API safeguards

- Cached feed endpoints are limited to 120 requests per client per minute.
- CVE lookup, DShield IP lookup, and MITRE proxy requests share a stricter limit of 30 requests per client per minute.
- Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`; rejected requests return `429` and `Retry-After`.
- CVE lookups use a bounded 1,000-entry, 24-hour TTL/LRU cache.
- DShield IP lookups use a bounded 2,000-entry, one-hour TTL/LRU cache.
- Approved MITRE responses use a bounded 256-entry, five-minute TTL/LRU cache. Only the version endpoint and numeric weakness lookups are proxied.
- Lookup and feed refresh locks prevent simultaneous cache misses from duplicating upstream calls.

These in-memory limits apply per Uvicorn process. Use a shared Redis cache and rate limiter before running multiple workers or horizontally scaling the Render service.

## Project structure

```text
threat-watch/
|-- index.html       # Dashboard markup
|-- styles.css       # Layout, responsive styles, themes, and charts
|-- script.js        # Dashboard rendering, lookups, charts, and PDF export
|-- server.py        # FastAPI app, API proxies, ranking, timelines, and caches
|-- requirements.txt # Pinned FastAPI and Uvicorn dependencies
|-- owasp_2025.json  # Versioned OWASP category mappings
`-- README.md
```

OWASP badges indicate that a CWE maps to a ranked OWASP risk category. The displayed rank belongs to the broader OWASP category, not to the individual CWE.

## Troubleshooting

- **The dashboard says data is unavailable:** Confirm that the computer can reach the MITRE, CISA, FIRST, and NVD APIs, then select **Refresh data**. If only MITRE is unavailable, the CISA-backed rankings and charts still load with reduced CWE metadata.
- **Port 8000 is already in use:** Stop the other process, or set the `PORT` environment variable before starting the server (for example, `$env:PORT=8080; python server.py` in PowerShell).
- **The data appears stale:** Delete `.watchlist-cache.json`, `.cve-watchlist-cache.json`, and `.dshield-cache.json`, then restart the server to force fresh calculations.

## License

No license has been specified for this project yet.
