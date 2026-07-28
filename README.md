# Threat Watch

Threat Watch is a live security intelligence dashboard for exploring both software weakness patterns (CWEs) and individual vulnerabilities (CVEs).

The dashboard includes separate top-five watchlists and data-chart views for CWE and CVE intelligence. It combines CISA Known Exploited Vulnerabilities (KEV) data with FIRST EPSS likelihood data, MITRE CWE records, and NVD CVE enrichment.

## Features

- Displays the current CWE catalog version and catalog totals
- Ranks five high-priority weaknesses using CISA KEV, ransomware, recency, and EPSS signals
- Ranks five recently exploited CVEs using KEV, ransomware, recency, EPSS, and CVSS signals
- Provides separate CWE and CVE chart views through a persistent side navigation
- Shows threat scores and full descriptions for watchlist entries
- Identifies mappings to ranked OWASP Top 10:2025 risk categories
- Looks up individual weaknesses by CWE number
- Looks up individual vulnerabilities by CVE identifier
- Exports the current top-five watchlist as a PDF report
- Supports light and dark themes
- Caches the generated watchlist for 24 hours to reduce external API requests

## Data sources

- [MITRE CWE REST API](https://github.com/CWE-CAPEC/REST-API-wg) for CWE catalog metadata and weakness records
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for evidence of exploitation in the wild
- [FIRST EPSS](https://www.first.org/epss/) for exploit-probability percentiles
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for CVE descriptions, CVSS scores, status, references, and CWE mappings
- [OWASP Top 10:2025](https://owasp.org/Top10/) and [MITRE CWE View 1450](https://cwe.mitre.org/data/definitions/1450.html) for CWE-to-OWASP category mappings

An internet connection is required when the server retrieves fresh data. Threat Watch is an informational dashboard; its threat scores are project-specific rankings and should not be treated as official risk ratings.

## Run locally

### Requirements

- Python 3.9 or newer
- A modern web browser
- An internet connection for live API data

No Python packages or JavaScript dependencies need to be installed.

### Start the app

1. Clone the repository and enter its directory:

   ```bash
   git clone https://github.com/NoDisassemble/cwe-watchlist.git
   cd cwe-watchlist
   ```

2. Start the local server:

   ```bash
   python server.py
   ```

   On Windows, if `python` is not recognized, use:

   ```powershell
   py server.py
   ```

3. Open [http://localhost:8000](http://localhost:8000) in your browser.

4. Press `Ctrl+C` in the terminal to stop the server.

Do not open `index.html` directly. The Python server is required because it serves the site and proxies requests to the external APIs.

## Project structure

```text
cwe-watchlist/
|-- index.html    # Dashboard markup
|-- styles.css    # Layout, responsive styles, and themes
|-- script.js     # Dashboard rendering, lookup, and PDF export
|-- server.py     # Static server, API proxies, CWE/CVE ranking, and caches
|-- owasp_2025.json # Versioned OWASP category mappings
`-- README.md
```

OWASP badges indicate that a CWE maps to a ranked OWASP risk category. The displayed rank belongs to the broader OWASP category, not to the individual CWE.

## Troubleshooting

- **The dashboard says data is unavailable:** Confirm that the computer can reach the MITRE, CISA, and FIRST APIs, then select **Refresh data**.
- **Port 8000 is already in use:** Stop the other process using that port, or change `8000` near the bottom of `server.py` and open the matching URL.
- **The data appears stale:** Delete `.watchlist-cache.json` and restart the server to force a fresh watchlist calculation.

## License

No license has been specified for this project yet.
