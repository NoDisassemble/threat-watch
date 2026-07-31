# Threat Watch

Current release: **v2.2.0**

Threat Watch is a live security intelligence dashboard for exploring APT and country-attributed threat actors, software weakness patterns (CWEs), individual vulnerabilities (CVEs), community honeypot observations, and ransomware leak-site activity.

The dashboard combines the public MISP threat-actor galaxy with CISA Known Exploited Vulnerabilities (KEV), FIRST EPSS likelihood data, MITRE CWE records, NVD CVE enrichment, DShield telemetry, Cloudflare Radar attack aggregates, and RansomLook observations.

## Features

- Opens on a unified dashboard with data-and-chart summaries across five intelligence domains
- Shows a near-live activity stage with switchable DShield source geography, Cloudflare Radar target countries, and origin-to-target attack flows
- Provides a searchable, country-filterable catalog of APT and country-attributed threat actors
- Shows actor aliases, suspected sponsors, target sectors, attribution confidence, and supporting references
- Charts country attribution, target sectors, metadata completeness, and alias/reference depth for the actor catalog
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
- Enriches a bounded set of top DShield sources with country and network ownership once per hourly refresh
- Provides a dedicated DShield chart view for attacker volume and breadth, port activity and source diversity, SSH usernames, and indicator composition
- Looks up public IP reputation through the DShield API
- Caches DShield telemetry for one hour in accordance with the provider's feed guidance
- Caches normalized Cloudflare Radar target and flow telemetry for one hour with stale-data fallback
- Uses independent single-flight refresh locks so concurrent cache misses produce only one upstream refresh per feed
- Ranks the ten most active ransomware groups by unique public victim claims observed over a rolling 30-day window
- Charts ransomware claim volume, seven-day activity, activity share, and the daily discovery timeline
- Caches the normalized RansomLook snapshot for one hour and falls back to stale data during upstream interruptions

## Data sources

- [MITRE CWE REST API](https://github.com/CWE-CAPEC/REST-API-wg) for CWE catalog metadata and weakness records
- [MISP Galaxy](https://github.com/MISP/misp-galaxy) for community-maintained threat-actor profiles, aliases, attribution metadata, sectors, and references
- [Natural Earth](https://www.naturalearthdata.com/) CC0 land geometry for the overview activity-map silhouette
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for evidence of exploitation in the wild
- [FIRST EPSS](https://www.first.org/epss/) for exploit-probability percentiles
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for CVE descriptions, CVSS scores, status, references, and CWE mappings
- [OWASP Top 10:2025](https://owasp.org/Top10/) and [MITRE CWE View 1450](https://cwe.mitre.org/data/definitions/1450.html) for CWE-to-OWASP category mappings
- [SANS Internet Storm Center / DShield](https://isc.sans.edu/feeds_doc.html) for community firewall, Cowrie SSH/Telnet, web-scanner, targeted-port, and IP reputation telemetry
- [Cloudflare Radar](https://developers.cloudflare.com/radar/) for aggregate layer 7 target-country and origin-to-target attack shares
- [RansomLook](https://www.ransomlook.io/doc/) for public ransomware-group leak-site posts and discovery timestamps

DShield data is used with attribution to SANS Technology Institute, Internet Storm Center. Its published terms permit use with attribution but prohibit resale. The public feeds are observational and should not be treated as a definitive blocklist.

Cloudflare Radar target and flow values are aggregate percentages of mitigated layer 7 requests, not individual live attacks. Target geography reflects the attacked zone's billing country, and origin geography does not establish the location of a human operator.

RansomLook posts are public leak-site claims rather than independently verified incidents. Threat Watch deduplicates and summarizes them for defensive research, preserves source attribution, and does not expose the raw upstream feed through its API.

MISP actor attribution can be disputed and its entries may represent actors, activity clusters, campaigns, or operations. Threat Watch includes only profiles with structured country or suspected-state-sponsor fields, displays the underlying references, and does not treat inclusion as proof of government control or current activity.

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

   To enable the target and flow map views locally, copy `.env.example` to `.env` and add a Cloudflare token scoped to **Account > Radar > Read**:

   ```dotenv
   CLOUDFLARE_API_TOKEN=your-token
   ```

   The local `.env` file is ignored by Git. Existing system and Render environment variables take precedence over values in this file.

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

## Deploy on Render

The included `render.yaml` configures Threat Watch as a Python web service. It installs the pinned dependencies before starting FastAPI:

```text
Build Command: python -m pip install -r requirements.txt
Start Command: python -u server.py
```

For an existing Render service created outside a Blueprint, set those commands under **Settings > Build & Deploy**, then select **Manual Deploy > Clear build cache & deploy**. The server reads Render's `PORT` environment variable automatically.

Set `CLOUDFLARE_API_TOKEN` under the service's **Environment** settings to enable Radar target and flow views. The Blueprint declares this key with `sync: false`; never commit the token value.

## API documentation

FastAPI generates the API schema and interactive documentation automatically:

- ReDoc: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- Swagger UI: [http://localhost:8000/api/swagger](http://localhost:8000/api/swagger)
- OpenAPI JSON: [http://localhost:8000/api/openapi.json](http://localhost:8000/api/openapi.json)

The normalized ransomware, actor, and Radar feeds are available at `GET /api/ransomware`, `GET /api/apt`, and `GET /api/radar` and are included in both generated documentation views.

The documented API covers the APT catalog, CWE and CVE watchlists, CVE lookup, DShield activity and IP lookup, Cloudflare Radar targets and flows, ransomware group activity, and the read-only MITRE CWE proxy.

### API safeguards

- Cached feed endpoints are limited to 120 requests per client per minute.
- CVE lookup, DShield IP lookup, and MITRE proxy requests share a stricter limit of 30 requests per client per minute.
- Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`; rejected requests return `429` and `Retry-After`.
- CVE lookups use a bounded 1,000-entry, 24-hour TTL/LRU cache.
- DShield IP lookups use a bounded 2,000-entry, one-hour TTL/LRU cache.
- Approved MITRE responses use a bounded 256-entry, five-minute TTL/LRU cache. Only the version endpoint and numeric weakness lookups are proxied.
- Lookup and feed refresh locks prevent simultaneous cache misses from duplicating upstream calls.
- Ransomware data is deduplicated, normalized, and cached for one hour; visitors receive the cached Top 10 and chart dataset instead of the raw upstream feed.
- MISP actor data is normalized and cached for 24 hours, with stale-data fallback during upstream interruptions.

These in-memory limits apply per Uvicorn process. Use a shared Redis cache and rate limiter before running multiple workers or horizontally scaling the Render service.

## Release checklist

For every release, update the `VERSION` constant in `server.py`, the current release at the top of this README, and `CHANGELOG.md` before creating the commit and Git tag. The sidebar reads `/api/version`, so its visible release branding follows the backend version automatically.

## Project structure

```text
threat-watch/
|-- index.html       # Dashboard markup
|-- styles.css       # Layout, responsive styles, themes, and charts
|-- script.js        # Dashboard rendering, lookups, charts, and PDF export
|-- server.py        # FastAPI app, API proxies, rankings, timelines, and caches
|-- requirements.txt # Pinned FastAPI and Uvicorn dependencies
|-- render.yaml      # Render build, start, and health-check configuration
|-- owasp_2025.json  # Versioned OWASP category mappings
`-- README.md
```

OWASP badges indicate that a CWE maps to a ranked OWASP risk category. The displayed rank belongs to the broader OWASP category, not to the individual CWE.

## Troubleshooting

- **The dashboard says data is unavailable:** Confirm that the computer can reach the MITRE, MISP GitHub, CISA, FIRST, NVD, DShield, Cloudflare Radar, and RansomLook sources, then select **Refresh data**. Target and flow views also require `CLOUDFLARE_API_TOKEN`. If only MITRE is unavailable, the CISA-backed rankings and charts still load with reduced CWE metadata.
- **Port 8000 is already in use:** Stop the other process, or set the `PORT` environment variable before starting the server (for example, `$env:PORT=8080; python server.py` in PowerShell).
- **The data appears stale:** Delete `.watchlist-cache.json`, `.cve-watchlist-cache.json`, `.dshield-cache.json`, `.radar-cache.json`, `.ransomware-cache.json`, and `.apt-cache.json`, then restart the server to force fresh calculations.

## License

No license has been specified for this project yet.
