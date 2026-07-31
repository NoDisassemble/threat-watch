# Changelog

All notable changes to Threat Watch are documented here.

## [2.2.0] - 2026-07-30

### Added

- Added a searchable APT and country-attributed threat-actor catalog backed by the public MISP Galaxy repository
- Added actor aliases, suspected sponsors, target sectors, attribution confidence, and primary research references
- Added 24-hour single-flight caching with stale-data fallback for the normalized actor catalog
- Added APT summary metrics and country-attribution distribution to the overview dashboard
- Added Actor Catalog charts for country attribution, target sectors, metadata completeness, and alias/reference depth
- Added a near-live DShield activity stage above the overview cards with an animated source map, replaying activity feed, source-country totals, and targeted-port totals
- Added hourly country and network enrichment for a bounded set of top DShield sources
- Replaced the schematic activity map with a detailed CC0 Natural Earth silhouette and removed the scanning haze animation
- Added authenticated Cloudflare Radar target-country and origin-to-target flow telemetry through a server-side API proxy
- Added Sources, Targets, and Flows controls to the overview threat map with view-specific labels, legends, ranked feeds, and methodology notes
- Added animated aggregate attack paths using Cloudflare-observed layer 7 origin and target country pairs
- Added one-hour Radar caching with stale-data fallback and a Render secret placeholder for `CLOUDFLARE_API_TOKEN`

### Changed

- Widened the overview workspace, enlarged the threat map, rebalanced space away from the source feed, and arranged dashboard cards two per desktop row
- Tightened dashboard-card height and moved the overview headline onto one line
- Clarified the difference between individual source IPs, country markers, targets, and aggregate attack paths

## [2.1.0] - 2026-07-29

### Added

- Added a RansomLook-backed ransomware Top 10 based on unique public victim claims observed over 30 days
- Added ransomware activity metrics, ranked group cards, a landing-page summary, and dedicated data charts
- Added one-hour single-flight caching with stale-data fallback for ransomware activity
- Added sidebar release branding driven by the backend version endpoint
- Added an explicit Render Blueprint with dependency installation and health-check configuration

## [2.0.0] - 2026-07-29

### Added

- Unified overview dashboard for CWE, CVE, and honeypot intelligence
- DShield community honeypot feed, charts, indicators, and IP reputation lookup
- FastAPI backend with OpenAPI 3.1, ReDoc, and Swagger UI
- Bounded TTL/LRU caches, single-flight refresh locks, per-client rate limits, and restricted MITRE proxy routes
- Dedicated chart views and responsive navigation for all tracked intelligence domains

### Changed

- Expanded CWE and CVE rankings from Top 5 to Top 10
- Updated the CWE report export for ten records and multipage output
- Standardized page heading sizes, spacing, and dashboard navigation
- Added pinned FastAPI and Uvicorn runtime dependencies

[2.1.0]: https://github.com/NoDisassemble/threat-watch/releases/tag/v2.1.0
[2.2.0]: https://github.com/NoDisassemble/threat-watch/releases/tag/v2.2.0
[2.0.0]: https://github.com/NoDisassemble/threat-watch/releases/tag/v2.0.0
