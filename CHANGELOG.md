# Changelog

All notable changes to Threat Watch are documented here.

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
[2.0.0]: https://github.com/NoDisassemble/threat-watch/releases/tag/v2.0.0
