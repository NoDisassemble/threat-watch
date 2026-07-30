# Changelog

All notable changes to Threat Watch are documented here.

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

[2.0.0]: https://github.com/NoDisassemble/threat-watch/releases/tag/v2.0.0
