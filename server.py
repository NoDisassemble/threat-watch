"""Serve the Threat Watch SPA and APIs with FastAPI.

Run: python server.py
Then open: http://localhost:8000
"""

import json
import os
import ipaddress
import re
from collections import defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from threading import Lock
from time import monotonic, time as wall_time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

MITRE_API = "https://cwe-api.mitre.org"
# Single source of truth for API metadata and the version shown in the sidebar.
VERSION = "2.2.0"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_FILE = Path(__file__).with_name(".watchlist-cache.json")
CVE_CACHE_FILE = Path(__file__).with_name(".cve-watchlist-cache.json")
DSHIELD_CACHE_FILE = Path(__file__).with_name(".dshield-cache.json")
RANSOMWARE_CACHE_FILE = Path(__file__).with_name(".ransomware-cache.json")
APT_CACHE_FILE = Path(__file__).with_name(".apt-cache.json")
RADAR_CACHE_FILE = Path(__file__).with_name(".radar-cache.json")
OWASP_MAP_FILE = Path(__file__).with_name("owasp_2025.json")
CACHE_MAX_AGE = timedelta(hours=24)
DSHIELD_CACHE_MAX_AGE = timedelta(hours=1)
RANSOMWARE_CACHE_MAX_AGE = timedelta(hours=1)
APT_CACHE_MAX_AGE = timedelta(hours=24)
RADAR_CACHE_MAX_AGE = timedelta(hours=1)
DSHIELD_TOP_IPS_API = "https://isc.sans.edu/api/topips/records/20?json"
DSHIELD_TOP_PORTS_API = "https://isc.sans.edu/api/topports/records/20?json"
DSHIELD_INTELFEED_API = "https://isc.sans.edu/api/intelfeed?json"
DSHIELD_USERNAMES_API = "https://isc.sans.edu/sshallusernames.json"
RANSOMLOOK_POSTS_API = "https://www.ransomlook.io/api/posts?days=30"
MISP_THREAT_ACTORS_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)
CLOUDFLARE_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top"
RANSOMWARE_WINDOW_DAYS = 30
# Thirteen calendar buckets cover the rolling 365-day window, including both
# partial boundary months.
TIMELINE_MONTHS = 13
BASE_DIR = Path(__file__).resolve().parent
STATIC_FILES = {"index.html", "styles.css", "script.js"}
CWE_REFRESH_LOCK = Lock()
CVE_REFRESH_LOCK = Lock()
DSHIELD_REFRESH_LOCK = Lock()
RANSOMWARE_REFRESH_LOCK = Lock()
APT_REFRESH_LOCK = Lock()
RADAR_REFRESH_LOCK = Lock()
CVE_LOOKUP_REFRESH_LOCK = Lock()
DSHIELD_IP_REFRESH_LOCK = Lock()
MITRE_PROXY_REFRESH_LOCK = Lock()
CVE_LOOKUP_TTL = timedelta(hours=24)
DSHIELD_IP_TTL = timedelta(hours=1)
MITRE_PROXY_TTL = timedelta(minutes=5)
MITRE_ALLOWED_PATHS = (
    re.compile(r"cwe/version"),
    re.compile(r"cwe/weakness/\d+(?:,\d+){0,49}"),
)


class TTLCache:
    """Thread-safe bounded in-memory TTL/LRU cache."""
    def __init__(self, max_size):
        self.max_size = max_size
        self.entries = OrderedDict()
        self.lock = Lock()

    def get(self, key):
        now = monotonic()
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                return False, None
            expires_at, value = entry
            if expires_at <= now:
                del self.entries[key]
                return False, None
            self.entries.move_to_end(key)
            return True, value

    def set(self, key, value, ttl_seconds):
        with self.lock:
            self.entries[key] = (monotonic() + ttl_seconds, value)
            self.entries.move_to_end(key)
            while len(self.entries) > self.max_size:
                self.entries.popitem(last=False)


class SlidingWindowRateLimiter:
    """Bounded per-client request limiter for a single application process."""
    def __init__(self, max_clients=10000):
        self.max_clients = max_clients
        self.clients = OrderedDict()
        self.lock = Lock()

    def check(self, key, limit, window_seconds):
        now = monotonic()
        cutoff = now - window_seconds
        with self.lock:
            requests = self.clients.get(key, deque())
            while requests and requests[0] <= cutoff:
                requests.popleft()
            allowed = len(requests) < limit
            if allowed:
                requests.append(now)
            self.clients[key] = requests
            self.clients.move_to_end(key)
            while len(self.clients) > self.max_clients:
                self.clients.popitem(last=False)
            remaining = max(0, limit - len(requests))
            retry_after = max(1, int(window_seconds - (now - requests[0]))) if requests else window_seconds
            return allowed, remaining, retry_after


CVE_LOOKUP_CACHE = TTLCache(max_size=1000)
DSHIELD_IP_CACHE = TTLCache(max_size=2000)
MITRE_PROXY_CACHE = TTLCache(max_size=256)
API_RATE_LIMITER = SlidingWindowRateLimiter()


class OwaspCategory(BaseModel):
    code: str
    rank: int
    name: str
    url: str


class TimelinePoint(BaseModel):
    month: str
    count: int


class WeaknessTimeline(BaseModel):
    id: str
    points: List[TimelinePoint] = Field(default_factory=list)


class CweWatchlistItem(BaseModel):
    id: str
    kev_count: int
    ransomware_count: int
    recent_count: int
    epss_percentile: float
    threat_score: float
    owasp: List[OwaspCategory] = Field(default_factory=list)


class CweWatchlistResponse(BaseModel):
    items: List[CweWatchlistItem] = Field(default_factory=list)
    catalog_date: Optional[str] = None
    method: Optional[str] = None
    exploitation_timeline: List[WeaknessTimeline] = Field(default_factory=list)
    owasp_edition: Optional[str] = None
    error: Optional[str] = None


class CveRecord(BaseModel):
    id: Optional[str] = None
    description: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    status: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwes: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class CveWatchlistItem(CveRecord):
    id: str
    vendor: str
    product: str
    name: str
    short_description: str = ""
    date_added: str
    due_date: Optional[str] = None
    required_action: str = ""
    ransomware: bool = False
    epss_probability: float = 0
    epss_percentile: float = 0
    threat_score: float = 0


class CveWatchlistResponse(BaseModel):
    items: List[CveWatchlistItem] = Field(default_factory=list)
    catalog_date: Optional[str] = None
    candidate_count: int = 0
    method: Optional[str] = None
    window_days: int = 0
    exploitation_timeline: List[TimelinePoint] = Field(default_factory=list)
    error: Optional[str] = None


class DshieldAttacker(BaseModel):
    rank: Optional[int] = None
    ip: str
    reports: int = 0
    targets: int = 0
    country: Optional[str] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None


class DshieldPort(BaseModel):
    rank: Optional[int] = None
    port: int
    records: int = 0
    targets: int = 0
    sources: int = 0


class DshieldUsername(BaseModel):
    username: str
    count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class DshieldIndicator(BaseModel):
    ip: Optional[str] = None
    category: str


class DshieldActivityResponse(BaseModel):
    top_attackers: List[DshieldAttacker] = Field(default_factory=list)
    top_ports: List[DshieldPort] = Field(default_factory=list)
    top_ports_date: Optional[str] = None
    usernames: List[DshieldUsername] = Field(default_factory=list)
    indicators: List[DshieldIndicator] = Field(default_factory=list)
    indicator_counts: Dict[str, int] = Field(default_factory=dict)
    indicator_total: int = 0
    generated_at: Optional[str] = None
    cache_seconds: int = 0
    errors: List[str] = Field(default_factory=list)
    attribution: Optional[str] = None
    schema_version: int = 1
    error: Optional[str] = None


class DshieldIpResponse(BaseModel):
    ip: Optional[str] = None
    reports: Optional[int] = None
    targets: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    updated: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None
    network: Optional[str] = None
    comment: Optional[str] = None
    error: Optional[str] = None


class RadarTarget(BaseModel):
    rank: int
    country: str
    country_name: str
    value: float = 0


class RadarFlow(BaseModel):
    rank: int
    origin_country: str
    origin_name: str
    target_country: str
    target_name: str
    value: float = 0


class RadarActivityResponse(BaseModel):
    targets: List[RadarTarget] = Field(default_factory=list)
    flows: List[RadarFlow] = Field(default_factory=list)
    period_start: Optional[str] = None
    period_end: Optional[str] = None
    generated_at: Optional[str] = None
    cache_seconds: int = 0
    source: Optional[str] = None
    methodology: Optional[str] = None
    stale: bool = False
    warning: Optional[str] = None
    schema_version: int = 1
    error: Optional[str] = None


class RansomwareVictimClaim(BaseModel):
    title: str
    discovered: str


class RansomwareGroupActivity(BaseModel):
    name: str
    claim_count: int = 0
    recent_7d_count: int = 0
    previous_7d_count: int = 0
    share_percentage: float = 0
    last_seen: Optional[str] = None
    recent_victims: List[RansomwareVictimClaim] = Field(default_factory=list)


class DailyActivityPoint(BaseModel):
    date: str
    count: int = 0


class RansomwareActivityResponse(BaseModel):
    items: List[RansomwareGroupActivity] = Field(default_factory=list)
    total_claims: int = 0
    active_groups: int = 0
    window_days: int = 30
    generated_at: Optional[str] = None
    cache_seconds: int = 0
    daily_activity: List[DailyActivityPoint] = Field(default_factory=list)
    source: Optional[str] = None
    methodology: Optional[str] = None
    stale: bool = False
    warning: Optional[str] = None
    error: Optional[str] = None


class AptActor(BaseModel):
    name: str
    uuid: str
    description: str = ""
    country_code: Optional[str] = None
    suspected_sponsor: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    sectors: List[str] = Field(default_factory=list)
    classifications: List[str] = Field(default_factory=list)
    incident_type: Optional[str] = None
    attribution_confidence: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class AptCatalogResponse(BaseModel):
    items: List[AptActor] = Field(default_factory=list)
    actor_count: int = 0
    country_count: int = 0
    suspected_sponsor_count: int = 0
    generated_at: Optional[str] = None
    cache_seconds: int = 0
    source: Optional[str] = None
    methodology: Optional[str] = None
    stale: bool = False
    warning: Optional[str] = None
    error: Optional[str] = None


app = FastAPI(
    title="Threat Watch API",
    summary="Live vulnerability, threat actor, and community telemetry intelligence",
    description=(
        "Backend API for the Threat Watch SPA. It combines MITRE CWE, CISA KEV, "
        "FIRST EPSS, NVD CVE, the MISP threat-actor galaxy, SANS ISC/DShield "
        "community telemetry, Cloudflare Radar attack aggregates, and RansomLook "
        "leak-site observations."
    ),
    version=VERSION,
    docs_url="/api/swagger",
    redoc_url="/api/docs",
    openapi_url="/api/openapi.json",
    contact={"name": "Threat Watch", "url": "https://github.com/NoDisassemble/threat-watch"},
    license_info={"name": "No project license specified"},
)


def client_address(request: Request):
    """Use Render's first forwarded address when valid, then socket peer data."""
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    candidates = []
    if os.environ.get("RENDER", "").lower() == "true":
        candidates.append(forwarded)
    candidates.append(request.client.host if request.client else "")
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return "unknown"


@app.middleware("http")
async def api_security(request: Request, call_next):
    """Rate-limit public APIs and attach baseline response security headers."""
    path = request.url.path
    docs_paths = {app.docs_url, app.redoc_url, app.openapi_url}
    limit = None
    window_seconds = 60
    if path.startswith("/api/") and path not in docs_paths:
        expensive = path.startswith(("/api/cve/", "/api/dshield/ip/", "/api/v1/"))
        limit = 30 if expensive else 120
        bucket = "lookup" if expensive else "feed"
        key = f"{client_address(request)}:{bucket}"
        allowed, remaining, retry_after = API_RATE_LIMITER.check(key, limit, window_seconds)
        rate_headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(wall_time() + retry_after)),
        }
        if not allowed:
            rate_headers.update({
                "Retry-After": str(retry_after),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
                "Referrer-Policy": "strict-origin-when-cross-origin",
            })
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers=rate_headers,
            )
    else:
        rate_headers = {}

    response = await call_next(request)
    response.headers.update(rate_headers)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def cache_response(response: Response, seconds: int):
    response.headers["Cache-Control"] = f"public, max-age={seconds}"


def single_flight(lock):
    """Allow only one cache check/refresh operation at a time per feed."""
    def decorator(function):
        @wraps(function)
        def synchronized(*args, **kwargs):
            with lock:
                return function(*args, **kwargs)
        return synchronized
    return decorator


def month_key(value):
    """Return a sortable YYYY-MM key for an ISO date, or None when invalid."""
    try:
        return datetime.fromisoformat(value).date().strftime("%Y-%m")
    except (TypeError, ValueError):
        return None


def recent_months(today, count=TIMELINE_MONTHS):
    """Return the most recent calendar months in chronological order."""
    months = []
    year, month = today.year, today.month
    for offset in range(count - 1, -1, -1):
        index = year * 12 + month - 1 - offset
        months.append(f"{index // 12:04d}-{index % 12 + 1:02d}")
    return months


def load_owasp_mappings():
    """Build a CWE-to-category lookup from the versioned OWASP mapping file."""
    try:
        source = json.loads(OWASP_MAP_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    mappings = defaultdict(list)
    for category in source.get("categories", []):
        details = {key: category[key] for key in ("code", "rank", "name", "url")}
        for cwe_id in category.get("cwes", []):
            mappings[str(cwe_id)].append(details)
    return dict(mappings)


OWASP_MAPPINGS = load_owasp_mappings()


def add_owasp_mappings(data):
    """Annotate watchlist items without changing their threat ranking."""
    for item in data.get("items", []):
        item["owasp"] = OWASP_MAPPINGS.get(str(item.get("id")), [])
    data["owasp_edition"] = "2025"
    return data


@app.get("/api/version", tags=["System"])
def app_version(response: Response):
    """Return the current Threat Watch release version for UI branding."""
    cache_response(response, 3600)
    return {"version": VERSION}


@app.get("/api/watchlist", response_model=CweWatchlistResponse, tags=["CWE"])
def cwe_watchlist(response: Response):
    """Return the ten highest-ranked weakness patterns."""
    cache_response(response, int(CACHE_MAX_AGE.total_seconds()))
    return get_threat_watchlist()


@app.get("/api/cve-watchlist", response_model=CveWatchlistResponse, tags=["CVE"])
def cve_watchlist(response: Response):
    """Return the ten highest-ranked actively exploited vulnerabilities."""
    cache_response(response, int(CACHE_MAX_AGE.total_seconds()))
    return get_cve_watchlist()


@app.get("/api/cve/{cve_id}", response_model=CveRecord, tags=["CVE"])
def cve_record(cve_id: str, response: Response):
    """Look up and normalize one CVE record from NVD."""
    normalized = cve_id.upper()
    if not normalized.startswith("CVE-"):
        normalized = f"CVE-{normalized}"
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise HTTPException(status_code=400, detail="Enter a valid CVE identifier.")
    hit, record = CVE_LOOKUP_CACHE.get(normalized)
    cache_status = "HIT" if hit else "MISS"
    if not hit:
        with CVE_LOOKUP_REFRESH_LOCK:
            hit, record = CVE_LOOKUP_CACHE.get(normalized)
            cache_status = "HIT" if hit else "MISS"
            if not hit:
                try:
                    record = fetch_nvd_cves([normalized]).get(normalized)
                except (HTTPError, URLError, json.JSONDecodeError) as error:
                    raise HTTPException(status_code=502, detail="Unable to reach the NVD CVE API.") from error
                ttl = CVE_LOOKUP_TTL.total_seconds() if record else 600
                CVE_LOOKUP_CACHE.set(normalized, record, ttl)
    if not record:
        raise HTTPException(status_code=404, detail=f"No NVD record was found for {normalized}.")
    cache_response(response, int(CVE_LOOKUP_TTL.total_seconds()))
    response.headers["X-Threat-Watch-Cache"] = cache_status
    return record


@app.get("/api/dshield", response_model=DshieldActivityResponse, tags=["Honeypots"])
def dshield_activity(response: Response):
    """Return a compact snapshot of public DShield community telemetry."""
    cache_response(response, int(DSHIELD_CACHE_MAX_AGE.total_seconds()))
    return get_dshield_activity()


@app.get("/api/radar", response_model=RadarActivityResponse, tags=["Network telemetry"])
def radar_activity(response: Response):
    """Return normalized Cloudflare Radar target countries and attack paths."""
    data = get_radar_activity()
    cache_response(response, 60 if data.get("error") else int(RADAR_CACHE_MAX_AGE.total_seconds()))
    return data


@app.get("/api/ransomware", response_model=RansomwareActivityResponse, tags=["Ransomware"])
def ransomware_activity(response: Response):
    """Return ransomware groups ranked by unique public victim claims over 30 days."""
    cache_response(response, int(RANSOMWARE_CACHE_MAX_AGE.total_seconds()))
    return get_ransomware_activity()


@app.get("/api/apt", response_model=AptCatalogResponse, tags=["Threat actors"])
def apt_catalog(response: Response):
    """Return country-attributed APT and threat-actor profiles from MISP Galaxy."""
    cache_response(response, int(APT_CACHE_MAX_AGE.total_seconds()))
    return get_apt_catalog()


@app.get("/api/dshield/ip/{address}", response_model=DshieldIpResponse, tags=["Honeypots"])
def dshield_ip(address: str, response: Response):
    """Look up one public IP address in the DShield reputation database."""
    try:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Enter a valid public IP address.") from error
    key = str(parsed)
    hit, result = DSHIELD_IP_CACHE.get(key)
    cache_status = "HIT" if hit else "MISS"
    if not hit:
        with DSHIELD_IP_REFRESH_LOCK:
            hit, result = DSHIELD_IP_CACHE.get(key)
            cache_status = "HIT" if hit else "MISS"
            if not hit:
                result = get_dshield_ip(key)
                if not result.get("error"):
                    DSHIELD_IP_CACHE.set(key, result, DSHIELD_IP_TTL.total_seconds())
    if result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])
    cache_response(response, int(DSHIELD_IP_TTL.total_seconds()))
    response.headers["X-Threat-Watch-Cache"] = cache_status
    return result


@app.get("/api/v1/{mitre_path:path}", tags=["MITRE proxy"], response_model=None)
def mitre_proxy(mitre_path: str):
    """Proxy a read-only MITRE CWE API path through the same origin."""
    if not any(pattern.fullmatch(mitre_path) for pattern in MITRE_ALLOWED_PATHS):
        raise HTTPException(status_code=404, detail="MITRE proxy path is not allowed.")
    hit, cached = MITRE_PROXY_CACHE.get(mitre_path)
    if hit:
        status_code, body, media_type = cached
        return Response(
            content=body, status_code=status_code, media_type=media_type,
            headers={"Cache-Control": "public, max-age=300", "X-Threat-Watch-Cache": "HIT"},
        )

    target_url = f"{MITRE_API}/api/v1/{mitre_path}"
    with MITRE_PROXY_REFRESH_LOCK:
        hit, cached = MITRE_PROXY_CACHE.get(mitre_path)
        if hit:
            status_code, body, media_type = cached
            cache_status = "HIT"
        else:
            request = UrlRequest(target_url, headers={"Accept": "application/json", "User-Agent": f"Threat-Watch/{VERSION}"})
            try:
                with urlopen(request, timeout=20) as upstream:
                    status_code = upstream.status
                    body = upstream.read()
                    media_type = upstream.headers.get_content_type()
                    MITRE_PROXY_CACHE.set(
                        mitre_path, (status_code, body, media_type), MITRE_PROXY_TTL.total_seconds()
                    )
                    cache_status = "MISS"
            except HTTPError as error:
                return Response(
                    content=error.read(), status_code=error.code,
                    media_type=error.headers.get_content_type() if error.headers else "application/json",
                    headers={"Cache-Control": "no-store"},
                )
            except URLError as error:
                raise HTTPException(status_code=502, detail="Unable to reach the MITRE CWE API.") from error
    return Response(
        content=body, status_code=status_code, media_type=media_type,
        headers={"Cache-Control": "public, max-age=300", "X-Threat-Watch-Cache": cache_status},
    )


@app.get("/", include_in_schema=False)
def spa_index():
    return FileResponse(BASE_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/{asset_path:path}", include_in_schema=False)
def spa_assets(asset_path: str):
    """Serve the small set of SPA assets and support history-style fallbacks."""
    if asset_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found.")
    if asset_path in STATIC_FILES:
        return FileResponse(BASE_DIR / asset_path, headers={"Cache-Control": "public, max-age=300"})
    return FileResponse(BASE_DIR / "index.html", headers={"Cache-Control": "no-cache"})


def fetch_json(url):
    request = UrlRequest(url, headers={"Accept": "application/json", "User-Agent": f"Threat-Watch/{VERSION}"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def fetch_radar_json(path, name):
    """Fetch one authenticated Cloudflare Radar aggregate without exposing its token."""
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Cloudflare Radar is not configured.")
    query = urlencode({"dateRange": "1d", "limit": 12, "format": "json", "name": name})
    request = UrlRequest(
        f"{CLOUDFLARE_RADAR_BASE}/{path}?{query}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"Threat-Watch/{VERSION}",
        },
    )
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ValueError("Cloudflare Radar returned an unexpected response.")
    return payload


def radar_result_items(payload, name):
    """Return the named Radar result list while tolerating its default top_0 key."""
    result = payload.get("result", {})
    if not isinstance(result, dict):
        raise ValueError("Cloudflare Radar returned an unexpected result.")
    items = result.get(name)
    if not isinstance(items, list):
        items = result.get("top_0")
    if not isinstance(items, list):
        raise ValueError("Cloudflare Radar did not return ranked data.")
    return items


def radar_country_code(value):
    """Normalize one ISO alpha-2 country code from the Radar response."""
    code = str(value or "").strip().upper()
    return code if re.fullmatch(r"[A-Z]{2}", code) else None


def radar_date_range(payload):
    """Extract the observation window from Radar metadata."""
    result = payload.get("result", {}) if isinstance(payload, dict) else {}
    meta = result.get("meta", {}) if isinstance(result, dict) else {}
    date_range = meta.get("dateRange", {}) if isinstance(meta, dict) else {}
    if isinstance(date_range, list):
        date_range = date_range[0] if date_range else {}
    if not isinstance(date_range, dict):
        return None, None
    return date_range.get("startTime"), date_range.get("endTime")


@single_flight(RADAR_REFRESH_LOCK)
def get_radar_activity():
    """Cache and normalize Cloudflare's aggregate layer 7 target telemetry."""
    cached_data = None
    if RADAR_CACHE_FILE.exists():
        try:
            cached = json.loads(RADAR_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            cached_data = cached["data"]
            if (cached_data.get("schema_version") == 1 and
                    datetime.now(timezone.utc) - created < RADAR_CACHE_MAX_AGE):
                return cached_data
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            cached_data = None

    try:
        targets_payload = fetch_radar_json("locations/target", "targets")
        flows_payload = fetch_radar_json("attacks", "flows")
        target_items = radar_result_items(targets_payload, "targets")
        flow_items = radar_result_items(flows_payload, "flows")
    except (HTTPError, URLError, json.JSONDecodeError, RuntimeError, TypeError, ValueError):
        if cached_data:
            stale_data = dict(cached_data)
            stale_data.update({
                "stale": True,
                "warning": "Cloudflare Radar is temporarily unavailable; showing the last cached snapshot.",
            })
            return stale_data
        return {"error": "Cloudflare Radar target telemetry is temporarily unavailable."}

    targets = []
    for item in target_items:
        if not isinstance(item, dict):
            continue
        code = radar_country_code(item.get("targetCountryAlpha2"))
        try:
            value = round(float(item.get("value") or 0), 4)
            rank = int(item.get("rank") or len(targets) + 1)
        except (TypeError, ValueError):
            continue
        if code:
            targets.append({
                "rank": rank,
                "country": code,
                "country_name": clean_actor_text(item.get("targetCountryName"), 80) or code,
                "value": value,
            })

    flows = []
    for item in flow_items:
        if not isinstance(item, dict):
            continue
        origin = radar_country_code(item.get("originCountryAlpha2"))
        target = radar_country_code(item.get("targetCountryAlpha2"))
        try:
            value = round(float(item.get("value") or 0), 4)
            rank = int(item.get("rank") or len(flows) + 1)
        except (TypeError, ValueError):
            continue
        if origin and target:
            flows.append({
                "rank": rank,
                "origin_country": origin,
                "origin_name": clean_actor_text(item.get("originCountryName"), 80) or origin,
                "target_country": target,
                "target_name": clean_actor_text(item.get("targetCountryName"), 80) or target,
                "value": value,
            })

    if not targets or not flows:
        if cached_data:
            stale_data = dict(cached_data)
            stale_data.update({
                "stale": True,
                "warning": "Cloudflare Radar returned incomplete data; showing the last cached snapshot.",
            })
            return stale_data
        return {"error": "Cloudflare Radar did not return usable target telemetry."}

    period_start, period_end = radar_date_range(targets_payload)
    now = datetime.now(timezone.utc)
    data = {
        "targets": sorted(targets, key=lambda item: item["rank"])[:12],
        "flows": sorted(flows, key=lambda item: item["rank"])[:12],
        "period_start": period_start,
        "period_end": period_end,
        "generated_at": now.isoformat(),
        "cache_seconds": int(RADAR_CACHE_MAX_AGE.total_seconds()),
        "source": "Cloudflare Radar",
        "methodology": (
            "Percent share of Cloudflare-observed mitigated layer 7 requests over the last 24 hours. "
            "Target geography uses the attacked zone's billing country."
        ),
        "stale": False,
        "schema_version": 1,
    }
    try:
        RADAR_CACHE_FILE.write_text(json.dumps({
            "created_at": now.isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


def normalize_dshield_ip_record(payload):
    """Flatten the occasionally nested DShield IP response."""
    record = payload.get("ip", payload) if isinstance(payload, dict) else {}
    if not isinstance(record, dict):
        return {}
    return {
        "ip": record.get("number") or record.get("ip"),
        "reports": record.get("count"),
        "targets": record.get("attacks"),
        "first_seen": record.get("mindate"),
        "last_seen": record.get("maxdate"),
        "updated": record.get("updated"),
        "country": str(record.get("country") or record.get("ascountry") or "").strip(),
        "asn": str(record.get("as") or "").strip(),
        "as_name": str(record.get("asname") or "").strip(),
        "network": str(record.get("network") or "").strip(),
        "comment": record.get("comment"),
    }


def get_dshield_ip(address):
    """Look up a public IPv4 or IPv6 address in DShield."""
    try:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError
    except ValueError:
        return {"error": "Enter a valid public IP address."}
    try:
        return normalize_dshield_ip_record(fetch_json(f"https://isc.sans.edu/api/ip/{parsed}?json"))
    except (HTTPError, URLError, json.JSONDecodeError):
        return {"error": "Unable to reach the DShield IP API."}


def enrich_dshield_attacker(item):
    """Add bounded DShield-owned country and network context to one top source."""
    address = item.get("ip")
    if not address:
        return item
    hit, record = DSHIELD_IP_CACHE.get(address)
    if not hit:
        record = get_dshield_ip(address)
        if record and not record.get("error"):
            DSHIELD_IP_CACHE.set(address, record, DSHIELD_IP_TTL.total_seconds())
    if record and not record.get("error"):
        enriched = dict(item)
        enriched.update({
            "country": clean_actor_text(record.get("country"), 2).upper() or None,
            "asn": clean_actor_text(record.get("asn"), 20) or None,
            "as_name": clean_actor_text(record.get("as_name"), 100) or None,
        })
        return enriched
    return item


def enrich_dshield_attackers(items, limit=12):
    """Enrich top sources concurrently while keeping upstream requests bounded."""
    enriched = list(items)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(enrich_dshield_attacker, item): index
            for index, item in enumerate(enriched[:limit])
        }
        for future in as_completed(futures):
            try:
                enriched[futures[future]] = future.result()
            except (HTTPError, URLError, ValueError):
                continue
    return enriched


def clean_dshield_username(value):
    """Keep display-safe Cowrie usernames and discard binary probe payloads."""
    username = str(value or "").strip()
    if not username or len(username) > 80 or any(ord(character) < 32 for character in username):
        return None
    return username if re.search(r"[A-Za-z0-9]", username) else None


@single_flight(DSHIELD_REFRESH_LOCK)
def get_dshield_activity():
    """Aggregate public DShield community telemetry into a compact dashboard payload."""
    if DSHIELD_CACHE_FILE.exists():
        try:
            cached = json.loads(DSHIELD_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            if (cached["data"].get("schema_version") == 3 and
                    datetime.now(timezone.utc) - created < DSHIELD_CACHE_MAX_AGE):
                return cached["data"]
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            pass

    errors = []
    top_attackers = []
    top_ports = []
    top_ports_date = None
    usernames = []
    indicators = []
    indicator_counts = {"ssh": 0, "web": 0}

    try:
        payload = fetch_json(DSHIELD_TOP_IPS_API)
        top_attackers = [{
            "rank": item.get("rank"), "ip": item.get("source"),
            "reports": item.get("reports", 0), "targets": item.get("targets", 0),
        } for item in payload if isinstance(item, dict) and item.get("source")]
    except (HTTPError, URLError, json.JSONDecodeError, TypeError):
        errors.append("Top attacker data is temporarily unavailable.")

    try:
        payload = fetch_json(DSHIELD_TOP_PORTS_API)
        records = payload.values() if isinstance(payload, dict) else payload
        top_ports = sorted([{
            "rank": item.get("rank"), "port": item.get("targetport"),
            "records": item.get("records", 0), "targets": item.get("targets", 0),
            "sources": item.get("sources", 0),
        } for item in records if isinstance(item, dict) and item.get("targetport") is not None],
            key=lambda item: item["rank"] or 999)
        top_ports_date = payload.get("date") if isinstance(payload, dict) else None
        if not top_ports:
            completed_day = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
            payload = fetch_json(
                f"https://isc.sans.edu/api/topports/records/20/{completed_day}?json"
            )
            records = payload.values() if isinstance(payload, dict) else payload
            top_ports = sorted([{
                "rank": item.get("rank"), "port": item.get("targetport"),
                "records": item.get("records", 0), "targets": item.get("targets", 0),
                "sources": item.get("sources", 0),
            } for item in records if isinstance(item, dict) and item.get("targetport") is not None],
                key=lambda item: item["rank"] or 999)
            top_ports_date = payload.get("date", completed_day) if isinstance(payload, dict) else completed_day
    except (HTTPError, URLError, json.JSONDecodeError, TypeError):
        errors.append("Target port data is temporarily unavailable.")

    if top_attackers:
        top_attackers = enrich_dshield_attackers(top_attackers)

    try:
        payload = fetch_json(DSHIELD_USERNAMES_API)
        cleaned = []
        for item in payload:
            username = clean_dshield_username(item.get("username")) if isinstance(item, dict) else None
            if username:
                cleaned.append({
                    "username": username, "count": int(item.get("count") or 0),
                    "first_seen": item.get("firstseen"), "last_seen": item.get("lastseen"),
                })
        usernames = sorted(cleaned, key=lambda item: item["count"], reverse=True)[:15]
    except (HTTPError, URLError, json.JSONDecodeError, TypeError, ValueError):
        errors.append("SSH username data is temporarily unavailable.")

    try:
        payload = fetch_json(DSHIELD_INTELFEED_API)
        for item in payload:
            if not isinstance(item, dict):
                continue
            labels = {label.strip().lower() for label in str(item.get("description", "")).split(",")}
            category = "ssh" if "dshieldssh" in labels else "web" if "webscanner" in labels else None
            if category:
                indicator_counts[category] += 1
                if len(indicators) < 100:
                    indicators.append({"ip": item.get("ip"), "category": category})
    except (HTTPError, URLError, json.JSONDecodeError, TypeError):
        errors.append("Honeypot indicator data is temporarily unavailable.")

    if not any((top_attackers, top_ports, usernames, indicators)):
        return {"error": "DShield telemetry is temporarily unavailable.", "errors": errors}

    data = {
        "top_attackers": top_attackers,
        "top_ports": top_ports,
        "top_ports_date": top_ports_date,
        "usernames": usernames,
        "indicators": indicators,
        "indicator_counts": indicator_counts,
        "indicator_total": sum(indicator_counts.values()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_seconds": int(DSHIELD_CACHE_MAX_AGE.total_seconds()),
        "errors": errors,
        "attribution": "SANS Technology Institute, Internet Storm Center",
        "schema_version": 3,
    }
    try:
        DSHIELD_CACHE_FILE.write_text(json.dumps({
            "created_at": datetime.now(timezone.utc).isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


def clean_ransomlook_text(value, max_length):
    """Normalize untrusted leak-site text before including it in API responses."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = "".join(character for character in text if character.isprintable())
    return text[:max_length]


def parse_ransomlook_timestamp(value):
    """Parse a RansomLook discovery timestamp as an aware UTC datetime."""
    parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@single_flight(RANSOMWARE_REFRESH_LOCK)
def get_ransomware_activity():
    """Rank groups by unique public victim claims in a rolling 30-day window."""
    cached_data = None
    if RANSOMWARE_CACHE_FILE.exists():
        try:
            cached = json.loads(RANSOMWARE_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            cached_data = cached["data"]
            if datetime.now(timezone.utc) - created < RANSOMWARE_CACHE_MAX_AGE:
                return cached_data
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            cached_data = None

    try:
        payload = fetch_json(RANSOMLOOK_POSTS_API)
        posts = payload.get("posts") if isinstance(payload, dict) else None
        if not isinstance(posts, list):
            raise ValueError("RansomLook returned an unexpected response.")
    except (HTTPError, URLError, json.JSONDecodeError, TypeError, ValueError):
        if cached_data:
            stale_data = dict(cached_data)
            stale_data.update({
                "stale": True,
                "warning": "RansomLook is temporarily unavailable; showing the last cached snapshot.",
            })
            return stale_data
        return {"error": "RansomLook ransomware activity is temporarily unavailable."}

    now = datetime.now(timezone.utc)
    today = now.date()
    window_start = today - timedelta(days=RANSOMWARE_WINDOW_DAYS - 1)
    recent_start = today - timedelta(days=6)
    previous_start = today - timedelta(days=13)
    groups = defaultdict(list)
    group_names = {}
    seen_claims = set()

    for post in posts:
        if not isinstance(post, dict):
            continue
        group = clean_ransomlook_text(post.get("group_name"), 80)
        title = clean_ransomlook_text(post.get("post_title"), 180)
        if not group or not title:
            continue
        try:
            discovered = parse_ransomlook_timestamp(post.get("discovered"))
        except (TypeError, ValueError):
            continue
        if discovered.date() < window_start or discovered > now + timedelta(hours=1):
            continue
        canonical_group = group.casefold()
        key = (canonical_group, title.casefold())
        if key in seen_claims:
            continue
        seen_claims.add(key)
        group_names.setdefault(canonical_group, group)
        groups[canonical_group].append({"title": title, "discovered": discovered})

    total_claims = len(seen_claims)
    ranked_groups = []
    for canonical_group, claims in groups.items():
        ordered = sorted(claims, key=lambda item: item["discovered"], reverse=True)
        recent_count = sum(item["discovered"].date() >= recent_start for item in ordered)
        previous_count = sum(
            previous_start <= item["discovered"].date() < recent_start for item in ordered
        )
        ranked_groups.append({
            "name": group_names[canonical_group],
            "claim_count": len(ordered),
            "recent_7d_count": recent_count,
            "previous_7d_count": previous_count,
            "share_percentage": round(len(ordered) / total_claims * 100, 1) if total_claims else 0,
            "last_seen": ordered[0]["discovered"].isoformat(),
            "recent_victims": [
                {"title": item["title"], "discovered": item["discovered"].isoformat()}
                for item in ordered[:4]
            ],
        })
    ranked_groups.sort(
        key=lambda item: (item["claim_count"], item["recent_7d_count"], item["last_seen"]),
        reverse=True,
    )

    daily_counts = defaultdict(int)
    for claims in groups.values():
        for claim in claims:
            daily_counts[claim["discovered"].date().isoformat()] += 1
    daily_activity = [{
        "date": (window_start + timedelta(days=offset)).isoformat(),
        "count": daily_counts[(window_start + timedelta(days=offset)).isoformat()],
    } for offset in range(RANSOMWARE_WINDOW_DAYS)]

    data = {
        "items": ranked_groups[:10],
        "total_claims": total_claims,
        "active_groups": len(groups),
        "window_days": RANSOMWARE_WINDOW_DAYS,
        "generated_at": now.isoformat(),
        "cache_seconds": int(RANSOMWARE_CACHE_MAX_AGE.total_seconds()),
        "daily_activity": daily_activity,
        "source": "RansomLook",
        "methodology": "Unique public victim claims grouped by source-reported ransomware group.",
        "stale": False,
    }
    try:
        RANSOMWARE_CACHE_FILE.write_text(json.dumps({
            "created_at": now.isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


def clean_actor_text(value, max_length):
    """Normalize community-maintained actor metadata for safe, compact display."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = "".join(character for character in text if character.isprintable())
    return text[:max_length]


def actor_list(value, limit, max_length=100):
    """Coerce a scalar or list-valued MISP field to a bounded string list."""
    values = value if isinstance(value, list) else [value] if value else []
    cleaned = []
    seen = set()
    for item in values:
        text = clean_actor_text(item, max_length)
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


@single_flight(APT_REFRESH_LOCK)
def get_apt_catalog():
    """Normalize country-attributed profiles from the public MISP Galaxy repository."""
    cached_data = None
    if APT_CACHE_FILE.exists():
        try:
            cached = json.loads(APT_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            cached_data = cached["data"]
            if datetime.now(timezone.utc) - created < APT_CACHE_MAX_AGE:
                return cached_data
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            cached_data = None

    try:
        payload = fetch_json(MISP_THREAT_ACTORS_URL)
        values = payload.get("values") if isinstance(payload, dict) else None
        if not isinstance(values, list):
            raise ValueError("MISP Galaxy returned an unexpected response.")
    except (HTTPError, URLError, json.JSONDecodeError, TypeError, ValueError):
        if cached_data:
            stale_data = dict(cached_data)
            stale_data.update({
                "stale": True,
                "warning": "MISP Galaxy is temporarily unavailable; showing the last cached snapshot.",
            })
            return stale_data
        return {"error": "MISP Galaxy threat-actor data is temporarily unavailable."}

    actors = []
    countries = set()
    sponsor_count = 0
    for value in values:
        if not isinstance(value, dict):
            continue
        meta = value.get("meta") if isinstance(value.get("meta"), dict) else {}
        country_code = clean_actor_text(meta.get("country"), 2).upper()
        if not re.fullmatch(r"[A-Z]{2}", country_code):
            country_code = None
        sponsor = clean_actor_text(meta.get("cfr-suspected-state-sponsor"), 100) or None
        # Country and sponsor fields are the only structured attribution signals in
        # this feed. Entries without either are intentionally excluded from this view.
        if not country_code and not sponsor:
            continue
        name = clean_actor_text(value.get("value"), 100)
        uuid = clean_actor_text(value.get("uuid"), 50)
        if not name or not uuid:
            continue
        references = [reference for reference in actor_list(meta.get("refs"), 8, 500)
                      if re.fullmatch(r"https?://[^\s]+", reference)]
        sectors = actor_list(meta.get("targeted-sector"), 8)
        sectors += [sector for sector in actor_list(meta.get("cfr-target-category"), 8)
                    if sector.casefold() not in {item.casefold() for item in sectors}]
        classifications = actor_list(meta.get("threat-actor-classification"), 5)
        actors.append({
            "name": name,
            "uuid": uuid,
            "description": clean_actor_text(value.get("description"), 700),
            "country_code": country_code,
            "suspected_sponsor": sponsor,
            "aliases": actor_list(meta.get("synonyms"), 14),
            "sectors": sectors[:8],
            "classifications": classifications,
            "incident_type": clean_actor_text(meta.get("cfr-type-of-incident"), 80) or None,
            "attribution_confidence": clean_actor_text(meta.get("attribution-confidence"), 20) or None,
            "references": references,
        })
        if country_code:
            countries.add(country_code)
        sponsor_count += int(bool(sponsor))

    actors.sort(key=lambda actor: actor["name"].casefold())
    now = datetime.now(timezone.utc)
    data = {
        "items": actors,
        "actor_count": len(actors),
        "country_count": len(countries),
        "suspected_sponsor_count": sponsor_count,
        "generated_at": now.isoformat(),
        "cache_seconds": int(APT_CACHE_MAX_AGE.total_seconds()),
        "source": "MISP Galaxy threat-actor cluster",
        "methodology": (
            "Profiles with structured country or suspected-state-sponsor metadata; "
            "alphabetical and not ranked by danger or current activity."
        ),
        "stale": False,
    }
    try:
        APT_CACHE_FILE.write_text(json.dumps({
            "created_at": now.isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


def epss_scores(cve_ids):
    """Return EPSS probability and percentile values in request-sized batches."""
    scores = {}
    for start in range(0, len(cve_ids), 100):
        query = urlencode({"cve": ",".join(cve_ids[start:start + 100])})
        try:
            data = fetch_json(f"{EPSS_API}?{query}")
            scores.update({item["cve"]: {
                "probability": float(item["epss"]),
                "percentile": float(item["percentile"]),
            } for item in data.get("data", [])})
        except (HTTPError, URLError, KeyError, ValueError):
            # KEV evidence still produces a useful ranking if EPSS is temporarily unavailable.
            continue
    return scores


def fetch_nvd_cves(cve_ids):
    """Fetch and normalize NVD records for a small set of CVE identifiers."""
    if not cve_ids:
        return {}
    query = urlencode({"cveIds": ",".join(cve_ids)})
    data = fetch_json(f"{NVD_API}?{query}")
    records = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        metric = next(iter(metrics.get("cvssMetricV40", [])), None)
        metric = metric or next(iter(metrics.get("cvssMetricV31", [])), None)
        metric = metric or next(iter(metrics.get("cvssMetricV30", [])), None)
        cvss_data = (metric or {}).get("cvssData", {})
        weaknesses = [description.get("value") for group in cve.get("weaknesses", [])
                      for description in group.get("description", [])
                      if description.get("value", "").startswith("CWE-")]
        references = [item.get("url") for item in cve.get("references", []) if item.get("url")]
        records[cve_id] = {
            "id": cve_id,
            "description": description,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "status": cve.get("vulnStatus"),
            "cvss_score": cvss_data.get("baseScore"),
            "cvss_severity": cvss_data.get("baseSeverity"),
            "cvss_vector": cvss_data.get("vectorString"),
            "cwes": list(dict.fromkeys(weaknesses)),
            "references": references[:5],
        }
    return records


def load_kev_catalog():
    """Load the KEV catalog from CISA or its official GitHub mirror."""
    for url in KEV_URLS:
        try:
            return fetch_json(url)
        except (HTTPError, URLError):
            continue
    return None


@single_flight(CVE_REFRESH_LOCK)
def get_cve_watchlist():
    """Rank recently active CVEs using KEV, ransomware, EPSS, recency, and CVSS."""
    if CVE_CACHE_FILE.exists():
        try:
            cached = json.loads(CVE_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            if (datetime.now(timezone.utc) - created < CACHE_MAX_AGE
                    and "exploitation_timeline" in cached["data"]
                    and len(cached["data"].get("items", [])) >= 10):
                return cached["data"]
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            pass

    catalog = load_kev_catalog()
    if catalog is None:
        return {"items": [], "error": "Unable to load the CISA KEV catalog."}

    today = datetime.now(timezone.utc).date()
    cutoff = today - timedelta(days=365)
    timeline_months = recent_months(today)
    monthly_kev_additions = defaultdict(int)
    candidates = []
    for vulnerability in catalog.get("vulnerabilities", []):
        cve_id = vulnerability.get("cveID")
        try:
            date_added = datetime.fromisoformat(vulnerability.get("dateAdded", "")).date()
        except (TypeError, ValueError):
            continue
        if not cve_id or date_added < cutoff:
            continue
        monthly_kev_additions[date_added.strftime("%Y-%m")] += 1
        candidates.append({
            "id": cve_id,
            "vendor": vulnerability.get("vendorProject", "Unknown vendor"),
            "product": vulnerability.get("product", "Unknown product"),
            "name": vulnerability.get("vulnerabilityName", cve_id),
            "short_description": vulnerability.get("shortDescription", ""),
            "date_added": date_added.isoformat(),
            "due_date": vulnerability.get("dueDate"),
            "required_action": vulnerability.get("requiredAction", ""),
            "ransomware": vulnerability.get("knownRansomwareCampaignUse") == "Known",
            "cwes": vulnerability.get("cwes", []),
        })

    epss = epss_scores([item["id"] for item in candidates])
    for item in candidates:
        age_days = max(0, (today - datetime.fromisoformat(item["date_added"]).date()).days)
        recency = max(0, 10 * (1 - age_days / 365))
        item_epss = epss.get(item["id"], {})
        item["epss_probability"] = round(item_epss.get("probability", 0) * 100, 2)
        item["epss_percentile"] = round(item_epss.get("percentile", 0) * 100, 1)
        item["threat_score"] = 40 + (15 if item["ransomware"] else 0) + recency + item["epss_probability"] * .25

    # NVD enrichment is only needed for the strongest preliminary candidates.
    candidates.sort(key=lambda item: item["threat_score"], reverse=True)
    preliminary = candidates[:20]
    try:
        nvd = fetch_nvd_cves([item["id"] for item in preliminary])
    except (HTTPError, URLError):
        nvd = {}

    for item in preliminary:
        enrichment = nvd.get(item["id"], {})
        item.update({key: value for key, value in enrichment.items()
                     if key != "id" and value not in (None, "", [])})
        cvss = float(item.get("cvss_score") or 0)
        item["threat_score"] = round(min(100, item["threat_score"] + cvss), 1)

    preliminary.sort(key=lambda item: item["threat_score"], reverse=True)
    running_total = 0
    exploitation_timeline = []
    for month in timeline_months:
        running_total += monthly_kev_additions[month]
        exploitation_timeline.append({"month": month, "count": running_total})
    data = {
        "items": preliminary[:10],
        "catalog_date": catalog.get("dateReleased"),
        "candidate_count": len(candidates),
        "method": "CISA KEV + FIRST EPSS + NVD CVSS",
        "window_days": 365,
        "exploitation_timeline": exploitation_timeline,
    }
    try:
        CVE_CACHE_FILE.write_text(json.dumps({
            "created_at": datetime.now(timezone.utc).isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


@single_flight(CWE_REFRESH_LOCK)
def get_threat_watchlist():
    """Rank CWEs using CISA active-exploitation evidence plus EPSS likelihood."""
    if CACHE_FILE.exists():
        cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        created = datetime.fromisoformat(cached["created_at"])
        if (datetime.now(timezone.utc) - created < CACHE_MAX_AGE
                and "exploitation_timeline" in cached["data"]
                and len(cached["data"].get("items", [])) >= 10):
            return add_owasp_mappings(cached["data"])

    catalog = load_kev_catalog()
    if catalog is None:
        return {"items": [], "error": "Unable to load the CISA KEV catalog."}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=365)
    timeline_months = recent_months(datetime.now(timezone.utc).date())
    groups = defaultdict(lambda: {"cves": [], "ransomware": 0, "recent": 0, "dates": []})
    for vulnerability in catalog.get("vulnerabilities", []):
        cve_id = vulnerability.get("cveID")
        if not cve_id:
            continue
        is_recent = vulnerability.get("dateAdded", "") >= cutoff.isoformat()
        is_ransomware = vulnerability.get("knownRansomwareCampaignUse") == "Known"
        for cwe in vulnerability.get("cwes", []):
            if not cwe.startswith("CWE-"):
                continue
            group = groups[cwe]
            group["cves"].append(cve_id)
            group["ransomware"] += int(is_ransomware)
            group["recent"] += int(is_recent)
            added_month = month_key(vulnerability.get("dateAdded"))
            if added_month:
                group["dates"].append(added_month)

    # CISA KEV is the primary signal: every count represents a CVE exploited in the wild.
    ranked = sorted(groups.items(), key=lambda pair: len(pair[1]["cves"]) * 10 + pair[1]["ransomware"] * 20 + pair[1]["recent"] * 25, reverse=True)[:10]
    cve_ids = list({cve for _, group in ranked for cve in group["cves"]})
    epss = epss_scores(cve_ids)
    items = []
    for cwe, group in ranked:
        percentiles = [epss[cve]["percentile"] for cve in group["cves"] if cve in epss]
        average_epss = sum(percentiles) / len(percentiles) if percentiles else 0
        kev_count = len(group["cves"])
        score = kev_count * 10 + group["ransomware"] * 20 + group["recent"] * 25 + round(average_epss * 10, 1)
        items.append({
            "id": cwe.replace("CWE-", "", 1), "kev_count": kev_count,
            "ransomware_count": group["ransomware"], "recent_count": group["recent"],
            "epss_percentile": round(average_epss * 100, 1), "threat_score": round(score, 1),
        })

    exploitation_timeline = []
    for cwe, group in ranked:
        exploitation_timeline.append({
            "id": cwe,
            "points": [
                {"month": month, "count": sum(added <= month for added in group["dates"])}
                for month in timeline_months
            ],
        })

    data = {
        "items": items,
        "catalog_date": catalog.get("dateReleased"),
        "method": "CISA KEV + EPSS",
        "exploitation_timeline": exploitation_timeline,
    }
    add_owasp_mappings(data)
    CACHE_FILE.write_text(json.dumps({"created_at": datetime.now(timezone.utc).isoformat(), "data": data}), encoding="utf-8")
    return data


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    print(f"Threat Watch is available at http://localhost:{port}")
    print(f"ReDoc API documentation: http://localhost:{port}/api/docs")
    uvicorn.run(app, host="0.0.0.0", port=port)
