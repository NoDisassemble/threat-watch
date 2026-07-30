"""Serve the Threat Watch SPA and APIs with FastAPI.

Run: python server.py
Then open: http://localhost:8000
"""

import json
import os
import ipaddress
import re
from collections import defaultdict, deque, OrderedDict
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
VERSION = "2.0.0"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_FILE = Path(__file__).with_name(".watchlist-cache.json")
CVE_CACHE_FILE = Path(__file__).with_name(".cve-watchlist-cache.json")
DSHIELD_CACHE_FILE = Path(__file__).with_name(".dshield-cache.json")
OWASP_MAP_FILE = Path(__file__).with_name("owasp_2025.json")
CACHE_MAX_AGE = timedelta(hours=24)
DSHIELD_CACHE_MAX_AGE = timedelta(hours=1)
DSHIELD_TOP_IPS_API = "https://isc.sans.edu/api/topips/records/20?json"
DSHIELD_TOP_PORTS_API = "https://isc.sans.edu/api/topports/records/20?json"
DSHIELD_INTELFEED_API = "https://isc.sans.edu/api/intelfeed?json"
DSHIELD_USERNAMES_API = "https://isc.sans.edu/sshallusernames.json"
# Thirteen calendar buckets cover the rolling 365-day window, including both
# partial boundary months.
TIMELINE_MONTHS = 13
BASE_DIR = Path(__file__).resolve().parent
STATIC_FILES = {"index.html", "styles.css", "script.js"}
CWE_REFRESH_LOCK = Lock()
CVE_REFRESH_LOCK = Lock()
DSHIELD_REFRESH_LOCK = Lock()
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
    usernames: List[DshieldUsername] = Field(default_factory=list)
    indicators: List[DshieldIndicator] = Field(default_factory=list)
    indicator_counts: Dict[str, int] = Field(default_factory=dict)
    indicator_total: int = 0
    generated_at: Optional[str] = None
    cache_seconds: int = 0
    errors: List[str] = Field(default_factory=list)
    attribution: Optional[str] = None
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


app = FastAPI(
    title="Threat Watch API",
    summary="Live CWE, CVE, and community honeypot intelligence",
    description=(
        "Backend API for the Threat Watch SPA. It combines MITRE CWE, CISA KEV, "
        "FIRST EPSS, NVD CVE, and SANS ISC/DShield community telemetry."
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
            if datetime.now(timezone.utc) - created < DSHIELD_CACHE_MAX_AGE:
                return cached["data"]
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            pass

    errors = []
    top_attackers = []
    top_ports = []
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
    except (HTTPError, URLError, json.JSONDecodeError, TypeError):
        errors.append("Target port data is temporarily unavailable.")

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
        "usernames": usernames,
        "indicators": indicators,
        "indicator_counts": indicator_counts,
        "indicator_total": sum(indicator_counts.values()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_seconds": int(DSHIELD_CACHE_MAX_AGE.total_seconds()),
        "errors": errors,
        "attribution": "SANS Technology Institute, Internet Storm Center",
    }
    try:
        DSHIELD_CACHE_FILE.write_text(json.dumps({
            "created_at": datetime.now(timezone.utc).isoformat(), "data": data
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
