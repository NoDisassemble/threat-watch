"""Serve the dashboard and proxy MITRE CWE API requests on the same origin.

Run: python server.py
Then open: http://localhost:8000
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MITRE_API = "https://cwe-api.mitre.org"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_FILE = Path(__file__).with_name(".watchlist-cache.json")
CVE_CACHE_FILE = Path(__file__).with_name(".cve-watchlist-cache.json")
OWASP_MAP_FILE = Path(__file__).with_name("owasp_2025.json")
CACHE_MAX_AGE = timedelta(hours=24)


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


class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/watchlist":
            self.send_json(get_threat_watchlist())
            return
        if self.path == "/api/cve-watchlist":
            self.send_json(get_cve_watchlist())
            return
        if self.path.startswith("/api/cve/"):
            cve_id = self.path.removeprefix("/api/cve/").upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            try:
                self.send_json(fetch_nvd_cves([cve_id]).get(cve_id, {}))
            except (HTTPError, URLError):
                self.send_json({"error": "Unable to reach the NVD CVE API."})
            return
        if self.path.startswith("/api/v1/"):
            self.proxy_request()
            return
        super().do_GET()

    def proxy_request(self):
        target_url = f"{MITRE_API}{self.path}"
        request = Request(target_url, headers={"Accept": "application/json", "User-Agent": "Threat-Watch/2.0"})

        try:
            with urlopen(request, timeout=20) as response:
                body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get_content_type())
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get_content_type() if error.headers else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except URLError:
            body = b'{"error":"Unable to reach the MITRE CWE API."}'
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def send_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def fetch_json(url):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "Threat-Watch/2.0"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


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


def get_cve_watchlist():
    """Rank recently active CVEs using KEV, ransomware, EPSS, recency, and CVSS."""
    if CVE_CACHE_FILE.exists():
        try:
            cached = json.loads(CVE_CACHE_FILE.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(cached["created_at"])
            if datetime.now(timezone.utc) - created < CACHE_MAX_AGE:
                return cached["data"]
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            pass

    catalog = load_kev_catalog()
    if catalog is None:
        return {"items": [], "error": "Unable to load the CISA KEV catalog."}

    today = datetime.now(timezone.utc).date()
    cutoff = today - timedelta(days=365)
    candidates = []
    for vulnerability in catalog.get("vulnerabilities", []):
        cve_id = vulnerability.get("cveID")
        try:
            date_added = datetime.fromisoformat(vulnerability.get("dateAdded", "")).date()
        except (TypeError, ValueError):
            continue
        if not cve_id or date_added < cutoff:
            continue
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
    data = {
        "items": preliminary[:5],
        "catalog_date": catalog.get("dateReleased"),
        "candidate_count": len(candidates),
        "method": "CISA KEV + FIRST EPSS + NVD CVSS",
        "window_days": 365,
    }
    try:
        CVE_CACHE_FILE.write_text(json.dumps({
            "created_at": datetime.now(timezone.utc).isoformat(), "data": data
        }), encoding="utf-8")
    except OSError:
        pass
    return data


def get_threat_watchlist():
    """Rank CWEs using CISA active-exploitation evidence plus EPSS likelihood."""
    if CACHE_FILE.exists():
        cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        created = datetime.fromisoformat(cached["created_at"])
        if datetime.now(timezone.utc) - created < CACHE_MAX_AGE:
            return add_owasp_mappings(cached["data"])

    catalog = load_kev_catalog()
    if catalog is None:
        return {"items": [], "error": "Unable to load the CISA KEV catalog."}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=365)
    groups = defaultdict(lambda: {"cves": [], "ransomware": 0, "recent": 0})
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

    # CISA KEV is the primary signal: every count represents a CVE exploited in the wild.
    ranked = sorted(groups.items(), key=lambda pair: len(pair[1]["cves"]) * 10 + pair[1]["ransomware"] * 20 + pair[1]["recent"] * 25, reverse=True)[:5]
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

    data = {"items": items, "catalog_date": catalog.get("dateReleased"), "method": "CISA KEV + EPSS"}
    add_owasp_mappings(data)
    CACHE_FILE.write_text(json.dumps({"created_at": datetime.now(timezone.utc).isoformat(), "data": data}), encoding="utf-8")
    return data


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"Threat Watch is available on port {port}")
    server.serve_forever()
