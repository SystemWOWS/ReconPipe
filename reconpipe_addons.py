"""Pipeline, reporting, and alerting helpers used by reconpipe."""
from __future__ import annotations

import json
import math
import os
import random
import re
import shutil
import smtplib
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import urllib.request
import urllib.error

JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".svelte"}
IAC_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "dockerfile",
}
IAC_EXTENSIONS = {".tf", ".tfvars", ".yml", ".yaml", ".json", ".env"}
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "_ga", "ref", "source", "mc_cid", "mc_eid",
}
JS_ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v[0-9]+)/[a-zA-Z0-9/_-]+)["\']',
    r'fetch\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(\s*["\']([^"\']+)["\']',
    r'\.get\(\s*["\']([^"\']+)["\']',
    r'\.post\(\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest.*?open\([^,]+,\s*["\']([^"\']+)',
    r'["\'](wss?://[^"\']+)["\']',
    r'["\'](/graphql[^"\']*)["\']',
]
# LinkFinder-style extractor used by jsleak (byt3hx/jsleak).
JSLEAK_LINKFINDER_RE = re.compile(
    r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|"""
    r"""((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|"""
    r"""([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)"""
    r"""(?:[\?|#][^"|']{0,}|))|"""
    r"""([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|"""
    r"""([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)"""
    r"""(?:[\?|#][^"|']{0,}|)))(?:"|')"""
)
SECRETS_PATTERNS_DB_URL = (
    "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml"
)
SECRETS_DB_SKIP_NAME = re.compile(
    r"\b(arn|s3 bucket|elb|rds|ec2|elasticache|api gateway|hostname|"
    r"internal|external|cred file|filename|website|domain name)\b",
    re.I,
)
SECRETS_DB_SKIP_REGEX = re.compile(
    r"execute-api|\.elb\.amazonaws|\.rds\.amazonaws|\.cache\.amazonaws|"
    r"s3://|\.compute(?:-1)?\.|aws_access_key_id",
    re.I,
)
SECRETS_DB_PREFIX_MARKERS = (
    "akia", "asia", "ghp_", "gho_", "ghs_", "github_pat", "glpat-",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk_live", "sk_test", "pk_live",
    "pk_test", "sg.", "shpat_", "dop_v1", "phc_", "lin_api", "npm_",
)
SECRETS_DB_MAX = 350
JSLEAK_SECRET_LINE = re.compile(
    r"^\[\+\] Found \[(?P<name>[^\]]+)\] \[(?P<secret>.+)\] \[(?P<url>.+)\]\s*$"
)
JSLEAK_LINK_LINE = re.compile(
    r"^\[\+\] Found link: \[(?P<link>[^\]]+)\] in \[(?P<base>[^\]]+)\]\s*$"
)
JS_SECRET_PATTERNS = [
    r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{16,})["\']',
    r'(?:secret|token|password)\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'Authorization["\']?\s*[:=]\s*["\']Bearer\s+([^"\']+)["\']',
    r'(?:AWS|aws)[_-]?(?:ACCESS|SECRET)[_-]?(?:KEY|ID)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
]
DOCKER_IMAGES = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "katana": "projectdiscovery/katana",
    "nuclei": "projectdiscovery/nuclei",
    "trufflehog": "trufflesecurity/trufflehog",
    "amass": "caffix/amass",
    "dnsx": "projectdiscovery/dnsx",
    "naabu": "projectdiscovery/naabu",
    "gitleaks": "zricethezav/gitleaks",
}
CVSS_BY_SEVERITY = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.1,
}
STAGE_ORDER = ["chaos", "httpx", "discovery", "trufflehog", "validate"]


def parse_header_list(items: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for raw in items or []:
        text = str(raw or "")
        if ":" not in text:
            continue
        name, val = text.split(":", 1)
        name = name.strip()
        if name:
            headers[name] = val.strip()
    return headers


def polite_delay_seconds(polite: bool, rps: float) -> float:
    if rps and rps > 0:
        return max(0.0, 1.0 / float(rps))
    if polite:
        return 0.5
    return 0.0


def get_proxy_handler(proxy_url: str, proxy_auth: str = "") -> Optional[urllib.request.BaseHandler]:
    target = (proxy_url or "").strip()
    if not target:
        return None
    proxies = {"http": target, "https": target}
    handler = urllib.request.ProxyHandler(proxies)
    if proxy_auth:
        user, _, password = proxy_auth.partition(":")
        auth = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        auth.add_password(None, target, user, password)
        return urllib.request.ProxyHandler(proxies)
    return handler


def install_urllib_proxy(proxy_url: str, proxy_auth: str = "", extra_headers: Optional[Dict[str, str]] = None) -> None:
    handlers = []
    ph = get_proxy_handler(proxy_url, proxy_auth)
    if ph:
        handlers.append(ph)
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    extra = extra_headers or {}
    if extra:
        opener.addheaders = list(opener.addheaders) + [(k, v) for k, v in extra.items()]
    urllib.request.install_opener(opener)


def aiohttp_proxy_url(proxy_url: str, proxy_auth: str = "") -> str:
    url = (proxy_url or "").strip()
    if not url:
        return ""
    if proxy_auth and "@" not in url:
        user, _, password = proxy_auth.partition(":")
        parsed = urlparse(url)
        netloc = f"{user}:{password}@{parsed.netloc}"
        return urlunparse((parsed.scheme, netloc, parsed.path, "", parsed.query, ""))
    return url


def merge_subdomain_sources(sources: Dict[str, List[str]]) -> Tuple[List[str], Dict[str, List[str]]]:
    all_subs: Dict[str, List[str]] = {}
    for tool, subs in (sources or {}).items():
        for sub in subs or []:
            normalized = (sub or "").lower().strip().rstrip(".")
            if normalized.startswith("*."):
                normalized = normalized[2:]
            if not normalized:
                continue
            all_subs.setdefault(normalized, [])
            if tool not in all_subs[normalized]:
                all_subs[normalized].append(str(tool))
    return sorted(all_subs.keys()), all_subs


def extract_js_urls(urls: List[str]) -> List[str]:
    out = []
    for u in urls or []:
        path = urlparse(u).path.lower()
        if any(path.endswith(ext) for ext in JS_EXTENSIONS):
            out.append(u)
    return out


def extract_jsleak_links(content: str, limit: int = 250) -> List[str]:
    """LinkFinder-style quoted paths/URLs (jsleak)."""
    text = (content or "")[:500_000]
    out: List[str] = []
    seen = set()
    for match in JSLEAK_LINKFINDER_RE.finditer(text):
        val = (match.group(1) or "").strip().strip("'\"")
        if not val or len(val) > 400 or val in seen:
            continue
        seen.add(val)
        out.append(val)
        if len(out) >= limit:
            break
    return out


def extract_endpoints_from_js(content: str) -> List[str]:
    endpoints = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content or "", re.I):
            val = match.group(1) if match.lastindex else match.group(0)
            val = (val or "").strip()
            if val and len(val) < 400:
                endpoints.add(val)
    for val in extract_jsleak_links(content):
        if val:
            endpoints.add(val)
    return sorted(endpoints)


def extract_js_secret_assignments(content: str) -> List[Dict[str, str]]:
    hits = []
    for pattern in JS_SECRET_PATTERNS:
        for match in re.finditer(pattern, content or "", re.I):
            hits.append({"pattern": pattern, "value": match.group(1)})
    return hits


def parse_source_map(map_content: str) -> Dict[str, str]:
    data = json.loads(map_content)
    sources: Dict[str, str] = {}
    if not isinstance(data, dict):
        return sources
    names = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if isinstance(names, list) and isinstance(contents, list):
        for name, content in zip(names, contents):
            if content:
                sources[str(name)] = str(content)
    return sources


def normalize_url(url: str) -> str:
    parsed = urlparse((url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return (url or "").strip()
    params = parse_qs(parsed.query, keep_blank_values=True)
    filtered = {k: v for k, v in params.items() if k.lower() not in TRACKING_PARAMS}
    sorted_query = urlencode(sorted((k, v) for k, v in filtered.items()), doseq=True)
    host = parsed.netloc.lower()
    if host.endswith(":80") and parsed.scheme == "http":
        host = host[:-3]
    if host.endswith(":443") and parsed.scheme == "https":
        host = host[:-4]
    path = parsed.path or "/"
    return f"{parsed.scheme}://{host}{path}{'?' + sorted_query if sorted_query else ''}"


def dedupe_urls(urls: List[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for url in urls or []:
        text = (url or "").strip()
        if not text:
            continue
        normalized = normalize_url(text)
        key = normalized or text
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


class AdaptiveConcurrency:
    def __init__(self, initial: int = 10, min_: int = 2, max_: int = 50):
        self.current = int(initial)
        self.min = int(min_)
        self.max = int(max_)
        self.response_times: List[float] = []

    def record(self, response_time: float, status: int) -> int:
        self.response_times.append(float(response_time))
        if len(self.response_times) >= 10:
            avg = sum(self.response_times[-10:]) / 10
            if avg > 5.0 or int(status) == 429:
                self.current = max(self.min, self.current - 2)
            elif avg < 0.5 and int(status) < 400:
                self.current = min(self.max, self.current + 1)
        return self.current


@dataclass
class PipelineCheckpoint:
    stage: str
    completed_at: str
    data: Dict[str, Any]


def save_checkpoint(output_dir: Path, stage: str, data: Optional[Dict] = None) -> Path:
    payload = {
        "stage": stage,
        "completed_at": datetime.now().isoformat(),
        "data": data or {},
    }
    path = Path(output_dir) / "checkpoint.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_checkpoint(output_dir: Path) -> Optional[Dict]:
    cp_file = Path(output_dir) / "checkpoint.json"
    if not cp_file.exists():
        return None
    try:
        data = json.loads(cp_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def checkpoint_reached(checkpoint: Optional[Dict], stage: str) -> bool:
    if not checkpoint:
        return False
    done = str(checkpoint.get("stage") or "")
    if done not in STAGE_ORDER or stage not in STAGE_ORDER:
        return False
    return STAGE_ORDER.index(done) >= STAGE_ORDER.index(stage)


@dataclass
class ScanCredentials:
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    basic_auth: Optional[Tuple[str, str]] = None
    bearer_token: Optional[str] = None


def load_credentials(creds_file: Path) -> ScanCredentials:
    text = Path(creds_file).read_text(encoding="utf-8")
    try:
        import yaml  # local optional
        data = yaml.safe_load(text) or {}
    except Exception:
        data = json.loads(text)
    if not isinstance(data, dict):
        data = {}
    cookies = data.get("cookies") or {}
    headers = data.get("headers") or {}
    basic = data.get("basic_auth")
    pair = None
    if isinstance(basic, (list, tuple)) and len(basic) == 2:
        pair = (str(basic[0]), str(basic[1]))
    elif isinstance(data.get("username"), str) and isinstance(data.get("password"), str):
        pair = (str(data["username"]), str(data["password"]))
    return ScanCredentials(
        cookies={str(k): str(v) for k, v in (cookies.items() if isinstance(cookies, dict) else [])},
        headers={str(k): str(v) for k, v in (headers.items() if isinstance(headers, dict) else [])},
        basic_auth=pair,
        bearer_token=(str(data["bearer_token"]).strip() if data.get("bearer_token") else None),
    )


def credentials_to_headers(creds: Optional[ScanCredentials]) -> Dict[str, str]:
    if not creds:
        return {}
    headers = dict(creds.headers)
    if creds.cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in creds.cookies.items())
        if cookie:
            headers.setdefault("Cookie", cookie)
    if creds.bearer_token:
        headers.setdefault("Authorization", f"Bearer {creds.bearer_token}")
    return headers


def parse_burp_xml(burp_file: Path) -> List[str]:
    tree = ET.parse(burp_file)
    urls: List[str] = []
    for item in tree.findall(".//item"):
        url = item.find("url")
        if url is not None and url.text:
            urls.append(url.text.strip())
    return dedupe_urls(urls)


def parse_nuclei_output(path: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if ln.startswith("{"):
            try:
                data = json.loads(ln)
            except Exception:
                continue
            if isinstance(data, dict):
                items.append(data)
                continue
        items.append({"raw": ln})
    return items


@dataclass
class StageMetrics:
    name: str
    started: float
    ended: float = 0
    items_in: int = 0
    items_out: int = 0
    errors: int = 0

    @property
    def duration(self) -> float:
        return self.ended - self.started if self.ended else time.monotonic() - self.started

    @property
    def throughput(self) -> float:
        return self.items_out / self.duration if self.duration > 0 else 0


class PipelineMetrics:
    def __init__(self) -> None:
        self.stages: List[StageMetrics] = []

    def start_stage(self, name: str, items_in: int = 0) -> StageMetrics:
        if self.stages and not self.stages[-1].ended:
            self.finish_stage(self.stages[-1].name, self.stages[-1].items_out, self.stages[-1].errors)
        stage = StageMetrics(name=name, started=time.monotonic(), items_in=items_in)
        self.stages.append(stage)
        return stage

    def finish_stage(self, name: str, items_out: int = 0, errors: int = 0) -> None:
        for stage in reversed(self.stages):
            if stage.name == name and not stage.ended:
                stage.ended = time.monotonic()
                stage.items_out = items_out
                stage.errors = errors
                return

    def to_report(self) -> Dict[str, Any]:
        return {
            "total_duration": sum(s.duration for s in self.stages),
            "stages": [
                {
                    "name": s.name,
                    "duration": round(s.duration, 3),
                    "in": s.items_in,
                    "out": s.items_out,
                    "errors": s.errors,
                    "throughput": round(s.throughput, 3),
                }
                for s in self.stages
            ],
        }


class FindingsStream:
    def __init__(self, output_dir: Path):
        self.stream_file = Path(output_dir) / "findings_stream.jsonl"
        self.callbacks: List[Callable] = []

    def emit(self, finding: Dict) -> None:
        safe = dict(finding)
        try:
            with self.stream_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(safe, default=str) + "\n")
        except OSError:
            return
        for cb in self.callbacks:
            try:
                cb(finding)
            except Exception:
                continue


def run_cmd_with_retry(run_cmd, cmd: List[str], max_retries: int = 3, base_delay: float = 1.0, **kwargs) -> Tuple[int, bytes]:
    last: Tuple[int, bytes] = (-1, b"")
    for attempt in range(max(1, max_retries)):
        last = run_cmd(cmd, **kwargs)
        rc = last[0]
        if rc == 0:
            return last
        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.4)
            time.sleep(delay)
    return last


def docker_cmd_for(tool: str, args: List[str], mount_dir: Path) -> Optional[List[str]]:
    image = DOCKER_IMAGES.get(tool)
    if not image:
        return None
    return ["docker", "run", "--rm", "-v", f"{mount_dir}:/data", image, *args]


def build_amass_cmd(domain: str, output_file: str, passive_only: bool = True) -> List[str]:
    cmd = ["amass", "enum"]
    if passive_only:
        cmd.append("-passive")
    cmd.extend(["-d", domain, "-o", output_file])
    return cmd


def build_assetfinder_cmd(domain: str) -> List[str]:
    return ["assetfinder", "--subs-only", domain]


def build_findomain_cmd(domain: str, output_file: str) -> List[str]:
    return ["findomain", "-t", domain, "-u", output_file]


def build_dnsx_cmd(input_file: str, output_file: str) -> List[str]:
    return ["dnsx", "-l", input_file, "-o", output_file, "-silent"]


def build_waybackurls_cmd(domain: str) -> List[str]:
    return ["waybackurls", domain]


def build_hakrawler_cmd(url: str, depth: int = 3) -> List[str]:
    return ["hakrawler", "-url", url, "-depth", str(depth), "-plain"]


def build_paramspider_cmd(domain: str, output_dir: str) -> List[str]:
    return ["paramspider", "-d", domain, "--output", output_dir, "--level", "high"]


def build_linkfinder_cmd(js_file: str, output_file: str = "cli") -> List[str]:
    return ["linkfinder", "-i", js_file, "-o", output_file]


def build_naabu_cmd(subdomains_file: str, output_file: str) -> List[str]:
    return [
        "naabu", "-l", subdomains_file,
        "-p", "80,443,8080,8443,8000,3000,5000,9000",
        "-o", output_file, "-silent",
    ]


def build_whatweb_cmd(urls_file: str, output_file: str) -> List[str]:
    return ["whatweb", "-i", urls_file, "--log-json", output_file, "-q"]


def build_wappalyzer_cmd(url: str) -> List[str]:
    return ["wappalyzer", url, "--pretty"]


def build_gowitness_cmd(urls_file: str, output_dir: str) -> List[str]:
    return ["gowitness", "file", "-f", urls_file, "-P", output_dir, "--disable-logging"]


def build_nuclei_cmd(urls_file: str, output_file: str, templates: Optional[List[str]] = None) -> List[str]:
    cmd = ["nuclei", "-l", urls_file, "-o", output_file, "-silent"]
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    else:
        cmd.extend(["-t", "exposures/", "-t", "misconfiguration/"])
    return cmd


def inspect_connection_uri(uri: str) -> Dict[str, Any]:
    parsed = urlparse(uri or "")
    user = parsed.username or ""
    password = parsed.password or ""
    host = parsed.hostname or ""
    scheme = parsed.scheme or ""
    result = {
        "validated": True,
        "status_code": None,
        "valid": False,
        "note": "",
        "uri": {"scheme": scheme, "host": host, "username": user, "has_password": bool(password)},
    }
    if user and password and host:
        result["valid"] = True
        result["note"] = (
            f"Connection URI with credentials (not connected); "
            f"scheme={scheme} host={host} user={user}"
        )
        return result
    result["note"] = "URI missing user/password/host — not treated as a live secret"
    return result


def is_supabase_anon(jwt_meta: Optional[Dict]) -> bool:
    if not jwt_meta or not jwt_meta.get("ok"):
        return False
    claims = jwt_meta.get("claims") or {}
    role = str(jwt_meta.get("role") or claims.get("role") or "").lower()
    iss = str(jwt_meta.get("iss") or claims.get("iss") or "").lower()
    if role == "anon" and ("supabase" in iss or claims.get("ref") or "supabase" in str(claims).lower()):
        return True
    if role == "anon" and "supabase" in json.dumps(claims, default=str).lower():
        return True
    return role == "anon" and ("supabase.co" in iss or bool(claims.get("ref")))


def jwt_provider_kind(jwt_meta: Optional[Dict]) -> str:
    if not jwt_meta or not jwt_meta.get("ok"):
        return ""
    blob = json.dumps(jwt_meta.get("claims") or {}, default=str).lower()
    iss = str(jwt_meta.get("iss") or "").lower()
    combined = iss + " " + blob
    if "supabase" in combined:
        role = str(jwt_meta.get("role") or (jwt_meta.get("claims") or {}).get("role") or "")
        return "supabase_anon" if role == "anon" else "supabase_service"
    if "1password" in combined or "agilebits" in combined:
        return "onepassword_connect"
    if "monday" in combined:
        return "monday_api"
    return ""


def jwt_age_days(jwt_meta: Optional[Dict]) -> Optional[float]:
    if not jwt_meta:
        return None
    iat = jwt_meta.get("iat")
    if not isinstance(iat, (int, float)):
        claims = jwt_meta.get("claims") or {}
        iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        return None
    now = datetime.now(timezone.utc).timestamp()
    return max(0.0, (now - float(iat)) / 86400.0)


def finding_cvss(severity: str) -> float:
    return CVSS_BY_SEVERITY.get((severity or "").lower(), 5.3)


def annotate_finding_intel(finding: Dict, entropy_fn=None) -> Dict:
    item = dict(finding)
    key = str(item.get("key") or "")
    typ = str(item.get("type") or "")
    if entropy_fn and key and "entropy" not in item:
        try:
            item["entropy"] = round(float(entropy_fn(key)), 3)
        except Exception:
            pass
    jwt_meta = item.get("jwt") if isinstance(item.get("jwt"), dict) else None
    age = jwt_age_days(jwt_meta)
    if age is not None:
        item["secret_age_days"] = round(age, 2)
    if typ:
        item.setdefault("revocation", REVOCATION_PLACEHOLDER.get(typ) or "")
        tags = COMPLIANCE_PLACEHOLDER.get(typ)
        if tags:
            item["compliance"] = list(tags)
    return item


# Filled by reconpipe after config load via bind_config_lookups
REVOCATION_PLACEHOLDER: Dict[str, str] = {}
COMPLIANCE_PLACEHOLDER: Dict[str, List[str]] = {}


def bind_config_lookups(revocation: Dict[str, str], compliance: Dict[str, List[str]]) -> None:
    REVOCATION_PLACEHOLDER.clear()
    REVOCATION_PLACEHOLDER.update(revocation)
    COMPLIANCE_PLACEHOLDER.clear()
    COMPLIANCE_PLACEHOLDER.update(compliance)


def executive_summary(domain: str, findings: List[Dict], valid_count: int, exposures: int) -> str:
    crit = sum(1 for f in findings if str(f.get("severity")) == "critical")
    high = sum(1 for f in findings if str(f.get("severity")) == "high")
    if valid_count:
        return (
            f"Scan of {domain} confirmed {valid_count} live credential(s) "
            f"({crit} critical, {high} high). "
            f"{exposures} exposure surface(s) were also recorded. "
            f"Rotate confirmed secrets and restrict the leaking assets immediately."
        )
    if findings:
        return (
            f"Scan of {domain} produced {len(findings)} candidate finding(s) "
            f"with no live-validated keys. Review unverified hits and rotate anything "
            f"that looks production-grade. Exposures: {exposures}."
        )
    return f"Scan of {domain} found no credential candidates. Exposures: {exposures}."


def write_jsonld_report(path: Path, domain: str, findings: List[Dict]) -> Path:
    graph = []
    for f in findings or []:
        graph.append({
            "@type": "Vulnerability",
            "name": str(f.get("type") or "secret"),
            "severity": f.get("severity"),
            "cvss": finding_cvss(str(f.get("severity") or "medium")),
            "description": f.get("note") or "",
            "url": f.get("source_url"),
        })
    payload = {
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": f"ReconPipe findings for {domain}",
        "dateCreated": datetime.now().isoformat(),
        "hasPart": graph,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return Path(path)


def nuclei_template_for(finding: Dict) -> str:
    typ = str(finding.get("type") or "secret")
    src = str(finding.get("source_url") or "")
    key_prefix = str(finding.get("key") or "")[:8]
    ident = re.sub(r"[^a-z0-9-]+", "-", typ.lower())
    return (
        f"id: reconpipe-{ident}\n"
        f"info:\n"
        f"  name: ReconPipe retest {typ}\n"
        f"  severity: {finding.get('severity') or 'medium'}\n"
        f"  description: Retest leaked {typ} originally seen at {src} (prefix {key_prefix})\n"
        f"requests:\n"
        f"  - method: GET\n"
        f"    path:\n"
        f"      - \"{{{{BaseURL}}}}\"\n"
    )


def write_nuclei_templates(output_dir: Path, findings: List[Dict]) -> int:
    folder = Path(output_dir) / "nuclei_templates"
    folder.mkdir(parents=True, exist_ok=True)
    count = 0
    for f in findings or []:
        if not f.get("valid"):
            continue
        typ = re.sub(r"[^a-z0-9_]+", "-", str(f.get("type") or "secret"))
        h = str(f.get("hash") or "x")[:12]
        (folder / f"{typ}-{h}.yaml").write_text(nuclei_template_for(f), encoding="utf-8")
        count += 1
    return count


def global_fingerprint_path() -> Path:
    env = (os.environ.get("RECONPIPE_HOME") or "").strip()
    base = Path(env).expanduser() if env else Path.home() / ".reconpipe"
    base.mkdir(parents=True, exist_ok=True)
    return base / "seen_findings.json"


def update_global_fingerprints(findings: List[Dict]) -> Dict[str, Any]:
    path = global_fingerprint_path()
    existing: Dict[str, Any] = {"hashes": []}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            pass
    known = set(str(x) for x in (existing.get("hashes") or []))
    new_hashes = []
    for f in findings or []:
        h = str(f.get("hash") or "").strip()
        if h and h not in known:
            new_hashes.append(h)
            known.add(h)
    existing["hashes"] = sorted(known)
    existing["updated"] = datetime.now().isoformat()
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return {"new": new_hashes, "total": len(known), "path": str(path)}


def notify_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    token = (bot_token or "").strip()
    chat = (chat_id or "").strip()
    if not token or not chat:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({"chat_id": chat, "text": (text or "")[:3500]}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "ReconPipe/1.2"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


def notify_email(
    host: str,
    to_addr: str,
    subject: str,
    body: str,
    port: int = 587,
    user: str = "",
    password: str = "",
    from_addr: str = "",
) -> bool:
    if not host or not to_addr:
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr or user or "reconpipe@localhost"
    msg["To"] = to_addr
    msg.set_content(body[:8000])
    try:
        with smtplib.SMTP(host, int(port), timeout=15) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
            except Exception:
                pass
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception:
        return False


def notify_pagerduty(routing_key: str, summary: str, severity: str = "error") -> bool:
    key = (routing_key or "").strip()
    if not key:
        return False
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": (summary or "ReconPipe finding")[:1024],
            "severity": severity if severity in {"critical", "error", "warning", "info"} else "error",
            "source": "reconpipe",
        },
    }
    req = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "ReconPipe/1.2"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


def notify_opsgenie(api_key: str, message: str) -> bool:
    key = (api_key or "").strip()
    if not key:
        return False
    payload = {"message": (message or "ReconPipe")[:130], "priority": "P2"}
    req = urllib.request.Request(
        "https://api.opsgenie.com/v2/alerts",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"GenieKey {key}",
            "User-Agent": "ReconPipe/1.2",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
WAYBACK_MAX = 150
SENSITIVE_PATHS = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.test",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/env.bak",
    "/backup.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.js",
    "/config.json",
    "/env.js",
    "/credentials.json",
    "/google-services.json",
    "/aws-exports.js",
    "/firebase-config.js",
    "/appsettings.json",
    "/appsettings.Production.json",
    "/web.config",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/actuator/env",
    "/.aws/credentials",
    "/id_rsa",
    "/.htpasswd",
    "/wp-config.php.bak",
    "/application.properties",
    "/application.yml",
    "/secrets.yml",
    "/docker-compose.yml",
    "/main.js.map",
    "/static/js/main.js.map",
)


def is_archive_org_url(url: str) -> bool:
    host = (urlparse(url).netloc or "").lower()
    return "web.archive.org" in host or host.endswith("archive.org")


def wayback_id_url(timestamp: str, original: str) -> str:
    ts = re.sub(r"\D", "", str(timestamp or ""))
    orig = (original or "").strip()
    return f"https://web.archive.org/web/{ts}id_/{orig}"


def pick_cdx_snapshot(data: Any) -> Optional[Dict[str, str]]:
    if not isinstance(data, list) or len(data) < 2:
        return None
    best: Optional[Dict[str, str]] = None
    for row in data[1:]:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        ts, original = str(row[0] or ""), str(row[1] or "")
        if not ts.isdigit() or not original.strip():
            continue
        if best is None or ts > best["timestamp"]:
            best = {"timestamp": ts, "original": original.strip()}
    return best


def cdx_lookup(url: str, timeout: int = 12) -> Optional[Dict[str, str]]:
    """Latest HTTP-200 Wayback snapshot for url, or None. Network call."""
    target = (url or "").strip()
    if not target or is_archive_org_url(target):
        return None
    qs = urlencode(
        {
            "url": target,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "filter": "statuscode:200",
            "limit": "20",
        }
    )
    req = urllib.request.Request(
        WAYBACK_CDX + "?" + qs,
        headers={"User-Agent": "ReconPipe/1.2 (+wayback-cdx)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(raw) if raw.strip() else []
    except Exception:
        return None
    snap = pick_cdx_snapshot(data)
    if not snap:
        return None
    snap["archive_url"] = wayback_id_url(snap["timestamp"], snap["original"])
    return snap


def fetch_wayback_body(
    url: str,
    timeout: int = 15,
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
) -> Optional[Tuple[bytes, Dict[str, str]]]:
    """Download the raw (id_) Wayback snapshot for a live-dead URL."""
    snap = cdx_lookup(url, timeout=min(timeout, 12))
    if not snap:
        return None
    req = urllib.request.Request(
        snap["archive_url"],
        headers={"User-Agent": ua, "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read() or b""
            snap["content_type"] = resp.headers.get("Content-Type") or ""
    except Exception:
        return None
    if not body:
        return None
    return body, snap


def looks_like_html_shell(body: bytes) -> bool:
    head = (body or b"").lstrip()[:256].lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def origin_from_host(host: str) -> str:
    text = (host or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        parsed = urlparse(text)
        if not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"
    if ":" in text and text.rsplit(":", 1)[-1].isdigit():
        port = text.rsplit(":", 1)[-1]
        scheme = "http" if port in {"80", "8080", "8000", "3000", "5000", "8888"} else "https"
        return f"{scheme}://{text}"
    return f"https://{text}"


def sensitive_urls_for_hosts(hosts: List[str], limit_hosts: int = 40) -> List[str]:
    urls: List[str] = []
    seen = set()
    for host in (hosts or [])[: max(0, int(limit_hosts))]:
        origin = origin_from_host(host)
        if not origin:
            continue
        for path in SENSITIVE_PATHS:
            url = origin.rstrip("/") + path
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
    return urls


def probe_sensitive_url(
    url: str,
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    timeout: int = 6,
) -> bool:
    """True when the path looks like a real leak file, not an HTML catch-all."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            if status != 200:
                return False
            ct = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ct.startswith(("image/", "video/", "audio/", "font/")):
                return False
            body = resp.read(2 * 1024 * 1024)
        if len(body) < 8:
            return False
        path = urlparse(url).path.lower()
        if looks_like_html_shell(body) and not path.endswith((".html", ".htm")):
            return False
        return True
    except Exception:
        return False


def build_clone_cmd(url: str, dest: str, shallow: bool = False) -> List[str]:
    cmd = ["git", "clone"]
    if shallow:
        cmd.extend(["--depth", "1"])
    cmd.extend([url, dest])
    return cmd


def trufflehog_git_cmd(repo: str) -> List[str]:
    """Scan git history. Accepts a remote URL or a local clone path."""
    target = (repo or "").strip()
    if target and not re.match(r"^(https?://|file://|git@)", target, re.I):
        target = Path(target).resolve().as_uri()
    return ["trufflehog", "--no-update", "--json", "git", target]


def leak_wordlist_path() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "leak_paths.txt"


def env_like_urls(urls: List[str]) -> List[str]:
    """URLs whose path looks like an env file (archives often keep these)."""
    hits: List[str] = []
    seen = set()
    for raw in urls or []:
        text = (raw or "").strip()
        if not text:
            continue
        path = urlparse(text).path.lower() if "://" in text else text.lower()
        name = path.rsplit("/", 1)[-1].split("?")[0]
        if (
            name.startswith(".env")
            or name.endswith(".env")
            or ".env." in name
            or name in {"env", "env.local", "env.production", "env.backup"}
        ):
            if text not in seen:
                seen.add(text)
                hits.append(text)
    return hits


# Keep source-ish and env-ish URLs from noisy archive dumps (.env.local is not `.env$`).
DISCOVERY_KEEP_URL_RE = re.compile(
    r"(?:\.(?:js|json|jsx|ts|tsx|map|html|htm|css|env|config|conf|yml|yaml|xml|ini|php|asp|aspx)(?:\?|$|#))"
    r"|(?:/\.env(?:\.[A-Za-z0-9._-]*)?)(?:\?|$|#)"
    r"|(?:/(?:backup\.env|env\.bak|env\.local|env\.production|env\.development|"
    r"env\.staging|env\.backup)(?:\?|$|#))",
    re.I,
)


def collect_http_urls_from_text(text: str) -> List[str]:
    urls: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line.split()[0].rstrip("',\"<>"))
            continue
        for m in re.finditer(r"https?://[^\s\"'<>]+", line):
            urls.append(m.group(0).rstrip("',\"<>"))
    return urls


def harvest_discovery_url_pool(output_dir: Path, extra: Optional[List[str]] = None) -> List[str]:
    """Raw HTTP URLs from discovery tool dumps (including rows filtered from files_to_scan)."""
    chunks: List[str] = []
    if extra:
        chunks.append("\n".join(extra))
    root = Path(output_dir)
    for name in ("katana_urls.txt", "files_to_scan.txt", "gau_urls.txt", "wayback_urls.txt"):
        p = root / name
        if p.is_file():
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
    for sub in ("waymore_out", "gospider_out"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if not p.is_file() or p.stat().st_size > 5_000_000:
                continue
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    urls: List[str] = []
    seen = set()
    for blob in chunks:
        for url in collect_http_urls_from_text(blob):
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


PUBLIC_APIS_README_URL = (
    "https://raw.githubusercontent.com/public-apis/public-apis/master/README.md"
)
PUBLIC_API_SKIP_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "gist.github.com",
    "postman.com", "getpostman.com", "youtube.com", "youtu.be",
    "twitter.com", "x.com", "facebook.com", "linkedin.com",
    "wikipedia.org", "google.com", "googlesource.com", "googleapis.com",
    "npmjs.com", "npmjs.org", "pypi.org", "readthedocs.io", "medium.com",
    "discord.com", "discord.gg", "apple.com", "microsoft.com",
}
PUBLIC_API_SKIP_NEEDLES = {
    "api", "http", "https", "json", "xml", "data", "test", "demo", "news",
    "weather", "maps", "map", "books", "music", "video", "food", "cats",
    "dogs", "dog", "cat", "nasa", "google", "github", "twitter", "facebook",
}
PUBLIC_API_URL_RE = re.compile(
    r"""https?://(?P<host>[^/\s"'<>]+)(?P<path>/[^?\s"'<>]*)?\?(?P<query>[^\s"'<>]+)""",
    re.I,
)
PUBLIC_API_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
PUBLIC_API_ALWAYS_PARAMS = {
    "apikey", "api_key", "appid", "app_id", "access_key", "auth_key",
    "x-api-key", "x_api_key", "client_key",
}
PUBLIC_API_CATALOG_PARAMS = PUBLIC_API_ALWAYS_PARAMS | {
    "key", "token", "access_token",
}
_PUBLIC_APIS_INDEX: Optional[Dict[str, Any]] = None


def public_apis_catalog_path() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "public_apis.json"


def _skipped_public_api_host(host: str) -> bool:
    h = (host or "").lower().strip(".")
    if h.startswith("www."):
        h = h[4:]
    for skip in PUBLIC_API_SKIP_HOSTS:
        if h == skip or h.endswith("." + skip):
            return True
    return False


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip(".").split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac"} and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def hosts_from_docs_url(url: str) -> List[str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return []
    host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0]
    if not host or _skipped_public_api_host(host):
        return []
    if host.startswith("www."):
        host = host[4:]
    domain = registrable_domain(host)
    out: List[str] = []
    for item in (host, domain):
        if item and item not in out and not _skipped_public_api_host(item):
            out.append(item)
    return out


def parse_public_apis_markdown(text: str) -> List[Dict[str, Any]]:
    """Parse public-apis README tables; keep rows that require an API key."""
    row_re = re.compile(
        r"^\|\s*\[(?P<name>[^\]]+)\]\((?P<url>[^)]+)\)\s*\|"
        r"[^|]*\|"
        r"\s*`?(?P<auth>[^|`\n]+)`?",
        re.M,
    )
    keep_auth = {"apikey", "x-mashape-key"}
    entries: List[Dict[str, Any]] = []
    seen = set()
    for m in row_re.finditer(text or ""):
        auth_raw = (m.group("auth") or "").strip().strip("`")
        auth_norm = re.sub(r"\s+", "", auth_raw).lower()
        if auth_norm not in keep_auth:
            continue
        name = (m.group("name") or "").strip()
        url = (m.group("url") or "").strip()
        if not name or not url:
            continue
        hosts = hosts_from_docs_url(url)
        ident = (name.lower(), tuple(hosts), url.split("?")[0])
        if ident in seen:
            continue
        seen.add(ident)
        entries.append({
            "name": name,
            "auth": "apiKey" if auth_norm == "apikey" else "X-Mashape-Key",
            "url": url.split("?")[0],
            "hosts": hosts,
        })
    return entries


def build_public_apis_index(entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    rows = list(entries or [])
    by_host: Dict[str, Dict[str, Any]] = {}
    by_domain: Dict[str, Dict[str, Any]] = {}
    needles: List[Tuple[str, Dict[str, Any]]] = []
    for row in rows:
        for host in row.get("hosts") or []:
            h = str(host).lower()
            by_host.setdefault(h, row)
            by_domain.setdefault(registrable_domain(h), row)
        name = str(row.get("name") or "").strip().lower()
        compact = re.sub(r"[^a-z0-9]+", "", name)
        if len(name) >= 8 and name not in PUBLIC_API_SKIP_NEEDLES:
            needles.append((name, row))
        if compact != name and len(compact) >= 8 and compact not in PUBLIC_API_SKIP_NEEDLES:
            needles.append((compact, row))
    return {
        "entries": rows,
        "by_host": by_host,
        "by_domain": by_domain,
        "needles": needles,
    }


def reset_public_apis_index() -> None:
    global _PUBLIC_APIS_INDEX
    _PUBLIC_APIS_INDEX = None


def load_public_apis_index(path: Optional[Path] = None, force: bool = False) -> Dict[str, Any]:
    global _PUBLIC_APIS_INDEX
    if _PUBLIC_APIS_INDEX is not None and not force and path is None:
        return _PUBLIC_APIS_INDEX
    catalog = Path(path) if path else public_apis_catalog_path()
    entries: List[Dict[str, Any]] = []
    if catalog.is_file():
        try:
            data = json.loads(catalog.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                entries = [e for e in (data.get("entries") or []) if isinstance(e, dict)]
            elif isinstance(data, list):
                entries = [e for e in data if isinstance(e, dict)]
        except Exception:
            entries = []
    index = build_public_apis_index(entries)
    if path is None:
        _PUBLIC_APIS_INDEX = index
    return index


def lookup_public_api_host(host: str, index: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    idx = index if index is not None else load_public_apis_index()
    h = (host or "").lower().strip(".").split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    if not h:
        return None
    by_host = idx.get("by_host") or {}
    if h in by_host:
        return by_host[h]
    domain = registrable_domain(h)
    by_domain = idx.get("by_domain") or {}
    if domain in by_domain:
        return by_domain[domain]
    parts = h.split(".")
    for i in range(1, max(len(parts) - 1, 1)):
        suffix = ".".join(parts[i:])
        if suffix in by_host:
            return by_host[suffix]
    return None


def match_public_api_hint(
    text: str,
    start: int,
    end: int,
    window: int = 220,
    index: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    idx = index if index is not None else load_public_apis_index()
    if not (idx.get("entries") or idx.get("by_host")):
        return None
    chunk = (text or "")[max(0, start - window): min(len(text or ""), end + window)]
    lower = chunk.lower()
    for m in PUBLIC_API_HOST_RE.finditer(lower):
        hit = lookup_public_api_host(m.group(0), idx)
        if hit:
            return hit
    for needle, row in idx.get("needles") or []:
        if needle and needle in lower:
            return row
    return None


def public_api_query_secrets(
    text: str,
    index: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Pull API keys out of query strings on catalog hosts (and obvious api_key params)."""
    idx = index if index is not None else load_public_apis_index()
    hits: List[Dict[str, Any]] = []
    seen = set()
    for m in PUBLIC_API_URL_RE.finditer(text or ""):
        host = (m.group("host") or "").lower().split("@")[-1].split(":")[0]
        query = m.group("query") or ""
        try:
            params = parse_qs(query, keep_blank_values=False)
        except Exception:
            continue
        catalog = lookup_public_api_host(host, idx)
        for raw_name, values in params.items():
            pname = re.sub(r"[-]", "_", (raw_name or "").lower())
            allowed = PUBLIC_API_CATALOG_PARAMS if catalog else PUBLIC_API_ALWAYS_PARAMS
            if pname not in allowed and raw_name.lower() not in allowed:
                continue
            for val in values or []:
                key = (val or "").strip().strip("'\"")
                if len(key) < 16 or len(key) > 120:
                    continue
                if key.startswith("http://") or key.startswith("https://"):
                    continue
                ident = (key, (catalog or {}).get("name") if catalog else host)
                if ident in seen:
                    continue
                seen.add(ident)
                hits.append({
                    "type": "public_api_key" if catalog else "generic_secret",
                    "key": key,
                    "likely_service": (catalog or {}).get("name") or "",
                    "public_api": bool(catalog),
                    "detector": "public_api_query",
                    "start": m.start(),
                    "end": m.end(),
                    "host": host,
                })
    return hits


def write_public_apis_catalog(entries: List[Dict[str, Any]], path: Optional[Path] = None) -> Path:
    dest = Path(path) if path else public_apis_catalog_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": "https://github.com/public-apis/public-apis",
        "readme": PUBLIC_APIS_README_URL,
        "count": len(entries),
        "entries": entries,
    }
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    reset_public_apis_index()
    return dest


def refresh_public_apis_catalog(
    path: Optional[Path] = None,
    timeout: int = 30,
    markdown: Optional[str] = None,
) -> Tuple[Path, int]:
    """Rebuild the bundled catalog from the public-apis README (or provided markdown)."""
    text = markdown
    if text is None:
        req = urllib.request.Request(
            PUBLIC_APIS_README_URL,
            headers={"User-Agent": "ReconPipe/public-apis-catalog"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
    entries = parse_public_apis_markdown(text or "")
    dest = write_public_apis_catalog(entries, path)
    return dest, len(entries)


def bundled_secrets_db_path() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "secrets_patterns.yml"


def secrets_db_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")[:48]
    return f"spd_{slug or 'pattern'}"


def iter_secrets_pattern_entries(data: Any) -> List[Dict[str, str]]:
    """Normalize secrets-patterns-db / jsleak YAML into {name, regex, confidence}."""
    if isinstance(data, dict):
        items = data.get("patterns") or data.get("rules") or []
    elif isinstance(data, list):
        items = data
    else:
        return []
    rows: List[Dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        inner = item.get("pattern") if isinstance(item.get("pattern"), dict) else item
        if not isinstance(inner, dict):
            continue
        name = str(inner.get("name") or inner.get("Name") or "").strip()
        regex = str(
            inner.get("regex") or inner.get("Regex") or inner.get("pattern") or ""
        ).strip()
        conf = str(inner.get("confidence") or inner.get("Confidence") or "medium").strip().lower()
        if name and regex:
            rows.append({"name": name, "regex": regex, "confidence": conf})
    return rows


def secrets_regex_compiles(pattern: str) -> bool:
    if not pattern or len(pattern) > 500:
        return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def secrets_db_is_duplicate(regex: str, existing: Dict[str, str]) -> bool:
    rx = (regex or "").strip()
    if not rx:
        return True
    low = rx.lower()
    for old in (existing or {}).values():
        if old == rx:
            return True
        old_l = (old or "").lower()
        for marker in SECRETS_DB_PREFIX_MARKERS:
            if marker in low and marker in old_l:
                return True
    return False


def filter_secrets_db_entries(
    entries: List[Dict[str, str]],
    existing_patterns: Optional[Dict[str, str]] = None,
    *,
    include_medium: bool = False,
    limit: int = SECRETS_DB_MAX,
) -> List[Dict[str, str]]:
    """Keep high-confidence key regexes; drop infra URLs and duplicates."""
    existing = dict(existing_patterns or {})
    allow = {"high"} if not include_medium else {"high", "medium"}
    kept: List[Dict[str, str]] = []
    seen_rx = set()
    for row in entries or []:
        conf = (row.get("confidence") or "medium").lower()
        if conf not in allow:
            continue
        name = row.get("name") or ""
        regex = (row.get("regex") or "").strip()
        if SECRETS_DB_SKIP_NAME.search(name) or SECRETS_DB_SKIP_REGEX.search(regex):
            continue
        if not secrets_regex_compiles(regex):
            continue
        if regex in seen_rx or secrets_db_is_duplicate(regex, existing):
            continue
        seen_rx.add(regex)
        existing[secrets_db_slug(name)] = regex
        kept.append({"name": name, "regex": regex, "confidence": conf})
        if len(kept) >= max(1, int(limit)):
            break
    return kept


def write_jsleak_patterns_yaml(entries: List[Dict[str, str]], path: Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = ["patterns:"]
    for row in entries or []:
        regex = (row.get("regex") or "").strip()
        if not regex:
            continue
        lines.append("  - pattern:")
        lines.append(f"      name: {json.dumps(row.get('name') or 'pattern')}")
        lines.append(f"      regex: {json.dumps(regex)}")
        lines.append(f"      confidence: {json.dumps(row.get('confidence') or 'high')}")
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def write_secrets_db_yaml(entries: List[Dict[str, str]], path: Path) -> Path:
    return write_jsleak_patterns_yaml(entries, path)


def refresh_secrets_pattern_db(
    path: Path,
    *,
    existing_patterns: Optional[Dict[str, str]] = None,
    include_medium: bool = False,
    timeout: int = 45,
    yaml_text: Optional[str] = None,
) -> Tuple[Path, int]:
    """Download secrets-patterns-db and write a filtered jsleak-compatible YAML."""
    text = yaml_text
    if text is None:
        req = urllib.request.Request(
            SECRETS_PATTERNS_DB_URL,
            headers={"User-Agent": "ReconPipe/secrets-patterns-db"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
    try:
        import yaml as _yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to parse secrets-patterns-db") from exc
    data = _yaml.safe_load(text or "") or {}
    filtered = filter_secrets_db_entries(
        iter_secrets_pattern_entries(data),
        existing_patterns,
        include_medium=include_medium,
    )
    dest = write_secrets_db_yaml(filtered, path)
    return dest, len(filtered)


def build_jsleak_cmd(
    pattern_file: Optional[str] = None,
    concurrency: int = 15,
    secrets: bool = True,
) -> List[str]:
    cmd = ["jsleak", "-l", "-e", "-c", str(max(1, int(concurrency)))]
    if secrets and pattern_file:
        cmd.extend(["-s", "-t", str(pattern_file)])
    return cmd


def parse_jsleak_output(text: str) -> Dict[str, List[Dict[str, str]]]:
    secrets: List[Dict[str, str]] = []
    links: List[Dict[str, str]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        sm = JSLEAK_SECRET_LINE.match(line)
        if sm:
            secrets.append({
                "name": sm.group("name"),
                "secret": sm.group("secret"),
                "source_url": sm.group("url"),
            })
            continue
        lm = JSLEAK_LINK_LINE.match(line)
        if lm:
            links.append({"url": lm.group("link"), "base": lm.group("base")})
    return {"secrets": secrets, "links": links}


def build_gitleaks_cmd(source: str, report: str, git: bool = False) -> List[str]:
    """Current Gitleaks v8+ subcommands (`dir` / `git`)."""
    sub = "git" if git else "dir"
    return [
        "gitleaks", sub, source,
        "-f", "json",
        "-r", report,
        "--no-banner",
        "--exit-code", "0",
    ]


def build_gitleaks_detect_cmd(source: str, report: str, git: bool = False) -> List[str]:
    """Legacy `gitleaks detect` (still on many installs)."""
    cmd = [
        "gitleaks", "detect",
        "--source", source,
        "-f", "json",
        "-r", report,
        "--no-banner",
        "--exit-code", "0",
    ]
    if not git:
        cmd.append("--no-git")
    return cmd


def build_spray_cmd(list_file: str, dict_file: str) -> List[str]:
    """Opt-in path brute: backups + common files + leak wordlist."""
    return ["spray", "-l", list_file, "-d", dict_file, "--bak", "--common"]


def parse_gitleaks_report(path: Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return []
    text = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        rows: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
        data = rows
    if isinstance(data, dict):
        data = data.get("findings") or data.get("leaks") or []
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


def clone_repo(
    url: str,
    dest: Path,
    timeout: int = 300,
    shallow: bool = False,
) -> Tuple[bool, Path]:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        return True, dest
    cmd = build_clone_cmd(url, str(dest), shallow=shallow)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return proc.returncode == 0, dest
    except Exception:
        return False, dest


def list_repo_files(root: Path) -> List[Path]:
    files: List[Path] = []
    skip_dirs = {".git", "node_modules", "vendor", "dist", "build"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def is_iac_file(path: Path) -> bool:
    name = path.name.lower()
    if name in IAC_NAMES:
        return True
    if path.suffix.lower() in {".tf", ".tfvars"}:
        return True
    if name.endswith(".yaml") or name.endswith(".yml"):
        lowered = path.read_text(encoding="utf-8", errors="ignore")[:400].lower() if path.is_file() else ""
        if "kind:" in lowered or "apiversion:" in lowered:
            return True
    return False


def collect_iac_files(root: Path) -> List[Path]:
    return [p for p in list_repo_files(root) if is_iac_file(p) or p.suffix.lower() in {".env", ".json"}]


def export_hackerone_markdown(findings: List[Dict]) -> str:
    lines = ["## Summary", "", "Leaked credentials discovered by ReconPipe.", "", "## Steps to reproduce", ""]
    for f in findings or []:
        if not f.get("valid"):
            continue
        lines += [
            f"- Type: `{f.get('type')}` ({f.get('severity')})",
            f"  - Source: {f.get('source_url')}",
            f"  - Note: {f.get('note')}",
            f"  - Revoke: {f.get('revocation') or 'provider dashboard'}",
            "",
        ]
    if len(lines) == 5:
        lines.append("_No validated findings._")
    return "\n".join(lines)


def export_jira_markdown(findings: List[Dict]) -> str:
    lines = ["h2. Credential leak (ReconPipe)", ""]
    for f in findings or []:
        if not f.get("valid"):
            continue
        lines.append(
            f"* {f.get('severity', '').upper()} - {f.get('type')} @ {f.get('source_url')} — {f.get('note')}"
        )
    return "\n".join(lines) + "\n"


def load_scan_profiles(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.is_file():
        return {}
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return data if isinstance(data, dict) else {}


def save_scan_profile(path: Path, name: str, opts: Dict[str, Any]) -> Path:
    profiles = load_scan_profiles(path)
    profiles[name] = dict(opts)
    text = json.dumps(profiles, indent=2)
    try:
        import yaml
        text = yaml.safe_dump(profiles, sort_keys=False)
    except Exception:
        pass
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
    return Path(path)


def collect_tool_stdout_lines(output: bytes) -> List[str]:
    if not output:
        return []
    return [ln.strip() for ln in output.decode("utf-8", errors="ignore").splitlines() if ln.strip()]
