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


def extract_endpoints_from_js(content: str) -> List[str]:
    endpoints = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content or "", re.I):
            val = match.group(1) if match.lastindex else match.group(0)
            val = (val or "").strip()
            if val and len(val) < 400:
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


def clone_repo(url: str, dest: Path, timeout: int = 180) -> Tuple[bool, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", url, str(dest)]
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
