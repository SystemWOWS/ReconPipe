"""Wave-3 sources: code search, mobile apps, buckets, OpenAPI, SQLite, ETag, CT."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "ReconPipe/1.3"
GITHUB_SEARCH = "https://api.github.com/search/code"
GITLAB_SEARCH = "https://gitlab.com/api/v4/search"
S3_HOST_TMPL = "{name}.s3.amazonaws.com"
GCS_URL_TMPL = "https://storage.googleapis.com/{name}/"
AZURE_URL_TMPL = "https://{name}.blob.core.windows.net/?restype=container&comp=list"
CERTSTREAM_WS = "wss://certstream.calidog.io/"
VALIDATION_CACHE_TTL = 6 * 3600
CODE_SEARCH_PER_PAGE = 30
MAX_CODE_URLS = 80
MAX_BUCKET_OBJECTS = 40
MAX_OPENAPI_PATHS = 200
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{8,}")
OPENAPI_HINT_RE = re.compile(r'"(?:swagger|openapi)"\s*:')
POSTMAN_HINT_RE = re.compile(r'"_postman_id"|info"\s*:\s*\{[^}]{0,200}"schema".*postman', re.I | re.S)
MOBILE_KEEP_SUFFIX = {
    ".js", ".json", ".xml", ".html", ".htm", ".txt", ".properties",
    ".plist", ".env", ".yml", ".yaml", ".cfg", ".ini", ".gradle",
}
MOBILE_KEEP_NAMES = {
    "androidmanifest.xml", "google-services.json", "google-services.json",
    "awsconfiguration.json", "network_security_config.xml", "info.plist",
    "strings.xml", "config.json", "firebase-config.json",
}
MOBILE_PKG_SUFFIX = {".apk", ".xapk", ".apkm", ".ipa"}

GENERIC_PAIRS = (
    ("paypal_client_id", "paypal_secret", "paypal_secret", "paypal_client_id"),
    ("woocommerce_key", "woocommerce_secret", "woocommerce_secret", "woocommerce_key"),
    ("mixpanel_token", "mixpanel_secret", "mixpanel_secret", "mixpanel_token"),
    ("algolia_api", "algolia_admin", "algolia_admin", "algolia_api"),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Any:
    hdrs = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    req = Request(url, headers=hdrs)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace") or "null")


def _http_text(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 12) -> Tuple[int, str, Dict[str, str]]:
    hdrs = {"User-Agent": UA, **(headers or {})}
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            meta = {k.lower(): v for k, v in (resp.headers.items() if resp.headers else [])}
            return int(resp.status), body, meta
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        meta = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return int(exc.code), body, meta
    except (URLError, OSError, TimeoutError):
        return 0, "", {}


#  GitHub / GitLab code search 

def github_search_queries(domain: str, org: str = "", extra_hosts: Optional[Iterable[str]] = None) -> List[str]:
    host = (domain or "").strip().lower().lstrip(".")
    if not host:
        return []
    q = [
        f'"{host}" (api_key OR apikey OR secret OR token OR AKIA OR ghp_ OR sk_live OR .env)',
        f'"{host}" filename:.env',
        f'"{host}" filename:config.json',
        f'"{host}" extension:js (AIza OR firebase OR aws_access)',
        f'"{host}" (filename:mcp.json OR filename:claude_desktop_config.json OR filename:.mcp.json)',
        f'"{host}" (sk-ant- OR sk-proj- OR hf_ OR "mcpServers")',
    ]
    if org:
        q.append(f'org:{org.strip()} "{host}"')
    for extra in list(extra_hosts or [])[:8]:
        extra = (extra or "").strip().lower()
        if extra and extra != host:
            q.append(f'"{extra}" (api_key OR secret OR token)')
    # de-dupe, cap
    seen: Set[str] = set()
    out: List[str] = []
    for item in q:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out[:12]


def github_raw_url(html_url: str, sha: str = "", path: str = "") -> str:
    """Turn a GitHub blob URL into a raw.githubusercontent.com URL."""
    text = (html_url or "").strip()
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$",
        text,
    )
    if m:
        owner, repo, ref, rest = m.group(1), m.group(2), m.group(3), m.group(4)
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rest}"
    if sha and path and text:
        m2 = re.match(r"https?://github\.com/([^/]+)/([^/]+)", text)
        if m2:
            return f"https://raw.githubusercontent.com/{m2.group(1)}/{m2.group(2)}/{sha}/{path.lstrip('/')}"
    return text


def parse_github_search_payload(data: Any) -> List[Dict[str, str]]:
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        repo = it.get("repository") if isinstance(it.get("repository"), dict) else {}
        html = str(it.get("html_url") or "")
        path = str(it.get("path") or "")
        sha = str(it.get("sha") or "")
        raw = github_raw_url(html, sha=sha, path=path)
        if not raw.startswith("http"):
            continue
        rows.append({
            "html_url": html,
            "raw_url": raw,
            "path": path,
            "repo": str(repo.get("full_name") or ""),
            "sha": sha,
        })
    return rows


def parse_gitlab_search_payload(data: Any) -> List[Dict[str, str]]:
    items = data if isinstance(data, list) else []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        path = str(it.get("filename") or it.get("path") or "")
        project = str(it.get("project_id") or "")
        ref = str(it.get("ref") or "main")
        data_field = it.get("data") or ""
        web = str(it.get("web_url") or "")
        if web and "/-/blob/" in web:
            raw = web.replace("/-/blob/", "/-/raw/")
        else:
            raw = web
        if not raw:
            continue
        rows.append({
            "html_url": web,
            "raw_url": raw,
            "path": path,
            "repo": project,
            "sha": ref,
            "snippet": str(data_field)[:4000],
        })
    return rows


def collect_code_search_urls(
    domain: str,
    *,
    github_token: str = "",
    gitlab_token: str = "",
    org: str = "",
    extra_hosts: Optional[Iterable[str]] = None,
    fetch_json: Optional[Callable[..., Any]] = None,
) -> List[str]:
    """Return raw file URLs from GitHub/GitLab code search. fetch_json is injectable."""
    do_fetch = fetch_json or _http_json
    urls: List[str] = []
    seen: Set[str] = set()

    gh_headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        gh_headers["Authorization"] = f"Bearer {github_token}"

    pages = 2 if github_token else 1
    for query in github_search_queries(domain, org=org, extra_hosts=extra_hosts):
        for page in range(1, pages + 1):
            from urllib.parse import urlencode
            url = GITHUB_SEARCH + "?" + urlencode({
                "q": query, "per_page": CODE_SEARCH_PER_PAGE, "page": page,
            })
            try:
                payload = do_fetch(url, headers=gh_headers, timeout=20)
            except Exception:
                break
            rows = parse_github_search_payload(payload)
            if not rows:
                break
            for row in rows:
                raw = row.get("raw_url") or ""
                if raw and raw not in seen:
                    seen.add(raw)
                    urls.append(raw)
            if len(urls) >= MAX_CODE_URLS:
                return urls[:MAX_CODE_URLS]

    if gitlab_token:
        gl_headers = {"PRIVATE-TOKEN": gitlab_token}
        from urllib.parse import urlencode
        url = GITLAB_SEARCH + "?" + urlencode({
            "scope": "blobs", "search": domain, "per_page": CODE_SEARCH_PER_PAGE,
        })
        try:
            payload = do_fetch(url, headers=gl_headers, timeout=20)
        except Exception:
            payload = []
        for row in parse_gitlab_search_payload(payload):
            raw = row.get("raw_url") or ""
            if raw and raw not in seen:
                seen.add(raw)
                urls.append(raw)
    return urls[:MAX_CODE_URLS]


#  OpenAPI / Swagger / Postman 

def looks_like_openapi(text: str) -> bool:
    blob = (text or "").lstrip()[:4000]
    if not blob:
        return False
    if OPENAPI_HINT_RE.search(blob):
        return True
    try:
        data = json.loads(text)
    except Exception:
        return False
    return isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data)


def looks_like_postman(text: str) -> bool:
    blob = (text or "")[:8000]
    if POSTMAN_HINT_RE.search(blob):
        return True
    try:
        data = json.loads(text)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    schema = str(info.get("schema") or "")
    return "postman" in schema.lower() or ("item" in data and "info" in data)


def _join_url(base: str, path: str) -> str:
    path = path or ""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    if not base:
        return path
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def parse_openapi_spec(data: Any, source_url: str = "") -> Dict[str, Any]:
    """Extract endpoint URLs and example/auth strings from OpenAPI 2/3 JSON."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", errors="ignore")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return {"urls": [], "secrets": []}
    if not isinstance(data, dict):
        return {"urls": [], "secrets": []}

    parsed = urlparse(source_url or "")
    default_base = ""
    if parsed.scheme and parsed.netloc:
        default_base = f"{parsed.scheme}://{parsed.netloc}"

    bases: List[str] = []
    host = str(data.get("host") or "")
    base_path = str(data.get("basePath") or "")
    schemes = data.get("schemes") if isinstance(data.get("schemes"), list) else ["https"]
    if host:
        scheme = str(schemes[0] if schemes else "https")
        bases.append(f"{scheme}://{host}{base_path}")
    servers = data.get("servers") if isinstance(data.get("servers"), list) else []
    for srv in servers:
        if isinstance(srv, dict) and srv.get("url"):
            url = str(srv["url"])
            if url.startswith("/"):
                url = _join_url(default_base, url)
            elif "://" not in url:
                url = _join_url(default_base, url)
            bases.append(url.rstrip("/"))
    if not bases:
        bases = [default_base.rstrip("/")] if default_base else [""]

    urls: List[str] = []
    paths = data.get("paths") if isinstance(data.get("paths"), dict) else {}
    for path in list(paths.keys())[:MAX_OPENAPI_PATHS]:
        for base in bases[:3]:
            urls.append(_join_url(base, str(path)))

    secrets: List[Dict[str, str]] = []
    comps = data.get("components") if isinstance(data.get("components"), dict) else {}
    schemes_map = {}
    if isinstance(data.get("securityDefinitions"), dict):
        schemes_map.update(data["securityDefinitions"])
    if isinstance(comps.get("securitySchemes"), dict):
        schemes_map.update(comps["securitySchemes"])
    for name, spec in schemes_map.items():
        if not isinstance(spec, dict):
            continue
        for key in ("value", "example", "default"):
            val = spec.get(key)
            if isinstance(val, str) and len(val) >= 12:
                secrets.append({"name": str(name), "value": val, "where": "securityScheme"})
        for nested in spec.get("flows") or []:
            pass
        flows = spec.get("flows") if isinstance(spec.get("flows"), dict) else {}
        for flow in flows.values():
            if not isinstance(flow, dict):
                continue
            for key in ("tokenUrl", "authorizationUrl"):
                val = flow.get(key)
                if isinstance(val, str) and val.startswith("http"):
                    urls.append(val)

    def _walk_examples(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in {"example", "examples", "default", "value"} and isinstance(v, str) and len(v) >= 16:
                    if re.search(r"(key|token|secret|bearer|api)", lk) or re.match(
                        r"^(sk_|ghp_|AKIA|AIza|eyJ)", v
                    ):
                        secrets.append({"name": str(k), "value": v, "where": "example"})
                else:
                    _walk_examples(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:40]:
                _walk_examples(item, depth + 1)

    _walk_examples(data)
    # de-dupe urls
    seen: Set[str] = set()
    uniq = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return {"urls": uniq[:MAX_OPENAPI_PATHS], "secrets": secrets[:80]}


def parse_postman_collection(data: Any) -> Dict[str, Any]:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return {"urls": [], "secrets": []}
    if not isinstance(data, dict):
        return {"urls": [], "secrets": []}

    urls: List[str] = []
    secrets: List[Dict[str, str]] = []

    def grab_url(node: Any) -> None:
        if isinstance(node, str) and node.startswith("http"):
            urls.append(node)
        elif isinstance(node, dict):
            raw = node.get("raw")
            if isinstance(raw, str) and raw.startswith("http"):
                urls.append(raw)
            elif isinstance(node.get("host"), list):
                proto = str(node.get("protocol") or "https")
                host = ".".join(str(p) for p in node["host"])
                path = node.get("path")
                path_s = "/" + "/".join(str(p) for p in path) if isinstance(path, list) else ""
                urls.append(f"{proto}://{host}{path_s}")

    def walk_items(items: Any) -> None:
        if not isinstance(items, list):
            return
        for it in items:
            if not isinstance(it, dict):
                continue
            if "item" in it:
                walk_items(it.get("item"))
            req = it.get("request") if isinstance(it.get("request"), dict) else {}
            grab_url(req.get("url"))
            auth = req.get("auth") if isinstance(req.get("auth"), dict) else {}
            for apikey in auth.get("apikey") or []:
                if isinstance(apikey, dict) and apikey.get("value"):
                    secrets.append({
                        "name": str(apikey.get("key") or "apikey"),
                        "value": str(apikey["value"]),
                        "where": "postman.auth",
                    })
            for hdr in req.get("header") or []:
                if not isinstance(hdr, dict):
                    continue
                name = str(hdr.get("key") or "")
                val = str(hdr.get("value") or "")
                if name.lower() in {"authorization", "x-api-key", "api-key"} and len(val) >= 8:
                    secrets.append({"name": name, "value": val, "where": "postman.header"})
            walk_items(it.get("item"))

    walk_items(data.get("item"))
    for var in data.get("variable") or []:
        if isinstance(var, dict) and var.get("value"):
            val = str(var["value"])
            key = str(var.get("key") or "var")
            if len(val) >= 12 and re.search(r"(key|token|secret|password)", key, re.I):
                secrets.append({"name": key, "value": val, "where": "postman.variable"})
    seen: Set[str] = set()
    uniq = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return {"urls": uniq[:MAX_OPENAPI_PATHS], "secrets": secrets[:80]}


def harvest_spec_urls(text: str, source_url: str = "") -> List[str]:
    if looks_like_openapi(text):
        return list(parse_openapi_spec(text, source_url).get("urls") or [])
    if looks_like_postman(text):
        return list(parse_postman_collection(text).get("urls") or [])
    return []


def harvest_spec_secret_findings(text: str, source_url: str = "") -> List[Dict[str, str]]:
    parsed: Dict[str, Any] = {"secrets": []}
    if looks_like_openapi(text):
        parsed = parse_openapi_spec(text, source_url)
    elif looks_like_postman(text):
        parsed = parse_postman_collection(text)
    out: List[Dict[str, str]] = []
    for row in parsed.get("secrets") or []:
        val = str(row.get("value") or "")
        if len(val) < 12:
            continue
        out.append({
            "type": "generic_secret",
            "key": val,
            "source_url": source_url,
            "scanner": "openapi",
            "note": f"Example/auth from {row.get('where') or 'spec'} ({row.get('name')})",
            "confidence": 55,
        })
    return out


# APK / IPA 

def extract_printable_strings(data: bytes, min_len: int = 8) -> str:
    chunks = [m.group().decode("ascii", errors="ignore") for m in PRINTABLE_RE.finditer(data or b"")]
    return "\n".join(c for c in chunks if len(c) >= min_len)


def extract_mobile_archive(
    archive: Path, dest: Path, limit_files: int = 400, depth: int = 0
) -> List[Path]:
    """Unzip APK/IPA/XAPK/APKM and write text-ish members (+ strings dump of binaries)."""
    archive = Path(archive)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    if not archive.is_file():
        return written
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile:
        return written
    strings_buf: List[str] = []
    with zf:
        names = zf.namelist()[: max(50, limit_files * 2)]
        for name in names:
            if name.endswith("/"):
                continue
            low = name.lower()
            base = Path(low).name
            suffix = Path(low).suffix
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            is_pkg = suffix in MOBILE_PKG_SUFFIX
            if info.file_size > 80_000_000:
                continue
            if info.file_size > 4_000_000 and not is_pkg:
                continue
            try:
                blob = zf.read(name)
            except Exception:
                continue
            keep = (
                suffix in MOBILE_KEEP_SUFFIX
                or base in MOBILE_KEEP_NAMES
                or low.endswith(".jsbundle")
            )
            safe = re.sub(r"[^a-zA-Z0-9._/-]", "_", name).replace("..", "_")
            out = dest / safe
            if keep:
                out.parent.mkdir(parents=True, exist_ok=True)
                try:
                    text = blob.decode("utf-8")
                except Exception:
                    text = blob.decode("utf-8", errors="ignore")
                out.write_text(text, encoding="utf-8")
                written.append(out)
            elif is_pkg and depth < 1:
                pkg_path = dest / "_nested" / Path(safe).name
                pkg_path.parent.mkdir(parents=True, exist_ok=True)
                pkg_path.write_bytes(blob)
                nested_dest = pkg_path.parent / (pkg_path.stem + "_unpacked")
                written.extend(
                    extract_mobile_archive(
                        pkg_path, nested_dest, max(1, limit_files - len(written)), depth + 1
                    )
                )
            else:
                extracted = extract_printable_strings(blob)
                if extracted:
                    strings_buf.append(f"--- {name} ---\n{extracted}")
            if len(written) >= limit_files:
                break
    if strings_buf:
        dump = dest / "_apk_strings.txt"
        dump.write_text("\n\n".join(strings_buf)[:2_000_000], encoding="utf-8")
        written.append(dump)
    return written


# Cloud buckets

def bucket_name_candidates(domain: str) -> List[str]:
    host = (domain or "").strip().lower().lstrip(".")
    if not host or "." not in host and len(host) < 3:
        # still allow single-label org names
        host = host or ""
    if not host:
        return []
    labels = [p for p in host.split(".") if p and p not in {"www", "com", "net", "org", "io", "co"}]
    base = labels[0] if labels else host.split(".")[0]
    slug = host.replace(".", "-")
    compact = re.sub(r"[^a-z0-9]", "", host)
    names = [
        host, base, slug, compact, f"{base}-assets", f"{base}-static",
        f"{base}-media", f"{base}-cdn", f"{base}-backup", f"{base}-prod",
        f"{base}-dev", f"{base}-staging", f"assets-{base}", f"{slug}-assets",
        f"{base}prod", f"{base}static",
    ]
    seen: Set[str] = set()
    out: List[str] = []
    for n in names:
        n = re.sub(r"[^a-z0-9.-]", "", n).strip(".-")
        if len(n) < 3 or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out[:24]


def parse_s3_listing(xml_text: str) -> List[str]:
    keys = re.findall(r"<Key>([^<]+)</Key>", xml_text or "")
    return [k for k in keys if k]


def parse_gcs_listing(text: str) -> List[str]:
    keys = re.findall(r"<Key>([^<]+)</Key>", text or "")
    if keys:
        return keys
    try:
        data = json.loads(text)
        items = data.get("items") if isinstance(data, dict) else []
        return [str(it.get("name")) for it in items or [] if isinstance(it, dict) and it.get("name")]
    except Exception:
        return []


def parse_azure_listing(xml_text: str) -> List[str]:
    return re.findall(r"<Name>([^<]+)</Name>", xml_text or "")


def classify_bucket_response(status: int, body: str) -> str:
    text = body or ""
    if status == 200 and ("<ListBucketResult" in text or "<ListBucket" in text or '"items"' in text or "<EnumerationResults" in text):
        return "open"
    if status == 200 and text.strip():
        return "open"
    if status in (401, 403):
        return "exists"
    if status == 404:
        return "missing"
    return "other"


KEEP_OBJECT_RE = re.compile(
    r"\.(?:js|json|map|html|txt|xml|env|yml|yaml|properties|config)$", re.I
)


def bucket_object_urls(kind: str, name: str, keys: List[str]) -> List[str]:
    urls: List[str] = []
    for key in keys:
        if not KEEP_OBJECT_RE.search(key) and not key.lower().endswith((".js", ".json")):
            if not re.search(r"(env|config|secret|firebase|google-services)", key, re.I):
                continue
        if kind == "s3":
            urls.append(f"https://{name}.s3.amazonaws.com/{key.lstrip('/')}")
        elif kind == "gcs":
            urls.append(f"https://storage.googleapis.com/{name}/{key.lstrip('/')}")
        elif kind == "azure":
            urls.append(f"https://{name}.blob.core.windows.net/{key.lstrip('/')}")
        if len(urls) >= MAX_BUCKET_OBJECTS:
            break
    return urls


def probe_buckets(
    domain: str,
    *,
    fetch: Optional[Callable[..., Tuple[int, str, Dict[str, str]]]] = None,
) -> Dict[str, Any]:
    """Guess + probe S3/GCS/Azure names derived from the target domain."""
    getter = fetch or _http_text
    found: List[Dict[str, Any]] = []
    object_urls: List[str] = []
    for name in bucket_name_candidates(domain):
        targets = [
            ("s3", f"https://{name}.s3.amazonaws.com/"),
            ("gcs", f"https://storage.googleapis.com/{name}"),
            ("azure", f"https://{name}.blob.core.windows.net/?restype=container&comp=list"),
        ]
        for kind, url in targets:
            try:
                status, body, _meta = getter(url, timeout=8)
            except Exception:
                continue
            klass = classify_bucket_response(status, body)
            if klass == "missing":
                continue
            row = {"kind": kind, "name": name, "url": url, "status": status, "access": klass}
            found.append(row)
            if klass == "open":
                if kind == "s3":
                    keys = parse_s3_listing(body)
                elif kind == "gcs":
                    keys = parse_gcs_listing(body)
                else:
                    keys = parse_azure_listing(body)
                object_urls.extend(bucket_object_urls(kind, name, keys))
    return {"buckets": found, "urls": object_urls}


#  ETag download cache 

def load_etag_cache(path: Path) -> Dict[str, Dict[str, str]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def save_etag_cache(path: Path, cache: Dict[str, Dict[str, str]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(cache, indent=2), encoding="utf-8")


def etag_request_headers(entry: Optional[Dict[str, str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not entry:
        return headers
    etag = (entry.get("etag") or "").strip()
    last_mod = (entry.get("last_modified") or "").strip()
    if etag:
        headers["If-None-Match"] = etag
    if last_mod:
        headers["If-Modified-Since"] = last_mod
    return headers


def etag_cache_update(entry: Dict[str, str], headers: Dict[str, str], sha256: str = "") -> Dict[str, str]:
    out = dict(entry or {})
    etag = headers.get("etag") or headers.get("ETag") or ""
    last_mod = headers.get("last-modified") or headers.get("Last-Modified") or ""
    if etag:
        out["etag"] = etag
    if last_mod:
        out["last_modified"] = last_mod
    if sha256:
        out["sha256"] = sha256
    out["checked_at"] = _now_iso()
    return out


#  SQLite finding store + validation cache 

def findings_db_path(explicit: Optional[Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    env = (os.environ.get("RECONPIPE_HOME") or "").strip()
    root = Path(env).expanduser() if env else Path.home() / ".reconpipe"
    root.mkdir(parents=True, exist_ok=True)
    return root / "findings.db"


def connect_store(path: Optional[Path] = None) -> sqlite3.Connection:
    db = findings_db_path(path)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.execute(
        """CREATE TABLE IF NOT EXISTS findings (
            hash TEXT PRIMARY KEY,
            type TEXT,
            domain TEXT,
            source TEXT,
            valid INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            last_valid TEXT,
            note TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS validation_cache (
            key_hash TEXT PRIMARY KEY,
            type TEXT,
            valid INTEGER,
            status_code INTEGER,
            note TEXT,
            checked_at TEXT,
            ttl_seconds INTEGER
        )"""
    )
    conn.commit()
    return conn


def upsert_findings(conn: sqlite3.Connection, domain: str, findings: List[Dict]) -> Dict[str, int]:
    now = _now_iso()
    new_rows = 0
    newly_valid = 0
    for f in findings or []:
        h = str(f.get("hash") or "")
        if not h and f.get("type") and f.get("key"):
            h = hashlib.sha256(f"{f.get('type')}:{f.get('key')}".encode()).hexdigest()
        if not h:
            continue
        valid = 1 if f.get("valid") else 0
        cur = conn.execute("SELECT valid, first_seen FROM findings WHERE hash=?", (h,))
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO findings(hash,type,domain,source,valid,first_seen,last_seen,last_valid,note) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    h, str(f.get("type") or ""), domain, str(f.get("source_url") or ""),
                    valid, now, now, now if valid else "", str(f.get("note") or "")[:500],
                ),
            )
            new_rows += 1
            if valid:
                newly_valid += 1
        else:
            was_valid = int(row[0] or 0)
            last_valid = now if valid else ""
            conn.execute(
                "UPDATE findings SET last_seen=?, valid=?, note=?, domain=?, "
                "last_valid=CASE WHEN ?=1 THEN ? ELSE last_valid END WHERE hash=?",
                (now, valid, str(f.get("note") or "")[:500], domain, valid, last_valid or now, h),
            )
            if valid and not was_valid:
                newly_valid += 1
    conn.commit()
    return {"new": new_rows, "newly_valid": newly_valid}


def cache_get(conn: sqlite3.Connection, key_hash: str, now_ts: Optional[float] = None) -> Optional[Dict[str, Any]]:
    cur = conn.execute(
        "SELECT valid, status_code, note, checked_at, ttl_seconds, type FROM validation_cache WHERE key_hash=?",
        (key_hash,),
    )
    row = cur.fetchone()
    if not row:
        return None
    valid, status, note, checked_at, ttl, typ = row
    ttl = int(ttl or VALIDATION_CACHE_TTL)
    try:
        checked = datetime.strptime(str(checked_at), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - checked).total_seconds()
    except Exception:
        return None
    if age > ttl:
        return None
    return {
        "valid": bool(valid),
        "status_code": status,
        "note": (note or "") + " (cached)",
        "validated": True,
        "from_cache": True,
        "type": typ,
    }


def cache_put(conn: sqlite3.Connection, key_hash: str, finding: Dict, ttl: int = VALIDATION_CACHE_TTL) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO validation_cache(key_hash,type,valid,status_code,note,checked_at,ttl_seconds) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            key_hash,
            str(finding.get("type") or ""),
            1 if finding.get("valid") else 0,
            finding.get("status_code"),
            str(finding.get("note") or "")[:500],
            _now_iso(),
            int(ttl),
        ),
    )
    conn.commit()


#  git blame / log -S 

def git_commit_for_secret(repo: Path, rel_path: str, snippet: str) -> Optional[Dict[str, str]]:
    """First commit that introduced snippet (git log -S). Offline-friendly if git missing."""
    repo = Path(repo)
    needle = (snippet or "").strip()
    if not needle or not repo.is_dir():
        return None
    needle = needle[:80]
    cmd = [
        "git", "-C", str(repo), "log", "-S", needle,
        "--pretty=format:%H\t%an\t%ad\t%s", "--date=iso", "-1", "--", rel_path or ".",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    line = (proc.stdout or b"").decode("utf-8", errors="replace").strip().splitlines()
    if not line:
        return None
    parts = line[0].split("\t", 3)
    if len(parts) < 3:
        return None
    return {
        "commit": parts[0],
        "author": parts[1],
        "date": parts[2],
        "subject": parts[3] if len(parts) > 3 else "",
    }


def annotate_repo_findings(findings: List[Dict], repo: Path) -> int:
    n = 0
    repo = Path(repo)
    for f in findings or []:
        src = str(f.get("source_url") or f.get("source_file") or "")
        try:
            path = Path(src)
            if path.is_file() and (repo in path.parents or str(path).startswith(str(repo))):
                rel = str(path.relative_to(repo))
            elif src.startswith(str(repo)):
                rel = str(Path(src).relative_to(repo))
            else:
                continue
        except Exception:
            continue
        meta = git_commit_for_secret(repo, rel, str(f.get("key") or ""))
        if meta:
            f["git_commit"] = meta.get("commit")
            f["git_author"] = meta.get("author")
            f["git_date"] = meta.get("date")
            f["git_subject"] = meta.get("subject")
            n += 1
    return n


#  Docker Hub + public image layers 

DOCKER_HUB_SEARCH = "https://hub.docker.com/v2/search/repositories/"
MAX_HUB_IMAGES = 12
MAX_IMAGE_SCAN = 8
IMAGE_FROM_RE = re.compile(
    r"(?im)^\s*(?:FROM|image:)\s+['\"]?([a-z0-9][a-z0-9._\-/:@]+)['\"]?"
)
IMAGE_REF_RE = re.compile(
    r"""(?ix)
    \b(
      (?:ghcr\.io|quay\.io|gcr\.io|public\.ecr\.aws|docker\.io|registry\.hub\.docker\.com)/
      [a-z0-9._\-]+/[a-z0-9._\-]+(?::[A-Za-z0-9._\-]+)?
    )\b
    """
)
SKIP_BASE_IMAGES = frozenset({
    "python", "node", "nodejs", "nginx", "alpine", "ubuntu", "debian", "golang",
    "busybox", "redis", "postgres", "postgresql", "mysql", "mariadb", "httpd",
    "maven", "gradle", "openjdk", "eclipse-temurin", "amazonlinux", "centos",
    "fedora", "scratch", "distroless", "php", "ruby", "rust", "amazoncorretto",
})
LAYER_KEEP_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".env.bak", "mcp.json", "mcp_config.json", "claude_desktop_config.json",
    ".mcp.json", ".claude.json", "application_default_credentials.json",
    "credentials.json", "credentials", "id_rsa", ".npmrc", ".pypirc", ".netrc",
    "secrets.yml", "secrets.yaml", "service-account.json", "google-services.json",
    "adc.json", "gcp-credentials.json", "config.json",
})
LAYER_PATH_HINTS = (
    ".cursor/", ".anthropic/", ".claude/", ".config/gcloud/", ".aws/",
    ".continue/", "mcpservers", ".huggingface/", ".cache/huggingface/",
)
AI_PROVIDER_TYPES = frozenset({
    "openai_key", "anthropic_key", "huggingface_token", "mcp_credential",
    "google_api",
})
MCP_SOURCE_RE = re.compile(
    r"mcp\.json|mcp_config|claude_desktop_config|\.cursor[/\\]|\.anthropic[/\\]|"
    r"mcpServers|\.mcp\.json|\.continue[/\\]|image_layers",
    re.I,
)
TRIVY_TYPE_HINTS = (
    ("openai", "openai_key"),
    ("anthropic", "anthropic_key"),
    ("huggingface", "huggingface_token"),
    ("hugging-face", "huggingface_token"),
    ("aws-access", "aws_access_key"),
    ("github", "github_pat"),
    ("stripe", "stripe_live"),
    ("gcp", "gcp_service_acct"),
    ("google", "google_api"),
    ("slack", "slack_token"),
    ("private-key", "private_key_pem"),
)


def docker_hub_queries(domain: str) -> List[str]:
    host = (domain or "").strip().lower().lstrip(".")
    if not host:
        return []
    slug = host.split(".")[0]
    out = [host]
    if slug and slug != host and len(slug) >= 3:
        out.append(slug)
    return out[:3]


def parse_docker_hub_search(data: Any) -> List[Dict[str, str]]:
    items = data.get("results") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("repo_name") or it.get("name") or "").strip()
        if not name:
            continue
        rows.append({
            "repo_name": name,
            "star_count": str(it.get("star_count") or it.get("star_count") or "0"),
            "pull_count": str(it.get("pull_count") or "0"),
            "is_official": "1" if it.get("is_official") else "0",
            "description": str(it.get("short_description") or "")[:240],
        })
    return rows


def collect_docker_hub_images(
    domain: str,
    *,
    extra_hosts: Optional[Iterable[str]] = None,
    fetch_json: Optional[Callable[..., Any]] = None,
    limit: int = MAX_HUB_IMAGES,
) -> List[str]:
    """Public Docker Hub repos matching the target. fetch_json is injectable."""
    do_fetch = fetch_json or _http_json
    seen: Set[str] = set()
    out: List[str] = []
    queries = docker_hub_queries(domain)
    for extra in list(extra_hosts or [])[:6]:
        host = (extra or "").strip().lower()
        if "://" in host:
            host = urlparse(host).hostname or ""
        else:
            host = host.split("/")[0].split(":")[0]
        if host and host not in queries:
            queries.extend(docker_hub_queries(host)[:1])
    for query in queries:
        url = DOCKER_HUB_SEARCH + "?" + urlencode({
            "query": query, "page_size": "25",
        })
        try:
            payload = do_fetch(url, headers={"Accept": "application/json"}, timeout=20)
        except TypeError:
            try:
                payload = do_fetch(url)
            except Exception:
                continue
        except Exception:
            continue
        for row in parse_docker_hub_search(payload):
            name = row["repo_name"]
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
            if len(out) >= limit:
                return out
    return out


def extract_image_refs(text: str) -> List[str]:
    blob = text or ""
    found: List[str] = []
    seen: Set[str] = set()
    for rx in (IMAGE_FROM_RE, IMAGE_REF_RE):
        for m in rx.finditer(blob):
            ref = (m.group(1) or "").strip().strip("'\"")
            if not ref or ref in seen or ref.lower() in {"scratch"}:
                continue
            seen.add(ref)
            found.append(ref)
    return found


def normalize_image_ref(ref: str) -> str:
    text = (ref or "").strip().strip("'\"")
    if text.startswith("docker.io/"):
        text = text[len("docker.io/"):]
    if text.startswith("library/") and "/" in text[8:]:
        pass
    return text


def image_belongs_to_target(ref: str, domain: str) -> bool:
    host = (domain or "").strip().lower().lstrip(".")
    if not host:
        return False
    slug = host.split(".")[0]
    r = (ref or "").lower()
    if host and host.replace(".", "") in r.replace(".", "").replace("/", ""):
        return True
    if host and host in r:
        return True
    if slug and len(slug) >= 3:
        ns = r.split("/", 1)[0]
        name = r.split("/")[-1].split(":")[0]
        if slug == ns or slug == name or slug in ns:
            return True
    return False


def select_images_for_target(
    refs: Iterable[str],
    domain: str,
    *,
    hub_hits: Optional[Iterable[str]] = None,
    limit: int = MAX_IMAGE_SCAN,
) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    forced = {normalize_image_ref(x) for x in (hub_hits or []) if x}
    for raw in list(refs or []) + list(hub_hits or []):
        ref = normalize_image_ref(raw)
        if not ref or ref in seen:
            continue
        name = ref.split("/")[-1].split(":")[0].lower()
        ns = ref.split("/")[0].split(":")[0].lower()
        if ref not in forced and name in SKIP_BASE_IMAGES and (
            "/" not in ref or ns in {"library", "docker.io"}
        ):
            continue
        if ref not in forced and not image_belongs_to_target(ref, domain):
            continue
        seen.add(ref)
        out.append(ref)
        if len(out) >= limit:
            break
    return out


def keep_layer_member(name: str) -> bool:
    n = (name or "").replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    n = n.lstrip("/")
    base = n.rsplit("/", 1)[-1].lower()
    if base in LAYER_KEEP_NAMES or base.startswith(".env"):
        return True
    low = n.lower()
    if any(h in low for h in LAYER_PATH_HINTS) and base.endswith(
        (".json", ".yml", ".yaml", ".toml", ".env", ".txt", ".jsonl")
    ):
        return True
    return False


def _safe_layer_dest(dest: Path, member_name: str) -> Optional[Path]:
    rel = (member_name or "").replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    path = dest / rel
    try:
        path.resolve().relative_to(dest.resolve())
    except (OSError, ValueError):
        return None
    return path


def _extract_cred_from_layer_bytes(data: bytes, dest: Path, remaining: int) -> List[Path]:
    written: List[Path] = []
    if remaining <= 0 or not data:
        return written
    try:
        bio = io.BytesIO(data)
        with tarfile.open(fileobj=bio, mode="r:*") as inner:
            for member in inner.getmembers():
                if remaining - len(written) <= 0:
                    break
                if not member.isfile() or member.size > 2_000_000:
                    continue
                if not keep_layer_member(member.name):
                    continue
                target = _safe_layer_dest(dest, member.name)
                if target is None:
                    continue
                src = inner.extractfile(member)
                if src is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(src.read() or b"")
                written.append(target)
    except Exception:
        return written
    return written


def extract_docker_save_credentials(
    archive: Path,
    dest: Path,
    limit: int = 200,
) -> List[Path]:
    """Pull credential-like files out of a `docker save` tarball (all layers)."""
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    if not archive.is_file():
        return written
    try:
        with tarfile.open(archive, "r:*") as outer:
            for member in outer.getmembers():
                if len(written) >= limit or not member.isfile():
                    continue
                name = (member.name or "").replace("\\", "/")
                handle = outer.extractfile(member)
                if handle is None:
                    continue
                payload = handle.read() or b""
                if name.endswith("/layer.tar") or name.endswith("layer.tar"):
                    written.extend(
                        _extract_cred_from_layer_bytes(
                            payload, dest, limit - len(written)
                        )
                    )
                    continue
                if keep_layer_member(name) and member.size <= 2_000_000:
                    target = _safe_layer_dest(dest, name)
                    if target is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
                    written.append(target)
    except Exception:
        return written
    return written[:limit]


def docker_save_image(ref: str, tar_path: Path, timeout: int = 120) -> Optional[Path]:
    """docker pull + docker save. Returns tar path or None."""
    image = (ref or "").strip()
    if not image:
        return None
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        pull = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            timeout=timeout,
        )
        if pull.returncode != 0:
            return None
        save = subprocess.run(
            ["docker", "save", image, "-o", str(tar_path)],
            capture_output=True,
            timeout=timeout,
        )
        if save.returncode != 0 or not tar_path.is_file():
            return None
        return tar_path
    except Exception:
        return None


def trivy_type_for(rule_id: str, match: str = "") -> str:
    rid = re.sub(r"[^a-z0-9-]", "", (rule_id or "").lower())
    for needle, mapped in TRIVY_TYPE_HINTS:
        if needle in rid:
            if mapped == "github_pat" and (match or "").startswith("github_pat_"):
                return "github_fine_pat"
            if mapped == "stripe_live" and (match or "").startswith("sk_test_"):
                return "stripe_test"
            return mapped
    return "generic_secret"


def findings_from_trivy_secrets(data: Any, image: str = "") -> List[Dict[str, Any]]:
    results = data.get("Results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []
    out: List[Dict[str, Any]] = []
    for block in results:
        if not isinstance(block, dict):
            continue
        target = str(block.get("Target") or image or "")
        for sec in block.get("Secrets") or []:
            if not isinstance(sec, dict):
                continue
            match = str(sec.get("Match") or sec.get("Title") or "").strip()
            if not match:
                continue
            rule = str(sec.get("RuleID") or sec.get("Category") or "")
            out.append({
                "type": trivy_type_for(rule, match),
                "key": match,
                "source_url": target,
                "scanner": "trivy_image",
                "detector": rule,
                "image": image,
                "verified": False,
            })
    return out


def parse_trivy_json(blob: str) -> Any:
    text = (blob or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        return {}


def trivy_image_secrets(ref: str, timeout: int = 180) -> List[Dict[str, Any]]:
    image = (ref or "").strip()
    if not image:
        return []
    try:
        proc = subprocess.run(
            [
                "trivy", "image", "--scanners", "secret",
                "--format", "json", "--quiet", image,
            ],
            capture_output=True,
            timeout=timeout,
        )
        data = parse_trivy_json((proc.stdout or b"").decode("utf-8", errors="replace"))
        return findings_from_trivy_secrets(data, image=image)
    except Exception:
        return []


def scan_public_image_layers(
    refs: List[str],
    dest: Path,
    *,
    pull_and_save: Optional[Callable[[str, Path], Optional[Path]]] = None,
    trivy_scan: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    max_images: int = MAX_IMAGE_SCAN,
) -> Tuple[List[Path], List[Dict[str, Any]]]:
    """Extract baked-in credential files and optional Trivy secret hits."""
    dest.mkdir(parents=True, exist_ok=True)
    files: List[Path] = []
    findings: List[Dict[str, Any]] = []
    saver = pull_and_save if pull_and_save is not None else docker_save_image
    trivy = trivy_scan
    for i, ref in enumerate(list(refs or [])[: max(0, int(max_images))]):
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", ref)[:80] or f"image{i}"
        img_dir = dest / slug
        tar_path = dest / f"{slug}.tar"
        saved = None
        try:
            saved = saver(ref, tar_path)
        except Exception:
            saved = None
        if saved:
            files.extend(extract_docker_save_credentials(Path(saved), img_dir))
            try:
                Path(saved).unlink(missing_ok=True)
            except Exception:
                pass
        if trivy is not None:
            try:
                findings.extend(trivy(ref) or [])
            except Exception:
                pass
    return files, findings


#  AI / MCP verdict scoring 

def mcp_source(finding: Dict[str, Any]) -> bool:
    if finding.get("mcp_config"):
        return True
    src = str(finding.get("source_url") or finding.get("file") or "")
    return bool(MCP_SOURCE_RE.search(src))


def ai_verdict_for(finding: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Prioritize AI-provider and MCP-config leaks.
    GitGuardian 2026: 8.8% of MCP-config secrets were still live — high validate value.
    """
    score = 40
    try:
        score = int(finding.get("confidence") or score)
    except Exception:
        score = 40
    reasons: List[str] = []
    typ = str(finding.get("type") or "")
    if typ in AI_PROVIDER_TYPES:
        score += 12
        reasons.append("ai_provider")
    if mcp_source(finding):
        score += 18
        reasons.append("mcp_config")
    if finding.get("valid"):
        score += 25
        reasons.append("live")
    elif finding.get("validated") and not finding.get("valid"):
        score -= 8
        reasons.append("dead")
    sev = str(finding.get("severity") or "").lower()
    if sev == "critical":
        score += 8
    elif sev == "high":
        score += 4
    if finding.get("image") or str(finding.get("scanner") or "").startswith("trivy"):
        score += 6
        reasons.append("image_layer")
    score = max(0, min(100, score))
    if score >= 80 or (finding.get("valid") and (typ in AI_PROVIDER_TYPES or mcp_source(finding))):
        verdict = "P1"
    elif score >= 60 or typ in AI_PROVIDER_TYPES or mcp_source(finding):
        verdict = "P2"
    else:
        verdict = "P3"
    return score, verdict, reasons


def apply_ai_verdict(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for f in findings or []:
        score, verdict, reasons = ai_verdict_for(f)
        f["ai_score"] = score
        f["ai_verdict"] = verdict
        f["ai_reasons"] = reasons
    return sorted(
        findings or [],
        key=lambda x: (
            0 if x.get("valid") else 1,
            -int(x.get("ai_score") or 0),
            str(x.get("type") or ""),
        ),
    )


#  Proximity / extra pairing  

def pair_generic_findings(findings: List[Dict]) -> List[Dict]:
    """Attach partner values for PayPal / Woo / Mixpanel / Algolia halves."""
    by_src: Dict[str, Dict[str, str]] = {}
    for f in findings or []:
        src = str(f.get("source_url") or f.get("file") or "")
        t = str(f.get("type") or "")
        key = str(f.get("key") or "")
        if not src or not key:
            continue
        by_src.setdefault(src, {})[t] = key

    paired = 0
    for f in findings or []:
        src = str(f.get("source_url") or f.get("file") or "")
        bucket = by_src.get(src) or {}
        t = str(f.get("type") or "")
        for left, right, left_field, right_field in GENERIC_PAIRS:
            if t == left and not f.get(left_field) and bucket.get(right):
                f[left_field] = bucket[right]
                f["paired"] = True
                paired += 1
            elif t == right and not f.get(right_field) and bucket.get(left):
                f[right_field] = bucket[left]
                f["paired"] = True
                paired += 1
    if paired:
        for f in findings or []:
            if f.get("paired"):
                try:
                    f["confidence"] = min(99, int(f.get("confidence") or 50) + 8)
                except Exception:
                    f["confidence"] = 60
    return findings


def proximity_partners(content: str, a: str, b: str, window: int = 240) -> bool:
    """True if both strings appear within `window` characters."""
    if not content or not a or not b:
        return False
    ia = content.find(a)
    ib = content.find(b)
    if ia < 0 or ib < 0:
        return False
    return abs(ia - ib) <= window


#  CI defaults + crt.sh / certstream 

CI_SKIP_FLAGS = (
    "skip_chaos", "skip_httpx", "skip_gau", "skip_discovery", "skip_intel",
    "skip_crtsh", "skip_amass", "skip_assetfinder", "skip_findomain",
    "skip_dnsx", "skip_naabu", "skip_whatweb", "skip_gowitness",
    "skip_hakrawler", "skip_paramspider", "skip_sensitive_paths",
    "skip_wayback_bodies", "skip_js_history", "skip_jsleak", "skip_code_search",
    "skip_docker_hub", "skip_image_layers", "skip_buckets",
    "no_notify",
)


def apply_ci_defaults(args: Any) -> Any:
    """Shift-left: scan local repo, skip live recon, keep SARIF + fail-on-valid."""
    for name in CI_SKIP_FLAGS:
        if hasattr(args, name):
            setattr(args, name, True)
    if not getattr(args, "repo", None):
        args.repo = str(Path.cwd())
    if not (getattr(args, "domain", None) or "").strip():
        args.domain = "local"
    if not getattr(args, "sarif", None):
        args.sarif = "results.sarif"
    return args


def crtsh_hosts_from_payload(data: Any) -> List[str]:
    rows = data if isinstance(data, list) else []
    hosts: Set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = str(row.get(field) or "")
            for part in re.split(r"[\s,]+", raw):
                h = part.strip().lower().lstrip("*.")
                if h and "." in h:
                    hosts.add(h)
    return sorted(hosts)


def certstream_domains_from_message(msg: Any) -> List[str]:
    if isinstance(msg, str):
        try:
            msg = json.loads(msg)
        except Exception:
            return []
    if not isinstance(msg, dict):
        return []
    data = msg.get("data") if isinstance(msg.get("data"), dict) else msg
    leaf = data.get("leaf_cert") if isinstance(data.get("leaf_cert"), dict) else {}
    names = leaf.get("all_domains") or []
    extra = data.get("all_domains") or []
    out: List[str] = []
    for n in list(names) + list(extra):
        h = str(n or "").strip().lower().lstrip("*.")
        if h:
            out.append(h)
    return out


def hosts_matching_domain(hosts: Iterable[str], domain: str) -> List[str]:
    d = (domain or "").strip().lower().lstrip(".")
    if not d:
        return []
    out: List[str] = []
    for h in hosts:
        h = (h or "").strip().lower().lstrip("*.")
        if h == d or h.endswith("." + d):
            out.append(h)
    return out


def merge_unique(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in seq:
        s = (item or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out
