"""Wave-3 sources: code search, mobile apps, buckets, OpenAPI, SQLite, ETag, CT."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urljoin, urlparse
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
MAX_CI_REPOS = 8
MAX_CI_RUNS = 5
MAX_CI_JOBS = 8
MAX_CI_ARTIFACTS = 6
MAX_CI_BYTES = 2_000_000
MAX_CI_ZIP_BYTES = 8_000_000
MAX_PASTE_HITS = 40
MAX_PASTE_FETCH = 25
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{8,}")
OPENAPI_HINT_RE = re.compile(r'"(?:swagger|openapi)"\s*:')
POSTMAN_HINT_RE = re.compile(r'"_postman_id"|info"\s*:\s*\{[^}]{0,200}"schema".*postman', re.I | re.S)
MOBILE_KEEP_SUFFIX = {
    ".js", ".json", ".xml", ".html", ".htm", ".txt", ".properties",
    ".plist", ".env", ".yml", ".yaml", ".cfg", ".ini", ".gradle",
    ".bundle", ".jsbundle", ".map", ".kt", ".java", ".smali", ".dart.js",
    ".xcconfig", ".mobileprovision", ".entitlements", ".ts",
}
MOBILE_KEEP_NAMES = {
    "androidmanifest.xml", "google-services.json",
    "awsconfiguration.json", "network_security_config.xml", "info.plist",
    "strings.xml", "config.json", "firebase-config.json",
    "googleservice-info.plist", "assetmanifest.json", "assetmanifest.bin",
    "app.json", "eas.json", "index.android.bundle", "main.jsbundle",
    "kernel_blob.bin", "flutter_assets",
    "capacitor.config.json", "capacitor.config.ts", "sentry.properties",
    "react-native.config.js", "app.config.js", "app.config.ts",
    ".env.production", ".env.staging", "google-services.json",
}
MOBILE_PKG_SUFFIX = {".apk", ".xapk", ".apkm", ".ipa", ".aab", ".apks"}

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


def _http_bytes(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 25,
    max_bytes: int = MAX_CI_ZIP_BYTES,
) -> Tuple[int, bytes, Dict[str, str]]:
    hdrs = {"User-Agent": UA, **(headers or {})}
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(max(1, int(max_bytes)) + 1)
            meta = {k.lower(): v for k, v in (resp.headers.items() if resp.headers else [])}
            return int(resp.status), body[:max_bytes], meta
    except HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_bytes) or b""
        except Exception:
            pass
        meta = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return int(exc.code), body, meta
    except (URLError, OSError, TimeoutError):
        return 0, b"", {}


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


#  CI logs / build artifacts (GitHub Actions + GitLab jobs) 

GITHUB_API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4"
PASTEBIN_SCRAPE = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_SCRAPE_ITEM = "https://scrape.pastebin.com/api_scrape_item.php"
PASTEBIN_RAW = "https://pastebin.com/raw/"
PSBDMP_SEARCH = "https://psbdmp.ws/api/v3/search/"
GIST_PUBLIC = "https://api.github.com/gists/public"
GIST_SEARCH = "https://gist.github.com/search"
GHOSTBIN_SEARCH = (
    "https://ghostbin.com/search",
    "https://ghostbin.co/search",
)
PASTE_PREFIXES = (
    "AKIA", "ASIA", "sk-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk_live_",
    "sk_test_", "ghp_", "github_pat_", "glpat-", "hf_", "xoxb-", "xoxp-",
    "xoxa-", "AIza", "SG.", "npm_",
)
CI_LOG_SUFFIX = {
    ".log", ".txt", ".env", ".json", ".yml", ".yaml", ".xml", ".properties",
    ".toml", ".ini", ".cfg", ".conf", ".pem", ".out",
}
GIST_HREF_RE = re.compile(
    r'href="(?:https://gist\.github\.com)?/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([a-fA-F0-9]{20,40})"',
)
GHOSTBIN_HREF_RE = re.compile(
    r'href="(?:https://ghostbin\.(?:com|co))?/(?:paste/)?([A-Za-z0-9]{4,16})"',
)
FORGE_GITHUB_RE = re.compile(
    r"(?:github\.com[:/]|raw\.githubusercontent\.com/)(?P<owner>[^/\s]+)(?:/(?P<repo>[^/\s.#?]+))?",
    re.I,
)


def _safe_rel_write(dest: Path, rel: str, data: bytes) -> Optional[Path]:
    name = re.sub(r"[^a-zA-Z0-9._/-]", "_", (rel or "file").replace("\\", "/"))
    name = name.replace("..", "_").lstrip("/")
    if not name:
        return None
    path = dest / name
    try:
        path.resolve().relative_to(dest.resolve())
    except (OSError, ValueError):
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def keep_ci_member(name: str) -> bool:
    n = (name or "").replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    base = n.rsplit("/", 1)[-1].lower()
    if base.startswith(".env") or base in {"credentials", "id_rsa", "mcp.json"}:
        return True
    suffix = Path(base).suffix
    if suffix in CI_LOG_SUFFIX or base.endswith(".log"):
        return True
    # GitHub Actions log ZIPs often use "1_Build" with no extension
    return not suffix


def extract_zip_scan_files(blob: bytes, dest: Path, limit: int = 80) -> List[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    if not blob:
        return written
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        text_path = dest / "artifact.bin.txt"
        try:
            text_path.write_bytes(blob[:MAX_CI_BYTES])
            written.append(text_path)
        except Exception:
            pass
        return written
    with zf:
        for info in zf.infolist()[:400]:
            if info.is_dir() or info.file_size > MAX_CI_BYTES:
                continue
            if not keep_ci_member(info.filename):
                continue
            try:
                data = zf.read(info.filename)
            except Exception:
                continue
            path = _safe_rel_write(dest, info.filename, data)
            if path:
                written.append(path)
            if len(written) >= limit:
                break
    return written


def parse_forge_repo(url: str) -> Optional[Dict[str, str]]:
    text = (url or "").strip()
    if not text:
        return None
    if text.startswith("git@"):
        text = text.replace(":", "/", 1).replace("git@", "https://", 1)
    if text.endswith(".git"):
        text = text[:-4]
    gh = FORGE_GITHUB_RE.search(text)
    if gh:
        owner = (gh.group("owner") or "").strip()
        repo = (gh.group("repo") or "").strip().rstrip(".git")
        if owner and owner.lower() not in {"http:", "https:"}:
            return {"forge": "github", "owner": owner, "repo": repo}
    gl = re.search(r"gitlab\.com[:/](?P<rest>.+)", text, re.I)
    if gl:
        rest = (gl.group("rest") or "").split("?", 1)[0].split("#", 1)[0]
        rest = rest.replace("\\", "/")
        if rest.endswith(".git"):
            rest = rest[:-4]
        if "/-/" in rest:
            rest = rest.split("/-/", 1)[0]
        rest = rest.strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) >= 2:
            return {
                "forge": "gitlab",
                "owner": parts[0],
                "repo": "/".join(parts[1:]),
                "project": "/".join(parts),
            }
    return None


def repos_from_code_urls(urls: Iterable[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for raw in urls or []:
        parsed = parse_forge_repo(raw)
        if not parsed:
            continue
        key = f"{parsed.get('forge')}:{parsed.get('owner')}:{parsed.get('repo')}"
        if key in seen or not parsed.get("repo"):
            continue
        seen.add(key)
        out.append(parsed)
    return out[:MAX_CI_REPOS]


def parse_github_org_repos(data: Any) -> List[Dict[str, str]]:
    items = data if isinstance(data, list) else []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        full = str(it.get("full_name") or "")
        if "/" not in full:
            continue
        owner, repo = full.split("/", 1)
        if it.get("private"):
            continue
        rows.append({"forge": "github", "owner": owner, "repo": repo})
    return rows


def parse_github_workflow_runs(data: Any) -> List[Dict[str, str]]:
    items = data.get("workflow_runs") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        rid = str(it.get("id") or "")
        if not rid:
            continue
        rows.append({
            "id": rid,
            "name": str(it.get("name") or it.get("display_title") or ""),
            "status": str(it.get("status") or ""),
            "conclusion": str(it.get("conclusion") or ""),
            "html_url": str(it.get("html_url") or ""),
        })
    return rows


def parse_github_artifacts(data: Any) -> List[Dict[str, str]]:
    items = data.get("artifacts") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict) or it.get("expired"):
            continue
        aid = str(it.get("id") or "")
        if not aid:
            continue
        size = int(it.get("size_in_bytes") or 0)
        if size > MAX_CI_ZIP_BYTES:
            continue
        rows.append({
            "id": aid,
            "name": str(it.get("name") or "artifact"),
            "size": str(size),
        })
    return rows


def parse_gitlab_jobs(data: Any) -> List[Dict[str, str]]:
    items = data if isinstance(data, list) else []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        jid = str(it.get("id") or "")
        if not jid:
            continue
        art = it.get("artifacts_file") if isinstance(it.get("artifacts_file"), dict) else {}
        rows.append({
            "id": jid,
            "name": str(it.get("name") or it.get("stage") or "job"),
            "status": str(it.get("status") or ""),
            "has_artifacts": "1" if art or it.get("artifacts") else "0",
        })
    return rows


def collect_ci_targets(
    *,
    repo_url: str = "",
    github_org: str = "",
    code_urls: Optional[Iterable[str]] = None,
    fetch_json: Optional[Callable[..., Any]] = None,
    github_token: str = "",
) -> List[Dict[str, str]]:
    """Repos to pull CI logs from: --repo, --github-org, and code-search hits."""
    do_fetch = fetch_json or _http_json
    targets: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def _add(row: Optional[Dict[str, str]]) -> None:
        if not row or not row.get("repo"):
            return
        key = f"{row.get('forge')}:{row.get('owner')}:{row.get('repo')}"
        if key in seen:
            return
        seen.add(key)
        targets.append(row)

    _add(parse_forge_repo(repo_url))
    for row in repos_from_code_urls(code_urls or []):
        _add(row)

    org = (github_org or "").strip()
    owners: List[str] = []
    if org:
        owners.append(org)
    for row in targets:
        if row.get("forge") == "github":
            own = str(row.get("owner") or "")
            if own and own not in owners:
                owners.append(own)
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    def _list_public_repos(name: str) -> List[Dict[str, str]]:
        listed: List[Dict[str, str]] = []
        for url in (
            f"{GITHUB_API}/orgs/{quote(name)}/repos?type=public&per_page=20",
            f"{GITHUB_API}/users/{quote(name)}/repos?type=owner&per_page=20",
        ):
            try:
                payload = do_fetch(url, headers=headers, timeout=20)
            except TypeError:
                try:
                    payload = do_fetch(url)
                except Exception:
                    payload = []
            except Exception:
                payload = []
            listed = parse_github_org_repos(payload)
            if listed:
                return listed
        return listed

    for org_name in owners[:3]:
        if len(targets) >= MAX_CI_REPOS:
            break
        for row in _list_public_repos(org_name):
            _add(row)
            if len(targets) >= MAX_CI_REPOS:
                break
    return targets[:MAX_CI_REPOS]


def collect_ci_log_files(
    targets: List[Dict[str, str]],
    dest: Path,
    *,
    fetch_json: Optional[Callable[..., Any]] = None,
    fetch_bytes: Optional[Callable[..., Any]] = None,
    github_token: str = "",
    gitlab_token: str = "",
) -> List[Path]:
    """Download recent public Actions/GitLab job logs and artifacts into dest."""
    do_fetch = fetch_json or _http_json
    do_bytes = fetch_bytes or _http_bytes
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    gh_headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        gh_headers["Authorization"] = f"Bearer {github_token}"
    gl_headers = {"Accept": "application/json"}
    if gitlab_token:
        gl_headers["PRIVATE-TOKEN"] = gitlab_token

    def _pull_zip(url: str, headers: Dict[str, str], subdir: Path) -> None:
        try:
            status, blob, _meta = do_bytes(url, headers=headers, timeout=25, max_bytes=MAX_CI_ZIP_BYTES)
        except TypeError:
            try:
                got = do_bytes(url)
                if isinstance(got, tuple) and len(got) >= 2:
                    status, blob = int(got[0] or 0), got[1] or b""
                else:
                    return
            except Exception:
                return
        except Exception:
            return
        if status not in (200, 302) or not blob:
            return
        if blob[:2] == b"PK":
            written.extend(extract_zip_scan_files(blob, subdir))
        else:
            path = _safe_rel_write(subdir, "log.txt", blob[:MAX_CI_BYTES])
            if path:
                written.append(path)

    for target in (targets or [])[:MAX_CI_REPOS]:
        forge = target.get("forge")
        owner = target.get("owner") or ""
        repo = target.get("repo") or ""
        if not owner or not repo:
            continue
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", f"{owner}_{repo.replace('/', '_')}")[:80]
        sub = dest / slug
        sub.mkdir(parents=True, exist_ok=True)
        if forge == "github":
            runs_url = (
                f"{GITHUB_API}/repos/{quote(owner)}/{quote(repo)}/actions/runs"
                f"?per_page={MAX_CI_RUNS}&status=completed"
            )
            try:
                payload = do_fetch(runs_url, headers=gh_headers, timeout=20)
            except TypeError:
                try:
                    payload = do_fetch(runs_url)
                except Exception:
                    payload = {}
            except Exception:
                payload = {}
            for run in parse_github_workflow_runs(payload)[:MAX_CI_RUNS]:
                rid = run["id"]
                log_url = f"{GITHUB_API}/repos/{quote(owner)}/{quote(repo)}/actions/runs/{rid}/logs"
                _pull_zip(log_url, {**gh_headers, "Accept": "*/*"}, sub / f"run_{rid}")
                art_url = f"{GITHUB_API}/repos/{quote(owner)}/{quote(repo)}/actions/runs/{rid}/artifacts"
                try:
                    arts = do_fetch(art_url, headers=gh_headers, timeout=20)
                except TypeError:
                    try:
                        arts = do_fetch(art_url)
                    except Exception:
                        arts = {}
                except Exception:
                    arts = {}
                for art in parse_github_artifacts(arts)[:MAX_CI_ARTIFACTS]:
                    zip_url = (
                        f"{GITHUB_API}/repos/{quote(owner)}/{quote(repo)}"
                        f"/actions/artifacts/{art['id']}/zip"
                    )
                    _pull_zip(zip_url, {**gh_headers, "Accept": "*/*"}, sub / f"art_{art['id']}")
        elif forge == "gitlab":
            project = target.get("project") or f"{owner}/{repo}"
            pid = quote(project, safe="")
            jobs_url = f"{GITLAB_API}/projects/{pid}/jobs?per_page={MAX_CI_JOBS}"
            try:
                payload = do_fetch(jobs_url, headers=gl_headers, timeout=20)
            except TypeError:
                try:
                    payload = do_fetch(jobs_url)
                except Exception:
                    payload = []
            except Exception:
                payload = []
            for job in parse_gitlab_jobs(payload)[:MAX_CI_JOBS]:
                jid = job["id"]
                trace_url = f"{GITLAB_API}/projects/{pid}/jobs/{jid}/trace"
                try:
                    status, blob, _meta = do_bytes(
                        trace_url, headers=gl_headers, timeout=20, max_bytes=MAX_CI_BYTES
                    )
                except TypeError:
                    try:
                        got = do_bytes(trace_url)
                        status, blob = int(got[0] or 0), got[1] or b""
                    except Exception:
                        continue
                except Exception:
                    continue
                if status == 200 and blob:
                    path = _safe_rel_write(sub, f"job_{jid}.log", blob[:MAX_CI_BYTES])
                    if path:
                        written.append(path)
                if job.get("has_artifacts") == "1":
                    art_url = f"{GITLAB_API}/projects/{pid}/jobs/{jid}/artifacts"
                    _pull_zip(art_url, gl_headers, sub / f"job_{jid}_artifacts")
    return written


#  Paste sites (Pastebin / Gists / Ghostbin) 

def paste_search_terms(domain: str) -> List[str]:
    host = (domain or "").strip().lower().lstrip(".")
    if not host:
        return []
    terms = [host]
    slug = host.split(".")[0]
    if slug and slug != host and len(slug) >= 3:
        terms.append(slug)
    for prefix in ("AKIA", "sk-proj-", "sk-ant-", "ghp_", "hf_"):
        terms.append(f"{host} {prefix}")
    return terms[:8]


def paste_blob_matches(text: str, domain: str) -> bool:
    blob = text or ""
    host = (domain or "").strip().lower().lstrip(".")
    if host and host.lower() in blob.lower():
        return True
    return any(p in blob for p in PASTE_PREFIXES)


def parse_pastebin_scrape(data: Any) -> List[Dict[str, str]]:
    items = data if isinstance(data, list) else []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        key = str(it.get("key") or it.get("paste_key") or "").strip()
        if not key:
            continue
        rows.append({
            "id": key,
            "title": str(it.get("title") or ""),
            "raw_url": str(it.get("scrape_url") or (PASTEBIN_RAW + key)),
        })
    return rows


def parse_psbdmp_search(data: Any) -> List[Dict[str, str]]:
    if isinstance(data, dict):
        items = data.get("data") or data.get("result") or data.get("dumps") or []
    else:
        items = data
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    for it in items:
        if isinstance(it, str):
            pid = it.strip()
            snippet = ""
        elif isinstance(it, dict):
            pid = str(it.get("id") or it.get("key") or "").strip()
            snippet = str(it.get("text") or it.get("tags") or "")
        else:
            continue
        if not pid:
            continue
        rows.append({
            "id": pid,
            "title": snippet[:200],
            "raw_url": PASTEBIN_RAW + pid,
            "dump_url": f"https://psbdmp.ws/dump/{pid}",
        })
    return rows


def parse_gist_list(data: Any) -> List[Dict[str, str]]:
    items = data if isinstance(data, list) else []
    rows: List[Dict[str, str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        gid = str(it.get("id") or "").strip()
        if not gid:
            continue
        files = it.get("files") if isinstance(it.get("files"), dict) else {}
        names = " ".join(str(n) for n in files.keys())
        desc = str(it.get("description") or "")
        raws = []
        for meta in files.values():
            if isinstance(meta, dict) and meta.get("raw_url"):
                raws.append(str(meta["raw_url"]))
        rows.append({
            "id": gid,
            "title": f"{desc} {names}".strip(),
            "html_url": str(it.get("html_url") or f"https://gist.github.com/{gid}"),
            "raw_url": raws[0] if raws else "",
            "api_url": str(it.get("url") or f"{GITHUB_API}/gists/{gid}"),
        })
    return rows


def parse_gist_detail(data: Any) -> List[Dict[str, str]]:
    if not isinstance(data, dict):
        return []
    files = data.get("files") if isinstance(data.get("files"), dict) else {}
    out: List[Dict[str, str]] = []
    for name, meta in files.items():
        if not isinstance(meta, dict):
            continue
        content = str(meta.get("content") or "")
        raw = str(meta.get("raw_url") or "")
        out.append({
            "filename": str(name),
            "content": content,
            "raw_url": raw,
            "truncated": "1" if meta.get("truncated") else "0",
        })
    return out


def parse_gist_search_html(html: str) -> List[str]:
    ids: List[str] = []
    seen: Set[str] = set()
    for _user, gid in GIST_HREF_RE.findall(html or ""):
        if gid not in seen:
            seen.add(gid)
            ids.append(gid)
    return ids[:MAX_PASTE_HITS]


def parse_ghostbin_search_html(html: str) -> List[str]:
    ids: List[str] = []
    seen: Set[str] = set()
    for gid in GHOSTBIN_HREF_RE.findall(html or ""):
        if gid.lower() in {"search", "paste", "login", "static"}:
            continue
        if gid not in seen:
            seen.add(gid)
            ids.append(gid)
    return ids[:20]


def collect_paste_files(
    domain: str,
    dest: Path,
    *,
    fetch_json: Optional[Callable[..., Any]] = None,
    fetch_text: Optional[Callable[..., Any]] = None,
    fetch_bytes: Optional[Callable[..., Any]] = None,
    github_token: str = "",
    use_pastebin_scrape: bool = True,
) -> List[Path]:
    """Keyword-search paste sites for the target domain and known key prefixes."""
    do_fetch = fetch_json or _http_json
    do_text = fetch_text or _http_text
    do_bytes = fetch_bytes or _http_bytes
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    host = (domain or "").strip().lower().lstrip(".")
    if not host:
        return written
    gh_headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        gh_headers["Authorization"] = f"Bearer {github_token}"

    def _write(rel: str, blob: str) -> None:
        if not paste_blob_matches(blob, host):
            return
        path = _safe_rel_write(dest, rel, blob.encode("utf-8", errors="replace")[:MAX_CI_BYTES])
        if path:
            written.append(path)

    def _get_json(url: str, headers: Optional[Dict[str, str]] = None) -> Any:
        try:
            return do_fetch(url, headers=headers or {}, timeout=20)
        except TypeError:
            try:
                return do_fetch(url)
            except Exception:
                return None
        except Exception:
            return None

    def _get_text(url: str, headers: Optional[Dict[str, str]] = None) -> str:
        try:
            got = do_text(url, headers=headers or {}, timeout=15)
            if isinstance(got, tuple) and len(got) >= 2:
                return str(got[1] or "")
            return str(got or "")
        except TypeError:
            try:
                got = do_text(url)
                return str(got[1] if isinstance(got, tuple) else got or "")
            except Exception:
                return ""
        except Exception:
            return ""

    def _get_bytes(url: str) -> bytes:
        try:
            got = do_bytes(url, headers={}, timeout=15, max_bytes=MAX_CI_BYTES)
            if isinstance(got, tuple) and len(got) >= 2:
                return got[1] or b""
            return b""
        except TypeError:
            try:
                got = do_bytes(url)
                return got[1] if isinstance(got, tuple) else b""
            except Exception:
                return b""
        except Exception:
            return b""

    # Pastebin scraping API (Pro + linked IP) — recent pastes, then prefix/domain filter
    if use_pastebin_scrape:
        scrape = _get_json(PASTEBIN_SCRAPE + "?limit=100")
        for row in parse_pastebin_scrape(scrape)[:MAX_PASTE_FETCH]:
            raw = _get_text(row["raw_url"])
            if not raw:
                item_url = f"{PASTEBIN_SCRAPE_ITEM}?i={quote(row['id'])}"
                raw = _get_text(item_url)
            if raw:
                _write(f"pastebin_{row['id']}.txt", raw)
            if len(written) >= MAX_PASTE_HITS:
                return written

    # psbdmp.ws — keyword search of Pastebin dumps (no Pro account)
    for term in paste_search_terms(host):
        payload = _get_json(PSBDMP_SEARCH + quote(term, safe=""))
        for row in parse_psbdmp_search(payload)[:12]:
            body = _get_text(row["raw_url"]) or _get_text(row.get("dump_url") or "")
            if not body and row.get("title"):
                body = row["title"]
            if body:
                _write(f"psbdmp_{row['id']}.txt", body)
            if len(written) >= MAX_PASTE_HITS:
                return written

    # GitHub Gists — public timeline + gist.github.com search (code search skips gists)
    gists = parse_gist_list(_get_json(GIST_PUBLIC + "?per_page=50", gh_headers) or [])
    gist_ids = [g["id"] for g in gists if paste_blob_matches(g.get("title") or "", host)]
    for term in paste_search_terms(host)[:2]:
        html = _get_text(GIST_SEARCH + "?" + urlencode({"q": f"{term} (AKIA OR sk- OR ghp_ OR hf_)"}))
        gist_ids.extend(parse_gist_search_html(html))
    seen_g: Set[str] = set()
    for gid in gist_ids:
        if gid in seen_g or len(written) >= MAX_PASTE_HITS:
            break
        seen_g.add(gid)
        detail = _get_json(f"{GITHUB_API}/gists/{gid}", gh_headers) or {}
        for file_row in parse_gist_detail(detail):
            content = file_row.get("content") or ""
            if file_row.get("truncated") == "1" and file_row.get("raw_url"):
                content = _get_text(file_row["raw_url"]) or content
            if content:
                _write(f"gist_{gid}_{file_row.get('filename') or 'file'}.txt", content)

    # Ghostbin — often offline in 2026; probe search HTML and ignore empty/dead hosts
    for base in GHOSTBIN_SEARCH:
        html = _get_text(base + "?" + urlencode({"q": host}))
        if not html or "not found" in html.lower()[:400]:
            continue
        for gid in parse_ghostbin_search_html(html)[:8]:
            raw = _get_text(f"https://ghostbin.com/paste/{gid}/raw") or _get_text(
                f"https://ghostbin.co/paste/{gid}/raw"
            )
            if raw:
                _write(f"ghostbin_{gid}.txt", raw)
    return written[:MAX_PASTE_HITS]


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
    written.extend(decompile_mobile_archive(archive, dest))
    return written


def _collect_decompiled_text(root: Path, limit: int = 200) -> List[Path]:
    out: List[Path] = []
    if not root.is_dir():
        return out
    keep_suffix = MOBILE_KEEP_SUFFIX | {".java", ".kt", ".smali", ".xml", ".json"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in keep_suffix and path.name.lower() not in MOBILE_KEEP_NAMES:
            continue
        if path.stat().st_size > 4_000_000:
            continue
        out.append(path)
        if len(out) >= limit:
            break
    return out


def decompile_mobile_archive(archive: Path, dest: Path) -> List[Path]:
    """Optional jadx / apktool / plutil — user does not unzip by hand."""
    archive = Path(archive)
    dest = Path(dest)
    extra: List[Path] = []
    suffix = archive.suffix.lower()
    if suffix not in {".apk", ".xapk", ".apkm", ".aab", ".apks", ".ipa"}:
        return extra

    def _run(cmd: List[str], timeout: int = 180) -> bool:
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
        return int(proc.returncode or 0) == 0

    android_pkg = suffix in {".apk", ".xapk", ".apkm", ".aab", ".apks"}
    jadx = shutil.which("jadx")
    if jadx and android_pkg:
        out = dest / "_jadx"
        if _run([jadx, "-d", str(out), "-q", "--no-res", str(archive)]):
            extra.extend(_collect_decompiled_text(out))
    apktool = shutil.which("apktool")
    if apktool and android_pkg:
        out = dest / "_apktool"
        if _run([apktool, "d", "-f", "-o", str(out), str(archive)]):
            extra.extend(_collect_decompiled_text(out))
    plutil = shutil.which("plutil")
    if plutil:
        for plist in dest.rglob("*.plist"):
            try:
                if plist.stat().st_size > 2_000_000:
                    continue
                xml_out = plist.with_suffix(plist.suffix + ".xml.txt")
                if _run([plutil, "-convert", "xml1", "-o", str(xml_out), str(plist)]):
                    extra.append(xml_out)
            except OSError:
                continue
    return extra


PACKAGE_ID_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+(?:@[\w.+-]+)?$"
)
MAX_PLAY_PACKAGES = 8


def parse_package_id(value: str) -> str:
    """Android application id, optional apkeep `@version` suffix."""
    text = (value or "").strip()
    if not text or not PACKAGE_ID_RE.match(text):
        return ""
    return text


def parse_package_ids(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for raw in values or []:
        for part in re.split(r"[\s,;]+", str(raw or "")):
            pkg = parse_package_id(part)
            if not pkg or pkg.lower() in seen:
                continue
            seen.add(pkg.lower())
            out.append(pkg)
            if len(out) >= MAX_PLAY_PACKAGES:
                return out
    return out


def list_downloaded_apks(directory: Path) -> List[Path]:
    root = Path(directory)
    if not root.is_dir():
        return []
    found: List[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in MOBILE_PKG_SUFFIX:
            found.append(path)
    return found


def apkeep_cmd(package: str, dest: Path) -> List[str]:
    return ["apkeep", "-a", package, str(dest)]


def gplaycli_cmd(package: str, dest: Path) -> List[str]:
    app_id = package.split("@", 1)[0]
    return ["gplaycli", "-d", app_id, "-y", "-f", str(dest)]


def fetch_android_packages(
    packages: Iterable[str],
    dest: Path,
    *,
    run: Optional[Callable[..., Tuple[int, bytes]]] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
    docker_fallback: bool = False,
    timeout: int = 180,
) -> List[Path]:
    """
    Download Play-store package ids with apkeep (preferred) or gplaycli.
    Does not hit the network when `run` / `which` are injected in tests.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    ids = parse_package_ids(packages)
    if not ids:
        return []
    do_which = which or shutil.which
    do_run = run
    have_apkeep = bool(do_which("apkeep"))
    have_gplay = bool(do_which("gplaycli"))
    have_docker = bool(docker_fallback and do_which("docker"))
    if not have_apkeep and not have_gplay and not have_docker:
        return []
    written: List[Path] = []
    before = {str(p.resolve()) for p in list_downloaded_apks(dest)}

    def _exec(cmd: List[str]) -> int:
        if do_run is not None:
            try:
                rc, _out = do_run(cmd, timeout=timeout)
            except TypeError:
                rc, _out = do_run(cmd)
            return int(rc or 0)
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return int(proc.returncode or 0)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return 1

    for pkg in ids:
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", pkg)[:80]
        out_dir = dest / slug
        out_dir.mkdir(parents=True, exist_ok=True)
        cmds: List[List[str]] = []
        if have_apkeep:
            cmds.append(apkeep_cmd(pkg, out_dir))
        if have_gplay:
            cmds.append(gplaycli_cmd(pkg, out_dir))
        if have_docker:
            cmds.append([
                "docker", "run", "--rm",
                "-v", f"{out_dir.resolve()}:/out",
                "ghcr.io/efforg/apkeep:latest",
                "-a", pkg, "/out",
            ])
        for cmd in cmds:
            if _exec(cmd) == 0 and list_downloaded_apks(out_dir):
                break
        for path in list_downloaded_apks(out_dir):
            key = str(path.resolve())
            if key not in before:
                written.append(path)
                before.add(key)
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
    Rule-based priority for AI-vendor keys and MCP-config leaks. Not an LLM call.
    P1: live AI/MCP credential, or score >= 80.
    P2: AI/MCP hit (unverified/dead) or score >= 60.
    P3: everything else.
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
        f["priority"] = verdict
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
    "skip_ci_logs", "skip_pastes",
    "no_notify",
)


# Domain on an Apps-only run only names the workspace and reports.
# Host enum, resolution, port scan, and live fingerprinting stay off.
APPS_ONLY_SKIP_FLAGS = (
    "skip_chaos",
    "skip_subfinder",
    "skip_amass",
    "skip_assetfinder",
    "skip_findomain",
    "skip_dnsx",
    "skip_naabu",
    "skip_httpx",
    "skip_whatweb",
    "skip_gowitness",
    "skip_gau",
    "skip_discovery",
    "skip_hakrawler",
    "skip_paramspider",
    "skip_intel",
    "skip_crtsh",
    "skip_jsleak",
    "skip_wayback_bodies",
    "skip_js_history",
    "skip_sensitive_paths",
    "skip_code_search",
    "skip_ci_logs",
    "skip_pastes",
    "skip_docker_hub",
    "skip_image_layers",
    "skip_buckets",
    "skip_openapi",
)


def apply_apps_only_options(opts: Dict[str, Any]) -> Dict[str, Any]:
    """Turn off live recon so an APK/IPA scan does not crawl the workspace domain."""
    for name in APPS_ONLY_SKIP_FLAGS:
        opts[name] = True
    opts["spray"] = False
    return opts


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
