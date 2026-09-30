import argparse
import asyncio
import base64
import csv
import fnmatch
import hmac
import html
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import hashlib
import threading
import time
import urllib.request
import urllib.error
import smtplib
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, nullcontext
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, quote, urlencode, unquote

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  
    YAML_AVAILABLE = False

import reconpipe_addons as addons
import reconpipe_wave3 as wave3
import reconpipe_llm as rp_llm
import reconpipe_reports as rp_reports

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception  
    BotoCoreError = Exception

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# Secret patterns / validators / confidence — loaded from config.yaml (+ --config merges)
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

@dataclass
class ValidatorSpec:
    """Typed validator definition (replaces dict-of-dicts coupling bugs)."""
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Tuple[str, str]] = None
    json_body: Optional[Dict[str, Any]] = None
    valid_codes: List[int] = field(default_factory=lambda: [200])
    invalid_codes: List[int] = field(default_factory=lambda: [401])
    restricted_codes: List[int] = field(default_factory=list)
    restricted_body_reasons: List[str] = field(default_factory=list)
    notes: Dict[int, str] = field(default_factory=dict)
    check_body: bool = False
    body_ok_field: str = "ok"
    skip_reason: str = ""
    needs_domain: bool = False
    jwt_inspect: bool = False
    aws_sts: bool = False
    twilio_pair: bool = False
    slack_webhook_probe: bool = False
    webhook: bool = False
    google_api_spray: bool = False
    azure_sas_inspect: bool = False
    gcp_sa_inspect: bool = False
    uri_inspect: bool = False
    needs_vault: bool = False
    needs_grafana: bool = False
    needs_n8n: bool = False

    def note_for(self, status: int, default: str = "") -> str:
        if status in self.notes:
            return self.notes[status]
        return default or f"VALID (HTTP {status})"


PATTERNS: Dict[str, str] = {}
VALIDATORS: Dict[str, ValidatorSpec] = {}
CONFIDENCE: Dict[str, int] = {}
INFORMATIONAL_TYPES: frozenset = frozenset()
INFORMATIONAL_NOTES: Dict[str, str] = {}
EXPOSURE_TYPES: frozenset = frozenset()
EXPOSURE_NOTES: Dict[str, str] = {}
MIN_CONFIDENCE = 30
SCOPE_INCLUDE: List[str] = []
SCOPE_EXCLUDE: List[str] = []
SEVERITY_MAP: Dict[str, str] = {}
REVOCATION_URLS: Dict[str, str] = {}
COMPLIANCE_TAGS: Dict[str, List[str]] = {}
SCAN_PROXY = ""
SCAN_PROXY_AUTH = ""
SCAN_EXTRA_HEADERS: Dict[str, str] = {}
SCAN_POLITE_DELAY = 0.0
SCAN_RPS = 0.0
SCAN_CREDENTIALS: Optional["ScanCredentials"] = None
DOCKER_FALLBACK = False
FINDINGS_STREAM: Optional["FindingsStream"] = None
PIPELINE_METRICS: Optional["PipelineMetrics"] = None
_POLITE_LOCK = threading.Lock()
_POLITE_LAST = 0.0
SCAN_WAYBACK_BODIES = True
SCAN_JS_HISTORY = True
SCAN_JS_HISTORY_MAX = 15
SCAN_SOURCEMAPS = True
SCAN_PUBLIC_APIS = True
WAYBACK_BY_FILE: Dict[str, Dict[str, str]] = {}
DOWNLOAD_ETAG_CACHE: Dict[str, Dict[str, str]] = {}
VALIDATION_STORE = None  
SCAN_VALIDATION_CACHE = True

_VALIDATOR_FIELD_NAMES = {f.name for f in fields(ValidatorSpec)}


def _coerce_validator(raw: Dict[str, Any]) -> ValidatorSpec:
    data = dict(raw or {})
    notes: Dict[int, str] = {}
    if isinstance(data.get("notes"), dict):
        for k, v in data["notes"].items():
            try:
                notes[int(k)] = str(v)
            except (TypeError, ValueError):
                continue
    for key in list(data.keys()):
        if key.startswith("note_") and key[5:].isdigit():
            notes[int(key[5:])] = str(data.pop(key))
    data["notes"] = notes

    auth = data.get("auth")
    if isinstance(auth, (list, tuple)) and len(auth) == 2:
        data["auth"] = (str(auth[0]), str(auth[1]))
    elif auth is not None and not isinstance(auth, tuple):
        data["auth"] = None

    for list_key in (
        "valid_codes", "invalid_codes", "restricted_codes", "restricted_body_reasons",
    ):
        if list_key in data and data[list_key] is None:
            data[list_key] = []
        if list_key in data and not isinstance(data[list_key], list):
            data[list_key] = list(data[list_key]) if data[list_key] is not None else []

    if "headers" in data and not isinstance(data.get("headers"), dict):
        data["headers"] = {}

    filtered = {k: v for k, v in data.items() if k in _VALIDATOR_FIELD_NAMES}
    return ValidatorSpec(**filtered)


def _merge_validator(base: ValidatorSpec, overlay: Dict[str, Any]) -> ValidatorSpec:
    """Overlay dict fields onto an existing ValidatorSpec (deep-merge notes/headers)."""
    merged = {f.name: getattr(base, f.name) for f in fields(ValidatorSpec)}
    has_note_keys = any(
        k == "notes" or (isinstance(k, str) and k.startswith("note_") and k[5:].isdigit())
        for k in overlay
    )
    incoming = _coerce_validator(overlay)
    for f in fields(ValidatorSpec):
        if f.name == "notes":
            if has_note_keys:
                notes = dict(merged["notes"])
                notes.update(incoming.notes)
                merged["notes"] = notes
            continue
        if f.name == "headers" and "headers" in overlay and isinstance(overlay["headers"], dict):
            headers = dict(merged["headers"])
            headers.update({str(k): str(v) for k, v in overlay["headers"].items()})
            merged["headers"] = headers
            continue
        if f.name in overlay:
            merged[f.name] = getattr(incoming, f.name)
    return ValidatorSpec(**merged)


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    if not YAML_AVAILABLE:
        raise RuntimeError(
            "PyYAML is required for config loading. Install: pip install pyyaml"
        )
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {path}")
    return data


def apply_config_dict(data: Dict[str, Any], *, replace: bool = False) -> None:
    """
    Apply a config mapping onto module globals.
    replace=True clears patterns/validators/confidence first (default file load).
    replace=False merges (--config drop-in overlays).
    """
    global PATTERNS, VALIDATORS, CONFIDENCE, MIN_CONFIDENCE
    global INFORMATIONAL_TYPES, INFORMATIONAL_NOTES, EXPOSURE_TYPES, EXPOSURE_NOTES
    global SCOPE_INCLUDE, SCOPE_EXCLUDE
    global SEVERITY_MAP, REVOCATION_URLS, COMPLIANCE_TAGS

    if replace:
        PATTERNS = {}
        VALIDATORS = {}
        CONFIDENCE = {}
        INFORMATIONAL_NOTES = {}
        EXPOSURE_NOTES = {}
        SCOPE_INCLUDE = []
        SCOPE_EXCLUDE = []
        SEVERITY_MAP = {}
        REVOCATION_URLS = {}
        COMPLIANCE_TAGS = {}

    if "min_confidence" in data and data["min_confidence"] is not None:
        MIN_CONFIDENCE = int(data["min_confidence"])

    for name, pattern in (data.get("patterns") or {}).items():
        if pattern is None:
            PATTERNS.pop(str(name), None)
        else:
            PATTERNS[str(name)] = str(pattern)

    for name, conf in (data.get("confidence") or {}).items():
        if conf is None:
            CONFIDENCE.pop(str(name), None)
        else:
            CONFIDENCE[str(name)] = int(conf)

    for name, raw in (data.get("validators") or {}).items():
        key = str(name)
        if raw is None:
            VALIDATORS.pop(key, None)
            continue
        if not isinstance(raw, dict):
            raise ValueError(f"validator {key} must be a mapping")
        if key in VALIDATORS and not replace:
            VALIDATORS[key] = _merge_validator(VALIDATORS[key], raw)
        else:
            VALIDATORS[key] = _coerce_validator(raw)

    info = data.get("informational_types")
    if isinstance(info, dict):
        for name, note in info.items():
            if note is None:
                INFORMATIONAL_NOTES.pop(str(name), None)
            else:
                INFORMATIONAL_NOTES[str(name)] = str(note)
    elif isinstance(info, list):
        for name in info:
            INFORMATIONAL_NOTES.setdefault(str(name), "Informational")

    expo = data.get("exposure_types")
    if isinstance(expo, dict):
        for name, note in expo.items():
            if note is None:
                EXPOSURE_NOTES.pop(str(name), None)
            else:
                EXPOSURE_NOTES[str(name)] = str(note)
    elif isinstance(expo, list):
        for name in expo:
            EXPOSURE_NOTES.setdefault(str(name), "Exposure")

    INFORMATIONAL_TYPES = frozenset(INFORMATIONAL_NOTES.keys())
    EXPOSURE_TYPES = frozenset(EXPOSURE_NOTES.keys())

    scope = data.get("scope")
    if isinstance(scope, dict):
        if "include" in scope:
            raw_inc = scope.get("include") or []
            SCOPE_INCLUDE = [str(x) for x in raw_inc if x] if isinstance(raw_inc, list) else []
            if "exclude" in scope:
                raw_exc = scope.get("exclude") or []
                SCOPE_EXCLUDE = [str(x) for x in raw_exc if x] if isinstance(raw_exc, list) else []

    sev = data.get("severity")
    if isinstance(sev, dict):
        for name, level in sev.items():
            if level is None:
                SEVERITY_MAP.pop(str(name), None)
            else:
                SEVERITY_MAP[str(name)] = str(level).lower()

    rev = data.get("revocation")
    if isinstance(rev, dict):
        for name, url in rev.items():
            if url is None:
                REVOCATION_URLS.pop(str(name), None)
            else:
                REVOCATION_URLS[str(name)] = str(url)

    comp = data.get("compliance")
    if isinstance(comp, dict):
        for name, tags in comp.items():
            if tags is None:
                COMPLIANCE_TAGS.pop(str(name), None)
            elif isinstance(tags, list):
                COMPLIANCE_TAGS[str(name)] = [str(t) for t in tags if t]
            else:
                COMPLIANCE_TAGS[str(name)] = [str(tags)]


def load_config_file(path: Path, *, replace: bool = False) -> None:
    apply_config_dict(_load_yaml_file(path), replace=replace)


def load_default_config() -> None:
    if DEFAULT_CONFIG_PATH.exists():
        load_config_file(DEFAULT_CONFIG_PATH, replace=True)
    elif not YAML_AVAILABLE:
        raise RuntimeError(
            f"Missing {DEFAULT_CONFIG_PATH.name} and PyYAML — cannot load patterns/validators"
        )
    else:
        raise FileNotFoundError(f"Default config not found: {DEFAULT_CONFIG_PATH}")



# False-positive filters 
STOPWORDS = {
    "example", "sample", "dummy", "placeholder", "test", "demo",
    "null", "undefined", "none", "true", "false", "localhost",
    "your_key", "your_token", "insert_key", "api_key_here",
    "00000000-0000-0000-0000-000000000000",
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
}

# Plain words that pass length checks but are not secrets
DICTIONARY_WORDS = frozenset({
    "password", "passwd", "secret", "token", "apikey", "bearer",
    "changeme", "admin", "root", "username", "password1", "password123",
    "letmein", "welcome", "default", "qwerty", "abc123", "secretkey",
    "mysecret", "mytoken", "mypassword", "supersecret", "private",
})

GENERIC_SECRET_MIN_ENTROPY = 3.5

CONTEXT_WORDS = {
    "key", "api_key", "apikey", "token", "secret", "auth", "bearer",
    "authorization", "client_secret", "access_token", "private_key",
    "maps", "google", "firebase", "stripe", "slack", "twilio",
    "sendgrid", "mailgun", "heroku", "herokuapp", "platform-api", "shopify", "discord",
    "hubspot", "hapikey", "n8n",

    "openai", "anthropic", "gitlab", "mapbox", "npm", "pypi", "digitalocean",
    "aws_session", "session_token",
    "cloudflare", "huggingface", "notion", "grafana", "vault", "datadog",
    "linear", "supabase", "azure", "sas",
    "mcp", "claude", "cursor",
    "vercel", "netlify", "railway", "render", "flyio", "planetscale",
    "circleci", "sentry", "doppler", "pagerduty", "atlassian", "clerk",
    "mongodb", "postgres", "redis", "stripe", "algolia",
    "groq", "xai", "figma", "postman", "databricks", "perplexity", "fireworks",
    "razorpay", "flutterwave", "cloudinary", "sonar",
}

IGNORED_PATH_PATTERNS = [
    r"/vendor[s]?[\./]",
    r"/polyfills",
    r"/runtime\.",
    r"/test[s]?/",
    r"/spec/",
    r"/docs?/",
    r"/examples?/",
    r"/fixtures?/",
    r"chunk\.[a-f0-9]{6,}\.",
    r"/node_modules/",
]

# .map files are scanned
SOURCE_MAP_PATH_RE = re.compile(r"\.map(?:$|\?|#)", re.I)

BASELINE_FILE = ".reconpipe_ignore.json"

# config
load_default_config()
addons.bind_config_lookups(REVOCATION_URLS, COMPLIANCE_TAGS)

parse_header_list = addons.parse_header_list
polite_delay_seconds = addons.polite_delay_seconds
get_proxy_handler = addons.get_proxy_handler
install_urllib_proxy = addons.install_urllib_proxy
aiohttp_proxy_url = addons.aiohttp_proxy_url
merge_subdomain_sources = addons.merge_subdomain_sources
extract_js_urls = addons.extract_js_urls
extract_endpoints_from_js = addons.extract_endpoints_from_js
extract_js_secret_assignments = addons.extract_js_secret_assignments
parse_source_map = addons.parse_source_map
extract_source_mapping_url = addons.extract_source_mapping_url
source_map_url_candidates = addons.source_map_url_candidates
decode_source_map_data_url = addons.decode_source_map_data_url
safe_source_relpath = addons.safe_source_relpath
write_reconstructed_sources = addons.write_reconstructed_sources
source_fetch_urls = addons.source_fetch_urls
looks_like_js_url = addons.looks_like_js_url
parse_cdx_rows = addons.parse_cdx_rows
parse_cdx_text = addons.parse_cdx_text
select_oldest_snapshots = addons.select_oldest_snapshots
diff_removed_lines = addons.diff_removed_lines
list_cdx_snapshots = addons.list_cdx_snapshots
normalize_url = addons.normalize_url
dedupe_urls = addons.dedupe_urls
AdaptiveConcurrency = addons.AdaptiveConcurrency
PipelineCheckpoint = addons.PipelineCheckpoint
save_checkpoint = addons.save_checkpoint
load_checkpoint = addons.load_checkpoint
checkpoint_reached = addons.checkpoint_reached
ScanCredentials = addons.ScanCredentials
load_credentials = addons.load_credentials
credentials_to_headers = addons.credentials_to_headers
parse_burp_xml = addons.parse_burp_xml
parse_nuclei_output = addons.parse_nuclei_output
StageMetrics = addons.StageMetrics
PipelineMetrics = addons.PipelineMetrics
FindingsStream = addons.FindingsStream
docker_cmd_for = addons.docker_cmd_for
build_amass_cmd = addons.build_amass_cmd
build_assetfinder_cmd = addons.build_assetfinder_cmd
build_findomain_cmd = addons.build_findomain_cmd
build_dnsx_cmd = addons.build_dnsx_cmd
build_waybackurls_cmd = addons.build_waybackurls_cmd
build_hakrawler_cmd = addons.build_hakrawler_cmd
hakrawler_stdin = addons.hakrawler_stdin
build_paramspider_cmd = addons.build_paramspider_cmd
build_linkfinder_cmd = addons.build_linkfinder_cmd
build_naabu_cmd = addons.build_naabu_cmd
build_whatweb_cmd = addons.build_whatweb_cmd
build_wappalyzer_cmd = addons.build_wappalyzer_cmd
build_webanalyze_file_cmd = addons.build_webanalyze_file_cmd
build_httpx_tech_cmd = addons.build_httpx_tech_cmd
build_gowitness_cmd = addons.build_gowitness_cmd
build_nuclei_cmd = addons.build_nuclei_cmd
inspect_connection_uri = addons.inspect_connection_uri
is_supabase_anon = addons.is_supabase_anon
is_n8n_jwt = addons.is_n8n_jwt
jwt_provider_kind = addons.jwt_provider_kind
jwt_age_days = addons.jwt_age_days
finding_cvss = addons.finding_cvss
executive_summary = addons.executive_summary
write_jsonld_report = addons.write_jsonld_report
write_nuclei_templates = addons.write_nuclei_templates
update_global_fingerprints = addons.update_global_fingerprints
notify_telegram = addons.notify_telegram
notify_email = addons.notify_email
notify_pagerduty = addons.notify_pagerduty
notify_opsgenie = addons.notify_opsgenie
clone_repo = addons.clone_repo
list_repo_files = addons.list_repo_files
is_iac_file = addons.is_iac_file
collect_iac_files = addons.collect_iac_files
export_hackerone_markdown = addons.export_hackerone_markdown
export_jira_markdown = addons.export_jira_markdown
load_scan_profiles = addons.load_scan_profiles
save_scan_profile = addons.save_scan_profile
collect_tool_stdout_lines = addons.collect_tool_stdout_lines
cdx_lookup = addons.cdx_lookup
fetch_wayback_body = addons.fetch_wayback_body
pick_cdx_snapshot = addons.pick_cdx_snapshot
wayback_id_url = addons.wayback_id_url
sensitive_urls_for_hosts = addons.sensitive_urls_for_hosts
probe_sensitive_url = addons.probe_sensitive_url
origin_from_host = addons.origin_from_host
looks_like_html_shell = addons.looks_like_html_shell
trufflehog_git_cmd = addons.trufflehog_git_cmd
build_clone_cmd = addons.build_clone_cmd
leak_wordlist_path = addons.leak_wordlist_path
env_like_urls = addons.env_like_urls
mcp_like_urls = addons.mcp_like_urls
looks_like_mcp_config = addons.looks_like_mcp_config
extract_mcp_secrets = addons.extract_mcp_secrets
build_gitleaks_cmd = addons.build_gitleaks_cmd
build_gitleaks_detect_cmd = addons.build_gitleaks_detect_cmd
build_spray_cmd = addons.build_spray_cmd
parse_gitleaks_report = addons.parse_gitleaks_report
collect_http_urls_from_text = addons.collect_http_urls_from_text
harvest_discovery_url_pool = addons.harvest_discovery_url_pool
DISCOVERY_KEEP_URL_RE = addons.DISCOVERY_KEEP_URL_RE
parse_public_apis_markdown = addons.parse_public_apis_markdown
build_public_apis_index = addons.build_public_apis_index
load_public_apis_index = addons.load_public_apis_index
reset_public_apis_index = addons.reset_public_apis_index
lookup_public_api_host = addons.lookup_public_api_host
match_public_api_hint = addons.match_public_api_hint
public_api_query_secrets = addons.public_api_query_secrets
refresh_public_apis_catalog = addons.refresh_public_apis_catalog
public_apis_catalog_path = addons.public_apis_catalog_path
iter_secrets_pattern_entries = addons.iter_secrets_pattern_entries
filter_secrets_db_entries = addons.filter_secrets_db_entries
secrets_db_slug = addons.secrets_db_slug
bundled_secrets_db_path = addons.bundled_secrets_db_path
write_jsleak_patterns_yaml = addons.write_jsleak_patterns_yaml
refresh_secrets_pattern_db = addons.refresh_secrets_pattern_db
build_jsleak_cmd = addons.build_jsleak_cmd
parse_jsleak_output = addons.parse_jsleak_output
extract_jsleak_links = addons.extract_jsleak_links
WAYBACK_MAX = addons.WAYBACK_MAX
SENSITIVE_PATHS = addons.SENSITIVE_PATHS
github_search_queries = wave3.github_search_queries
github_raw_url = wave3.github_raw_url
parse_github_search_payload = wave3.parse_github_search_payload
parse_gitlab_search_payload = wave3.parse_gitlab_search_payload
collect_code_search_urls = wave3.collect_code_search_urls
parse_forge_repo = wave3.parse_forge_repo
repos_from_code_urls = wave3.repos_from_code_urls
collect_ci_targets = wave3.collect_ci_targets
collect_ci_log_files = wave3.collect_ci_log_files
collect_paste_files = wave3.collect_paste_files
parse_github_workflow_runs = wave3.parse_github_workflow_runs
parse_pastebin_scrape = wave3.parse_pastebin_scrape
parse_psbdmp_search = wave3.parse_psbdmp_search
parse_gist_search_html = wave3.parse_gist_search_html
docker_hub_queries = wave3.docker_hub_queries
parse_docker_hub_search = wave3.parse_docker_hub_search
collect_docker_hub_images = wave3.collect_docker_hub_images
extract_image_refs = wave3.extract_image_refs
select_images_for_target = wave3.select_images_for_target
extract_docker_save_credentials = wave3.extract_docker_save_credentials
findings_from_trivy_secrets = wave3.findings_from_trivy_secrets
scan_public_image_layers = wave3.scan_public_image_layers
apply_ai_verdict = wave3.apply_ai_verdict
ai_verdict_for = wave3.ai_verdict_for
keep_layer_member = wave3.keep_layer_member
looks_like_openapi = wave3.looks_like_openapi
looks_like_postman = wave3.looks_like_postman
parse_openapi_spec = wave3.parse_openapi_spec
parse_postman_collection = wave3.parse_postman_collection
harvest_spec_urls = wave3.harvest_spec_urls
harvest_spec_secret_findings = wave3.harvest_spec_secret_findings
extract_printable_strings = wave3.extract_printable_strings
extract_mobile_archive = wave3.extract_mobile_archive
parse_package_id = wave3.parse_package_id
parse_package_ids = wave3.parse_package_ids
fetch_android_packages = wave3.fetch_android_packages
apkeep_cmd = wave3.apkeep_cmd
gplaycli_cmd = wave3.gplaycli_cmd
bucket_name_candidates = wave3.bucket_name_candidates
parse_s3_listing = wave3.parse_s3_listing
classify_bucket_response = wave3.classify_bucket_response
probe_buckets = wave3.probe_buckets
load_etag_cache = wave3.load_etag_cache
save_etag_cache = wave3.save_etag_cache
etag_request_headers = wave3.etag_request_headers
etag_cache_update = wave3.etag_cache_update
findings_db_path = wave3.findings_db_path
connect_store = wave3.connect_store
upsert_findings = wave3.upsert_findings
cache_get = wave3.cache_get
cache_put = wave3.cache_put
git_commit_for_secret = wave3.git_commit_for_secret
annotate_repo_findings = wave3.annotate_repo_findings
pair_generic_findings = wave3.pair_generic_findings
proximity_partners = wave3.proximity_partners
apply_ci_defaults = wave3.apply_ci_defaults
apply_apps_only_options = wave3.apply_apps_only_options
APPS_ONLY_SKIP_FLAGS = wave3.APPS_ONLY_SKIP_FLAGS
crtsh_hosts_from_payload = wave3.crtsh_hosts_from_payload
certstream_domains_from_message = wave3.certstream_domains_from_message
hosts_matching_domain = wave3.hosts_matching_domain
merge_unique = wave3.merge_unique

# Logging
_FIND_LOGGED = 0
_FIND_LOG_CAP = 12
CONSOLE_KEEP_RE = re.compile(
    r"\[(?:\d)/6\]|\[(?:gui|[+*!\-]|FIND|VALID|ETA)\]|"
    r"Timing:|PIPELINE COMPLETE|ReconPipe GUI",
    re.I,
)


def reset_log_counters() -> None:
    global _FIND_LOGGED
    _FIND_LOGGED = 0


def verbose_logs() -> bool:
    return (os.environ.get("RECONPIPE_VERBOSE") or "").strip() in {"1", "true", "True", "yes"}


def console_keep_line(line: str) -> bool:
    """True if a pipeline line is worth showing in the GUI (stage/status only)."""
    text = (line or "").strip()
    if not text:
        return False
    if verbose_logs():
        return True
    return bool(CONSOLE_KEEP_RE.search(text))


def log(msg: str, level: str = "info") -> None:
    global _FIND_LOGGED
    ts = datetime.now().strftime("%H:%M:%S")
    if level == "find" and not verbose_logs():
        _FIND_LOGGED += 1
        if _FIND_LOGGED == _FIND_LOG_CAP + 1:
            print(
                f"{C.DIM}[{ts}]{C.RESET} {C.YELLOW}[FIND]{C.RESET} "
                f"… further hits written to findings.json (RECONPIPE_VERBOSE=1 for all)"
            )
            return
        if _FIND_LOGGED > _FIND_LOG_CAP:
            return
    icons = {
        "info":    f"{C.DIM}[{ts}]{C.RESET} {C.BLUE}[*]{C.RESET}",
        "success": f"{C.DIM}[{ts}]{C.RESET} {C.GREEN}[+]{C.RESET}",
        "warn":    f"{C.DIM}[{ts}]{C.RESET} {C.YELLOW}[!]{C.RESET}",
        "error":   f"{C.DIM}[{ts}]{C.RESET} {C.RED}[-]{C.RESET}",
        "find":    f"{C.DIM}[{ts}]{C.RESET} {C.YELLOW}[FIND]{C.RESET}",
        "valid":   f"{C.DIM}[{ts}]{C.RESET} {C.GREEN}{C.BOLD}[VALID]{C.RESET}",
    }
    print(f"{icons.get(level, icons['info'])} {msg}")


def step_header(num: int, title: str) -> None:
    print(f"\n{C.CYAN}{'─' * 62}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  [{num}/6] {title.upper()}{C.RESET}")
    print(f"{C.CYAN}{'─' * 62}{C.RESET}")
    if _ETA is not None:
        _ETA.begin_stage(num, title)


def fmt_hms(seconds: float) -> str:
    """Nmap-style elapsed/remaining clock: 0:12:40."""
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}:{m:02d}:{sec:02d}"


def fmt_remaining_short(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 90:
        return f"{s}s"
    m = max(1, (s + 30) // 60)
    if m < 90:
        return f"{m}m"
    h, mm = divmod(m, 60)
    return f"{h}h{mm:02d}m"


class ScanEta:
    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else None
        self.started = time.monotonic()
        self.stage = 1
        self.stage_name = "starting"
        self.stage_started = self.started
        self.progress = 0.0
        self.subs = 0
        self.live = 0
        self.urls = 0
        self.findings = 0
        self.skip_chaos = False
        self.skip_httpx = False
        self.skip_discovery = False
        self.skip_gau = False
        self.skip_intel = False
        self.skip_subfinder = False
        self.no_trufflehog = False
        self.no_validate = False
        self.concurrency = 20
        self.tools: Dict[str, bool] = {}
        self._last_log = 0.0
        self._hb_depth = 0
        self._hb_stop: Optional[threading.Event] = None
        self._hb_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def configure(self, **kwargs: Any) -> None:
        for key, val in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, val)

    def set_work(
        self,
        *,
        subs: Optional[int] = None,
        live: Optional[int] = None,
        urls: Optional[int] = None,
        findings: Optional[int] = None,
        progress: Optional[float] = None,
        log_now: bool = False,
    ) -> None:
        with self._lock:
            if subs is not None:
                self.subs = max(0, int(subs))
            if live is not None:
                self.live = max(0, int(live))
            if urls is not None:
                self.urls = max(0, int(urls))
            if findings is not None:
                self.findings = max(0, int(findings))
            if progress is not None:
                self.progress = min(1.0, max(0.0, float(progress)))
        if log_now:
            self.log_timing(force=True)
        else:
            self.write_status()

    def begin_stage(self, num: int, title: str) -> None:
        with self._lock:
            self.stage = int(num)
            self.stage_name = (title or "").strip() or f"stage {num}"
            self.stage_started = time.monotonic()
            self.progress = 0.0
        self.log_timing(force=True)

    def finish(self) -> None:
        with self._lock:
            self.stage = 6
            self.stage_name = "complete"
            self.progress = 1.0
        self.log_timing(force=True)
        self.write_status(remaining_s=0, pct=100)

    def budgets(self) -> Dict[int, float]:
        subs = max(self.subs, 1)
        live = self.live if self.live else max(1, subs // 3)
        urls = self.urls
        findings = self.findings
        tools = self.tools or {}

        chaos = 4.0 if self.skip_chaos else 22.0
        if not getattr(self, "skip_subfinder", False) and tools.get("subfinder"):
            chaos += 20.0
        if not self.skip_intel:
            chaos += 18.0
        httpx = 3.0 if self.skip_httpx else min(1500.0, max(20.0, (subs / 50.0) * 6.0 + 12.0))

        if self.skip_discovery:
            disco = 4.0
        else:
            katana = min(2400.0, live * 1.6 + 70.0) if tools.get("katana") else 5.0
            if self.skip_gau:
                passive = 4.0
            elif tools.get("waymore"):
                passive = min(900.0, live * 18.0 + 20.0)
            elif tools.get("gau") or tools.get("waybackurls"):
                passive = min(600.0, live * 8.0 + 15.0)
            else:
                passive = 8.0
            gospider = 80.0 if tools.get("gospider") else 5.0
            disco = katana + passive + gospider

        guessed_urls = urls if urls else max(int(live * 30), 15)
        if guessed_urls <= 0:
            scan = 6.0
        elif self.no_trufflehog or not tools.get("trufflehog"):
            scan = min(2400.0, guessed_urls * 0.14 + 15.0)
        else:
            dl = min(guessed_urls, 2000) * 0.32
            hog = 35.0 + min(guessed_urls, 2000) * 0.05
            scan = dl + hog

        if self.no_validate:
            val = 3.0
        else:
            nkeys = findings if findings else max(2, guessed_urls // 90)
            val = max(6.0, nkeys / max(int(self.concurrency) or 1, 1) * 1.15 + 4.0)

        return {
            1: chaos,
            2: httpx,
            3: disco,
            4: scan,
            5: val,
            6: 5.0,
        }

    def snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        elapsed = max(0.0, now - self.started)
        stage_elapsed = max(0.0, now - self.stage_started)
        budgets = self.budgets()
        stage = min(6, max(1, self.stage))
        budget = max(1.0, budgets.get(stage, 30.0))
        progress = self.progress
        if progress >= 0.03:
            rate = stage_elapsed / progress
            current_left = rate * (1.0 - progress)
        else:
            current_left = max(0.0, budget - stage_elapsed)
        if stage_elapsed > budget and progress < 0.99:
            current_left = max(current_left, min(90.0, budget * 0.25))
        future = sum(budgets[s] for s in range(stage + 1, 7))
        remaining = current_left + future
        total = elapsed + remaining
        pct = 100.0 if remaining <= 0.5 else min(99.0, 100.0 * elapsed / max(total, 1.0))
        etc = datetime.now() + timedelta(seconds=int(remaining))
        return {
            "stage": stage,
            "stage_name": self.stage_name,
            "elapsed_s": int(elapsed),
            "remaining_s": int(remaining),
            "pct": int(pct),
            "etc": etc.strftime("%H:%M:%S"),
            "etc_short": etc.strftime("%H:%M"),
            "timing": (
                f"About {int(pct)}% done; ETC: {etc.strftime('%H:%M')} "
                f"({fmt_hms(remaining)} remaining)"
            ),
            "subs": self.subs,
            "live": self.live,
            "urls": self.urls,
            "findings": self.findings,
        }

    def write_status(
        self,
        remaining_s: Optional[int] = None,
        pct: Optional[int] = None,
    ) -> None:
        if not self.output_dir:
            return
        snap = self.snapshot()
        if remaining_s is not None:
            snap["remaining_s"] = int(remaining_s)
        if pct is not None:
            snap["pct"] = int(pct)
            if remaining_s == 0:
                snap["timing"] = (
                    f"About 100% done; elapsed {fmt_hms(snap['elapsed_s'])}"
                )
        path = self.output_dir / "scan_status.json"
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(snap, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    def log_timing(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_log) < 25.0:
            self.write_status()
            return
        self._last_log = now
        snap = self.snapshot()
        log(
            f"Timing: {snap['timing']} - {self.stage_name} "
            f"(elapsed {fmt_hms(snap['elapsed_s'])})",
            "info",
        )
        self.write_status()

    @contextmanager
    def heartbeat(self, every: float = 30.0):
        with self._lock:
            self._hb_depth += 1
            start_thread = self._hb_depth == 1
        if start_thread:
            stop = threading.Event()
            self._hb_stop = stop

            def _loop() -> None:
                while not stop.wait(every):
                    self.log_timing(force=True)

            t = threading.Thread(target=_loop, daemon=True, name="reconpipe-eta")
            self._hb_thread = t
            t.start()
        try:
            yield
        finally:
            with self._lock:
                self._hb_depth = max(0, self._hb_depth - 1)
                stop_thread = self._hb_depth == 0
            if stop_thread:
                if self._hb_stop:
                    self._hb_stop.set()
                if self._hb_thread:
                    self._hb_thread.join(timeout=1.0)
                self._hb_stop = None
                self._hb_thread = None
                self.log_timing(force=True)


_ETA: Optional[ScanEta] = None


def set_scan_eta(eta: Optional[ScanEta]) -> None:
    global _ETA
    _ETA = eta


def eta_heartbeat(timeout: int = 0):
    if _ETA is None or int(timeout) < 45:
        return nullcontext()
    return _ETA.heartbeat()


# Saved keys / targets live in ~/.reconpipe
USER_KEY_FIELDS = (
    ("chaos", "chaos_key", ("CHAOS_KEY", "PDCP_API_KEY")),
    ("shodan", "shodan_key", ("SHODAN_API_KEY",)),
    ("censys_id", "censys_id", ("CENSYS_API_ID",)),
    ("censys_secret", "censys_secret", ("CENSYS_API_SECRET",)),
    ("zoomeye", "zoomeye_key", ("ZOOMEYE_API_KEY", "ZOOMEYE_KEY")),
    ("notify_webhook", "notify_webhook", ("RECONPIPE_NOTIFY_WEBHOOK",)),
    ("telegram_bot", "telegram_bot", ("TELEGRAM_BOT_TOKEN",)),
    ("telegram_chat", "telegram_chat", ("TELEGRAM_CHAT_ID",)),
    ("pagerduty", "pagerduty_key", ("PAGERDUTY_ROUTING_KEY",)),
    ("opsgenie", "opsgenie_key", ("OPSGENIE_API_KEY",)),
    ("github", "github_token", ("GITHUB_TOKEN", "GH_TOKEN")),
    ("gitlab", "gitlab_token", ("GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN")),
    ("llm", "llm_key", ("RECONPIPE_LLM_KEY",)),
)
HIT_SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".map", ".json", ".html", ".htm", ".env"}


def user_data_dir() -> Path:
    env = (os.environ.get("RECONPIPE_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".reconpipe"


def _ensure_user_dir() -> Path:
    path = user_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_user_yaml(name: str) -> Dict[str, Any]:
    path = user_data_dir() / name
    if not path.is_file():
        return {}
    try:
        if YAML_AVAILABLE:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_user_yaml(name: str, data: Dict[str, Any], *, private: bool = False) -> Path:
    path = _ensure_user_dir() / name
    text = yaml.safe_dump(data, sort_keys=False) if YAML_AVAILABLE else json.dumps(data, indent=2)
    path.write_text(text, encoding="utf-8")
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def load_user_keys() -> Dict[str, str]:
    raw = _load_user_yaml("keys.yaml")
    out: Dict[str, str] = {}
    for key, _arg, _env in USER_KEY_FIELDS:
        val = raw.get(key)
        if val is not None and str(val).strip():
            out[key] = str(val).strip()
    return out


def save_user_keys(values: Dict[str, str]) -> Path:
    current = _load_user_yaml("keys.yaml")
    for key, _arg, _env in USER_KEY_FIELDS:
        if key not in values:
            continue
        val = (values.get(key) or "").strip()
        if val:
            current[key] = val
        else:
            current.pop(key, None)
    return _save_user_yaml("keys.yaml", current, private=True)


def saved_keys_status() -> Dict[str, bool]:
    saved = load_user_keys()
    return {key: bool(saved.get(key)) for key, _arg, _env in USER_KEY_FIELDS}


def apply_saved_keys(args: Any) -> None:
    """CLI flag > environment > ~/.reconpipe/keys.yaml."""
    saved = load_user_keys()
    for key, arg_name, env_names in USER_KEY_FIELDS:
        current = getattr(args, arg_name, None)
        if (current or "").strip():
            continue
        picked = ""
        for env in env_names:
            picked = (os.environ.get(env) or "").strip()
            if picked:
                break
        if not picked:
            picked = (saved.get(key) or "").strip()
        setattr(args, arg_name, picked or None)


def list_saved_targets() -> List[Dict[str, str]]:
    rows = _load_user_yaml("targets.yaml").get("targets") or []
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, str]] = []
    for row in rows:
        if isinstance(row, dict) and (row.get("domain") or row.get("name")):
            out.append({str(k): "" if v is None else str(v) for k, v in row.items()})
    return out


def upsert_saved_target(entry: Dict[str, str]) -> List[Dict[str, str]]:
    domain = (entry.get("domain") or "").strip()
    if not domain:
        raise ValueError("domain is required")
    name = (entry.get("name") or domain).strip()
    row = {
        "name": name,
        "domain": domain,
        "files": (entry.get("files") or "").strip(),
        "subdomains": (entry.get("subdomains") or "").strip(),
        "output": (entry.get("output") or "").strip(),
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    rows = [r for r in list_saved_targets() if r.get("name") != name]
    rows.insert(0, row)
    _save_user_yaml("targets.yaml", {"targets": rows})
    return rows


def delete_saved_target(name: str) -> List[Dict[str, str]]:
    name = (name or "").strip()
    rows = [r for r in list_saved_targets() if r.get("name") != name]
    _save_user_yaml("targets.yaml", {"targets": rows})
    return rows


def find_saved_target(domain: str) -> Optional[Dict[str, str]]:
    want = (domain or "").strip().lower()
    if not want:
        return None
    named: Optional[Dict[str, str]] = None
    by_domain: Optional[Dict[str, str]] = None
    for row in list_saved_targets():
        if (row.get("name") or "").strip().lower() == want:
            named = row
            break
        if (row.get("domain") or "").strip().lower() == want and by_domain is None:
            by_domain = row
    return named or by_domain


def load_scan_history() -> List[Dict[str, str]]:
    rows = _load_user_yaml("history.yaml").get("runs") or []
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, str]] = []
    for row in rows:
        if isinstance(row, dict) and (row.get("domain") or row.get("output_dir")):
            out.append({str(k): "" if v is None else str(v) for k, v in row.items()})
    return out


def append_scan_history(entry: Dict[str, str], limit: int = 50) -> List[Dict[str, str]]:
    row = {str(k): "" if v is None else str(v) for k, v in (entry or {}).items()}
    if not row.get("domain") and not row.get("output_dir"):
        return load_scan_history()
    rows = [r for r in load_scan_history() if not (
        r.get("output_dir") == row.get("output_dir")
        and r.get("finished_at") == row.get("finished_at")
    )]
    rows.insert(0, row)
    kept = rows[: max(1, int(limit))]
    _save_user_yaml("history.yaml", {"runs": kept})
    return kept


def apply_rescan_defaults(args: Any) -> Any:
    domain = (getattr(args, "domain", None) or "").strip()
    row = find_saved_target(domain)
    if row:
        if not (getattr(args, "files", None) or "").strip():
            files = (row.get("files") or "").strip()
            if files and Path(files).is_file():
                args.files = files
        if not (getattr(args, "subdomains", None) or "").strip():
            subs = (row.get("subdomains") or "").strip()
            if subs and Path(subs).is_file():
                args.subdomains = subs
        if not (getattr(args, "output", None) or "").strip():
            out = (row.get("output") or "").strip()
            if out:
                args.output = out
    if not (getattr(args, "output", None) or "").strip() and domain:
        guess = Path(f"recon_{domain.replace('.', '_')}")
        if guess.is_dir():
            args.output = str(guess)
    args.resume = True
    return args


def remember_scan_target(
    domain: str,
    *,
    files: Optional[Path] = None,
    subdomains: Optional[Path] = None,
    output: Optional[Path] = None,
) -> Dict[str, str]:
    domain = (domain or "").strip()
    files_path = ""
    if files and Path(files).is_file():
        lists = _ensure_user_dir() / "lists"
        lists.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain)[:80] or "target"
        dest = lists / f"{safe}.txt"
        try:
            shutil.copy2(files, dest)
            files_path = str(dest)
        except OSError:
            files_path = str(Path(files).resolve())
    entry = {
        "name": domain,
        "domain": domain,
        "files": files_path,
        "subdomains": str(Path(subdomains).resolve()) if subdomains and Path(subdomains).is_file() else "",
        "output": str(Path(output).resolve()) if output else "",
    }
    upsert_saved_target(entry)
    try:
        append_scan_history({
            "domain": domain,
            "output_dir": entry["output"],
            "files": entry["files"],
            "subdomains": entry["subdomains"],
            "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception:
        pass
    return entry


def download_filename(url: str) -> str:
    tail = (url or "").split("/")[-1].split("?")[0]
    fname = hashlib.md5((url or "").encode()).hexdigest() + "_" + tail
    return re.sub(r"[^a-zA-Z0-9._-]", "_", fname)[:120]


SKIP_CONTENT_PREFIXES = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-rar",
    "application/wasm",
    "application/x-font",
    "application/font",
    "application/vnd.ms-fontobject",
)
KEEP_CONTENT_HINTS = (
    "javascript",
    "json",
    "xml",
    "html",
    "text/",
    "typescript",
    "ecmascript",
    "x-www-form-urlencoded",
)


def content_type_allowed(content_type: str) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    if not ct:
        return True
    if any(h in ct for h in KEEP_CONTENT_HINTS):
        return True
    return not any(ct.startswith(p) for p in SKIP_CONTENT_PREFIXES)


def _scope_patterns() -> Tuple[List[str], List[str]]:
    return list(SCOPE_INCLUDE), list(SCOPE_EXCLUDE)


def load_pattern_file(path: Optional[Path]) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    out: List[str] = []
    for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = ln.strip()
        if text and not text.startswith("#"):
            out.append(text)
    return out


def apply_scope_files(
    include_file: Optional[str] = None,
    exclude_file: Optional[str] = None,
) -> None:
    global SCOPE_INCLUDE, SCOPE_EXCLUDE
    extra_inc = load_pattern_file(Path(include_file) if include_file else None)
    extra_exc = load_pattern_file(Path(exclude_file) if exclude_file else None)
    if extra_inc:
        SCOPE_INCLUDE = list(dict.fromkeys(SCOPE_INCLUDE + extra_inc))
    if extra_exc:
        SCOPE_EXCLUDE = list(dict.fromkeys(SCOPE_EXCLUDE + extra_exc))


def default_scope_patterns(domain: str) -> List[str]:
    host = _host_from_target(domain)
    if not host or "." not in host:
        return [host] if host else []
    patterns = [host, f"*.{host}"]
    if host.startswith("www.") and host.count(".") >= 2:
        apex = host[4:]
        patterns.extend([apex, f"*.{apex}"])
    return list(dict.fromkeys(p for p in patterns if p))


def apply_default_target_scope(domain: str) -> List[str]:
    global SCOPE_INCLUDE
    if SCOPE_INCLUDE:
        return []
    added = default_scope_patterns(domain)
    if not added:
        return []
    SCOPE_INCLUDE = list(added)
    return added


def is_local_scan_path(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    low = text.lower()
    if low.startswith(("http://", "https://", "ftp://")):
        return False
    if "://" in text and not low.startswith("file:"):
        return False
    if low.startswith("file:"):
        return True
    if re.match(r"^[a-zA-Z]:[\\/]", text) or text.startswith("\\\\"):
        return True
    if text.startswith("/") or text.startswith("./") or text.startswith(".\\"):
        return True
    return "/" in text or "\\" in text


def _wayback_original_url(url: str) -> str:
    m = re.search(
        r"web\.archive\.org/web/\d+(?:id_)?/(https?://\S+)",
        url or "",
        re.I,
    )
    return (m.group(1) if m else "").rstrip(")")


def _host_from_target(value: str) -> str:
    text = (value or "").strip().lower()
    if "://" in text:
        text = (urlparse(text).hostname or "") or text
    if "/" in text:
        text = text.split("/", 1)[0]
    if ":" in text and not text.count(":") > 1:
        text = text.split(":", 1)[0]
    return text.strip().rstrip(".")


def normalize_scan_domain(value: str) -> str:
    """Host only. Chaos/subfinder need the apex (optus.com.au), not a URL or www."""
    host = _host_from_target(value)
    if host.startswith("www.") and host.count(".") >= 2:
        rest = host[4:]
        if "." in rest:
            host = rest
    return host


def resolve_chaos_key(args: Any = None) -> str:
    """CLI flag → CHAOS_KEY → PDCP_API_KEY → keys.yaml. Never log the value."""
    picked = ""
    if args is not None:
        picked = str(getattr(args, "chaos_key", None) or "").strip()
    if not picked:
        picked = (os.environ.get("CHAOS_KEY") or os.environ.get("PDCP_API_KEY") or "").strip()
    if not picked:
        picked = (load_user_keys().get("chaos") or "").strip()
    return picked


def parse_chaos_subdomain_payload(data: Any, domain: str) -> List[str]:
    """Chaos JSON lists labels (`www`) or FQDNs. Always return FQDNs including the apex."""
    apex = normalize_scan_domain(domain)
    raw: Any = []
    if isinstance(data, dict):
        raw = data.get("subdomains") or data.get("data") or []
    elif isinstance(data, list):
        raw = data
    hosts: List[str] = [apex] if apex else []
    for item in raw:
        if isinstance(item, dict):
            item = item.get("subdomain") or item.get("host") or item.get("name") or ""
        label = str(item or "").strip().lower().rstrip(".")
        if not label:
            continue
        if label == apex or (apex and label.endswith("." + apex)):
            hosts.append(label)
        elif "." not in label and apex:
            hosts.append(f"{label}.{apex}")
        else:
            hosts.append(label)
    return merge_host_lists([], hosts)


def query_chaos_http(
    domain: str,
    api_key: str,
    timeout: int = 45,
) -> List[str]:
    """Official Chaos DNS API (same dataset as chaos.projectdiscovery.io)."""
    apex = normalize_scan_domain(domain)
    key = (api_key or "").strip()
    if not apex or not key:
        return []
    url = f"https://dns.projectdiscovery.io/dns/{quote(apex, safe='.-')}/subdomains"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": key,
            "Accept": "application/json",
            "User-Agent": "ReconPipe",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        snippet = ""
        try:
            snippet = (exc.read() or b"").decode("utf-8", errors="replace")[:180]
        except Exception:
            snippet = ""
        if exc.code in (401, 403):
            log(
                "Chaos API rejected the key (HTTP "
                f"{exc.code}). Use a ProjectDiscovery Cloud key "
                "(PDCP_API_KEY / CHAOS_KEY / GUI Chaos field).",
                "warn",
            )
        else:
            log(f"Chaos HTTP {exc.code}: {snippet or exc.reason}", "warn")
        return []
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"Chaos HTTP failed: {exc}", "warn")
        return []
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        log("Chaos HTTP returned non-JSON", "warn")
        return []
    return parse_chaos_subdomain_payload(payload, apex)


def _glob_match_host(pattern: str, host: str) -> bool:
    pat = (pattern or "").strip().lower()
    h = (host or "").strip().lower().rstrip(".")
    if not pat or not h:
        return False
    if pat.startswith("^"):
        try:
            return bool(re.search(pat, h, re.I))
        except re.error:
            return False
    if pat.startswith("*."):
        suffix = pat[1:]  # .example.com
        return h == pat[2:] or h.endswith(suffix)
    return fnmatch.fnmatch(h, pat) or h == pat


def host_in_scope(host: str, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> bool:
    h = _host_from_target(host)
    if not h:
        return False
    inc = include if include is not None else SCOPE_INCLUDE
    exc = exclude if exclude is not None else SCOPE_EXCLUDE
    if inc and not any(_glob_match_host(p, h) for p in inc):
        return False
    if exc and any(_glob_match_host(p, h) for p in exc):
        return False
    return True


def url_in_scope(url: str, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> bool:
    if is_local_scan_path(url):
        return True
    original = _wayback_original_url(url)
    if original:
        return host_in_scope(_host_from_target(original), include, exclude)
    return host_in_scope(_host_from_target(url), include, exclude)


def filter_hosts_in_scope(hosts: List[str]) -> List[str]:
    if not SCOPE_INCLUDE and not SCOPE_EXCLUDE:
        return list(hosts)
    return [h for h in hosts if host_in_scope(h)]


def filter_urls_in_scope(urls: List[str]) -> List[str]:
    if not SCOPE_INCLUDE and not SCOPE_EXCLUDE:
        return list(urls)
    return [u for u in urls if url_in_scope(u)]


def finding_in_scope(finding: Dict) -> bool:
    src = str(finding.get("source_url") or finding.get("source") or "")
    if not src:
        return True
    if url_in_scope(src):
        return True
    original = str(finding.get("wayback_url") or "")
    if original and url_in_scope(original):
        return True
    return False


def filter_findings_in_scope(findings: List[Dict]) -> List[Dict]:
    if not SCOPE_INCLUDE and not SCOPE_EXCLUDE:
        return list(findings)
    return [f for f in findings if finding_in_scope(f)]


SEVERITY_CRITICAL = frozenset({
    "aws_access_key", "aws_secret", "gcp_service_acct", "private_key_pem",
    "stripe_live", "hashicorp_vault",
})
SEVERITY_HIGH = frozenset({
    "github_pat", "github_fine_pat", "github_oauth", "github_app", "gitlab_pat",
    "openai_key", "anthropic_key", "sendgrid", "heroku_api", "cloudflare_api",
    "huggingface_token", "notion_token", "linear_api_key", "supabase_service",
    "hubspot_api",
    "n8n_api",
    "digitalocean_pat", "npm_token", "pypi_token", "shopify_token", "shopify_secret",
    "slack_token", "twilio_sid", "twilio_token", "azure_sas", "mcp_credential",
})
SEVERITY_MEDIUM = frozenset({
    "stripe_test", "stripe_restricted", "firebase_key", "mailgun", "mailchimp",
    "discord_token", "discord_webhook", "telegram_bot", "grafana_token",
    "datadog_api_key", "mapbox_token",     "source_map_exposure", "google_api",
    "google_oauth", "slack_webhook",
})
SEVERITY_LOW = frozenset({
    "jwt", "generic_secret", "uuid_candidate", "stripe_publishable", "firebase_url",
})


def finding_severity(finding: Dict) -> str:
    """Exploitability tier, independent of regex confidence."""
    t = str(finding.get("type") or "")
    note = str(finding.get("note") or "").lower()
    if t in INFORMATIONAL_TYPES:
        return "low"
    mapped = SEVERITY_MAP.get(t)
    if mapped in {"critical", "high", "medium", "low"}:
        if mapped == "high" and "restricted" in note:
            return "medium"
        return mapped
    if t in SEVERITY_CRITICAL:
        return "critical"
    if t in SEVERITY_HIGH:
        if "restricted" in note:
            return "medium"
        return "high"
    if t in SEVERITY_MEDIUM:
        return "medium"
    if t in SEVERITY_LOW or t in EXPOSURE_TYPES:
        return "low"
    if finding.get("valid"):
        return "high"
    return "medium"


def redact_key(value: str, reveal: bool = False) -> str:
    text = value or ""
    if reveal or len(text) <= 8:
        return text if reveal else ("*" * len(text))
    return f"{text[:4]}…{text[-4:]}"


def annotate_severity(findings: List[Dict]) -> List[Dict]:
    out = []
    for f in findings:
        item = dict(f)
        item["severity"] = finding_severity(item)
        item["cvss"] = finding_cvss(item["severity"])
        typ = str(item.get("type") or "")
        if typ in REVOCATION_URLS:
            item["revocation"] = REVOCATION_URLS[typ]
        if typ in COMPLIANCE_TAGS:
            item["compliance"] = list(COMPLIANCE_TAGS[typ])
        key = str(item.get("key") or "")
        if key and item.get("entropy") is None:
            try:
                item["entropy"] = round(entropy(key), 3)
            except Exception:
                pass
        jwt_meta = item.get("jwt") if isinstance(item.get("jwt"), dict) else None
        age = jwt_age_days(jwt_meta)
        if age is not None:
            item["secret_age_days"] = round(age, 2)
        out.append(item)
    return out


def _report_rows(
    findings: List[Dict],
    exposures: Optional[List[Dict]] = None,
    informational: Optional[List[Dict]] = None,
) -> List[Dict]:
    rows: List[Dict] = []
    for f in findings or []:
        item = dict(f)
        item.setdefault("bucket", "finding")
        rows.append(item)
    for e in exposures or []:
        item = dict(e)
        item.setdefault("bucket", "exposure")
        rows.append(item)
    for i in informational or []:
        item = dict(i)
        item.setdefault("bucket", "informational")
        rows.append(item)
    for row in rows:
        row["severity"] = finding_severity(row)
        row["cvss"] = finding_cvss(row["severity"])
        row["redacted"] = redact_key(str(row.get("key") or ""))
        typ = str(row.get("type") or "")
        row.setdefault("revocation", REVOCATION_URLS.get(typ, ""))
        if typ in COMPLIANCE_TAGS:
            row.setdefault("compliance", list(COMPLIANCE_TAGS[typ]))
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(
        key=lambda r: (
            0 if r.get("bucket") == "finding" else 1,
            -int(r.get("ai_score") or 0),
            _sev_rank.get(str(r.get("severity") or ""), 9),
        )
    )
    return rows


def write_csv_report(
    path: Path,
    findings: List[Dict],
    exposures: Optional[List[Dict]] = None,
    informational: Optional[List[Dict]] = None,
) -> Path:
    rows = _report_rows(findings, exposures, informational)
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "severity", "type", "valid", "validated", "status_code",
                "key", "source_url", "note", "hash", "github_scopes",
                "cvss", "revocation", "compliance",
            ],
        )
        writer.writeheader()
        for row in rows:
            scopes = row.get("github_scopes")
            writer.writerow({
                "severity": row.get("severity") or "",
                "type": row.get("type") or "",
                "valid": row.get("valid"),
                "validated": row.get("validated"),
                "status_code": row.get("status_code") or "",
                "key": row.get("redacted") or redact_key(str(row.get("key") or "")),
                "source_url": row.get("source_url") or "",
                "note": row.get("note") or "",
                "hash": row.get("hash") or "",
                "github_scopes": ",".join(scopes) if isinstance(scopes, list) else (scopes or ""),
                "cvss": row.get("cvss") or "",
                "revocation": row.get("revocation") or "",
                "compliance": ",".join(row.get("compliance") or []) if isinstance(row.get("compliance"), list) else (row.get("compliance") or ""),
            })
    return path


def write_markdown_report(
    path: Path,
    domain: str,
    findings: List[Dict],
    exposures: Optional[List[Dict]] = None,
    informational: Optional[List[Dict]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Path:
    rows = _report_rows(findings, exposures, informational)
    extra = extra or {}
    valid_n = sum(1 for f in findings if f.get("valid"))
    exec_txt = extra.get("executive") or executive_summary(
        domain, findings, valid_n, len(exposures or [])
    )
    lines = [
        f"# ReconPipe report — {domain}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Executive summary",
        "",
        exec_txt,
        "",
        f"- Unique findings: {len(findings)}",
        f"- Valid: {valid_n}",
        f"- Exposures: {len(exposures or [])}",
        f"- Informational: {len(informational or [])}",
    ]
    if extra.get("new_count") is not None:
        lines.append(f"- New since last scan: {extra['new_count']}")
    lines += ["", "## Findings", ""]
    if not rows:
        lines.append("_No findings._")
    else:
        lines.append("| Severity | Type | Valid | Key | Source | Note |")
        lines.append("|---|---|---|---|---|---|")
        for row in rows:
            note = str(row.get("note") or "").replace("|", "\\|").replace("\n", " ")
            src = str(row.get("source_url") or "").replace("|", "\\|")
            revoke = str(row.get("revocation") or "").replace("|", "\\|")
            tags = row.get("compliance") or []
            if isinstance(tags, list) and tags:
                note = note + " [" + ",".join(str(t) for t in tags) + "]"
            if revoke:
                note = note + f" revoke:{revoke}"
            lines.append(
                f"| {row.get('severity')} | `{row.get('type')}` | {row.get('valid')} | "
                f"`{row.get('redacted')}` | {src} | {note} |"
            )
    path = Path(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_html_report(
    path: Path,
    domain: str,
    findings: List[Dict],
    exposures: Optional[List[Dict]] = None,
    informational: Optional[List[Dict]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Path:
    rows = _report_rows(findings, exposures, informational)
    extra = extra or {}
    valid_n = sum(1 for f in findings if f.get("valid"))
    exec_txt = html.escape(
        str(extra.get("executive") or executive_summary(domain, findings, valid_n, len(exposures or [])))
    )
    colors = {
        "critical": "#b91c1c",
        "high": "#c2410c",
        "medium": "#a16207",
        "low": "#64748b",
    }
    cards = []
    for row in rows:
        sev = str(row.get("severity") or "medium")
        color = colors.get(sev, "#64748b")
        src = html.escape(str(row.get("source_url") or ""))
        note = html.escape(str(row.get("note") or ""))
        key = html.escape(str(row.get("redacted") or ""))
        typ = html.escape(str(row.get("type") or ""))
        valid = "VALID" if row.get("valid") else ("checked" if row.get("validated") else "unverified")
        cvss = finding_cvss(sev)
        revoke = html.escape(str(row.get("revocation") or ""))
        verdict = html.escape(str(row.get("ai_verdict") or ""))
        tags = row.get("compliance") or []
        tag_html = ""
        if isinstance(tags, list) and tags:
            tag_html = " · " + html.escape(",".join(str(t) for t in tags))
        preview = ""
        if row.get("response_preview"):
            preview = (
                "<pre class='preview'>"
                + html.escape(str(row.get("response_preview"))[:800])
                + "</pre>"
            )
        cards.append(
            "<article class='hit'>"
            f"<div class='sev' style='background:{color}'>{html.escape(sev)}</div>"
            f"<div class='meta'><strong>{typ}</strong> · {valid}"
            + (f" · priority {verdict} (rules)" if verdict else "")
            + f" · CVSS {cvss}{tag_html}</div>"
            f"<div class='key'>{key}</div>"
            f"<div class='src'><a href='{src}'>{src}</a></div>"
            f"<div class='note'>{note}</div>"
            + (f"<div class='note'>Revoke: {revoke}</div>" if revoke else "")
            + preview
            + "</article>"
        )
    new_line = ""
    if extra.get("new_count") is not None:
        new_line = f"<div class='stat'>New since last scan <b>{extra['new_count']}</b></div>"
    body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>ReconPipe — {html.escape(domain)}</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; background:#0b1220; color:#e2e8f0; margin:0; }}
main {{ max-width: 980px; margin: 0 auto; padding: 24px; }}
h1 {{ margin: 0 0 8px; }}
.stats {{ display:flex; gap:12px; flex-wrap:wrap; margin: 16px 0 24px; }}
.stat {{ background:#111827; border:1px solid #1f2937; padding:10px 14px; border-radius:8px; }}
.hit {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:14px; margin:10px 0; }}
.sev {{ display:inline-block; color:#fff; font-size:12px; padding:2px 8px; border-radius:999px; text-transform:uppercase; }}
.key {{ font-family: ui-monospace, monospace; margin:8px 0; }}
.src a {{ color:#93c5fd; font-size:12px; word-break:break-all; }}
.note {{ color:#94a3b8; font-size:13px; margin-top:6px; }}
.exec {{ color:#cbd5e1; line-height:1.45; }}
.preview {{ background:#0b1220; padding:8px; font-size:11px; overflow:auto; }}
</style></head><body><main>
<h1>ReconPipe report</h1>
<p>{html.escape(domain)} · {html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
<p class="exec">{exec_txt}</p>
<div class="stats">
  <div class="stat">Findings <b>{len(findings)}</b></div>
  <div class="stat">Valid <b>{sum(1 for f in findings if f.get("valid"))}</b></div>
  <div class="stat">Exposures <b>{len(exposures or [])}</b></div>
  {new_line}
</div>
{''.join(cards) or '<p>No findings.</p>'}
</main></body></html>
"""
    path = Path(path)
    path.write_text(body, encoding="utf-8")
    return path


def split_tester_keys(text: str) -> List[str]:
    """Split a Key Tester paste into one credential per non-empty line."""
    out: List[str] = []
    for ln in (text or "").splitlines():
        item = ln.strip().strip(",")
        if item:
            out.append(item)
    return out


def attach_github_scopes(result: Dict, headers: Optional[Dict[str, str]]) -> None:
    if not headers:
        return
    lowered = {str(k).lower(): v for k, v in headers.items()}
    scopes = lowered.get("x-oauth-scopes") or lowered.get("x-accepted-oauth-scopes")
    accepted = lowered.get("x-accepted-oauth-scopes")
    if scopes:
        parsed = [s.strip() for s in str(scopes).split(",") if s.strip()]
        result["github_scopes"] = parsed
        extra = "scopes=" + ",".join(parsed)
        note = str(result.get("note") or "")
        if extra not in note:
            result["note"] = (note + " | " + extra).strip(" |")
    if accepted and "x-oauth-scopes" not in lowered:
        parsed = [s.strip() for s in str(accepted).split(",") if s.strip()]
        result.setdefault("github_scopes", parsed)


def compare_scan_runs(
    previous: List[Dict],
    current: List[Dict],
) -> Dict[str, List[Dict]]:
    def _hid(item: Dict) -> str:
        h = str(item.get("hash") or "").strip().lower()
        if h:
            return h
        return finding_hash(str(item.get("type") or ""), str(item.get("key") or ""))

    prev_map = {_hid(x): x for x in previous or [] if _hid(x)}
    curr_map = {_hid(x): x for x in current or [] if _hid(x)}
    new_items = [curr_map[h] for h in curr_map if h not in prev_map]
    gone = [prev_map[h] for h in prev_map if h not in curr_map]
    unchanged = [curr_map[h] for h in curr_map if h in prev_map]
    return {"new": new_items, "resolved": gone, "unchanged": unchanged}


def write_run_diff(output_dir: Path, current: List[Dict]) -> Dict[str, Any]:
    prev_path = Path(output_dir) / "previous_findings.json"
    findings_path = Path(output_dir) / "findings.json"
    previous: List[Dict] = []
    src = prev_path if prev_path.is_file() else findings_path
    if src.is_file():
        try:
            loaded = json.loads(src.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                previous = loaded
        except Exception:
            previous = []
    diff = compare_scan_runs(previous, current)
    payload = {
        "new_count": len(diff["new"]),
        "resolved_count": len(diff["resolved"]),
        "unchanged_count": len(diff["unchanged"]),
        "new": [
            {
                "type": f.get("type"),
                "hash": f.get("hash"),
                "severity": finding_severity(f),
                "source_url": f.get("source_url"),
                "key": redact_key(str(f.get("key") or "")),
            }
            for f in diff["new"]
        ],
        "resolved": [
            {
                "type": f.get("type"),
                "hash": f.get("hash"),
                "source_url": f.get("source_url"),
            }
            for f in diff["resolved"]
        ],
    }
    (Path(output_dir) / "findings_diff.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    if findings_path.is_file():
        try:
            shutil.copy2(findings_path, prev_path)
        except OSError:
            pass
    return payload


def _safe_notify_text(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9 .,_:()\[\]/+-]", " ", text or "")[:180]


def notify_desktop(title: str, body: str) -> bool:
    """Best-effort desktop toast. Never raises."""
    title = _safe_notify_text(title) or "ReconPipe"
    body = _safe_notify_text(body)
    try:
        if sys.platform.startswith("linux"):
            if shutil.which("notify-send"):
                subprocess.Popen(
                    ["notify-send", title, body],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
        elif sys.platform == "darwin":
            script = (
                f'display notification "{body.replace(chr(34), "")}" '
                f'with title "{title.replace(chr(34), "")}"'
            )
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        elif sys.platform == "win32":
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$n=New-Object System.Windows.Forms.NotifyIcon; "
                "$n.Icon=[System.Drawing.SystemIcons]::Information; $n.Visible=$true; "
                f"$n.ShowBalloonTip(6000,'{title}','{body}','Info')"
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-Command", ps],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    except Exception:
        return False
    return False


def notify_webhook(url: str, payload: Dict[str, Any]) -> bool:
    """POST a redacted payload. Discord/Slack wrappers when the URL matches."""
    target = (url or "").strip()
    if not target:
        return False
    body: Any = payload
    if "discord.com/api/webhooks" in target or "discordapp.com/api/webhooks" in target:
        text = payload.get("text") or json.dumps(payload)[:1800]
        body = {"content": str(text)[:1900]}
    elif "hooks.slack.com" in target:
        body = {"text": payload.get("text") or json.dumps(payload)[:1800]}
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        target,
        data=raw,
        headers={"Content-Type": "application/json", "User-Agent": "ReconPipe/1.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= int(resp.status) < 300
    except urllib.error.HTTPError as exc:
        return 200 <= int(exc.code) < 300
    except Exception:
        return False


def notify_scan_complete(
    domain: str,
    valid_findings: List[Dict],
    webhook: str = "",
    desktop: bool = True,
) -> None:
    n = len(valid_findings or [])
    title = "ReconPipe"
    if n:
        body = f"{n} valid key(s) on {domain}"
    else:
        body = f"Scan complete for {domain} — no valid keys"
    if desktop:
        notify_desktop(title, body)
    if webhook and n:
        payload = {
            "text": body,
            "domain": domain,
            "valid_count": n,
            "keys": [
                {
                    "type": f.get("type"),
                    "severity": finding_severity(f),
                    "key": redact_key(str(f.get("key") or "")),
                    "note": f.get("note"),
                    "source_url": f.get("source_url"),
                }
                for f in valid_findings[:25]
            ],
        }
        try:
            ok = notify_webhook(webhook, payload)
            if ok:
                log(f"Webhook notified ({n} valid)", "success")
            else:
                log("Webhook notify failed", "warn")
        except Exception as exc:
            log(f"Webhook notify error: {exc}", "warn")


def notify_stage_progress(webhook: str, stage: str, progress: float, metrics: Optional[Dict] = None) -> bool:
    if not (webhook or "").strip():
        return False
    payload = {
        "event": "stage_progress",
        "text": f"ReconPipe stage {stage} ({int(float(progress) * 100)}%)",
        "stage": stage,
        "progress": progress,
        "metrics": metrics or {},
        "timestamp": datetime.now().isoformat(),
    }
    return notify_webhook(webhook, payload)


def remember_wayback_file(path: Path, meta: Dict[str, str]) -> None:
    info = {k: str(v) for k, v in (meta or {}).items() if v}
    WAYBACK_BY_FILE[str(path)] = info
    try:
        WAYBACK_BY_FILE[str(path.resolve())] = info
    except Exception:
        pass
    WAYBACK_BY_FILE[path.name] = info


def annotate_wayback_findings(findings: List[Dict]) -> None:
    if not WAYBACK_BY_FILE:
        return
    for item in findings or []:
        src = str(item.get("source_url") or "")
        meta = WAYBACK_BY_FILE.get(src)
        if not meta and src:
            meta = WAYBACK_BY_FILE.get(Path(src).name)
        if not meta:
            continue
        item["from_wayback"] = True
        if meta.get("archive_url"):
            item["wayback_url"] = meta["archive_url"]
        original = meta.get("original") or ""
        if original:
            item["source_file"] = src
            item["source_url"] = original


def download_url_file(
    url: str,
    dl_dir: Path,
    ua: str,
    timeout: int = 8,
    wayback: bool = False,
) -> str:
    fname = download_filename(url)
    out_path = Path(dl_dir) / fname
    if not (url.startswith("http://") or url.startswith("https://")):
        src = Path(url)
        if src.is_file() and src.stat().st_size > 0:
            try:
                if not out_path.is_file():
                    shutil.copy2(src, out_path)
            except Exception:
                pass
            return "cached"
        return "skipped"
    if out_path.is_file() and out_path.stat().st_size > 0:
        return "cached"
    apply_polite_delay()
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": ua, **SCAN_EXTRA_HEADERS})
        with urllib.request.urlopen(req, timeout=min(5, timeout)) as resp:
            ct = resp.headers.get("Content-Type") or ""
            if not content_type_allowed(ct):
                return "skipped"
    except Exception:
        pass
    cond = etag_request_headers(DOWNLOAD_ETAG_CACHE.get(url) or {})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua, **SCAN_EXTRA_HEADERS, **cond})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type") or ""
            if not content_type_allowed(ct):
                return "skipped"
            blob = resp.read() or b""
            out_path.write_bytes(blob)
            hdrs = {k.lower(): v for k, v in (resp.headers.items() if resp.headers else [])}
            DOWNLOAD_ETAG_CACHE[url] = etag_cache_update(
                DOWNLOAD_ETAG_CACHE.get(url) or {},
                hdrs,
                hashlib.sha256(blob).hexdigest() if blob else "",
            )
        return "downloaded"
    except urllib.error.HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) == 304 and out_path.is_file():
            return "cached"
        if not wayback or not SCAN_WAYBACK_BODIES:
            return "error"
        apply_polite_delay()
        got = fetch_wayback_body(url, timeout=max(timeout, 15), ua=ua)
        if not got:
            return "error"
        body, meta = got
        ct = meta.get("content_type") or ""
        if ct and not content_type_allowed(ct):
            return "skipped"
        out_path.write_bytes(body)
        remember_wayback_file(out_path, {**meta, "original": meta.get("original") or url})
        return "wayback"
    except Exception:
        if not wayback or not SCAN_WAYBACK_BODIES:
            return "error"
        apply_polite_delay()
        got = fetch_wayback_body(url, timeout=max(timeout, 15), ua=ua)
        if not got:
            return "error"
        body, meta = got
        ct = meta.get("content_type") or ""
        if ct and not content_type_allowed(ct):
            return "skipped"
        out_path.write_bytes(body)
        remember_wayback_file(out_path, {**meta, "original": meta.get("original") or url})
        return "wayback"


def download_files_parallel(
    urls: List[str],
    dl_dir: Path,
    *,
    workers: int = 16,
    timeout: int = 8,
    wayback: bool = True,
) -> Dict[str, int]:
    dl_dir = Path(dl_dir)
    dl_dir.mkdir(parents=True, exist_ok=True)
    cache_path = Path(dl_dir).parent / "download_etag.json"
    global DOWNLOAD_ETAG_CACHE
    if not DOWNLOAD_ETAG_CACHE:
        DOWNLOAD_ETAG_CACHE = load_etag_cache(cache_path)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    counts = {"downloaded": 0, "cached": 0, "skipped": 0, "error": 0, "wayback": 0}
    workers = max(1, min(int(workers or 16), 32))
    if SCAN_POLITE_DELAY > 0:
        workers = 1
    url_status: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(download_url_file, url, dl_dir, ua, timeout, False): url
            for url in urls
        }
        done = 0
        for fut in as_completed(futs):
            url = futs[fut]
            status = "error"
            try:
                status = fut.result()
            except Exception:
                status = "error"
            url_status[url] = status
            counts[status] = counts.get(status, 0) + 1
            done += 1
            if done % 100 == 0:
                log(
                    f"  Downloaded: {counts['downloaded']}/{len(urls)} "
                    f"(cached {counts['cached']}, skipped {counts['skipped']})...",
                    "info",
                )
                if _ETA is not None:
                    _ETA.set_work(progress=min(0.55, done / max(len(urls), 1) * 0.55))
    if wayback and SCAN_WAYBACK_BODIES:
        failed = [u for u, st in url_status.items() if st == "error"][:WAYBACK_MAX]
        if failed:
            log(f"Wayback: retrying {len(failed)} dead URL(s) via CDX snapshots...", "info")
            wb_workers = 1 if SCAN_POLITE_DELAY > 0 else 2
            with ThreadPoolExecutor(max_workers=wb_workers) as pool:
                futs = {
                    pool.submit(download_url_file, url, dl_dir, ua, timeout, True): url
                    for url in failed
                }
                for fut in as_completed(futs):
                    status = "error"
                    try:
                        status = fut.result()
                    except Exception:
                        status = "error"
                    if status == "wayback":
                        counts["error"] = max(0, counts.get("error", 0) - 1)
                        counts["wayback"] = counts.get("wayback", 0) + 1
                    elif status != "error":
                        counts["error"] = max(0, counts.get("error", 0) - 1)
                        counts[status] = counts.get(status, 0) + 1
    if WAYBACK_BY_FILE:
        side = Path(dl_dir).parent / "wayback_sources.json"
        try:
            side.write_text(json.dumps(WAYBACK_BY_FILE, indent=2), encoding="utf-8")
        except Exception:
            pass
    try:
        save_etag_cache(cache_path, DOWNLOAD_ETAG_CACHE)
    except Exception:
        pass
    return counts


def iter_scan_files(*roots: Path, limit: int = 2500) -> List[Path]:
    out: List[Path] = []
    seen: Set[str] = set()
    for root in roots:
        if root is None:
            continue
        base = Path(root)
        if not base.exists():
            continue
        files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
        for path in files:
            try:
                key = str(path.resolve())
            except OSError:
                key = str(path)
            if key in seen:
                continue
            try:
                if path.stat().st_size > 4_000_000:
                    continue
            except OSError:
                continue
            seen.add(key)
            out.append(path)
            if len(out) >= limit:
                return out
    return out


def _http_get_bytes(url: str, timeout: int = 10) -> Optional[bytes]:
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    apply_polite_delay()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": ua, "Accept": "*/*", **SCAN_EXTRA_HEADERS}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type") or ""
            if ct and not content_type_allowed(ct) and "json" not in ct.lower():
                return None
            return resp.read() or b""
    except Exception:
        return None


def reconstruct_downloaded_js_maps(
    urls: List[str],
    dl_dir: Path,
    dest_dir: Path,
) -> Tuple[int, int]:
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    maps = 0
    files = 0
    index: List[Dict[str, str]] = []
    for url in urls:
        if maps >= addons.SOURCEMAP_MAX_MAPS:
            break
        if not looks_like_js_url(url):
            continue
        js_path = Path(dl_dir) / download_filename(url)
        if not js_path.is_file():
            continue
        try:
            js_text = js_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        map_blob: Optional[str] = None
        map_url_used = ""
        for cand in source_map_url_candidates(url, js_text):
            if cand.lower().startswith("data:"):
                map_blob = decode_source_map_data_url(cand)
                map_url_used = cand[:80]
            else:
                raw = _http_get_bytes(cand, timeout=10)
                if not raw:
                    continue
                try:
                    map_blob = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue
                map_url_used = cand
                map_disk = Path(dl_dir) / download_filename(cand)
                try:
                    if not map_disk.is_file():
                        map_disk.write_bytes(raw)
                except OSError:
                    pass
            if map_blob and looks_like_source_map_json(map_blob):
                break
            map_blob = None
        if not map_blob:
            continue
        prefix = hashlib.md5((map_url_used or url).encode()).hexdigest()[:10]
        written = write_reconstructed_sources(
            map_blob, dest_dir, prefix=prefix
        )
        if not written:
            for src_url in source_fetch_urls(map_blob, map_url_used):
                raw = _http_get_bytes(src_url, timeout=8)
                if not raw:
                    continue
                try:
                    text = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue
                rel = safe_source_relpath(urlparse(src_url).path or "source.js")
                path = dest_dir / prefix / rel
                try:
                    path.resolve().relative_to(dest_dir.resolve())
                except (OSError, ValueError):
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", errors="replace")
                written.append(path)
                if len(written) >= addons.RECONSTRUCT_MAX_FILES:
                    break
        if not written:
            continue
        maps += 1
        files += len(written)
        index.append(
            {
                "js_url": url,
                "map_url": map_url_used,
                "files": str(len(written)),
            }
        )
    if index:
        try:
            (dest_dir / "index.json").write_text(
                json.dumps(index, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        try:
            (dest_dir.parent / "reconstructed_sources.json").write_text(
                json.dumps(index, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
    return maps, files


def fetch_live_js_history(
    urls: List[str],
    dl_dir: Path,
    dest_dir: Path,
    max_versions: Optional[int] = None,
) -> Tuple[int, List[Dict]]:
    """
    Wayback CDX history for live JS. Oldest unique bodies first (hash-deduped),
    capped per URL by max_versions / --js-history-max (default 15).
    Consecutive unique versions are diffed; removed secret-like lines become findings.
    """
    dest_dir = Path(dest_dir)
    wb_dir = dest_dir / "_wayback"
    wb_dir.mkdir(parents=True, exist_ok=True)
    written_n = 0
    index: List[Dict[str, str]] = []
    removed_rows: List[Dict[str, str]] = []
    diff_findings: List[Dict] = []
    if max_versions is None:
        max_versions = SCAN_JS_HISTORY_MAX or addons.JS_HISTORY_MAX_VERSIONS
    try:
        per_url = max(1, min(int(max_versions), 200))
    except (TypeError, ValueError):
        per_url = addons.JS_HISTORY_MAX_VERSIONS
    fetch_budget = min(addons.JS_HISTORY_MAX_FETCH, max(per_url * 3, per_url))
    cdx_limit = min(addons.JS_HISTORY_CDX_LIMIT, max(per_url * 6, 24))
    js_urls = [u for u in urls if looks_like_js_url(u)][: addons.JS_HISTORY_MAX_URLS]
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    for url in js_urls:
        live = Path(dl_dir) / download_filename(url)
        live_bytes = b""
        live_hash = ""
        live_text = ""
        if live.is_file():
            try:
                live_bytes = live.read_bytes()
                live_hash = hashlib.sha256(live_bytes).hexdigest()
                live_text = live_bytes.decode("utf-8", errors="replace")
            except OSError:
                live_hash = ""
        snaps = select_oldest_snapshots(
            list_cdx_snapshots(url, timeout=20, limit=cdx_limit),
            fetch_budget,
        )
        seen_hash: Set[str] = set()
        if live_hash:
            seen_hash.add(live_hash)
        versions: List[Tuple[str, str, str]] = []  # ts, hash, text
        fetched = 0
        unique_kept = 0
        for snap in snaps:
            if unique_kept >= per_url or fetched >= fetch_budget:
                break
            archive = snap.get("archive_url") or ""
            if not archive:
                continue
            fetched += 1
            apply_polite_delay()
            try:
                req = urllib.request.Request(
                    archive, headers={"User-Agent": ua, "Accept": "*/*"}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = resp.read() or b""
            except Exception:
                continue
            if not body or looks_like_html_shell(body):
                continue
            body_hash = hashlib.sha256(body).hexdigest()
            if body_hash in seen_hash:
                continue
            seen_hash.add(body_hash)
            fname = f"{snap.get('timestamp') or 'snap'}_{download_filename(url)}"
            out = wb_dir / fname
            try:
                out.write_bytes(body)
            except OSError:
                continue
            remember_wayback_file(
                out,
                {
                    **snap,
                    "original": snap.get("original") or url,
                    "archive_url": archive,
                },
            )
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            versions.append((snap.get("timestamp") or "", body_hash, text))
            index.append(
                {
                    "js_url": url,
                    "timestamp": snap.get("timestamp") or "",
                    "archive_url": archive,
                    "sha256": body_hash,
                    "file": f"_wayback/{fname}",
                }
            )
            written_n += 1
            unique_kept += 1
        if live_text:
            versions.append(("live", live_hash or "live", live_text))
        for i in range(len(versions) - 1):
            old_ts, _, old_text = versions[i]
            new_ts, _, new_text = versions[i + 1]
            gone = diff_removed_lines(old_text, new_text)
            if not gone:
                continue
            hits = findings_from_removed_js_lines(
                gone,
                js_url=url,
                old_ts=old_ts,
                new_ts=new_ts,
            )
            diff_findings.extend(hits)
            if hits or gone:
                removed_rows.append(
                    {
                        "js_url": url,
                        "from": old_ts,
                        "to": new_ts,
                        "removed_lines": str(len(gone)),
                        "secret_hits": str(len(hits)),
                    }
                )
    if index:
        try:
            (dest_dir.parent / "js_history.json").write_text(
                json.dumps(index, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        try:
            (wb_dir / "index.json").write_text(
                json.dumps(index, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
    if removed_rows or diff_findings:
        payload = {
            "pairs": removed_rows,
            "findings": [
                {
                    "type": f.get("type"),
                    "source_url": f.get("source_url"),
                    "note": f.get("note"),
                    "from": f.get("history_from"),
                    "to": f.get("history_to"),
                }
                for f in diff_findings
            ],
        }
        try:
            (dest_dir.parent / "js_history_removed.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
    return written_n, diff_findings


def findings_from_removed_js_lines(
    lines: List[str],
    *,
    js_url: str,
    old_ts: str,
    new_ts: str,
) -> List[Dict]:
    """Regex-scan lines that vanished between consecutive JS snapshots."""
    hits: List[Dict] = []
    seen: Set[str] = set()
    note = (
        f"Removed between Wayback {old_ts or '?'} and {new_ts or 'live'} "
        f"— still present in an archived copy of {js_url}"
    )
    for line in lines:
        if len(line) < 8:
            continue
        for key_type, pattern in PATTERNS.items():
            if key_type in INFORMATIONAL_TYPES:
                continue
            for m in re.finditer(pattern, line):
                raw = m.group(0)
                grp = m.group(m.lastindex) if m.lastindex else raw
                key = grp if grp is not None else raw
                if looks_fake(key):
                    continue
                if key_type == "mapbox_token" and not is_mapbox_token(key):
                    continue
                key_type = refine_secret_type(key_type, key)
                marker = f"{key_type}:{key}"
                if marker in seen:
                    continue
                seen.add(marker)
                hits.append(
                    {
                        "type": key_type,
                        "key": key,
                        "source_url": js_url,
                        "scanner": "js_history_diff",
                        "verified": False,
                        "from_js_history": True,
                        "history_from": old_ts,
                        "history_to": new_ts,
                        "note": note,
                        "removed_line": line[:400],
                    }
                )
    return hits


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)


def pack_hit_bundle(
    output_dir: Path,
    findings: List[Dict],
    exposures: Optional[List[Dict]] = None,
    informational: Optional[List[Dict]] = None,
) -> Optional[Path]:
    """
    When secrets/exposures exist, copy JS/.map sources plus keys and summary
    into <output>/hits so the evidence is in one folder.
    """
    hits = list(findings or []) + list(exposures or [])
    if not hits and not (informational or []):
        return None
    dest = Path(output_dir) / "hits"
    sources = dest / "sources"
    sources.mkdir(parents=True, exist_ok=True)

    for name in (
        "findings.json",
        "valid_keys.json",
        "informational.json",
        "source_map_exposures.json",
        "reconstructed_sources.json",
        "js_history.json",
        "js_history_removed.json",
        "summary.txt",
        "results.sarif",
        "files_to_scan.txt",
        "report.html",
        "report.md",
        "findings.csv",
        "findings_diff.json",
        "remediation.md",
        "llm_report.json",
        "vendors.json",
        "vendors.html",
        "report_pentest.md",
        "report_executive.md",
        "report_executive.html",
    ):
        src = Path(output_dir) / name
        if src.is_file():
            shutil.copy2(src, dest / name)

    wanted_urls = set()
    wanted_local = set()
    for item in hits:
        srcu = str(item.get("source_url") or "").strip()
        if srcu.startswith("http://") or srcu.startswith("https://"):
            wanted_urls.add(srcu)
        elif srcu:
            wanted_local.add(srcu)

    dl = Path(output_dir) / "downloaded_files"
    copied = 0
    index: List[str] = []
    if dl.is_dir():
        wanted_names = {download_filename(u) for u in wanted_urls}
        wanted_names.update(Path(p).name for p in wanted_local)
        for src in dl.iterdir():
            if not src.is_file():
                continue
            suffix = src.suffix.lower()
            keep = src.name in wanted_names or suffix in HIT_SOURCE_EXT
            if not keep:
                continue
            _link_or_copy(src, sources / src.name)
            copied += 1
            if copied >= 2000:
                break

    index.append(f"sources copied: {copied}")
    for url in sorted(wanted_urls):
        index.append(url)
    (dest / "INDEX.txt").write_text("\n".join(index) + ("\n" if index else ""), encoding="utf-8")
    return dest


# Tool helpers
PIPELINE_TOOLS = [
    "chaos", "subfinder", "amass", "assetfinder", "findomain", "dnsx",
    "httpx", "katana", "waymore", "gospider", "gau", "waybackurls",
    "hakrawler", "paramspider", "linkfinder", "naabu", "whatweb",
    "webanalyze", "wappalyzer", "gowitness", "nuclei", "trufflehog", "gitleaks", "spray", "jsleak",
]
DISCOVERY_URL_CAP = 20000
DISCOVERY_PASSIVE_HOST_CAP = 80


def extend_url_set(
    dest: Set[str],
    items: Iterable[str],
    *,
    cap: int = DISCOVERY_URL_CAP,
) -> int:
    """Add URLs until dest hits cap. Returns how many new items were inserted."""
    added = 0
    for raw in items:
        if len(dest) >= cap:
            break
        line = (raw or "").strip()
        if not line:
            continue
        before = len(dest)
        dest.add(line)
        if len(dest) > before:
            added += 1
    return added


def url_set_full(dest: Set[str], cap: int = DISCOVERY_URL_CAP) -> bool:
    return len(dest) >= cap


_CMD_BLOB_CACHE: Dict[Tuple[str, Tuple[str, ...]], str] = {}


def _cmd_blob(path: str, *args: str) -> str:
    key = (str(path), tuple(str(a) for a in args))
    cached = _CMD_BLOB_CACHE.get(key)
    if cached is not None:
        return cached
    blob = ""
    try:
        proc = subprocess.run(
            [path, *args], capture_output=True, timeout=2.5
        )
        blob = ((proc.stdout or b"") + (proc.stderr or b"")).decode(
            "utf-8", errors="replace"
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        blob = ""
    _CMD_BLOB_CACHE[key] = blob
    return blob


def is_projectdiscovery_httpx(help_or_version: str) -> bool:
    """True if CLI text is ProjectDiscovery httpx, not the Python httpx client."""
    text = (help_or_version or "").lower()
    if not text.strip():
        return False
    if "no such option" in text or "usage: httpx [options] url" in text:
        return False
    if "projectdiscovery" in text:
        return True
    if "-silent" in text and ("-list" in text or "-l, -list" in text):
        return True
    if "current version" in text:
        return True
    return False


def is_python_httpx_cli(help_or_version: str) -> bool:
    text = (help_or_version or "").lower()
    return (
        "usage: httpx [options] url" in text
        or "httpx: a next generation http client" in text
        or ("no such option" in text and "url" in text)
    )


def _iter_named_binaries(names: List[str]) -> List[str]:
    """All matching executables on PATH plus common Go install dirs."""
    found: List[str] = []
    seen: set = set()
    extra = [
        str(Path.home() / "go" / "bin"),
        str(Path.home() / "bin"),
        "/usr/local/bin",
        "/usr/bin",
        "/opt/pd-bin",
        "/opt/homebrew/bin",
        str(Path.home() / ".local" / "bin"),
        str(Path.home() / "scoop" / "shims"),
    ]
    gobin = (os.environ.get("GOBIN") or "").strip()
    if gobin:
        extra.append(gobin)
    gopath = (os.environ.get("GOPATH") or "").strip()
    if gopath:
        extra.append(str(Path(gopath) / "bin"))
    dirs = list(os.environ.get("PATH", "").split(os.pathsep)) + extra
    suffixes = [""]
    if os.name == "nt":
        suffixes = [""] + [
            e for e in os.environ.get("PATHEXT", ".EXE;.BAT;.CMD").split(";") if e
        ]
    for directory in dirs:
        if not directory:
            continue
        for name in names:
            for suf in suffixes:
                cand = Path(directory) / f"{name}{suf}"
                try:
                    if not cand.is_file():
                        continue
                    if os.name != "nt" and not os.access(cand, os.X_OK):
                        continue
                    resolved = str(cand.resolve())
                except OSError:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                found.append(str(cand))
    return found


def _httpx_identify(path: str) -> str:
    return (
        _cmd_blob(path, "-version")
        + _cmd_blob(path, "-h")
        + _cmd_blob(path, "--help")
    )


def resolve_httpx_bin() -> Optional[str]:
    """
    Return ProjectDiscovery httpx path. Ignores pip/NiceGUI's Python `httpx` CLI.
    Override with env HTTPX_BIN.
    """
    env = (os.environ.get("HTTPX_BIN") or "").strip()
    if env and is_projectdiscovery_httpx(_httpx_identify(env)):
        return env
    for cand in _iter_named_binaries(["httpx", "httpx-toolkit"]):
        if is_projectdiscovery_httpx(_httpx_identify(cand)):
            return cand
    return None


def python_httpx_on_path() -> Optional[str]:
    for cand in _iter_named_binaries(["httpx"]):
        blob = _httpx_identify(cand)
        if is_python_httpx_cli(blob):
            return cand
        if blob and not is_projectdiscovery_httpx(blob) and (
            "usage: httpx" in blob.lower() or "no such option" in blob.lower()
        ):
            return cand
    return None


def log_httpx_missing() -> None:
    """Explain why live-host filtering is skipped when PD httpx is absent."""
    log("ProjectDiscovery httpx not found — treating all subdomains as live", "warn")
    env = (os.environ.get("HTTPX_BIN") or "").strip()
    if env:
        log(f"HTTPX_BIN={env} is not ProjectDiscovery httpx — ignoring", "warn")
    py = python_httpx_on_path()
    if py:
        log(
            f"PATH httpx is the Python client ({py}), not ProjectDiscovery httpx",
            "warn",
        )
        log(
            "NiceGUI/pip install a CLI named httpx; ReconPipe will not use it as a live-host filter",
            "warn",
        )
    log("Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "warn")
    log(
        "Then put $HOME/go/bin before ~/.local/bin, or set HTTPX_BIN=/path/to/pd/httpx",
        "warn",
    )
    log("On Kali: apt install httpx-toolkit  (binary name: httpx-toolkit)", "warn")


# Presence checks must not run `--help` (whatweb/gowitness/jsluice can hang past 5s
# and were reported MISSING even when installed). Look up the file instead.
TOOL_ALIASES: Dict[str, Tuple[str, ...]] = {
    "wappalyzer": ("webanalyze", "wappalyzer"),
    "webanalyze": ("webanalyze", "wappalyzer"),
    "whatweb": ("whatweb", "WhatWeb"),
    "gplaycli": ("gplaycli", "gplay-cli"),
    "linkfinder": ("linkfinder", "LinkFinder"),
    "paramspider": ("paramspider", "ParamSpider"),
}


def resolve_tool_path(name: str) -> Optional[str]:
    """First matching executable on PATH plus Go / local bin dirs."""
    aliases = list(TOOL_ALIASES.get(name, (name,)))
    if name not in aliases:
        aliases.append(name)
    found = _iter_named_binaries(aliases)
    return found[0] if found else None


def httpx_has_tech_detect(httpx_bin: Optional[str] = None) -> bool:
    path = httpx_bin or resolve_httpx_bin()
    if not path:
        return False
    blob = _httpx_identify(path)
    return help_has_flag(blob, "tech-detect") or help_has_flag(blob, "td")


def check_tool(name: str) -> bool:
    """True if the binary is on PATH (or an alias / httpx tech-detect for Wappalyzer)."""
    if name == "httpx":
        return resolve_httpx_bin() is not None
    if name in ("wappalyzer", "webanalyze"):
        if resolve_tool_path("webanalyze") or resolve_tool_path("wappalyzer"):
            return True
        return httpx_has_tech_detect()
    return resolve_tool_path(name) is not None


def probe_tools(tools: Optional[List[str]] = None) -> Dict[str, bool]:
    """Return {tool: available} for pipeline binaries (and optional extras)."""
    names = tools or PIPELINE_TOOLS
    return {name: check_tool(name) for name in names}


def help_has_flag(blob: str, flag: str) -> bool:
    """True if CLI help documents a flag. Empty blob → assume a modern CLI."""
    token = (flag or "").lstrip("-").lower()
    if not token:
        return False
    if not (blob or "").strip():
        return True
    text = blob.lower()
    if "no such option" in text and token in text and "usage: httpx [options] url" in text:
        return False
    return bool(
        re.search(
            rf"(?:^|[\s,|])-{{1,2}}{re.escape(token)}(?:\s|,|$|=|/)",
            text,
            re.M,
        )
    )


def _extend_if(cmd: List[str], blob: str, flag: str, *values: str) -> None:
    if help_has_flag(blob, flag):
        cmd.append(flag)
        cmd.extend(values)


def build_subfinder_cmd(
    domain: str,
    output_file: str,
    help_blob: Optional[str] = None,
) -> List[str]:
    blob = help_blob if help_blob is not None else _cmd_blob("subfinder", "-h")
    cmd = ["subfinder"]
    _extend_if(cmd, blob, "-d", domain)
    _extend_if(cmd, blob, "-o", output_file)
    _extend_if(cmd, blob, "-silent")
    if "-d" not in cmd:
        cmd.extend(["-d", domain])
    if "-o" not in cmd:
        cmd.extend(["-o", output_file])
    return cmd


def build_chaos_cmd(
    domain: str,
    output_file: str,
    api_key: str = "",
    help_blob: Optional[str] = None,
) -> List[str]:
    domain = normalize_scan_domain(domain)
    blob = help_blob if help_blob is not None else _cmd_blob("chaos", "-h")
    cmd = ["chaos"]
    _extend_if(cmd, blob, "-d", domain)
    _extend_if(cmd, blob, "-o", output_file)
    _extend_if(cmd, blob, "-silent")
    if api_key:
        _extend_if(cmd, blob, "-key", api_key)
    if "-d" not in cmd:
        cmd.extend(["-d", domain])
    if "-o" not in cmd:
        cmd.extend(["-o", output_file])
    return cmd


def build_katana_cmd(
    list_file: str,
    output_file: str,
    *,
    headless: bool = False,
    jsl: bool = False,
    help_blob: Optional[str] = None,
) -> List[str]:
    """ProjectDiscovery katana flags from current README (-silent, -list, -jc, -kf)."""
    blob = help_blob if help_blob is not None else _cmd_blob("katana", "-h")
    cmd = ["katana"]
    _extend_if(cmd, blob, "-silent")
    if help_has_flag(blob, "list"):
        cmd.extend(["-list", list_file])
    else:
        cmd.extend(["-u", list_file])
    _extend_if(cmd, blob, "-jc")
    if help_has_flag(blob, "kf"):
        cmd.extend(["-kf", "all"])
    _extend_if(cmd, blob, "-d", "3")
    _extend_if(cmd, blob, "-c", "20")
    _extend_if(cmd, blob, "-rl", "150")
    _extend_if(cmd, blob, "-timeout", "10")
    _extend_if(cmd, blob, "-o", output_file)
    if jsl:
        _extend_if(cmd, blob, "-jsl")
    if headless:
        _extend_if(cmd, blob, "-hl")
        _extend_if(cmd, blob, "-nos")
    return cmd


def build_gospider_cmd(list_file: str, output_dir: str, help_blob: Optional[str] = None) -> List[str]:
    blob = help_blob if help_blob is not None else _cmd_blob("gospider", "--help")
    cmd = ["gospider"]
    _extend_if(cmd, blob, "-S", list_file)
    _extend_if(cmd, blob, "-c", "10")
    _extend_if(cmd, blob, "-d", "3")
    _extend_if(cmd, blob, "--js")
    _extend_if(cmd, blob, "-t", "20")
    _extend_if(cmd, blob, "--sitemap")
    _extend_if(cmd, blob, "--robots")
    _extend_if(cmd, blob, "--delay", "1")
    _extend_if(cmd, blob, "-q")
    _extend_if(cmd, blob, "-o", output_dir)
    if "-S" not in cmd:
        cmd.extend(["-S", list_file, "-o", output_dir])
    return cmd


def build_waymore_cmd(host: str, output_file: str, help_blob: Optional[str] = None) -> List[str]:
    blob = help_blob if help_blob is not None else _cmd_blob("waymore", "--help")
    cmd = ["waymore"]
    _extend_if(cmd, blob, "-i", host)
    if help_has_flag(blob, "mode"):
        cmd.extend(["-mode", "U"])
    _extend_if(cmd, blob, "-oU", output_file)
    if "-i" not in cmd:
        cmd.extend(["-i", host, "-mode", "U", "-oU", output_file])
    return cmd


def build_gau_cmd(host: str, threads: int = 5, help_blob: Optional[str] = None) -> List[str]:
    blob = help_blob if help_blob is not None else _cmd_blob("gau", "--help")
    cmd = ["gau"]
    if help_has_flag(blob, "threads"):
        cmd.extend(["--threads", str(threads)])
    if help_has_flag(blob, "timeout"):
        cmd.extend(["--timeout", "30"])
    cmd.append(host)
    return cmd


def build_httpx_cmd(
    httpx_bin: str,
    list_file: str,
    output_file: str,
    *,
    threads: int = 50,
    timeout: int = 10,
    help_blob: Optional[str] = None,
) -> List[str]:
    """ProjectDiscovery httpx: -silent -nc -l -o -t -timeout (not the Python client)."""
    blob = help_blob if help_blob is not None else _httpx_identify(httpx_bin)
    cmd = [httpx_bin]
    _extend_if(cmd, blob, "-silent")
    _extend_if(cmd, blob, "-nc")
    if help_has_flag(blob, "list") or help_has_flag(blob, "l"):
        cmd.extend(["-l", list_file])
    else:
        cmd.extend(["-l", list_file])
    _extend_if(cmd, blob, "-o", output_file)
    _extend_if(cmd, blob, "-t", str(threads))
    _extend_if(cmd, blob, "-timeout", str(timeout))
    return cmd


def trufflehog_filesystem_cmd(scan_dir: str, help_blob: Optional[str] = None) -> List[str]:
    """
    TruffleHog v3: `trufflehog --no-update --json filesystem DIR`

    `--no-update` is always passed. Auto-update tries to replace the running
    binary and fails with "cannot move binary" on apt/Homebrew/root installs,
    then exits before scanning. `--path` is invalid on current builds.
    help_blob is accepted for tests but does not drop --no-update/--json.
    """
    return ["trufflehog", "--no-update", "--json", "filesystem", scan_dir]


CMD_TIMEOUT_RC = -2
CMD_NOTFOUND_RC = -1


def _snippet_bytes(data: Optional[bytes], limit: int = 500) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " | ".join(lines[:8])[:limit]


def _is_trufflehog_updater_error(text: str) -> bool:
    t = (text or "").lower()
    return "trufflehog updater" in t or "cannot move binary" in t


def _trufflehog_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = os.environ.copy()
    if extra:
        env.update(extra)
    env["TRUFFLEHOG_NO_UPDATE"] = "true"
    return env


def run_cmd(cmd: List[str], output_file: Optional[str] = None,
            stdin_data: Optional[bytes] = None, timeout: int = 300,
            discard_stdout: bool = False,
            env: Optional[Dict[str, str]] = None) -> Tuple[int, bytes]:
    """
    Run an external tool. Set discard_stdout=True when the tool writes its
    results to a file (-o / -oU) so URL dumps are not buffered in RAM.
    """
    run_env = env
    bin_name = Path(cmd[0]).name.lower() if cmd else ""
    if bin_name.startswith("trufflehog"):
        run_env = _trufflehog_env(env)
    try:
        with eta_heartbeat(timeout):
            proc = subprocess.run(
                cmd,
                input=stdin_data,
                stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=run_env,
            )
        stdout = b"" if discard_stdout else (proc.stdout or b"")
        if output_file and stdout:
            Path(output_file).write_bytes(stdout)
        if proc.returncode not in (0, None):
            err = _snippet_bytes(proc.stderr)
            if err:
                if _is_trufflehog_updater_error(err):
                    log(
                        "TruffleHog auto-update could not replace its binary "
                        "(install dir not writable). --no-update is always passed.",
                        "warn",
                    )
                else:
                    log(f"{cmd[0]} error: {err}", "warn")
        return proc.returncode, stdout
    except subprocess.TimeoutExpired as e:
        # Keep any stdout produced before the kill — callers may still use partial results
        partial = b"" if discard_stdout else (e.stdout or b"")
        if isinstance(partial, str):
            partial = partial.encode()
        log(f"Timed out: {' '.join(cmd)}", "warn")
        if output_file and partial:
            Path(output_file).write_bytes(partial)
        return CMD_TIMEOUT_RC, partial
    except (FileNotFoundError, OSError):
        log(f"Tool not found: {cmd[0]}", "error")
        return CMD_NOTFOUND_RC, b""


def run_cmd_with_retry(
    cmd: List[str],
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs: Any,
) -> Tuple[int, bytes]:
    return addons.run_cmd_with_retry(
        run_cmd, cmd, max_retries=max_retries, base_delay=base_delay, **kwargs
    )


# Dedup / filters / scanner
def deduplicate(findings: List[Dict]) -> List[Dict]:
    """Collapse findings that share the same type, key, and source URL."""
    seen: set = set()
    unique: List[Dict] = []
    for f in findings:
        h = hashlib.sha256(
            f"{f.get('type','')}:{f.get('key','')}:{f.get('source_url') or f.get('source') or ''}".encode()
        ).hexdigest()
        if h not in seen:
            seen.add(h)
            if not f.get("hash") and f.get("type") and f.get("key") is not None:
                f = {**f, "hash": finding_hash(str(f.get("type")), str(f.get("key")))}
            unique.append(f)
    return unique


def path_is_noisy(path: str) -> bool:
    p = path.lower()
    return any(re.search(rx, p, re.I) for rx in IGNORED_PATH_PATTERNS)


def is_source_map_path(path: str) -> bool:
    """True if URL/path looks like a JavaScript source map."""
    if not path:
        return False
    # Strip fragment; keep query so app.js.map?v=1 still matches
    clean = path.split("#", 1)[0]
    return bool(SOURCE_MAP_PATH_RE.search(clean))


def looks_like_source_map_json(content: str) -> bool:
    """True if body is a sourcemap JSON object (mappings + sources*)."""
    text = (content or "").lstrip()
    if not text.startswith("{"):
        return False
    try:
        data = json.loads(content)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return "mappings" in data and (
        "sources" in data or "sourcesContent" in data or "file" in data
    )


def expand_source_map_content(content: str) -> str:
    """
    Append decoded sourcesContent (and source paths) so secret regexes
    see the original unminified sources, not only the JSON wrapper.
    """
    try:
        data = json.loads(content)
    except Exception:
        return content
    if not isinstance(data, dict):
        return content
    parts = [content]
    sources = data.get("sources")
    if isinstance(sources, list) and sources:
        parts.append("\n".join(str(s) for s in sources if s))
    sc = data.get("sourcesContent")
    if isinstance(sc, list):
        for chunk in sc:
            if isinstance(chunk, str) and chunk.strip():
                parts.append(chunk)
    return "\n".join(parts) if len(parts) > 1 else content


def make_source_map_exposure(source_url: str, scanner: str = "custom_regex") -> Dict:
    """Build a source_map_exposure finding for a publicly reachable .map."""
    return {
        "type": "source_map_exposure",
        "key": source_url,
        "hash": finding_hash("source_map_exposure", source_url),
        "source_url": source_url,
        "scanner": scanner,
        "tier": "exposure",
        "confidence": CONFIDENCE.get("source_map_exposure", 92),
        "note": EXPOSURE_NOTES["source_map_exposure"],
        "verified": True,
        "valid": True,
        "validated": True,
    }


def has_context(content: str, start: int, end: int, window: int = 100) -> bool:
    left  = max(0, start - window)
    right = min(len(content), end + window)
    chunk = content[left:right].lower()
    return any(word in chunk for word in CONTEXT_WORDS)


HEROKU_CONTEXT_WORDS = ("heroku", "herokuapp", "platform-api", "heroku.com")


def has_heroku_context(content: str, start: int, end: int, window: int = 100) -> bool:
    """True if a UUID sits near Heroku-specific markers (not just generic bearer)."""
    left  = max(0, start - window)
    right = min(len(content), end + window)
    chunk = content[left:right].lower()
    return any(word in chunk for word in HEROKU_CONTEXT_WORDS)


def is_mapbox_token(value: str) -> bool:
    """True if pk.* payload base64url-decodes to JSON with Mapbox user fields."""
    if not value.startswith("pk.") or len(value) < 24:
        return False
    # Mapbox: pk.<base64url-json>[.<signature>...]
    b64 = value[3:].split(".", 1)[0]
    try:
        pad = "=" * ((4 - len(b64) % 4) % 4)
        raw = base64.urlsafe_b64decode(b64 + pad)
        data = json.loads(raw)
        return isinstance(data, dict) and ("u" in data or "ul" in data)
    except Exception:
        return False


def _b64url_json(segment: str) -> Optional[Dict]:
    """Decode a JWT base64url segment into a JSON object."""
    if not segment:
        return None
    try:
        pad = "=" * ((4 - len(segment) % 4) % 4)
        raw = base64.urlsafe_b64decode(segment + pad)
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def inspect_jwt(token: str) -> Dict:
    """
    Decode JWT header + payload (no signature verify).
    Surfaces alg/none, exp liveness, kid/iss/aud intelligence.
    """
    info: Dict = {
        "ok": False,
        "alg": None,
        "kid": None,
        "typ": None,
        "exp": None,
        "iat": None,
        "nbf": None,
        "iss": None,
        "aud": None,
        "sub": None,
        "expired": None,
        "alg_none": False,
        "live": False,
        "claims": {},
    }
    parts = (token or "").split(".")
    if len(parts) < 2:
        info["error"] = "not_jwt_shape"
        return info

    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    if header is None or payload is None:
        info["error"] = "decode_failed"
        return info

    info["ok"] = True
    info["alg"] = header.get("alg")
    info["kid"] = header.get("kid")
    info["typ"] = header.get("typ")
    alg = str(header.get("alg") if header.get("alg") is not None else "").strip().lower()
    info["alg_none"] = alg in ("none", "null")

    now = int(datetime.now(timezone.utc).timestamp())
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        info["exp"] = int(exp)
        info["expired"] = int(exp) < now
        info["live"] = not info["expired"]
    else:
        # No exp claim — treat as still actionable intel
        info["live"] = True

    for k in ("iss", "aud", "sub", "iat", "nbf"):
        if k in payload:
            info[k] = payload[k]

    keep = (
        "iss", "aud", "sub", "exp", "iat", "nbf", "azp", "scope", "scp",
        "email", "preferred_username", "cid", "client_id", "role", "ref",
    )
    info["claims"] = {k: payload[k] for k in keep if k in payload}
    if "role" in payload:
        info["role"] = payload.get("role")
    return info


def is_supabase_service(jwt_meta: Optional[Dict]) -> bool:
    """True when a JWT is a Supabase service_role / project token."""
    if not jwt_meta or not jwt_meta.get("ok"):
        return False
    iss = str(jwt_meta.get("iss") or "")
    claims = jwt_meta.get("claims") or {}
    role = str(jwt_meta.get("role") or claims.get("role") or "")
    blob = " ".join(
        [
            iss,
            str(claims.get("iss") or ""),
            str(claims.get("ref") or ""),
            role,
        ]
    ).lower()
    if role == "anon":
        return False
    if "supabase" in blob:
        return True
    if role == "service_role" and ("supabase.co" in iss.lower() or claims.get("ref")):
        return True
    return False


def is_n8n_api_token(value: str) -> bool:
    """Legacy n8n_api_ prefix or current public-API JWT (iss=n8n, aud=public-api)."""
    text = (value or "").strip()
    if text.startswith("n8n_api_") and len(text) >= 20:
        return True
    return is_n8n_jwt(inspect_jwt(text))


def refine_secret_type(key_type: str, key: str) -> str:
    """Reclassify JWTs / unknown hits that are actually n8n public API keys."""
    raw = (key or "").strip()
    if is_n8n_api_token(raw):
        return "n8n_api"
    return key_type or ""


def validate_azure_sas(token: str) -> Dict[str, Any]:
    """Local SAS parse: require sig=, classify by se= expiry. No HTTP."""
    text = (token or "").strip()
    qs = text.split("?", 1)[-1] if "?" in text else text
    params = parse_qs(qs.replace("&amp;", "&"), keep_blank_values=True)
    sig = (params.get("sig") or [""])[0]
    se = unquote((params.get("se") or [""])[0])
    st = unquote((params.get("st") or [""])[0])
    result: Dict[str, Any] = {
        "validated": True,
        "status_code": None,
        "valid": False,
        "note": "",
        "azure_sas": {"sig": bool(sig), "se": se, "st": st},
    }
    if not sig:
        result["note"] = "Invalid SAS: missing sig="
        return result
    expired = None
    if se:
        try:
            exp = datetime.fromisoformat(se.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            expired = datetime.now(timezone.utc) > exp
        except Exception:
            expired = None
    bits = [f"se={se}" if se else "no se=", f"st={st}" if st else ""]
    bits = [b for b in bits if b]
    if expired is True:
        result["note"] = "INTEL (expired Azure SAS); " + "; ".join(bits)
        result["valid"] = False
        return result
    if expired is False:
        result["valid"] = True
        result["note"] = "LIVE Azure SAS; " + "; ".join(bits)
        return result
    result["valid"] = True
    result["note"] = "Azure SAS (sig present; expiry unknown); " + "; ".join(bits)
    return result


def validate_gcp_service_account(blob: str) -> Dict[str, Any]:
    """Local JSON inspect — do not authenticate to Google with leaked material."""
    result: Dict[str, Any] = {
        "validated": True,
        "status_code": None,
        "valid": False,
        "note": "",
    }
    data = None
    try:
        data = json.loads(blob)
    except Exception:
        m = re.search(r"\{.*\}", blob or "", re.S)
        if m:
            try:
                data = json.loads(m.group(0))
            except Exception:
                data = None
    if not isinstance(data, dict):
        email = ""
        proj = ""
        em = re.search(r'"client_email"\s*:\s*"([^"]+)"', blob or "")
        pm = re.search(r'"project_id"\s*:\s*"([^"]+)"', blob or "")
        if em:
            email = em.group(1)
        if pm:
            proj = pm.group(1)
        if "service_account" in (blob or "") and "BEGIN" in (blob or ""):
            result["valid"] = True
            result["note"] = f"GCP service account JSON (client_email={email or '?'}; project={proj or '?'})"
            result["gcp_sa"] = {"client_email": email, "project_id": proj}
            return result
        result["note"] = "Could not parse GCP service account JSON"
        return result
    email = str(data.get("client_email") or "")
    proj = str(data.get("project_id") or "")
    pk = str(data.get("private_key") or "")
    if str(data.get("type") or "") == "service_account" and pk:
        result["valid"] = True
        result["note"] = f"GCP service account JSON; client_email={email or '?'}; project={proj or '?'}"
        result["gcp_sa"] = {"client_email": email, "project_id": proj}
        return result
    result["note"] = "JSON is not a GCP service_account blob"
    return result


def validate_jwt_inspect(token: str) -> Dict:
    """Classify a JWT from decoded claims (local, no network)."""
    analysis = inspect_jwt(token)
    result: Dict = {
        "validated": True,
        "status_code": None,
        "valid": False,
        "note": "",
        "jwt": analysis,
    }
    if not analysis.get("ok"):
        result["note"] = f"JWT decode failed ({analysis.get('error', 'unknown')})"
        return result

    bits: List[str] = []
    has_intel = bool(
        analysis.get("kid") or analysis.get("iss") or analysis.get("aud")
        or analysis.get("sub")
    )

    if analysis.get("alg_none"):
        bits.append("VULN: alg=none (signature bypass)")
        result["valid"] = True
    elif analysis.get("alg") is not None:
        bits.append(f"alg={analysis['alg']}")

    if analysis.get("kid"):
        bits.append(f"kid={analysis['kid']}")

    if analysis.get("iss"):
        bits.append(f"iss={analysis['iss']}")
    if analysis.get("aud") is not None:
        aud = analysis["aud"]
        if isinstance(aud, list):
            aud = ",".join(str(a) for a in aud[:4])
        bits.append(f"aud={aud}")
    if analysis.get("sub"):
        bits.append(f"sub={analysis['sub']}")

    if analysis.get("expired") is True:
        prefix = "INTEL (expired)"
        # Expired + kid/iss/aud/sub is still reportable intelligence
        if has_intel or analysis.get("alg_none"):
            result["valid"] = True
        else:
            result["note"] = "; ".join([prefix] + bits) if bits else "Expired JWT"
            return result
    elif analysis.get("expired") is False:
        prefix = "LIVE JWT"
        result["valid"] = True
        if analysis.get("exp"):
            bits.append(f"exp={analysis['exp']}")
    else:
        prefix = "JWT (no exp)"
        result["valid"] = True

    # Keep VULN: alg=none as the lead signal when present
    if analysis.get("alg_none"):
        result["note"] = "; ".join(bits)
    else:
        result["note"] = "; ".join([prefix] + bits)
    return result


def looks_fake(value: str) -> bool:
    """Reject stopwords, tiny values, and low-entropy placeholders."""
    v = value.strip().lower()
    if not v or len(v) < 8:
        return True
    if v in STOPWORDS:
        return True
    if len(set(v)) <= 2:
        return True
    for word in ["example", "placeholder", "dummy", "your_", "insert_", "replace_"]:
        if word in v:
            return True
    return False


_PIN_VALUE_PREFIX = re.compile(
    r"(?i)^sha(?:1|256)/[A-Za-z0-9+/]{27,88}={0,2}$"
)
_PIN_B64 = re.compile(r"^[A-Za-z0-9+/]{27,88}={0,2}$")
_PIN_HEX = re.compile(r"^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_PIN_CONTEXT = re.compile(
    r"certificate\s*pins?|cert(?:ificate)?\s*pins?|\bpin-set\b|\bpinning\b|"
    r"CertificatePinner|NSPinned|SPKI-SHA256|publicKeyHashes?|"
    r"digest\s*=\s*[\"']SHA-?256|\bsha256/|\bsha1/",
    re.I,
)
_PIN_PATH = re.compile(
    r"network_security_config|certificatepinner|nspinned|trustkit|"
    r"public_key_pins|pin-set|cert(?:ificate)?[_-]?pins?",
    re.I,
)
_PIN_LABEL = re.compile(
    r"certificate[_\s-]*pins?|cert(?:ificate)?[_\s-]*pins?|\bpinning\b|"
    r"public[_\s-]*key[_\s-]*pins?|\bspki\b",
    re.I,
)
_REAL_SECRET_PREFIX = re.compile(
    r"^(?:sk_live_|sk_test_|sk-proj-|sk-ant-|AKIA|ASIA|ghp_|github_pat_|xox[baprs]-|eyJ)"
)


def is_certificate_pin(
    value: str,
    content: str = "",
    start: int = 0,
    end: int = 0,
    source: str = "",
) -> bool:
    """True for public cert/SPKI pins. Those are not API keys."""
    text = (value or "").strip().strip("'\"")
    if not text or _REAL_SECRET_PREFIX.match(text):
        return False
    if _PIN_VALUE_PREFIX.match(text):
        return True
    window = ""
    if content and end >= start:
        window = content[max(0, start - 140): min(len(content), end + 140)]
    pinned = bool(_PIN_CONTEXT.search(window) or _PIN_PATH.search(source or ""))
    if not pinned:
        return False
    if _PIN_B64.match(text) or _PIN_HEX.match(text):
        return True
    return False


def is_certificate_pin_finding(finding: Dict) -> bool:
    label = " ".join(
        str(finding.get(k) or "")
        for k in ("type", "detector", "note", "likely_service")
    )
    if _PIN_LABEL.search(label):
        return True
    return is_certificate_pin(
        str(finding.get("key") or ""),
        source=str(
            finding.get("source_url")
            or finding.get("file")
            or finding.get("source")
            or ""
        ),
    )


def drop_certificate_pins(findings: List[Dict]) -> Tuple[List[Dict], int]:
    kept: List[Dict] = []
    dropped = 0
    for item in findings or []:
        if is_certificate_pin_finding(item):
            dropped += 1
            continue
        kept.append(item)
    return kept, dropped


def entropy(s: str) -> float:
    """Shannon entropy in bits/char over the observed alphabet."""
    if not s:
        return 0.0
    n = len(s)
    prob = [s.count(c) / n for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def is_dictionary_word(value: str) -> bool:
    """True for known plain-word tokens (generic_secret false positives)."""
    v = value.strip().lower()
    if not v:
        return True
    if v in DICTIONARY_WORDS or v in STOPWORDS:
        return True
    # Strip common separators and re-check (my-password, my_password)
    compact = re.sub(r"[\s_\-]+", "", v)
    return compact in DICTIONARY_WORDS or compact in STOPWORDS


def finding_hash(key_type: str, key: str) -> str:
    """Stable sha256 for baseline / --ignore-hash (type:key)."""
    return hashlib.sha256(f"{key_type}:{key}".encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_baseline(output_dir: Path) -> Dict[str, Dict]:
    """
    Load baseline map: {hash: {type, first_seen, sources: [urls], ignore_all?}}.

    Legacy list-of-hash strings migrate to ignore_all=True (preserve old global suppress).
    """
    fp = output_dir / BASELINE_FILE
    if not fp.exists():
        return {}
    try:
        raw = json.loads(fp.read_text())
    except Exception:
        return {}

    if isinstance(raw, list):
        migrated: Dict[str, Dict] = {}
        now = _now_iso()
        for h in raw:
            if isinstance(h, str) and h.strip():
                migrated[h.strip().lower()] = {
                    "type": "legacy",
                    "first_seen": now,
                    "sources": [],
                    "ignore_all": True,
                }
        return migrated

    if not isinstance(raw, dict):
        return {}

    out: Dict[str, Dict] = {}
    for h, ent in raw.items():
        if not isinstance(h, str):
            continue
        key = h.strip().lower()
        if isinstance(ent, dict):
            sources = ent.get("sources") or []
            if not isinstance(sources, list):
                sources = []
            out[key] = {
                "type": ent.get("type") or "unknown",
                "first_seen": ent.get("first_seen") or _now_iso(),
                "sources": [str(s) for s in sources if s],
                "ignore_all": bool(ent.get("ignore_all")),
            }
        elif isinstance(ent, str):
            # accidental {hash: url} — treat as single source
            out[key] = {
                "type": "unknown",
                "first_seen": _now_iso(),
                "sources": [ent] if ent else [],
                "ignore_all": False,
            }
    return out


def save_baseline(output_dir: Path, baseline: Dict[str, Dict]) -> None:
    fp = output_dir / BASELINE_FILE
    # Stable key order for readable diffs
    ordered = {k: baseline[k] for k in sorted(baseline.keys())}
    fp.write_text(json.dumps(ordered, indent=2))


def baseline_should_suppress(baseline: Dict[str, Dict], h: str, source: str) -> bool:
    """True if hash is ignore_all, or this exact source was already recorded."""
    ent = baseline.get((h or "").strip().lower())
    if not ent:
        return False
    if ent.get("ignore_all"):
        return True
    if not source:
        return False
    return source in (ent.get("sources") or [])


def baseline_record(
    baseline: Dict[str, Dict],
    h: str,
    key_type: str,
    source: str = "",
    ignore_all: bool = False,
) -> None:
    """Upsert a baseline entry; append source if new."""
    key = (h or "").strip().lower()
    if not key:
        return
    ent = baseline.get(key)
    if ent is None:
        baseline[key] = {
            "type": key_type or "unknown",
            "first_seen": _now_iso(),
            "sources": [source] if source and not ignore_all else [],
            "ignore_all": bool(ignore_all),
        }
        return
    if ignore_all:
        ent["ignore_all"] = True
    if key_type and (not ent.get("type") or ent.get("type") in ("unknown", "legacy", "manual")):
        ent["type"] = key_type
    if source and source not in (ent.get("sources") or []):
        ent.setdefault("sources", []).append(source)


def apply_ignore_hashes(output_dir: Path, hashes: List[str]) -> int:
    """Mark hashes ignore_all=True in baseline; return how many were applied."""
    baseline = load_baseline(output_dir)
    n = 0
    for raw in hashes:
        h = (raw or "").strip().lower()
        if not h:
            continue
        baseline_record(baseline, h, "manual", "", ignore_all=True)
        n += 1
    if n:
        save_baseline(output_dir, baseline)
    return n


def record_findings_in_baseline(output_dir: Path, findings: List[Dict]) -> int:
    """Record reported findings' type+source into baseline; return newly sourced count."""
    baseline = load_baseline(output_dir)
    added = 0
    for f in findings:
        t = f.get("type") or "unknown"
        key = f.get("key") or ""
        src = f.get("source_url") or f.get("source") or ""
        h = f.get("hash") or finding_hash(t, key)
        before = set((baseline.get(h) or {}).get("sources") or [])
        existed = h in baseline
        baseline_record(baseline, h, t, src)
        after = set((baseline.get(h) or {}).get("sources") or [])
        if not existed or (src and src not in before) or after != before:
            added += 1
    save_baseline(output_dir, baseline)
    return added


def filter_by_baseline(findings: List[Dict], baseline: Dict[str, Dict]) -> List[Dict]:
    """Drop findings already seen at the same source (or ignore_all hashes)."""
    out: List[Dict] = []
    for f in findings:
        t = f.get("type") or "unknown"
        key = f.get("key") or ""
        src = f.get("source_url") or f.get("source") or ""
        h = f.get("hash") or finding_hash(t, key)
        f["hash"] = h
        if baseline_should_suppress(baseline, h, src):
            continue
        out.append(f)
    return out


def score_confidence(key_type: str, key: str, content: str,
                     start: int, end: int) -> int:
    """Static weight + keyword proximity + Shannon entropy."""
    ent = entropy(key)

    if key_type == "generic_secret":
        # Entropy-weighted base (gate at GENERIC_SECRET_MIN_ENTROPY upstream)
        # ~3.5 → 45, ~4.5 → 55, ~5.5 → 65 before proximity bonuses
        base = 10 + int(min(max(ent, 0.0), 6.0) * 10)
    else:
        base = CONFIDENCE.get(key_type, 30)
        if ent >= 4.5:
            base = min(base + 5, 100)
        elif ent < 3.0 and len(key) >= 16:
            base = max(base - 5, 0)

    if has_context(content, start, end):
        base = min(base + 10, 100)

    nearby = content[max(0, start-50):min(len(content), end+50)]
    if re.search(r'[:=]\s*["\']', nearby):
        base = min(base + 5, 100)

    if any(w in key.lower() for w in ["test", "example", "demo", "sample"]):
        base = max(base - 20, 0)

    if len(key) < 16:
        base = max(base - 15, 0)

    return base


def attach_public_api_meta(item: Dict, hint: Optional[Dict]) -> Dict:
    if not hint:
        return item
    name = str(hint.get("name") or "").strip()
    if name:
        item["likely_service"] = name
    item["public_api"] = True
    if hint.get("auth"):
        item["public_api_auth"] = hint.get("auth")
    item["confidence"] = max(int(item.get("confidence") or 0), 55)
    return item


def collect_public_api_query_findings(
    content: str,
    source_url: str,
    *,
    seen_pairs: Optional[set] = None,
    baseline: Optional[Dict] = None,
    extra: Optional[Dict] = None,
) -> List[Dict]:
    if not SCAN_PUBLIC_APIS:
        return []
    extra = extra or {}
    seen_pairs = seen_pairs if seen_pairs is not None else set()
    baseline = baseline if baseline is not None else {}
    out: List[Dict] = []
    for hit in public_api_query_secrets(content):
        key = str(hit.get("key") or "")
        if looks_fake(key) or entropy(key) < GENERIC_SECRET_MIN_ENTROPY:
            continue
        key_type = str(hit.get("type") or "public_api_key")
        h = finding_hash(key_type, key)
        if baseline_should_suppress(baseline, h, source_url) or (h, source_url) in seen_pairs:
            continue
        seen_pairs.add((h, source_url))
        start = int(hit.get("start") or 0)
        end = int(hit.get("end") or start)
        confidence = max(score_confidence(key_type, key, content, start, end), 58)
        item: Dict = {
            "type": key_type,
            "key": key,
            "hash": h,
            "source_url": source_url,
            "scanner": "public_api_catalog",
            "verified": False,
            "confidence": confidence,
            "detector": hit.get("detector") or "public_api_query",
        }
        if hit.get("likely_service"):
            item["likely_service"] = hit["likely_service"]
            item["public_api"] = True
        if extra.get("from_wayback"):
            item["from_wayback"] = True
            if extra.get("wayback_url"):
                item["wayback_url"] = extra["wayback_url"]
        out.append(item)
    return out


def apply_secrets_pattern_entries(entries: List[Dict[str, str]]) -> int:
    """Merge filtered secrets-patterns-db rows into PATTERNS/CONFIDENCE."""
    global PATTERNS, CONFIDENCE
    added = 0
    for row in entries or []:
        regex = (row.get("regex") or "").strip()
        if not regex:
            continue
        name = row.get("name") or "pattern"
        slug = secrets_db_slug(name)
        base = slug
        n = 2
        while slug in PATTERNS:
            slug = f"{base}_{n}"
            n += 1
        PATTERNS[slug] = regex
        conf = 72 if (row.get("confidence") or "").lower() == "high" else 48
        CONFIDENCE[slug] = conf
        added += 1
    return added


def load_secrets_pattern_db_files(
    paths: List[Path],
    *,
    include_medium: bool = False,
) -> int:
    if not YAML_AVAILABLE:
        return 0
    added = 0
    existing = dict(PATTERNS)
    for path in paths:
        if not path or not Path(path).is_file():
            continue
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except Exception:
            log(f"secrets-patterns-db: could not read {path}", "warn")
            continue
        filtered = filter_secrets_db_entries(
            iter_secrets_pattern_entries(data),
            existing,
            include_medium=include_medium,
        )
        n = apply_secrets_pattern_entries(filtered)
        for row in filtered:
            existing[secrets_db_slug(row.get("name") or "pattern")] = row.get("regex") or ""
        added += n
        if n:
            log(f"secrets-patterns-db: +{n} regex(es) from {Path(path).name}", "info")
    return added


def findings_from_jsleak(rows: List[Dict[str, str]]) -> List[Dict]:
    out: List[Dict] = []
    for row in rows or []:
        secret = str(row.get("secret") or "").strip()
        if not secret or looks_fake(secret):
            continue
        if entropy(secret) < GENERIC_SECRET_MIN_ENTROPY:
            continue
        name = str(row.get("name") or "jsleak")
        key_type = secrets_db_slug(name)
        if key_type not in PATTERNS:
            key_type = "generic_secret"
        item = {
            "type": key_type,
            "key": secret,
            "source_url": str(row.get("source_url") or ""),
            "scanner": "jsleak",
            "detector": name,
            "verified": False,
            "confidence": CONFIDENCE.get(key_type, 60),
        }
        out.append(item)
    return out


def save_informational(output_dir: Path, items: List[Dict]) -> int:
    """Merge informational hits into informational.json; return newly added count."""
    if not items:
        return 0
    ifile = output_dir / "informational.json"
    existing: List[Dict] = []
    if ifile.exists():
        try:
            loaded = json.loads(ifile.read_text())
            if isinstance(loaded, list):
                existing = loaded
        except Exception:
            pass
    known = {(e.get("type"), e.get("key"), e.get("source_url")) for e in existing}
    added = 0
    for it in items:
        ident = (it.get("type"), it.get("key"), it.get("source_url"))
        if ident not in known:
            existing.append(it)
            known.add(ident)
            added += 1
    ifile.write_text(json.dumps(existing, indent=2))
    return added


def split_informational(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Separate actionable findings from public-by-design informational hits."""
    actionable, info = [], []
    for f in findings:
        if f.get("tier") == "informational" or f.get("type") in INFORMATIONAL_TYPES:
            f = {**f, "tier": "informational"}
            f.setdefault("note", INFORMATIONAL_NOTES.get(f.get("type", ""), "Informational"))
            info.append(f)
        else:
            actionable.append(f)
    return actionable, info


def save_exposures(output_dir: Path, items: List[Dict]) -> int:
    """Merge exposure findings into source_map_exposures.json; return newly added count."""
    if not items:
        return 0
    efile = output_dir / "source_map_exposures.json"
    existing: List[Dict] = []
    if efile.exists():
        try:
            loaded = json.loads(efile.read_text())
            if isinstance(loaded, list):
                existing = loaded
        except Exception:
            pass
    known = {(e.get("type"), e.get("key"), e.get("source_url")) for e in existing}
    added = 0
    for it in items:
        ident = (it.get("type"), it.get("key"), it.get("source_url"))
        if ident not in known:
            existing.append(it)
            known.add(ident)
            added += 1
    efile.write_text(json.dumps(existing, indent=2))
    return added


def split_exposures(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Separate secret findings from exposure-bucket findings (e.g. source maps)."""
    actionable, exposures = [], []
    for f in findings:
        if f.get("tier") == "exposure" or f.get("type") in EXPOSURE_TYPES:
            f = {**f, "tier": "exposure"}
            f.setdefault("note", EXPOSURE_NOTES.get(f.get("type", ""), "Exposure"))
            exposures.append(f)
        else:
            actionable.append(f)
    return actionable, exposures


MCP_CLASSIFY_SKIP = frozenset({
    "generic_secret", "uuid_candidate", "jwt", "firebase_url", "public_api_key",
})


def classify_secret_type(value: str) -> Optional[str]:
    """Map a raw MCP env/header value onto an existing PATTERNS type."""
    text = (value or "").strip()
    if not text:
        return None
    if is_n8n_api_token(text):
        return "n8n_api"
    for key_type, pattern in PATTERNS.items():
        if key_type in MCP_CLASSIFY_SKIP or key_type in INFORMATIONAL_TYPES:
            continue
        try:
            if re.search(pattern, text):
                return key_type
        except re.error:
            continue
    return None


def findings_from_mcp_content(
    page: str,
    url: str,
    scanner: str = "mcp_config",
) -> List[Dict]:
    """AI/MCP credential detection for mcp.json and sibling client configs."""
    if not looks_like_mcp_config(url, page):
        return []
    out: List[Dict] = []
    for row in extract_mcp_secrets(page, url):
        key = str(row.get("key") or "").strip()
        if not key or looks_fake(key):
            continue
        key_type = classify_secret_type(key) or "mcp_credential"
        item = {
            "type": key_type,
            "key": key,
            "hash": finding_hash(key_type, key),
            "source_url": url,
            "scanner": scanner,
            "verified": False,
            "mcp_config": True,
            "mcp_field": row.get("field") or "",
            "confidence": max(int(CONFIDENCE.get(key_type, 70)), 70),
        }
        out.append(item)
    return out


def _load_scan_text(url: str, ua: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """Load page text from a local path, live HTTP, or a Wayback snapshot."""
    extra: Dict[str, Any] = {}
    if not (url.startswith("http://") or url.startswith("https://")):
        path = Path(url)
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="ignore"), extra
            except Exception:
                return None, extra
        return None, extra
    apply_polite_delay()
    try:
        req_headers = {"User-Agent": ua, **SCAN_EXTRA_HEADERS}
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.read().decode("utf-8", errors="ignore"), extra
    except Exception:
        if not SCAN_WAYBACK_BODIES:
            return None, extra
        apply_polite_delay()
        got = fetch_wayback_body(url, timeout=15, ua=ua)
        if not got:
            return None, extra
        body, meta = got
        extra["from_wayback"] = True
        extra["wayback_url"] = meta.get("archive_url") or ""
        extra["wayback_original"] = meta.get("original") or url
        return body.decode("utf-8", errors="ignore"), extra


def custom_scan(urls_file: str, output_dir: Optional[Path] = None) -> List[Dict]:
    """HTTP regex scanner with confidence scoring, baseline suppression, and quarantine."""
    findings: List[Dict] = []
    informational: List[Dict] = []
    exposures: List[Dict] = []
    quarantine: List[Dict] = []
    seen_pairs: set = set()
    baseline: Dict[str, Dict] = load_baseline(output_dir) if output_dir else {}

    if not Path(urls_file).exists():
        return findings

    with open(urls_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    log(f"Custom scanner: {len(urls)} URLs", "info")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i, url in enumerate(urls, 1):
        if path_is_noisy(url):
            continue

        if i % 200 == 0:
            log(f"  Progress: {i}/{len(urls)} scanned...", "info")
            if _ETA is not None:
                _ETA.set_work(progress=i / max(len(urls), 1), log_now=True)

        try:
            page, extra = _load_scan_text(url, ua)
            if page is None:
                continue
            from_wayback = bool(extra.get("from_wayback"))

            from_source_map = is_source_map_path(url) or looks_like_source_map_json(page)
            if from_source_map:
                exp_h = finding_hash("source_map_exposure", url)
                if not baseline_should_suppress(baseline, exp_h, url) and (exp_h, url) not in seen_pairs:
                    seen_pairs.add((exp_h, url))
                    exposures.append(make_source_map_exposure(url, "custom_regex"))
                page = expand_source_map_content(page)

            for key_type, pattern in PATTERNS.items():
                for m in re.finditer(pattern, page):
                    raw = m.group(0)
                    grp = m.group(m.lastindex) if m.lastindex else raw
                    key = grp if grp is not None else raw

                    h = finding_hash(key_type, key)
                    if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                        continue
                    seen_pairs.add((h, url))

                    if looks_fake(key):
                        baseline_record(baseline, h, key_type, url)
                        continue

                    if is_certificate_pin(key, page, m.start(), m.end(), url):
                        baseline_record(baseline, h, key_type, url)
                        continue

                    if key_type == "mapbox_token" and not is_mapbox_token(key):
                        baseline_record(baseline, h, key_type, url)
                        continue

                    if key_type in INFORMATIONAL_TYPES:
                        informational.append({
                            "type": key_type,
                            "key": key,
                            "hash": h,
                            "source_url": url,
                            "scanner": "custom_regex",
                            "tier": "informational",
                            "note": INFORMATIONAL_NOTES.get(key_type, "Informational"),
                        })
                        continue

                    needs_context = key_type in {
                        "generic_secret", "uuid_candidate", "jwt",
                        "discord_token", "datadog_api_key", "hashicorp_vault",
                        "vercel_token", "netlify_pat", "algolia_api", "algolia_admin",
                        "pagerduty_api", "trello_api", "okta_api", "clerk_secret",
                    }
                    hint = (
                        match_public_api_hint(page, m.start(), m.end())
                        if SCAN_PUBLIC_APIS
                        else None
                    )
                    if needs_context and not has_context(page, m.start(), m.end()) and not hint:
                        baseline_record(baseline, h, key_type, url)
                        quarantine.append({
                            "type": key_type,
                            "key": key[:40],
                            "source_url": url,
                            "reason": "no_context",
                        })
                        continue

                    if key_type == "uuid_candidate":
                        if has_heroku_context(page, m.start(), m.end(), window=100):
                            key_type = "heroku_api"
                            h = finding_hash(key_type, key)
                            if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                                continue
                            seen_pairs.add((h, url))
                        else:
                            baseline_record(baseline, h, "uuid_candidate", url)
                            quarantine.append({
                                "type": "uuid_candidate",
                                "key": key[:40],
                                "source_url": url,
                                "reason": "uuid_no_heroku_context",
                            })
                            continue

                    if key_type == "generic_secret":
                        ent = entropy(key)
                        if ent < GENERIC_SECRET_MIN_ENTROPY:
                            baseline_record(baseline, h, key_type, url)
                            quarantine.append({
                                "type": key_type,
                                "key": key[:40],
                                "source_url": url,
                                "reason": f"low_entropy_{ent:.2f}",
                            })
                            continue
                        if is_dictionary_word(key):
                            baseline_record(baseline, h, key_type, url)
                            quarantine.append({
                                "type": key_type,
                                "key": key[:40],
                                "source_url": url,
                                "reason": "dictionary_word",
                            })
                            continue

                    jwt_meta: Optional[Dict] = None
                    if key_type in {"jwt", "supabase_service", "supabase_anon", "monday_api", "onepassword_connect"}:
                        jwt_meta = inspect_jwt(key)
                        if not jwt_meta.get("ok"):
                            baseline_record(baseline, h, key_type, url)
                            quarantine.append({
                                "type": key_type,
                                "key": key[:40],
                                "source_url": url,
                                "reason": f"jwt_{jwt_meta.get('error', 'decode_failed')}",
                            })
                            continue
                        if key_type == "supabase_service" and not is_supabase_service(jwt_meta):
                            continue
                        if key_type == "supabase_anon" and not is_supabase_anon(jwt_meta):
                            continue
                        if key_type == "jwt" and is_supabase_service(jwt_meta):
                            key_type = "supabase_service"
                            h = finding_hash(key_type, key)
                            if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                                continue
                            seen_pairs.add((h, url))
                        elif key_type == "jwt" and is_supabase_anon(jwt_meta):
                            key_type = "supabase_anon"
                            h = finding_hash(key_type, key)
                            if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                                continue
                            seen_pairs.add((h, url))
                        else:
                            kind = jwt_provider_kind(jwt_meta)
                            if key_type == "jwt" and kind:
                                key_type = kind
                                h = finding_hash(key_type, key)
                                if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                                    continue
                                seen_pairs.add((h, url))

                    confidence = score_confidence(key_type, key, page, m.start(), m.end())
                    if key_type == "jwt" and jwt_meta:
                        if jwt_meta.get("alg_none"):
                            confidence = max(confidence, 95)
                        elif jwt_meta.get("live"):
                            confidence = max(confidence, 78)
                        elif jwt_meta.get("kid") or jwt_meta.get("iss"):
                            confidence = max(confidence, 70)
                    if key_type == "supabase_service":
                        confidence = max(confidence, 90)
                    if confidence < MIN_CONFIDENCE:
                        baseline_record(baseline, h, key_type, url)
                        quarantine.append({
                            "type": key_type,
                            "key": key[:40],
                            "source_url": url,
                            "reason": f"low_confidence_{confidence}",
                        })
                        continue

                    finding: Dict = {
                        "type": key_type,
                        "key": key,
                        "hash": h,
                        "source_url": url,
                        "scanner": "custom_regex",
                        "verified": False,
                        "confidence": confidence,
                    }
                    if jwt_meta:
                        finding["jwt"] = jwt_meta
                    if from_source_map:
                        finding["from_source_map"] = True
                    if from_wayback:
                        finding["from_wayback"] = True
                        if extra.get("wayback_url"):
                            finding["wayback_url"] = extra["wayback_url"]
                    if hint:
                        attach_public_api_meta(finding, hint)
                    if looks_like_mcp_config(url, page):
                        finding["mcp_config"] = True
                    findings.append(finding)
                    if FINDINGS_STREAM is not None:
                        FINDINGS_STREAM.emit(finding)

            if SCAN_PUBLIC_APIS:
                for item in collect_public_api_query_findings(
                    page, url, seen_pairs=seen_pairs, baseline=baseline, extra=extra
                ):
                    findings.append(item)
                    if FINDINGS_STREAM is not None:
                        FINDINGS_STREAM.emit(item)

            for item in findings_from_mcp_content(page, url):
                h = item.get("hash") or finding_hash(item.get("type") or "", item.get("key") or "")
                item["hash"] = h
                if baseline_should_suppress(baseline, h, url) or (h, url) in seen_pairs:
                    continue
                seen_pairs.add((h, url))
                findings.append(item)
                if FINDINGS_STREAM is not None:
                    FINDINGS_STREAM.emit(item)

        except Exception:
            pass

    if output_dir:
        save_baseline(output_dir, baseline)
        if quarantine:
            qfile = output_dir / "quarantine.json"
            existing: List[Dict] = []
            if qfile.exists():
                try:
                    loaded = json.loads(qfile.read_text())
                    if isinstance(loaded, list):
                        existing = loaded
                except Exception:
                    pass
            known = {(e.get("type"), e.get("key"), e.get("reason")) for e in existing}
            added = 0
            for q in quarantine:
                ident = (q.get("type"), q.get("key"), q.get("reason"))
                if ident not in known:
                    existing.append(q)
                    known.add(ident)
                    added += 1
            qfile.write_text(json.dumps(existing, indent=2))
            log(f"Quarantined {added} new matches → quarantine.json ({len(existing)} total)", "warn")
        if informational:
            n = save_informational(output_dir, informational)
            log(f"Informational {n} public-by-design hits → informational.json", "info")
        if exposures:
            n = save_exposures(output_dir, exposures)
            log(f"Source map exposures: {n} → source_map_exposures.json", "warn")

    findings.extend(exposures)
    log(f"Custom scanner: {len(findings)} findings (confidence ≥ {MIN_CONFIDENCE})", "success")
    return findings


def _finding_source(f: Dict) -> str:
    return (f.get("source_url") or f.get("source") or "").strip()


def _source_host(src: str) -> str:
    if not src:
        return ""
    m = re.match(r"https?://([^/]+)", src, re.I)
    if m:
        return m.group(1).lower()
    try:
        return str(Path(src).resolve().parent).lower()
    except Exception:
        return src.lower()


def _host_complete_pairs(bucket: Dict[str, Dict], part_a: str, part_b: str) -> int:
    """
    Second pass: if a host has exactly one value for each half, fill incomplete
    same-host entries. Returns how many halves were filled.
    """
    filled = 0
    by_host: Dict[str, List[str]] = {}
    for src in bucket:
        host = _source_host(src)
        if host:
            by_host.setdefault(host, []).append(src)

    for srcs in by_host.values():
        a_vals = {bucket[s][part_a] for s in srcs if bucket[s].get(part_a)}
        b_vals = {bucket[s][part_b] for s in srcs if bucket[s].get(part_b)}
        if len(a_vals) != 1 or len(b_vals) != 1:
            continue
        a_val, b_val = next(iter(a_vals)), next(iter(b_vals))
        for s in srcs:
            if bucket[s].get(part_a) and not bucket[s].get(part_b):
                bucket[s][part_b] = b_val
                filled += 1
            elif bucket[s].get(part_b) and not bucket[s].get(part_a):
                bucket[s][part_a] = a_val
                filled += 1
    return filled


def build_credential_pairs(findings: List[Dict]) -> Dict[str, Dict[str, Dict]]:
    """Group AWS / Twilio credential halves by source URL/file."""
    pairs: Dict[str, Dict[str, Dict]] = {"aws": {}, "twilio": {}}
    for f in findings:
        src = _finding_source(f)
        key = f.get("key") or ""
        if not key:
            continue
        t = f.get("type")
        if t == "aws_access_key":
            pairs["aws"].setdefault(src, {})["access"] = key
        elif t == "aws_secret":
            pairs["aws"].setdefault(src, {})["secret"] = key
        elif t == "aws_session_token":
            pairs["aws"].setdefault(src, {})["session"] = key
        elif t == "twilio_sid":
            pairs["twilio"].setdefault(src, {})["sid"] = key
        elif t == "twilio_token":
            pairs["twilio"].setdefault(src, {})["token"] = key
    return pairs


def pair_credential_findings(findings: List[Dict]) -> List[Dict]:
    """
    Attach partner credentials onto findings before validation.

    Pass 1 — same source_url / file
    Pass 2 — same host (cross-file)
    Pass 3 — global unique leftover halves (single unpaired access+secret in scan)
    """
    pairs = build_credential_pairs(findings)
    host_filled = _host_complete_pairs(pairs["aws"], "access", "secret")
    host_filled += _host_complete_pairs(pairs["aws"], "access", "session")
    host_filled += _host_complete_pairs(pairs["aws"], "secret", "session")
    host_filled += _host_complete_pairs(pairs["twilio"], "sid", "token")

    aws_accesses = {p["access"] for p in pairs["aws"].values() if p.get("access")}
    aws_secrets = {p["secret"] for p in pairs["aws"].values() if p.get("secret")}
    aws_sessions = {p["session"] for p in pairs["aws"].values() if p.get("session")}
    tw_sids = {p["sid"] for p in pairs["twilio"].values() if p.get("sid")}
    tw_tokens = {p["token"] for p in pairs["twilio"].values() if p.get("token")}
    global_aws = (
        next(iter(aws_accesses)) if len(aws_accesses) == 1 else None,
        next(iter(aws_secrets)) if len(aws_secrets) == 1 else None,
    )
    global_session = next(iter(aws_sessions)) if len(aws_sessions) == 1 else None
    global_tw = (
        next(iter(tw_sids)) if len(tw_sids) == 1 else None,
        next(iter(tw_tokens)) if len(tw_tokens) == 1 else None,
    )

    aws_paired = tw_paired = 0
    for f in findings:
        src = _finding_source(f)
        t = f.get("type")
        bucket = pairs["aws"].get(src) or {}

        if t == "aws_access_key" and not f.get("aws_secret"):
            secret = bucket.get("secret")
            if not secret and global_aws[0] and global_aws[1] and f.get("key") == global_aws[0]:
                secret = global_aws[1]
            if secret:
                f["aws_secret"] = secret
                f["paired"] = True
                aws_paired += 1

        if t == "aws_access_key" and not f.get("aws_session_token"):
            session = bucket.get("session")
            if not session and global_session:
                session = global_session
            if session:
                f["aws_session_token"] = session
                f["paired"] = True

        elif t == "aws_secret" and not f.get("aws_access_key"):
            access = bucket.get("access")
            if not access and global_aws[0] and global_aws[1] and f.get("key") == global_aws[1]:
                access = global_aws[0]
            if access:
                f["aws_access_key"] = access
                f["paired"] = True
            if not f.get("aws_session_token"):
                session = bucket.get("session") or global_session
                if session:
                    f["aws_session_token"] = session

        elif t == "aws_session_token":
            if not f.get("aws_access_key"):
                access = bucket.get("access")
                if not access and global_aws[0]:
                    access = global_aws[0]
                if access:
                    f["aws_access_key"] = access
                    f["paired"] = True
            if not f.get("aws_secret"):
                secret = bucket.get("secret")
                if not secret and global_aws[1]:
                    secret = global_aws[1]
                if secret:
                    f["aws_secret"] = secret
                    f["paired"] = True

        elif t == "twilio_sid" and not f.get("twilio_token"):
            token = (pairs["twilio"].get(src) or {}).get("token")
            if not token and global_tw[0] and global_tw[1] and f.get("key") == global_tw[0]:
                token = global_tw[1]
            if token:
                f["twilio_token"] = token
                f["paired"] = True
                tw_paired += 1

        elif t == "twilio_token" and not f.get("twilio_sid"):
            sid = (pairs["twilio"].get(src) or {}).get("sid")
            if not sid and global_tw[0] and global_tw[1] and f.get("key") == global_tw[1]:
                sid = global_tw[0]
            if sid:
                f["twilio_sid"] = sid
                f["paired"] = True

    if aws_paired or tw_paired or host_filled:
        log(
            f"Credential pairs: aws={aws_paired} twilio={tw_paired} "
            f"(host-fill={host_filled})",
            "info",
        )
    return pair_generic_findings(findings)


# Back-compat alias
def pair_aws_findings(findings: List[Dict]) -> List[Dict]:
    return pair_credential_findings(findings)


def _aws_sts_sign(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
) -> Tuple[str, Dict[str, str], bytes]:
    """Build a signed STS GetCallerIdentity request (SigV4)."""
    method = "POST"
    service = "sts"
    region = "us-east-1"
    host = "sts.amazonaws.com"
    url = f"https://{host}/"
    amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    payload = b"Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(payload).hexdigest()
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    signed_names = ["content-type", "host", "x-amz-date"]
    hdr_map = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
    }
    if session_token:
        signed_names.append("x-amz-security-token")
        hdr_map["x-amz-security-token"] = session_token
    signed_names.sort()
    canonical_headers = "".join(f"{n}:{hdr_map[n]}\n" for n in signed_names)
    signed_headers = ";".join(signed_names)

    canonical_request = (
        f"{method}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": (
            f"{algorithm} Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return url, headers, payload


def validate_aws_sts_sync(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
) -> Dict:
    """Validate an AWS key pair via STS GetCallerIdentity (boto3 or SigV4)."""
    result = {"validated": True, "status_code": None, "valid": False, "note": ""}

    if BOTO3_AVAILABLE:
        try:
            kwargs = {
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
                "region_name": "us-east-1",
            }
            if session_token:
                kwargs["aws_session_token"] = session_token
            client = boto3.client("sts", **kwargs)
            ident = client.get_caller_identity()
            result["status_code"] = 200
            result["valid"] = True
            arn = ident.get("Arn", "")
            result["note"] = f"VALID: STS GetCallerIdentity{(' — ' + arn) if arn else ''}"
            return result
        except ClientError as e:
            code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            err = e.response.get("Error", {}).get("Code", "")
            result["status_code"] = code
            if err in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDenied",
                       "ExpiredToken", "InvalidToken"):
                result["note"] = f"Invalid/Revoked ({err})"
            else:
                result["note"] = f"Invalid/Revoked ({err or code})"
            return result
        except (BotoCoreError, Exception) as e:
            # Fall through to manual SigV4
            pass

    try:
        url, headers, payload = _aws_sts_sign(access_key, secret_key, session_token)
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "ignore")
            result["status_code"] = resp.status
            if resp.status == 200 and "GetCallerIdentityResult" in body:
                result["valid"] = True
                m = re.search(r"<Arn>([^<]+)</Arn>", body)
                arn = m.group(1) if m else ""
                result["note"] = f"VALID: STS GetCallerIdentity{(' — ' + arn) if arn else ''}"
            else:
                result["note"] = f"Inconclusive (HTTP {resp.status})"
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        err_body = e.read().decode("utf-8", "ignore") if hasattr(e, "read") else ""
        if e.code == 429:
            result["note"] = "Rate-limited/inconclusive (HTTP 429)"
        elif e.code == 403:
            result["note"] = "Invalid/Revoked (HTTP 403)"
            if "InvalidClientTokenId" in err_body or "SignatureDoesNotMatch" in err_body:
                result["note"] = f"Invalid/Revoked ({e.code})"
        else:
            result["note"] = f"HTTP {e.code}"
    except Exception as e:
        result["validated"] = False
        result["note"] = f"Error: {str(e)[:50]}"
    return result


async def validate_aws_sts_async(
    session,
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
) -> Dict:
    """Validate an AWS key pair via STS (boto3 in thread, else SigV4 aiohttp)."""
    if BOTO3_AVAILABLE:
        return await asyncio.to_thread(
            validate_aws_sts_sync, access_key, secret_key, session_token
        )

    result = {"validated": True, "status_code": None, "valid": False, "note": ""}
    try:
        url, headers, payload = _aws_sts_sign(access_key, secret_key, session_token)
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.post(url, data=payload, headers=headers, timeout=timeout) as resp:
            body = await resp.text()
            result["status_code"] = resp.status
            if resp.status == 200 and "GetCallerIdentityResult" in body:
                result["valid"] = True
                m = re.search(r"<Arn>([^<]+)</Arn>", body)
                arn = m.group(1) if m else ""
                result["note"] = f"VALID: STS GetCallerIdentity{(' — ' + arn) if arn else ''}"
            elif resp.status == 403:
                result["note"] = "Invalid/Revoked (HTTP 403)"
            elif resp.status == 429:
                result["note"] = "Rate-limited/inconclusive (HTTP 429)"
            else:
                result["note"] = f"Inconclusive (HTTP {resp.status})"
    except asyncio.TimeoutError:
        result["validated"] = False
        result["note"] = "Timeout during validation"
    except Exception as e:
        result["validated"] = False
        result["note"] = f"Error: {str(e)[:60]}"
    return result


def validate_twilio_pair_sync(sid: str, token: str) -> Dict:
    """Validate Twilio Account SID + Auth Token via Basic auth."""
    result = {"validated": True, "status_code": None, "valid": False, "note": ""}
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    creds = base64.b64encode(f"{sid}:{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result["status_code"] = resp.status
            if resp.status == 200:
                result["valid"] = True
                result["note"] = "VALID: Twilio Account SID+Token authenticated"
            else:
                result["note"] = f"Inconclusive (HTTP {resp.status})"
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        if e.code == 429:
            result["note"] = "Rate-limited/inconclusive (HTTP 429)"
        elif e.code in (401, 403):
            result["note"] = f"Invalid/Revoked (HTTP {e.code})"
        elif e.code == 404:
            result["note"] = "Invalid: Account SID not found (HTTP 404)"
        else:
            result["note"] = f"HTTP {e.code}"
    except Exception as e:
        result["validated"] = False
        result["note"] = f"Error: {str(e)[:50]}"
    return result


async def validate_twilio_pair_async(session, sid: str, token: str) -> Dict:
    """Validate Twilio Account SID + Auth Token via Basic auth (aiohttp)."""
    result = {"validated": True, "status_code": None, "valid": False, "note": ""}
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        auth = aiohttp.BasicAuth(sid, token)
        async with session.get(url, auth=auth, timeout=timeout) as resp:
            result["status_code"] = resp.status
            if resp.status == 200:
                result["valid"] = True
                result["note"] = "VALID: Twilio Account SID+Token authenticated"
            elif resp.status in (401, 403):
                result["note"] = f"Invalid/Revoked (HTTP {resp.status})"
            elif resp.status == 404:
                result["note"] = "Invalid: Account SID not found (HTTP 404)"
            elif resp.status == 429:
                result["note"] = "Rate-limited/inconclusive (HTTP 429)"
            else:
                result["note"] = f"Inconclusive (HTTP {resp.status})"
    except asyncio.TimeoutError:
        result["validated"] = False
        result["note"] = "Timeout during validation"
    except Exception as e:
        result["validated"] = False
        result["note"] = f"Error: {str(e)[:60]}"
    return result


def _aws_access_key_id(value: str) -> Optional[str]:
    m = re.match(r"^(AKIA|ASIA)[0-9A-Z]{16}$", (value or "").strip())
    return m.group(0) if m else None


def _parse_aws_rawv2(raw: str, raw_v2: str) -> Tuple[str, str]:
    """Split TruffleHog AWS Raw/RawV2 into (access_key_id, secret)."""
    access = _aws_access_key_id(raw) or ""
    secret = ""
    v2 = (raw_v2 or "").strip()
    if not v2:
        return access, secret

    if ":" in v2:
        left, right = v2.split(":", 1)
        access = _aws_access_key_id(left) or access
        secret = right.strip()
        return access, secret

    # RawV2 is often AKIA(20 chars) + secret(40) with no delimiter
    if access and v2.startswith(access):
        secret = v2[len(access):].lstrip(":")
        return access, secret

    m = re.match(r"^((?:AKIA|ASIA)[0-9A-Z]{16})(.+)$", v2)
    if m:
        return m.group(1), m.group(2).lstrip(":")
    return access, secret


def _th_raw_str(value) -> str:
    """Coerce TruffleHog Raw/RawV2 to a string; skip structured (dict/list) values."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "ignore").strip()
    return ""


def parse_trufflehog(output: bytes) -> List[Dict]:
    findings: List[Dict] = []
    # Exact DetectorName matches (normalized) — checked before substring fallback
    exact_map = {
        "slackwebhook":   "slack_webhook",
        "discordwebhook": "discord_webhook",
        "slack":          "slack_token",
    }
    # Substring fallback for human-readable names ("Google API Key" → googleapikey)
    type_map = {
        "googleapikey": "google_api", "googlesecrets": "google_api",
        "googlegemini": "google_api", "geminikey": "google_api",
        "github":       "github_pat",
        "gitlab":       "gitlab_pat",
        "stripe":       "stripe_live",
        "huggingface":  "huggingface_token",
        "openai":       "openai_key",
        "anthropic":    "anthropic_key",
        "sendgrid":     "sendgrid",
        "hubspot":      "hubspot_api",
        "n8n":          "n8n_api",
        "groq":         "groq_api",
        "figma":        "figma_token",
        "postman":      "postman_api",
        "databricks":   "databricks_token",
        "twilio":       "twilio_sid",
        "mailgun":      "mailgun",
        "jwt":          "jwt",
        "shopify":      "shopify_token",
        "discord":      "discord_token",
        "telegram":     "telegram_bot",
        "mapbox":       "mapbox_token",
        "digitalocean": "digitalocean_pat",
        "npm":          "npm_token",
        "pypi":         "pypi_token",
        "privatekey":   "private_key_pem",
        "slackwebhook": "slack_webhook",
    }

    for line in output.decode("utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            detector_raw = data.get("DetectorName", data.get("detector_name", "unknown"))
            # "Google API Key" → "googleapikey" so type_map keys match
            detector = re.sub(r"[^a-z0-9]", "", str(detector_raw).lower())

            source_url = ""
            git_commit = ""
            meta = data.get("SourceMetadata", {})
            if isinstance(meta, dict):
                d = meta.get("Data", {})
                if isinstance(d, dict):
                    source_url = (
                        (d.get("Filesystem") or {}).get("file", "") or
                        (d.get("Git") or {}).get("file", "") or
                        (d.get("Git") or {}).get("repository", "") or
                        (d.get("Web") or {}).get("url", "")
                    )
                    git_commit = str((d.get("Git") or {}).get("commit") or "")

            raw = _th_raw_str(data.get("Raw"))
            raw_v2 = _th_raw_str(data.get("RawV2"))
            if not raw:
                raw = _th_raw_str(data.get("raw"))

            # TruffleHog DetectorName is always "AWS" for both access keys and secrets.
            # Raw = AKIA..., RawV2 = AKIA+secret (optional ':' delimiter).
            if detector == "aws" or detector.startswith("aws"):
                access, secret = _parse_aws_rawv2(raw, raw_v2 or raw)
                # Shape-based fallback when Raw isn't an AKIA id
                if not access and _aws_access_key_id(raw):
                    access = raw
                if not secret and raw and not _aws_access_key_id(raw) and len(raw) >= 40:
                    secret = raw

                verified = data.get("Verified", data.get("verified", False))
                detector_name = data.get("DetectorName", "")
                if access:
                    rec = {
                        "type": "aws_access_key",
                        "detector": detector_name,
                        "key": access,
                        "aws_secret": secret or None,
                        "source_url": source_url,
                        "verified": verified,
                        "scanner": "trufflehog",
                    }
                    if git_commit:
                        rec["git_commit"] = git_commit
                    findings.append(rec)
                if secret:
                    rec = {
                        "type": "aws_secret",
                        "detector": detector_name,
                        "key": secret,
                        "aws_access_key": access or None,
                        "source_url": source_url,
                        "verified": verified,
                        "scanner": "trufflehog",
                    }
                    if git_commit:
                        rec["git_commit"] = git_commit
                    findings.append(rec)
                continue

            key_type = exact_map.get(detector, "unknown")
            if key_type == "unknown":
                for k, v in sorted(type_map.items(), key=lambda kv: -len(kv[0])):
                    if k in detector:
                        key_type = v
                        break
                if key_type == "unknown" and detector.startswith("slack"):
                    key_type = "slack_token"

            value = raw or raw_v2
            if value:
                # Distinguish classic ghp_ vs fine-grained github_pat_
                if key_type == "github_pat" and value.startswith("github_pat_"):
                    key_type = "github_fine_pat"
                elif key_type == "stripe_live" and value.startswith("rk_"):
                    key_type = "stripe_restricted"
                elif key_type == "stripe_live" and value.startswith("sk_test_"):
                    key_type = "stripe_test"
                elif key_type == "discord_token" and "/api/webhooks/" in value:
                    key_type = "discord_webhook"
                elif (
                    key_type in ("unknown", "slack_token")
                    and "hooks.slack.com/services/" in value
                ):
                    key_type = "slack_webhook"
                elif key_type == "unknown" and value.startswith("AIza") and len(value) >= 35:
                    key_type = "google_api"
                key_type = refine_secret_type(key_type, value)
                rec = {
                    "type": key_type,
                    "detector": data.get("DetectorName", ""),
                    "key": value,
                    "source_url": source_url,
                    "verified": data.get("Verified", data.get("verified", False)),
                    "scanner": "trufflehog",
                }
                if git_commit:
                    rec["git_commit"] = git_commit
                findings.append(rec)
        except Exception:
            pass

    return findings


GITLEAKS_RULE_MAP = {
    "aws-access-key": "aws_access_key",
    "aws-access-token": "aws_access_key",
    "awsaccesstoken": "aws_access_key",
    "aws-secret-key": "aws_secret",
    "github-pat": "github_pat",
    "githubpat": "github_pat",
    "github-fine-grained-pat": "github_fine_pat",
    "github-oauth": "github_oauth",
    "gitlab-pat": "gitlab_pat",
    "slack-access-token": "slack_token",
    "slack-bot-token": "slack_token",
    "slack-user-token": "slack_token",
    "slack-webhook-url": "slack_webhook",
    "stripe-access-token": "stripe_live",
    "generic-api-key": "generic_secret",
    "generic-secret": "generic_secret",
    "private-key": "private_key_pem",
    "jwt": "jwt",
    "discord-api-token": "discord_token",
    "telegram-bot-api-token": "telegram_bot",
    "heroku-api-key": "heroku_api",
    "npm": "npm_token",
    "npm-access-token": "npm_token",
    "pypi-upload-token": "pypi_token",
    "sendgrid-api-token": "sendgrid",
    "hubspot-api-key": "hubspot_api",
    "hubspot-api-token": "hubspot_api",
    "n8n": "n8n_api",
    "n8n-api-key": "n8n_api",
    "slack-app-token": "slack_app_token",
    "figma": "figma_token",
    "postman": "postman_api",
    "groq": "groq_api",
    "xai": "xai_api",
    "perplexity": "perplexity_api",
    "fireworks": "fireworks_api",
    "databricks": "databricks_token",
    "sonar": "sonar_token",
    "cloudinary": "cloudinary_url",
    "razorpay": "razorpay_key",
    "flutterwave": "flutterwave_secret",
    "twilio-api-key": "twilio_token",
    "openai": "openai_key",
    "anthropic": "anthropic_key",
    "huggingface": "huggingface_token",
}


def gitleaks_type_for(rule_id: str, secret: str) -> str:
    rid = re.sub(r"[^a-z0-9-]", "", (rule_id or "").lower())
    compact = rid.replace("-", "")
    mapped = GITLEAKS_RULE_MAP.get(rid) or GITLEAKS_RULE_MAP.get(compact)
    if not mapped:
        mapped = "generic_secret"
        if rid:
            for key, val in GITLEAKS_RULE_MAP.items():
                k = key.replace("-", "")
                if key in rid or (len(rid) >= 4 and rid in key) or (len(k) >= 4 and k in compact):
                    mapped = val
                    break
    if mapped == "github_pat" and (secret or "").startswith("github_pat_"):
        return "github_fine_pat"
    if mapped == "stripe_live" and (secret or "").startswith("sk_test_"):
        return "stripe_test"
    return refine_secret_type(mapped, secret)


def findings_from_gitleaks(rows: List[Dict], scanner: str = "gitleaks") -> List[Dict]:
    out: List[Dict] = []
    for row in rows or []:
        secret = str(row.get("Secret") or row.get("secret") or "").strip()
        if not secret or looks_fake(secret):
            continue
        rule = str(row.get("RuleID") or row.get("Rule") or row.get("rule_id") or "")
        key_type = gitleaks_type_for(rule, secret)
        src = str(
            row.get("File")
            or row.get("file")
            or row.get("Path")
            or row.get("Fingerprint")
            or ""
        )
        item = {
            "type": key_type,
            "key": secret,
            "source_url": src,
            "scanner": scanner,
            "detector": rule or row.get("Description") or "gitleaks",
            "verified": False,
        }
        commit = row.get("Commit") or row.get("commit")
        if commit:
            item["git_commit"] = str(commit)
        start_line = row.get("StartLine") or row.get("startLine") or row.get("Line")
        if start_line not in (None, ""):
            item["line"] = start_line
        author = row.get("Author") or row.get("author")
        if author:
            item["git_author"] = str(author)
        date = row.get("Date") or row.get("date")
        if date:
            item["git_date"] = str(date)
        out.append(item)
    return out


def run_gitleaks_source(source: Path, report: Path, git: bool = False) -> List[Dict]:
    report.parent.mkdir(parents=True, exist_ok=True)
    if report.exists():
        try:
            report.unlink()
        except OSError:
            pass
    cmds = [
        build_gitleaks_cmd(str(source), str(report), git=git),
        build_gitleaks_detect_cmd(str(source), str(report), git=git),
    ]
    for i, cmd in enumerate(cmds):
        rc, _ = run_cmd(cmd, timeout=300, discard_stdout=True)
        if rc == CMD_NOTFOUND_RC:
            if i == 0:
                log("gitleaks not found — skipping", "warn")
            return []
        if report.is_file() and report.stat().st_size > 0:
            rows = parse_gitleaks_report(report)
            return findings_from_gitleaks(
                rows, scanner="gitleaks_git" if git else "gitleaks"
            )
    return []


def run_spray_leak_probe(live_hosts: List[str], output_dir: Path) -> List[str]:
    wordlist = leak_wordlist_path()
    if not wordlist.is_file():
        log("spray: leak wordlist missing — skipping", "warn")
        return []
    origins: List[str] = []
    seen = set()
    for host in (live_hosts or [])[:25]:
        origin = origin_from_host(host)
        if origin and origin not in seen:
            seen.add(origin)
            origins.append(origin)
    if not origins:
        return []
    targets = Path(output_dir) / "spray_targets.txt"
    targets.write_text("\n".join(origins) + "\n", encoding="utf-8")
    log(f"spray: fuzzing leak/backup paths on {len(origins)} host(s)...", "info")
    rc, output = run_cmd(build_spray_cmd(str(targets), str(wordlist)), timeout=240)
    blob = (output or b"").decode("utf-8", errors="ignore")
    urls = collect_http_urls_from_text(blob)
    extra = Path(output_dir) / "spray_urls.txt"
    if extra.is_file():
        urls.extend(
            collect_http_urls_from_text(extra.read_text(encoding="utf-8", errors="ignore"))
        )
    urls = dedupe_urls(urls)[:500]
    if urls:
        extra.write_text("\n".join(urls) + "\n", encoding="utf-8")
        log(f"spray: {C.BOLD}{len(urls)}{C.RESET} URL(s)", "success")
    else:
        log("spray: no extra leak URLs", "info")
    return urls


def _body_has_restricted_reason(body_text: str, reasons: List[str]) -> bool:
    """True if response body cites a documented key-exists / restricted reason."""
    if not body_text or not reasons:
        return False
    # Reject explicit invalid-key signals first
    if re.search(r"API_KEY_INVALID|keyInvalid|INVALID_ARGUMENT", body_text, re.I):
        return False
    for reason in reasons:
        if reason in body_text:
            return True
    try:
        data = json.loads(body_text)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    err = data.get("error")
    if not isinstance(err, dict):
        return False
    found: List[str] = []
    if isinstance(err.get("status"), str):
        found.append(err["status"])
    for e in err.get("errors") or []:
        if isinstance(e, dict) and e.get("reason"):
            found.append(str(e["reason"]))
    for d in err.get("details") or []:
        if isinstance(d, dict) and d.get("reason"):
            found.append(str(d["reason"]))
    return any(r in found for r in reasons)


def classify_http_status(validator: ValidatorSpec, status: int,
                          body_text: str = "",
                          original_url: str = "",
                          final_url: str = "") -> Tuple[bool, str]:
    """
    Map an HTTP status (+ optional body/redirect) to (valid, note).
    Order: 429 → login-redirect → slack probe → invalid → valid → restricted → inconclusive.
    """
    if status == 429:
        return False, "Rate-limited/inconclusive (HTTP 429)"

    if final_url and _redirect_to_login(original_url, final_url):
        return False, (
            f"Inconclusive: redirected to login page ({_short_url(final_url)})"
        )

    if validator.slack_webhook_probe:
        return _classify_slack_webhook(status, body_text)

    if status in validator.invalid_codes:
        return False, f"Invalid/Revoked (HTTP {status})"
    if status in validator.valid_codes:
        note = validator.note_for(status)
        if final_url and original_url and final_url.rstrip("/") != original_url.rstrip("/"):
            note = f"{note} (via {_short_url(final_url)})"
        return True, note
    if status in validator.restricted_codes:
        reasons = validator.restricted_body_reasons or []
        if reasons:
            if _body_has_restricted_reason(body_text, reasons):
                return True, validator.note_for(
                    status, f"VALID (restricted HTTP {status})"
                )
            return False, (
                f"Inconclusive (HTTP {status}) — no key-restriction signal in body"
            )
        return True, validator.note_for(
            status, f"VALID (restricted HTTP {status})"
        )
    return False, f"Inconclusive (HTTP {status})"


GOOGLE_API_PROBES: List[Dict[str, Any]] = [
    {
        "id": "geolocation",
        "kind": "geolocation",
        "method": "POST",
        "url": "https://www.googleapis.com/geolocation/v1/geolocate?key={key}",
        "json_body": {"considerIp": True},
    },
    {
        "id": "geocoding",
        "kind": "maps_json",
        "method": "GET",
        "url": "https://maps.googleapis.com/maps/api/geocode/json?latlng=40.0,30.0&key={key}",
    },
    {
        "id": "timezone",
        "kind": "maps_json",
        "method": "GET",
        "url": (
            "https://maps.googleapis.com/maps/api/timezone/json"
            "?location=39.6034810,-119.6822510&timestamp=1331161200&key={key}"
        ),
    },
    {
        "id": "elevation",
        "kind": "maps_json",
        "method": "GET",
        "url": (
            "https://maps.googleapis.com/maps/api/elevation/json"
            "?locations=39.7391536,-104.9847034&key={key}"
        ),
    },
    {
        "id": "youtube",
        "kind": "youtube",
        "method": "GET",
        "url": (
            "https://www.googleapis.com/youtube/v3/activities"
            "?part=id&maxResults=1&channelId=UC-lHJZR3Gqxm24_Vd_AJ5Yw&key={key}"
        ),
    },
    {
        "id": "gemini",
        "kind": "gemini",
        "method": "GET",
        "url": "https://generativelanguage.googleapis.com/v1beta/models?key={key}",
    },
]


def interpret_google_probe(kind: str, status: int, body: str) -> str:
    """Map one Google probe to enabled | restricted | denied | invalid | error."""
    body = body or ""
    if re.search(r"API_KEY_INVALID|keyInvalid", body, re.I):
        return "invalid"
    if status == 429:
        return "error"
    if kind == "maps_json":
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        st = str((data or {}).get("status") or "")
        if st in {"OK", "ZERO_RESULTS", "INVALID_REQUEST"}:
            return "enabled"
        if st in {"REQUEST_DENIED", "OVER_DAILY_LIMIT", "OVER_QUERY_LIMIT"}:
            if re.search(r"invalid.+key|key.+invalid", body, re.I):
                return "invalid"
            return "restricted"
        if status == 200:
            return "restricted"
        if status in (400, 403):
            return "restricted"
        return "denied"
    if kind == "geolocation":
        if status == 200:
            return "enabled"
        if status in (400, 403):
            return "restricted"
        return "denied"
    if kind in {"youtube", "gemini"}:
        if status == 200:
            return "enabled"
        if status in (400, 403):
            return "restricted"
        return "denied"
    return "error"


def summarize_google_spray(results: Dict[str, str]) -> Tuple[bool, str]:
    enabled = [k for k, v in results.items() if v == "enabled"]
    restricted = [k for k, v in results.items() if v == "restricted"]
    denied = [k for k, v in results.items() if v == "denied"]
    invalid = [k for k, v in results.items() if v == "invalid"]
    if invalid and not enabled and not restricted:
        return False, "Invalid/Revoked Google API key"
    valid = bool(enabled or restricted)
    parts: List[str] = []
    if enabled:
        parts.append("enabled=" + ",".join(enabled))
    if restricted:
        parts.append("restricted=" + ",".join(restricted))
    if denied:
        parts.append("denied=" + ",".join(denied))
    if not parts:
        return False, "Inconclusive Google API probe"
    prefix = "VALID" if valid else "Invalid"
    return valid, f"{prefix}: " + "; ".join(parts)


def _google_probe_sync(key: str, spec: Dict[str, Any]) -> Tuple[int, str]:
    url = str(spec["url"]).format(key=key)
    method = str(spec.get("method") or "GET")
    body_bytes = None
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    if spec.get("json_body") is not None:
        body_bytes = json.dumps(spec["json_body"]).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return int(exc.code), raw
    except Exception:
        return 0, ""


def validate_google_api_spray_sync(key: str) -> Dict[str, Any]:
    results: Dict[str, str] = {}
    last_status = None
    for spec in GOOGLE_API_PROBES:
        status, body = _google_probe_sync(key, spec)
        last_status = status
        results[str(spec["id"])] = interpret_google_probe(str(spec["kind"]), status, body)
    valid, note = summarize_google_spray(results)
    return {
        "validated": True,
        "valid": valid,
        "status_code": last_status,
        "note": note,
        "google_services": results,
    }


async def validate_google_api_spray_async(session, key: str, limiter: "DomainRateLimiter") -> Dict[str, Any]:
    results: Dict[str, str] = {}
    last_status = None
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    timeout = aiohttp.ClientTimeout(total=10)
    for spec in GOOGLE_API_PROBES:
        url = str(spec["url"]).format(key=key)
        host = _host_from_url(url)
        dsem = await limiter.acquire(host)
        try:
            kwargs: Dict[str, Any] = {
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": True,
            }
            if spec.get("json_body") is not None:
                kwargs["json"] = spec["json_body"]
            async with session.request(str(spec.get("method") or "GET"), url, **kwargs) as resp:
                last_status = resp.status
                body = await resp.text()
            results[str(spec["id"])] = interpret_google_probe(
                str(spec["kind"]), int(last_status or 0), body
            )
        except Exception:
            results[str(spec["id"])] = "error"
        finally:
            limiter.release(dsem)
        await asyncio.sleep(0.12)
    valid, note = summarize_google_spray(results)
    return {
        "validated": True,
        "valid": valid,
        "status_code": last_status,
        "note": note,
        "google_services": results,
    }


LOGIN_REDIRECT_RE = re.compile(
    r"(?:/login\b|/signin\b|/sign-in\b|/log-in\b|/auth(?:/|$|\?)|/oauth|/sso\b|"
    r"/session/new|/account/login|/users/sign_in|"
    r"accounts\.google\.|login\.microsoftonline\.|okta\.com|auth0\.com|"
    r"cognito.*\.amazonaws\.com|/wp-login\.php)",
    re.I,
)


def _short_url(url: str, n: int = 80) -> str:
    u = (url or "").strip()
    return (u[: n - 1] + "…") if len(u) > n else u


def _host_from_url(url: str) -> str:
    try:
        host = (urlparse(url).netloc or "").lower()
        return host or "unknown"
    except Exception:
        return "unknown"


def _key_datacenter(key: str) -> str:
    """Mailchimp-style datacenter suffix (`hex-us12` → us12)."""
    if "-" not in (key or ""):
        return "us1"
    suffix = key.rsplit("-", 1)[-1]
    return suffix if suffix.lower().startswith("us") else "us1"


def _format_tpl(template: str, key: str, host: Optional[str] = "") -> str:
    host = host or ""
    return (template or "").format(
        key=key,
        domain=host,
        dc=_key_datacenter(key),
        vault=host,
        grafana=host,
    )


def _redirect_to_login(original_url: str, final_url: str) -> bool:
    """True if the client followed a redirect onto a login/SSO page."""
    if not final_url:
        return False
    orig = (original_url or "").rstrip("/")
    final = final_url.rstrip("/")
    if not final or final == orig:
        return False
    return bool(LOGIN_REDIRECT_RE.search(final))


def _classify_slack_webhook(status: int, body_text: str) -> Tuple[bool, str]:
    """Empty POST probe: 400 missing_text/invalid_payload ⇒ hook exists, no message sent."""
    if status == 429:
        return False, "Rate-limited/inconclusive (HTTP 429)"
    body = body_text or ""
    if status == 200:
        return True, "VALID: Slack webhook accepted probe"
    if status == 400 and re.search(
        r"missing_text|no_text|invalid_payload|invalid_json", body, re.I
    ):
        return True, "VALID: Slack webhook exists (empty probe rejected — no message sent)"
    if status in (404, 410, 403, 401):
        return False, f"Invalid/Revoked (HTTP {status})"
    return False, f"Inconclusive (HTTP {status})"


def _retry_delay(attempt: int, headers=None) -> float:
    """Exponential backoff with jitter; honor Retry-After when present."""
    if headers:
        ra = headers.get("Retry-After") or headers.get("retry-after")
        if ra is not None:
            try:
                return min(float(ra), 30.0) + random.uniform(0.0, 0.5)
            except (TypeError, ValueError):
                pass
    return min(0.5 * (2 ** attempt) + random.uniform(0.0, 0.75), 20.0)


class DomainRateLimiter:
    """Global cap + per-host asyncio.Semaphore for polite concurrent validation."""

    def __init__(self, global_limit: int = 10, per_domain: int = 2):
        self.global_sem = asyncio.Semaphore(max(1, global_limit))
        self.per_domain = max(1, per_domain)
        self._domain_sems: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()

    async def _domain_sem(self, host: str) -> asyncio.Semaphore:
        key = (host or "unknown").lower()
        async with self._lock:
            sem = self._domain_sems.get(key)
            if sem is None:
                sem = asyncio.Semaphore(self.per_domain)
                self._domain_sems[key] = sem
            return sem

    async def acquire(self, host: str) -> asyncio.Semaphore:
        dsem = await self._domain_sem(host)
        await self.global_sem.acquire()
        await dsem.acquire()
        return dsem

    def release(self, dsem: asyncio.Semaphore) -> None:
        dsem.release()
        self.global_sem.release()


# Async / sync validators
def _normalize_host(host: Optional[str]) -> str:
    """Strip scheme/path so URL templates get a bare hostname."""
    if not host:
        return ""
    host = re.sub(r"^https?://", "", host.strip(), flags=re.I)
    return host.split("/")[0].strip() or ""


def _n8n_instance_base(value: str) -> str:
    """Normalize --n8n-url / Key Tester host to https://host[:port] without /api/v1."""
    base = (value or "").strip().rstrip("/")
    if not base:
        return ""
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    base = re.sub(r"/api/v\d+$", "", base, flags=re.I)
    return base.rstrip("/")


def infer_n8n_base(source_url: str) -> str:
    """Pick an n8n Cloud (or n8n.*) host from the leak source when --n8n-url is unset."""
    src = source_url or ""
    m = re.search(
        r"https?://([A-Za-z0-9.-]+\.app\.n8n\.cloud)(?::(\d+))?", src, re.I
    )
    if m:
        host = m.group(1)
        port = m.group(2)
        return "https://" + host + (f":{port}" if port else "")
    m = re.search(r"https?://(n8n(?:\.[A-Za-z0-9.-]+)?)(?::(\d+))?", src, re.I)
    if m:
        host = m.group(1)
        port = m.group(2)
        return "https://" + host + (f":{port}" if port else "")
    return ""


def _validator_domain(
    validator: ValidatorSpec,
    domain: str,
    shop_domain: str = "",
    vault_addr: str = "",
    grafana_url: str = "",
    n8n_url: str = "",
) -> Optional[str]:
    """Pick the host for this validator, or None if a required host is missing."""
    if validator.needs_vault:
        base = (vault_addr or "").strip().rstrip("/")
        if not base:
            return None
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        return base
    if validator.needs_grafana:
        return _normalize_host(grafana_url) or None
    if validator.needs_n8n:
        return _n8n_instance_base(n8n_url) or None
    if validator.needs_domain:
        return _normalize_host(shop_domain) or _normalize_host(domain) or None
    return domain


def _apply_http_verdict(
    result: Dict,
    validator: ValidatorSpec,
    status: int,
    body_text: str,
    original_url: str,
    final_url: str,
    headers: Optional[Dict[str, str]] = None,
) -> None:
    result["validated"] = True
    result["status_code"] = status
    if final_url:
        result["final_url"] = final_url
    if validator.check_body and status == 200 and not validator.slack_webhook_probe:
        if _redirect_to_login(original_url, final_url):
            result["valid"] = False
            result["note"] = (
                f"Inconclusive: redirected to login page ({_short_url(final_url)})"
            )
            return
        try:
            body = json.loads(body_text) if body_text else {}
        except Exception:
            result["note"] = "Inconclusive: non-JSON 200"
            return
        if isinstance(body, dict) and body.get(validator.body_ok_field):
            result["valid"] = True
            result["note"] = "VALID: ok=true in response"
        elif isinstance(body, dict):
            result["note"] = "Invalid: ok=false in response"
        else:
            result["note"] = "Inconclusive: non-object JSON 200"
        if str(result.get("type") or "").startswith("github"):
            attach_github_scopes(result, headers)
        return

    is_valid, note = classify_http_status(
        validator, status, body_text, original_url, final_url
    )
    result["valid"] = is_valid
    result["note"] = note
    if is_valid and body_text and not validator.needs_n8n:
        result["response_preview"] = str(body_text)[:400]
    if str(result.get("type") or "").startswith("github"):
        attach_github_scopes(result, headers)


async def validate_one(session, finding: Dict, limiter: "DomainRateLimiter",
                        domain: str, shop_domain: str = "",
                        vault_addr: str = "", grafana_url: str = "") -> Dict:
    result = {**finding, "validated": False, "status_code": None, "valid": False, "note": ""}
    validator = VALIDATORS.get(finding.get("type", ""))
    if not validator:
        result["note"] = "No validator for this type"
        return result
    if validator.skip_reason:
        result["note"] = validator.skip_reason
        return result

    key_h = finding_hash(str(finding.get("type") or ""), str(finding.get("key") or ""))
    if SCAN_VALIDATION_CACHE and VALIDATION_STORE is not None and key_h:
        cached = cache_get(VALIDATION_STORE, key_h)
        if cached:
            result.update(cached)
            result["validated"] = True
            return result

    vault_addr = vault_addr or finding.get("vault_addr") or ""
    grafana_url = grafana_url or finding.get("grafana_url") or ""
    n8n_url = finding.get("n8n_url") or infer_n8n_base(str(finding.get("source_url") or ""))

    if validator.azure_sas_inspect:
        result.update(validate_azure_sas(finding.get("key") or ""))
        return result

    if validator.gcp_sa_inspect:
        result.update(validate_gcp_service_account(finding.get("key") or ""))
        return result

    if validator.uri_inspect:
        result.update(inspect_connection_uri(finding.get("key") or ""))
        return result

    if validator.google_api_spray:
        spray = await validate_google_api_spray_async(
            session, finding.get("key") or "", limiter
        )
        result.update(spray)
        return result

    # JWT — local header/payload inspection (no remote call)
    if validator.jwt_inspect:
        result.update(validate_jwt_inspect(finding.get("key") or ""))
        jwt_meta = result.get("jwt") if isinstance(result.get("jwt"), dict) else None
        n8n_follow = False
        if is_n8n_jwt(jwt_meta) and VALIDATORS.get("n8n_api"):
            finding["type"] = "n8n_api"
            result["type"] = "n8n_api"
            result["valid"] = False
            result["validated"] = False
            result["note"] = ""
            validator = VALIDATORS["n8n_api"]
            n8n_follow = True
        elif finding.get("type") == "supabase_service" or is_supabase_service(jwt_meta):
            result["type"] = "supabase_service"
            if result.get("valid"):
                result["note"] = "VALID Supabase service JWT; " + str(result.get("note") or "")
        elif finding.get("type") == "supabase_anon" or is_supabase_anon(jwt_meta):
            result["type"] = "supabase_anon"
            if result.get("valid"):
                result["note"] = "VALID Supabase anon JWT; " + str(result.get("note") or "")
        else:
            kind = jwt_provider_kind(jwt_meta)
            if kind and finding.get("type") in {"jwt", "onepassword_connect", "monday_api"}:
                result["type"] = kind
        if not n8n_follow:
            return result

    # AWS STS — requires paired secret on the finding (+ session for ASIA)
    if validator.aws_sts:
        secret = finding.get("aws_secret") or ""
        if not secret:
            result["note"] = "Skipped: no paired aws_secret for STS GetCallerIdentity"
            return result
        sess = finding.get("aws_session_token") or ""
        if str(finding.get("key", "")).startswith("ASIA") and not sess:
            result["note"] = "Skipped: ASIA temporary key needs paired aws_session_token"
            return result
        dsem = await limiter.acquire("sts.amazonaws.com")
        try:
            sts = await validate_aws_sts_async(
                session, finding["key"], secret, sess or None
            )
            result.update(sts)
            await asyncio.sleep(0.3 + random.uniform(0, 0.2))
        finally:
            limiter.release(dsem)
        return result

    # Twilio — requires paired Auth Token on the SID finding
    if validator.twilio_pair:
        token = finding.get("twilio_token") or ""
        if not token:
            result["note"] = "Skipped: no paired twilio_token for Basic SID:Token auth"
            return result
        dsem = await limiter.acquire("api.twilio.com")
        try:
            tw = await validate_twilio_pair_async(session, finding["key"], token)
            result.update(tw)
            await asyncio.sleep(0.3 + random.uniform(0, 0.2))
        finally:
            limiter.release(dsem)
        return result

    host = _validator_domain(
        validator, domain, shop_domain,
        vault_addr=vault_addr, grafana_url=grafana_url, n8n_url=n8n_url,
    )
    if validator.needs_domain and not host:
        result["note"] = "Skipped: pass --shopify-domain <store.myshopify.com>"
        return result
    if validator.needs_vault and not host:
        result["note"] = "Skipped: pass --vault-addr https://vault.example.com"
        return result
    if validator.needs_grafana and not host:
        result["note"] = "Skipped: pass --grafana-url grafana.example.com"
        return result
    if validator.needs_n8n and not host:
        result["note"] = "Skipped: pass --n8n-url https://tenant.app.n8n.cloud"
        return result

    key = finding["key"]
    url = _format_tpl(validator.url, key, host)
    limit_host = _host_from_url(url)
    method = (validator.method or "GET").lower()
    max_attempts = 4  # 1 try + up to 3 retries on 429

    dsem = await limiter.acquire(limit_host)
    try:
        try:
            headers = {
                k: _format_tpl(v, key, host)
                for k, v in validator.headers.items()
            }
            if host and not str(host).startswith(("http://", "https://")):
                headers.setdefault("Referer", f"https://{host}/")
                headers.setdefault("Origin", f"https://{host}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            for hk, hv in SCAN_EXTRA_HEADERS.items():
                headers.setdefault(hk, hv)

            auth = None
            if validator.auth:
                u, p = validator.auth
                auth = aiohttp.BasicAuth(
                    _format_tpl(u, key, host), _format_tpl(p, key, host)
                )

            timeout = aiohttp.ClientTimeout(total=10)
            for attempt in range(max_attempts):
                if SCAN_POLITE_DELAY:
                    await asyncio.sleep(SCAN_POLITE_DELAY)
                req_kwargs = {
                    "headers": headers,
                    "auth": auth,
                    "timeout": timeout,
                    "allow_redirects": True,
                }
                proxy = aiohttp_proxy_url(SCAN_PROXY, SCAN_PROXY_AUTH)
                if proxy:
                    req_kwargs["proxy"] = proxy
                if validator.json_body is not None:
                    req_kwargs["json"] = validator.json_body

                async with session.request(method, url, **req_kwargs) as resp:
                    status = resp.status
                    final_url = str(resp.url)
                    # Need body for restricted / check_body / slack probe / 429 retry decision
                    need_body = (
                        status == 429
                        or status in validator.restricted_codes
                        or validator.check_body
                        or validator.slack_webhook_probe
                        or status in (400, 401, 403)
                        or status in validator.valid_codes
                    )
                    body_text = await resp.text() if need_body else ""
                    hdrs = resp.headers

                if status == 429 and attempt < max_attempts - 1:
                    delay = _retry_delay(attempt, hdrs)
                    result["note"] = (
                        f"Rate-limited (HTTP 429), retrying in {delay:.1f}s…"
                    )
                    await asyncio.sleep(delay)
                    continue

                _apply_http_verdict(
                    result, validator, status, body_text, url, final_url,
                    headers={k: v for k, v in (hdrs.items() if hdrs else [])},
                )
                break
            else:
                result["validated"] = True
                result["status_code"] = 429
                result["valid"] = False
                result["note"] = "Rate-limited/inconclusive (HTTP 429)"

        except asyncio.TimeoutError:
            result["note"] = "Timeout during validation"
        except Exception as e:
            result["note"] = f"Error: {str(e)[:60]}"

        # Webhooks: stricter self-rate-limit; others get light jitter
        if validator.webhook:
            await asyncio.sleep(1.25 + random.uniform(0, 0.75))
        else:
            await asyncio.sleep(0.25 + random.uniform(0, 0.35))
    finally:
        limiter.release(dsem)
    return result


async def validate_all(findings: List[Dict], domain: str,
                        concurrency: int = 10,
                        shop_domain: str = "",
                        vault_addr: str = "",
                        grafana_url: str = "") -> List[Dict]:
    findings = pair_credential_findings(findings)
    per_domain = max(1, min(3, concurrency // 3 or 1))
    limiter = DomainRateLimiter(global_limit=concurrency, per_domain=per_domain)
    adaptive = AdaptiveConcurrency(initial=max(2, concurrency), min_=2, max_=max(concurrency, 50))
    remaining = list(findings)
    results: List[Dict] = []
    async with aiohttp.TCPConnector(limit=concurrency, limit_per_host=per_domain) as connector:
        async with aiohttp.ClientSession(connector=connector) as session:
            while remaining:
                batch_n = max(adaptive.min, min(adaptive.current, len(remaining)))
                batch = remaining[:batch_n]
                remaining = remaining[batch_n:]
                t0 = time.monotonic()
                batch_results = await asyncio.gather(*[
                    validate_one(
                        session, f, limiter, domain, shop_domain,
                        vault_addr=vault_addr, grafana_url=grafana_url,
                    )
                    for f in batch
                ])
                elapsed = (time.monotonic() - t0) / max(len(batch), 1)
                for item in batch_results:
                    status = int(item.get("status_code") or 0)
                    adaptive.record(elapsed, status or 200)
                    if VALIDATION_STORE is not None and not item.get("from_cache"):
                        kh = finding_hash(str(item.get("type") or ""), str(item.get("key") or ""))
                        if kh:
                            try:
                                cache_put(VALIDATION_STORE, kh, item)
                            except Exception:
                                pass
                    results.append(item)
            return results


async def validate_finding_configured(
    finding: Dict,
    domain: str,
    shop_domain: str = "",
    config_overlays: Optional[List[str]] = None,
) -> Dict:
    """
    Re-run a single finding through the configured provider validator.
    Used by the GUI; does not invent probes beyond VALIDATORS/config.yaml.
    """
    for cfg in config_overlays or []:
        path = Path(cfg)
        if path.exists():
            load_config_file(path, replace=False)

    shop = _normalize_host(shop_domain)
    if not AIOHTTP_AVAILABLE:
        results = validate_sync_fallback([finding], domain, shop)
        return results[0] if results else {**finding, "note": "Validation unavailable"}

    limiter = DomainRateLimiter(global_limit=1, per_domain=1)
    async with aiohttp.ClientSession() as session:
        return await validate_one(session, finding, limiter, domain, shop)


def validate_finding_configured_sync(
    finding: Dict,
    domain: str,
    shop_domain: str = "",
    config_overlays: Optional[List[str]] = None,
) -> Dict:
    """Blocking wrapper around validate_finding_configured for GUI workers."""
    return asyncio.run(
        validate_finding_configured(finding, domain, shop_domain, config_overlays)
    )


def validate_sync_fallback(findings: List[Dict], domain: str,
                            shop_domain: str = "") -> List[Dict]:
    """Basic synchronous validator when aiohttp is unavailable."""
    findings = pair_credential_findings(findings)
    results = []
    for f in findings:
        result = {**f, "validated": False, "status_code": None, "valid": False}
        validator = VALIDATORS.get(f.get("type", ""))
        if not validator:
            result["note"] = "No validator for this type"
            results.append(result)
            continue
        if validator.skip_reason:
            result["note"] = validator.skip_reason
            results.append(result)
            continue

        if validator.google_api_spray:
            result.update(validate_google_api_spray_sync(f.get("key") or ""))
            results.append(result)
            continue

        if validator.azure_sas_inspect:
            result.update(validate_azure_sas(f.get("key") or ""))
            results.append(result)
            continue

        if validator.gcp_sa_inspect:
            result.update(validate_gcp_service_account(f.get("key") or ""))
            results.append(result)
            continue

        if validator.uri_inspect:
            result.update(inspect_connection_uri(f.get("key") or ""))
            results.append(result)
            continue

        if validator.jwt_inspect:
            result.update(validate_jwt_inspect(f.get("key") or ""))
            jwt_meta = result.get("jwt") if isinstance(result.get("jwt"), dict) else None
            if is_n8n_jwt(jwt_meta) and VALIDATORS.get("n8n_api"):
                f["type"] = "n8n_api"
                result["type"] = "n8n_api"
                result["valid"] = False
                result["validated"] = False
                result["note"] = ""
                validator = VALIDATORS["n8n_api"]
            elif f.get("type") == "supabase_service" or is_supabase_service(jwt_meta):
                result["type"] = "supabase_service"
                if result.get("valid"):
                    result["note"] = "VALID Supabase service JWT; " + str(result.get("note") or "")
                results.append(result)
                continue
            elif f.get("type") == "supabase_anon" or is_supabase_anon(jwt_meta):
                result["type"] = "supabase_anon"
                if result.get("valid"):
                    result["note"] = "VALID Supabase anon JWT; " + str(result.get("note") or "")
                results.append(result)
                continue
            else:
                results.append(result)
                continue

        if validator.aws_sts:
            secret = f.get("aws_secret") or ""
            if not secret:
                result["note"] = "Skipped: no paired aws_secret for STS GetCallerIdentity"
                results.append(result)
                continue
            sess = f.get("aws_session_token") or ""
            if str(f.get("key", "")).startswith("ASIA") and not sess:
                result["note"] = "Skipped: ASIA temporary key needs paired aws_session_token"
                results.append(result)
                continue
            sts = validate_aws_sts_sync(f["key"], secret, sess or None)
            result.update(sts)
            results.append(result)
            continue

        if validator.twilio_pair:
            token = f.get("twilio_token") or ""
            if not token:
                result["note"] = "Skipped: no paired twilio_token for Basic SID:Token auth"
                results.append(result)
                continue
            tw = validate_twilio_pair_sync(f["key"], token)
            result.update(tw)
            results.append(result)
            continue

        vault_addr = f.get("vault_addr") or ""
        grafana_url = f.get("grafana_url") or ""
        n8n_url = f.get("n8n_url") or infer_n8n_base(str(f.get("source_url") or ""))
        host = _validator_domain(
            validator, domain, shop_domain,
            vault_addr=vault_addr, grafana_url=grafana_url, n8n_url=n8n_url,
        )
        if validator.needs_domain and not host:
            result["note"] = "Skipped: pass --shopify-domain <store.myshopify.com>"
            results.append(result)
            continue
        if validator.needs_vault and not host:
            result["note"] = "Skipped: pass --vault-addr https://vault.example.com"
            results.append(result)
            continue
        if validator.needs_grafana and not host:
            result["note"] = "Skipped: pass --grafana-url grafana.example.com"
            results.append(result)
            continue
        if validator.needs_n8n and not host:
            result["note"] = "Skipped: pass --n8n-url https://tenant.app.n8n.cloud"
            results.append(result)
            continue

        key = f["key"]
        url = _format_tpl(validator.url, key, host)
        max_attempts = 4
        try:
            headers = {k: _format_tpl(v, key, host) for k, v in validator.headers.items()}
            if host and not str(host).startswith(("http://", "https://")):
                headers.setdefault("Referer", f"https://{host}/")
                headers.setdefault("Origin", f"https://{host}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            if validator.auth:
                user, passwd = validator.auth
                creds = (
                    f"{_format_tpl(user, key, host)}:{_format_tpl(passwd, key, host)}"
                )
                headers["Authorization"] = (
                    "Basic " + base64.b64encode(creds.encode()).decode()
                )
            body_bytes = None
            if validator.json_body is not None:
                body_bytes = json.dumps(validator.json_body).encode()
                headers.setdefault("Content-Type", "application/json")

            for attempt in range(max_attempts):
                req = urllib.request.Request(
                    url, data=body_bytes, headers=headers,
                    method=(validator.method or "GET"),
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        status = resp.status
                        final_url = resp.geturl() or url
                        body_text = resp.read().decode("utf-8", "ignore")
                        hdrs = {k: v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    status = e.code
                    final_url = e.geturl() if hasattr(e, "geturl") and e.geturl() else url
                    try:
                        body_text = e.read().decode("utf-8", "ignore")
                    except Exception:
                        body_text = ""
                    hdrs = {k: v for k, v in (e.headers.items() if e.headers else [])}

                if status == 429 and attempt < max_attempts - 1:
                    delay = _retry_delay(attempt, hdrs)
                    time.sleep(delay)
                    continue

                _apply_http_verdict(
                    result, validator, status, body_text, url, final_url,
                    headers=hdrs,
                )
                break
            else:
                result["validated"] = True
                result["status_code"] = 429
                result["valid"] = False
                result["note"] = "Rate-limited/inconclusive (HTTP 429)"

        except Exception as e:
            result["note"] = f"Error: {str(e)[:50]}"

        if validator.webhook:
            time.sleep(1.25 + random.uniform(0, 0.5))
        results.append(result)
    return results


def write_sarif(
    findings: List[Dict],
    path: Path,
    domain: str = "",
) -> None:
    """
    Emit SARIF 2.1.0 for CI / code-scanning gate.
    valid=True (and exposure tier) → error; other findings → warning.
    """
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    for f in findings:
        t = str(f.get("type") or "unknown")
        is_error = bool(f.get("valid")) or f.get("tier") == "exposure"
        if t not in rules:
            rules[t] = {
                "id": t,
                "name": t,
                "shortDescription": {"text": f"ReconPipe detector: {t}"},
                "fullDescription": {
                    "text": f"Potential leaked credential or exposure ({t})"
                },
                "defaultConfiguration": {
                    "level": "error" if is_error else "warning"
                },
            }
        key = str(f.get("key") or "")
        uri = str(f.get("source_url") or f.get("source") or "unknown")
        # SARIF URIs should be plausible; keep as-is for http(s) / file paths
        results.append({
            "ruleId": t,
            "level": "error" if is_error else "warning",
            "message": {
                "text": str(
                    f.get("note")
                    or f"{t} finding ({'VALID' if f.get('valid') else 'unverified'})"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }],
            "properties": {
                "key_prefix": key[:32],
                "valid": bool(f.get("valid")),
                "confidence": f.get("confidence"),
                "severity": finding_severity(f),
                "hash": f.get("hash"),
                "scanner": f.get("scanner"),
            },
        })

    doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "reconpipe",
                    "version": "1.0",
                    "informationUri": "https://github.com/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"domain": domain},
        }],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


# Passive intel (Shodan / Censys / ZoomEye / crt.sh)
_OSINT_HOST_RE = re.compile(r"^[A-Za-z0-9._*-]{1,253}$")


def _osint_belongs(host: str, domain: str) -> bool:
    h = (host or "").lower().strip().rstrip(".")
    d = (domain or "").lower().strip().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if not h or not d or not _OSINT_HOST_RE.match(h):
        return False
    return h == d or h.endswith("." + d)


def _osint_http_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
) -> Any:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "ReconPipe/1.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8", errors="replace"))


def _osint_walk_hosts(obj: Any, domain: str, bucket: set) -> None:
    if len(bucket) >= 5000:
        return
    if isinstance(obj, str):
        text = obj.strip().lower().rstrip(".")
        if "://" in text:
            text = urlparse(text).hostname or ""
        for part in re.split(r"[\s,;]+", text):
            part = part.strip().lower().rstrip(".")
            if part.startswith("*."):
                part = part[2:]
            if _osint_belongs(part, domain):
                bucket.add(part)
    elif isinstance(obj, dict):
        for v in obj.values():
            _osint_walk_hosts(v, domain, bucket)
    elif isinstance(obj, list):
        for v in obj:
            _osint_walk_hosts(v, domain, bucket)


def query_shodan(domain: str, api_key: str, timeout: int = 20) -> List[str]:
    """Shodan DNS domain endpoint — subdomains for the apex name."""
    key = (api_key or "").strip()
    if not key:
        return []
    url = (
        f"https://api.shodan.io/dns/domain/{quote(domain)}"
        f"?{urlencode({'key': key})}"
    )
    data = _osint_http_json(url, timeout=timeout)
    found: set = set()
    if isinstance(data, dict):
        for sub in data.get("subdomains") or []:
            host = f"{sub}.{domain}".lower().strip(".") if sub else domain
            if _osint_belongs(host, domain):
                found.add(host)
        _osint_walk_hosts(data.get("data") or data, domain, found)
    return sorted(found)


def query_censys(
    domain: str,
    api_id: str,
    api_secret: str,
    timeout: int = 20,
) -> List[str]:
    """Censys Search v2 certificate + host name search."""
    api_id = (api_id or "").strip()
    api_secret = (api_secret or "").strip()
    if not api_id or not api_secret:
        return []
    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode("ascii")
    headers = {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
        "User-Agent": "ReconPipe/1.1",
    }
    found: set = set()
    queries = [
        (
            "https://search.censys.io/api/v2/certificates/search?"
            + urlencode({"q": f"names: {domain}", "per_page": 100})
        ),
        (
            "https://search.censys.io/api/v2/hosts/search?"
            + urlencode({"q": f"dns.names: {domain}", "per_page": 100})
        ),
    ]
    for url in queries:
        try:
            data = _osint_http_json(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        _osint_walk_hosts(data, domain, found)
    return sorted(found)


def query_zoomeye(domain: str, api_key: str, timeout: int = 20) -> List[str]:
    """ZoomEye domain/host search (api.zoomeye.ai, with .org fallback)."""
    key = (api_key or "").strip()
    if not key:
        return []
    headers = {"API-KEY": key, "User-Agent": "ReconPipe/1.1"}
    found: set = set()
    urls = [
        "https://api.zoomeye.ai/domain/search?"
        + urlencode({"q": domain, "type": 1, "page": 1}),
        "https://api.zoomeye.ai/host/search?"
        + urlencode({"query": f"site:{domain}", "page": 1}),
        "https://api.zoomeye.org/domain/search?"
        + urlencode({"q": domain, "type": 1, "page": 1}),
    ]
    for url in urls:
        try:
            data = _osint_http_json(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        _osint_walk_hosts(data, domain, found)
        if found:
            break
    return sorted(found)


def query_crtsh(domain: str, timeout: int = 20) -> List[str]:
    """crt.sh certificate transparency (no API key)."""
    url = "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"})
    data = _osint_http_json(url, timeout=timeout)
    found: set = set()
    _osint_walk_hosts(data, domain, found)
    return sorted(found)


def collect_certstream_hosts(domain: str, seconds: int) -> List[str]:
    """Listen to certstream CT for `seconds` and return hostnames under domain."""
    seconds = int(seconds or 0)
    if seconds <= 0 or not (domain or "").strip():
        return []
    if not AIOHTTP_AVAILABLE:
        log("certstream needs aiohttp — skipping", "warn")
        return []

    async def _listen() -> List[str]:
        found: List[str] = []
        deadline = time.monotonic() + seconds
        timeout = aiohttp.ClientTimeout(total=seconds + 5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(wave3.CERTSTREAM_WS, heartbeat=20) as ws:
                while time.monotonic() < deadline:
                    remaining = max(0.1, deadline - time.monotonic())
                    try:
                        msg = await asyncio.wait_for(ws.receive_json(), timeout=min(2.0, remaining))
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
                    names = certstream_domains_from_message(msg)
                    found.extend(hosts_matching_domain(names, domain))
        return merge_unique(found)

    log(f"certstream: listening {seconds}s for {domain}...", "info")
    try:
        return asyncio.run(_listen())
    except Exception as exc:
        log(f"certstream: {str(exc)[:120]}", "warn")
        return []


def osint_source_status(
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    zoomeye_key: str = "",
    skip_crtsh: bool = False,
    skip_intel: bool = False,
) -> Dict[str, str]:
    """GUI/preflight: key | env | on | off | skipped (never includes secret values)."""
    if skip_intel:
        return {k: "skipped" for k in ("shodan", "censys", "zoomeye", "crtsh")}
    if (shodan_key or "").strip():
        shodan = "key"
    elif os.environ.get("SHODAN_API_KEY"):
        shodan = "env"
    elif (load_user_keys().get("shodan") or "").strip():
        shodan = "saved"
    else:
        shodan = "off"
    if (censys_id or "").strip() and (censys_secret or "").strip():
        censys = "key"
    elif os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET"):
        censys = "env"
    elif (load_user_keys().get("censys_id") or "").strip() and (
        load_user_keys().get("censys_secret") or ""
    ).strip():
        censys = "saved"
    else:
        censys = "off"
    if (zoomeye_key or "").strip():
        zoomeye = "key"
    elif os.environ.get("ZOOMEYE_API_KEY") or os.environ.get("ZOOMEYE_KEY"):
        zoomeye = "env"
    elif (load_user_keys().get("zoomeye") or "").strip():
        zoomeye = "saved"
    else:
        zoomeye = "off"
    return {
        "shodan": shodan,
        "censys": censys,
        "zoomeye": zoomeye,
        "crtsh": "off" if skip_crtsh else "on",
    }


def collect_osint_hosts(
    domain: str,
    *,
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    zoomeye_key: str = "",
    skip_crtsh: bool = False,
    skip_intel: bool = False,
    timeout: int = 20,
) -> Dict[str, List[str]]:
    """Query optional intel APIs. Failures are logged; never abort the pipeline."""
    results: Dict[str, List[str]] = {}
    if skip_intel or not domain:
        return results

    shodan_key = shodan_key or os.environ.get("SHODAN_API_KEY", "") or load_user_keys().get("shodan", "")
    censys_id = censys_id or os.environ.get("CENSYS_API_ID", "") or load_user_keys().get("censys_id", "")
    censys_secret = censys_secret or os.environ.get("CENSYS_API_SECRET", "") or load_user_keys().get("censys_secret", "")
    zoomeye_key = (
        zoomeye_key
        or os.environ.get("ZOOMEYE_API_KEY", "")
        or os.environ.get("ZOOMEYE_KEY", "")
        or load_user_keys().get("zoomeye", "")
    )

    jobs = [
        ("shodan", bool((shodan_key or "").strip()),
         lambda: query_shodan(domain, shodan_key, timeout)),
        ("censys", bool((censys_id or "").strip() and (censys_secret or "").strip()),
         lambda: query_censys(domain, censys_id, censys_secret, timeout)),
        ("zoomeye", bool((zoomeye_key or "").strip()),
         lambda: query_zoomeye(domain, zoomeye_key, timeout)),
    ]
    for name, enabled, fn in jobs:
        if not enabled:
            continue
        try:
            hosts = fn()
        except Exception as exc:
            log(f"{name}: {str(exc)[:120]}", "warn")
            continue
        if hosts:
            results[name] = hosts
            log(f"{name}: +{len(hosts)} host(s)", "success")
        else:
            log(f"{name}: no extra hosts", "info")

    if not skip_crtsh:
        try:
            hosts = query_crtsh(domain, timeout)
            if hosts:
                results["crtsh"] = hosts
                log(f"crt.sh: +{len(hosts)} host(s)", "success")
            else:
                log("crt.sh: no extra hosts", "info")
        except Exception as exc:
            log(f"crt.sh: {str(exc)[:120]}", "warn")
    return results


def merge_host_lists(*lists: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for lst in lists:
        for h in lst or []:
            host = (h or "").strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host or host in seen:
                continue
            seen.add(host)
            out.append(host)
    return sorted(out)


def run_tool_maybe_docker(
    tool: str,
    cmd: List[str],
    *,
    timeout: int = 180,
    output_file: Optional[str] = None,
    discard_stdout: bool = False,
    mount_dir: Optional[Path] = None,
) -> Tuple[int, bytes]:
    """Run cmd; on missing binary optionally try docker. Retries transient failures."""
    rc, out = run_cmd_with_retry(
        cmd, max_retries=2, base_delay=0.4,
        output_file=output_file, timeout=timeout, discard_stdout=discard_stdout,
    )
    if rc != CMD_NOTFOUND_RC or not DOCKER_FALLBACK:
        return rc, out
    docker_cmd = docker_cmd_for(tool, cmd[1:], mount_dir or Path("."))
    if not docker_cmd:
        return rc, out
    log(f"{tool} missing — trying docker image", "warn")
    return run_cmd(docker_cmd, output_file=output_file, timeout=timeout, discard_stdout=discard_stdout)


def skip_completed_stage(resume_from: str, stage: str) -> bool:
    """True when --resume-from is later than this stage (it already finished)."""
    order = ["chaos", "httpx", "discovery", "trufflehog", "validate"]
    if not resume_from or resume_from not in order or stage not in order:
        return False
    return order.index(stage) < order.index(resume_from)


def apply_polite_delay() -> None:
    """Serialize a global delay between outbound HTTP requests."""
    global _POLITE_LAST
    delay = float(SCAN_POLITE_DELAY or 0)
    if delay <= 0:
        return
    with _POLITE_LOCK:
        now = time.monotonic()
        wait = delay - (now - _POLITE_LAST)
        if wait > 0:
            time.sleep(wait)
        _POLITE_LAST = time.monotonic()


def _metrics_start(name: str, items_in: int = 0) -> None:
    if PIPELINE_METRICS is not None:
        PIPELINE_METRICS.start_stage(name, items_in)


def _metrics_finish(name: str, items_out: int = 0, errors: int = 0) -> None:
    if PIPELINE_METRICS is not None:
        PIPELINE_METRICS.finish_stage(name, items_out, errors)


def configure_scan_runtime(args: Any, output_dir: Path) -> None:
    global SCAN_PROXY, SCAN_PROXY_AUTH, SCAN_EXTRA_HEADERS, SCAN_POLITE_DELAY
    global SCAN_RPS, SCAN_CREDENTIALS, DOCKER_FALLBACK, FINDINGS_STREAM, PIPELINE_METRICS
    global SCAN_WAYBACK_BODIES, SCAN_PUBLIC_APIS, SCAN_JS_HISTORY, SCAN_JS_HISTORY_MAX, SCAN_SOURCEMAPS
    SCAN_PROXY = (getattr(args, "proxy", None) or "").strip()
    SCAN_PROXY_AUTH = (getattr(args, "proxy_auth", None) or "").strip()
    SCAN_EXTRA_HEADERS = parse_header_list(getattr(args, "header", None) or [])
    SCAN_RPS = float(getattr(args, "requests_per_second", 0) or 0)
    SCAN_POLITE_DELAY = polite_delay_seconds(bool(getattr(args, "polite", False)), SCAN_RPS)
    DOCKER_FALLBACK = bool(getattr(args, "docker_fallback", False))
    SCAN_WAYBACK_BODIES = not bool(getattr(args, "skip_wayback_bodies", False))
    SCAN_JS_HISTORY = not bool(getattr(args, "skip_js_history", False))
    try:
        SCAN_JS_HISTORY_MAX = int(getattr(args, "js_history_max", None) or addons.JS_HISTORY_MAX_VERSIONS)
    except (TypeError, ValueError):
        SCAN_JS_HISTORY_MAX = addons.JS_HISTORY_MAX_VERSIONS
    SCAN_JS_HISTORY_MAX = max(1, min(SCAN_JS_HISTORY_MAX, 200))
    SCAN_SOURCEMAPS = not bool(getattr(args, "skip_sourcemaps", False))
    SCAN_PUBLIC_APIS = not bool(getattr(args, "skip_public_apis", False))
    WAYBACK_BY_FILE.clear()
    creds_file = (getattr(args, "credentials", None) or "").strip()
    SCAN_CREDENTIALS = None
    if creds_file:
        SCAN_CREDENTIALS = load_credentials(Path(creds_file))
        SCAN_EXTRA_HEADERS.update(credentials_to_headers(SCAN_CREDENTIALS))
    install_urllib_proxy(SCAN_PROXY, SCAN_PROXY_AUTH, SCAN_EXTRA_HEADERS)
    FINDINGS_STREAM = FindingsStream(output_dir)
    PIPELINE_METRICS = PipelineMetrics()
    addons.bind_config_lookups(REVOCATION_URLS, COMPLIANCE_TAGS)


def probe_sensitive_paths(live_hosts: List[str], output_dir: Path) -> List[str]:
    """GET a small leak-path list on live hosts; skip HTML catch-all pages."""
    candidates = sensitive_urls_for_hosts(live_hosts, limit_hosts=40)
    if not candidates:
        return []
    log(f"Sensitive paths: probing {len(candidates)} URL(s) on {min(len(live_hosts), 40)} host(s)...", "info")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    hits: List[str] = []
    workers = 1 if SCAN_POLITE_DELAY > 0 else 8

    def _one(url: str) -> Optional[str]:
        apply_polite_delay()
        return url if probe_sensitive_url(url, ua=ua, timeout=6) else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_one, u) for u in candidates]
        for fut in as_completed(futs):
            try:
                hit = fut.result()
            except Exception:
                hit = None
            if hit:
                hits.append(hit)
    hits = dedupe_urls(hits)
    if hits:
        (output_dir / "sensitive_paths.txt").write_text("\n".join(hits) + "\n", encoding="utf-8")
        log(f"Sensitive paths: {C.BOLD}{len(hits)}{C.RESET} exposed file(s)", "success")
    else:
        log("Sensitive paths: none exposed", "info")
    return hits


def merge_tool_hosts(sub_list: List[str], extra: List[str], label: str, output_dir: Path) -> List[str]:
    if not extra:
        log(f"{label}: no additional hosts", "info")
        return sub_list
    before = len(sub_list)
    merged = merge_host_lists(sub_list, extra)
    added = len(merged) - before
    (output_dir / "subdomains.txt").write_text("\n".join(merged) + "\n")
    log(f"{label}: {C.BOLD}{added}{C.RESET} new host(s) → {len(merged)} total", "success")
    return merged


def analyze_js_bundle(urls: List[str], output_dir: Path) -> List[str]:
    js_urls = extract_js_urls(urls)
    endpoints: List[str] = []
    js_secrets: List[Dict[str, str]] = []
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    for url in js_urls[:200]:
        try:
            apply_polite_delay()
            req = urllib.request.Request(url, headers={"User-Agent": ua, **SCAN_EXTRA_HEADERS})
            with urllib.request.urlopen(req, timeout=8) as resp:
                page = resp.read().decode("utf-8", errors="ignore")
            endpoints.extend(extract_endpoints_from_js(page))
            js_secrets.extend(extract_js_secret_assignments(page))
            if looks_like_source_map_json(page):
                parse_source_map(page)
        except Exception:
            continue
        if SCAN_POLITE_DELAY:
            time.sleep(SCAN_POLITE_DELAY)
    extra = []
    for ep in endpoints:
        if ep.startswith("http://") or ep.startswith("https://"):
            extra.append(ep)
        elif ep.startswith("/"):
            # relative — skip host join here; callers keep as intel
            extra.append(ep)
    (output_dir / "js_endpoints.json").write_text(
        json.dumps(sorted(set(endpoints)), indent=2), encoding="utf-8"
    )
    (output_dir / "js_secrets.json").write_text(
        json.dumps(js_secrets[:500], indent=2), encoding="utf-8"
    )
    log(f"JS analysis: {len(js_urls)} files, {len(set(endpoints))} endpoint(s), {len(js_secrets)} secret assignment(s)", "info")
    return extra


def send_extra_alerts(domain: str, valid_findings: List[Dict], args: Any) -> None:
    n = len(valid_findings or [])
    if n == 0:
        return
    text = f"ReconPipe: {n} valid key(s) on {domain}"
    if getattr(args, "telegram_bot", None) and getattr(args, "telegram_chat", None):
        if notify_telegram(args.telegram_bot, args.telegram_chat, text):
            log("Telegram notified", "success")
    if getattr(args, "smtp_host", None) and getattr(args, "smtp_to", None):
        if notify_email(
            args.smtp_host, args.smtp_to, text, text,
            port=int(getattr(args, "smtp_port", 587) or 587),
            user=getattr(args, "smtp_user", "") or "",
            password=getattr(args, "smtp_password", "") or "",
        ):
            log("Email notified", "success")
    if getattr(args, "pagerduty_key", None):
        if notify_pagerduty(args.pagerduty_key, text, "error"):
            log("PagerDuty notified", "success")
    if getattr(args, "opsgenie_key", None):
        if notify_opsgenie(args.opsgenie_key, text):
            log("Opsgenie notified", "success")


# Main
def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI ArgumentParser (shared by CLI and GUI)."""
    parser = argparse.ArgumentParser(
        prog="reconpipe",
        description="Automated API Key Leak Hunter — Chaos → httpx → gau → TruffleHog → Validate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconpipe.py -d example.com
  python reconpipe.py -d example.com --subdomains my_subs.txt
  python reconpipe.py -d example.com --no-trufflehog
  python reconpipe.py -d example.com --skip-chaos --skip-gau --files urls.txt
  python reconpipe.py -d example.com --concurrency 20 --output /tmp/scan
  python reconpipe.py -d example.com --config engagement.example.yaml
  python reconpipe.py -d example.com --files urls.txt --sarif out.sarif
        """
    )
    parser.add_argument("-d", "--domain", help="Target domain (required unless --domain-list)")
    parser.add_argument("--domain-list", metavar="FILE",
                        help="Scan one domain per line (each gets its own output directory)")
    parser.add_argument("--subdomains",        metavar="FILE", help="Use existing subdomain list (skips Chaos)")
    parser.add_argument("--files",             metavar="FILE",
                        help="Use existing URL list (skips URL discovery: katana/waymore/gau/gospider)")
    parser.add_argument("--skip-chaos",        action="store_true", help="Skip Chaos step")
    parser.add_argument("--skip-subfinder",    action="store_true", help="Skip subfinder subdomain enumeration")
    parser.add_argument("--skip-httpx",        action="store_true", help="Skip httpx live-host filter")
    parser.add_argument("--skip-gau",          action="store_true",
                        help="Skip passive archives only (waymore/gau/waybackurls); katana/gospider still run")
    parser.add_argument("--skip-discovery",    action="store_true",
                        help="Skip all URL discovery (katana/waymore/gau/gospider); scan live hosts only")
    parser.add_argument("--no-trufflehog",     action="store_true", help="Use built-in regex scanner only")
    parser.add_argument("--no-validate",       action="store_true", help="Skip key validation")
    parser.add_argument("--concurrency",       type=int, default=10, help="Async validation concurrency (default: 10)")
    parser.add_argument("--chaos-key",         metavar="KEY",  help="Chaos API key (or set env CHAOS_KEY)")
    parser.add_argument("--shodan-key",        metavar="KEY",  help="Shodan API key (or set env SHODAN_API_KEY)")
    parser.add_argument("--censys-id",         metavar="ID",   help="Censys API ID (or set env CENSYS_API_ID)")
    parser.add_argument("--censys-secret",     metavar="KEY",  help="Censys API secret (or set env CENSYS_API_SECRET)")
    parser.add_argument("--zoomeye-key",       metavar="KEY",  help="ZoomEye API key (or set env ZOOMEYE_API_KEY)")
    parser.add_argument("--skip-intel",        action="store_true",
                        help="Skip Shodan/Censys/ZoomEye/crt.sh host enrichment")
    parser.add_argument("--skip-crtsh",        action="store_true",
                        help="Skip crt.sh certificate-transparency lookup")
    parser.add_argument("--output", "-o",      metavar="DIR",  help="Output directory (default: recon_<domain>)")
    parser.add_argument("--gau-threads",       type=int, default=5, help="gau thread count (default: 5)")
    parser.add_argument("--headless",          action="store_true", help="Enable Katana headless Chrome mode for SPAs/React/Angular")
    parser.add_argument("--shopify-domain",    metavar="HOST",
                        help="Shopify store host for shpat_ validation (e.g. store.myshopify.com)")
    parser.add_argument(
        "--ignore-hash",
        action="append",
        default=[],
        metavar="SHA256",
        help="Permanently suppress a finding hash in baseline (repeatable; "
             "sets ignore_all — use hash from findings.json)",
    )
    parser.add_argument(
        "--config",
        action="append",
        default=[],
        metavar="FILE",
        help="YAML config overlay merged onto config.yaml (repeatable). "
             "Add/override patterns, validators, confidence, informational_types, "
             "exposure_types, min_confidence. Set a pattern/validator to null to remove.",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write SARIF 2.1.0 results (default: <output>/results.sarif)",
    )
    parser.add_argument(
        "--no-fail-on-valid",
        action="store_true",
        help="Do not exit 1 when validated live keys are found (default: exit 1 to gate CI)",
    )
    parser.add_argument("--exclude-pattern", metavar="FILE",
                        help="Host globs to exclude (one per line, e.g. *.cdn.example.com)")
    parser.add_argument("--include-pattern", metavar="FILE",
                        help="Only scan hosts matching these globs (one per line)")
    parser.add_argument(
        "--no-default-scope",
        action="store_true",
        help="Do not auto-limit hosts/URLs to the target domain and its subdomains",
    )
    parser.add_argument("--vault-addr", metavar="URL",
                        help="Vault address for hvs/hvb token lookup-self")
    parser.add_argument("--grafana-url", metavar="HOST",
                        help="Grafana host for glsa_ token checks")
    parser.add_argument(
        "--n8n-url",
        metavar="URL",
        help="n8n instance for public API key checks (https://tenant.app.n8n.cloud)",
    )
    parser.add_argument("--notify-webhook", metavar="URL",
                        help="POST redacted valid-key JSON to Slack/Discord/custom webhook")
    parser.add_argument("--no-notify", action="store_true",
                        help="Do not send a desktop notification when the scan finishes")
    parser.add_argument("--download-workers", type=int, default=16,
                        help="Parallel file download workers (default: 16)")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse files_to_scan.txt and skip re-download of existing files")
    parser.add_argument("--rescan", action="store_true",
                        help="Reuse the saved target (URL list + output dir) for this domain and --resume")
    parser.add_argument("--skip-amass", action="store_true", help="Skip amass subdomain enumeration")
    parser.add_argument("--amass-active", action="store_true", help="Run amass without -passive")
    parser.add_argument("--skip-assetfinder", action="store_true", help="Skip assetfinder")
    parser.add_argument("--skip-findomain", action="store_true", help="Skip findomain")
    parser.add_argument("--skip-dnsx", action="store_true", help="Skip dnsx resolution before httpx")
    parser.add_argument("--skip-hakrawler", action="store_true", help="Skip hakrawler")
    parser.add_argument("--skip-paramspider", action="store_true", help="Skip paramspider")
    parser.add_argument("--skip-naabu", action="store_true", help="Skip naabu port scan")
    parser.add_argument("--skip-whatweb", action="store_true", help="Skip whatweb fingerprinting")
    parser.add_argument("--skip-gowitness", action="store_true", help="Skip gowitness screenshots")
    parser.add_argument("--nuclei", action="store_true", help="Run nuclei exposures/misconfig templates")
    parser.add_argument("--nuclei-templates", metavar="PATH", action="append", default=[],
                        help="Nuclei template path (repeatable)")
    parser.add_argument("--nuclei-import", metavar="FILE", help="Import nuclei JSONL/text output")
    parser.add_argument("--proxy", metavar="URL", help="HTTP proxy for requests (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--proxy-auth", metavar="USER:PASS", help="Proxy authentication credentials")
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="NAME:VALUE", help="Custom header for HTTP requests (repeatable)")
    parser.add_argument("--polite", action="store_true", help="Add 500ms delay between requests")
    parser.add_argument("--requests-per-second", type=float, default=0,
                        help="Global rate limit (0 = unlimited)")
    parser.add_argument("--resume-from", choices=["chaos", "httpx", "discovery", "trufflehog", "validate"],
                        help="Resume pipeline from a checkpoint stage")
    parser.add_argument("--credentials", metavar="FILE",
                        help="YAML/JSON cookies+headers for authenticated scanning")
    parser.add_argument("--burp-import", metavar="FILE", help="Import URLs from Burp Suite XML export")
    parser.add_argument("--docker-fallback", action="store_true",
                        help="Run missing tools via docker run --rm when an image is known")
    parser.add_argument("--repo", metavar="URL", help="Clone a git repo and scan working tree + history")
    parser.add_argument("--repo-shallow", action="store_true",
                        help="Shallow clone (--depth 1); skips git history (default is full clone)")
    parser.add_argument("--iac-scan", action="store_true",
                        help="Also walk Docker/K8s/Terraform files under --repo or output dir")
    parser.add_argument("--skip-wayback-bodies", action="store_true",
                        help="Do not fetch Wayback snapshots when a discovered URL is dead")
    parser.add_argument("--skip-js-history", action="store_true",
                        help="Do not fetch older Wayback copies of JavaScript that is still live")
    parser.add_argument("--js-history-max", metavar="N", type=int, default=15,
                        help="Max unique Wayback JS versions per URL, oldest-first (default 15)")
    parser.add_argument("--skip-sourcemaps", action="store_true",
                        help="Do not fetch public JS source maps or reconstruct original sources")
    parser.add_argument("--skip-sensitive-paths", action="store_true",
                        help="Skip probing /.env, /.git/config, swagger.json, MCP configs, and similar leak paths")
    parser.add_argument("--skip-gitleaks", action="store_true",
                        help="Do not run Gitleaks (default: run when the binary is on PATH)")
    parser.add_argument("--spray", action="store_true",
                        help="Opt-in: brute extra leak/backup paths on live hosts with spray")
    parser.add_argument("--skip-public-apis", action="store_true",
                        help="Do not use the public-apis catalog to catch vendor query-string keys")
    parser.add_argument("--refresh-public-apis", action="store_true",
                        help="Rebuild wordlists/public_apis.json from GitHub before scanning")
    parser.add_argument("--secrets-db", metavar="FILE", action="append", default=[],
                        help="Load extra regexes from secrets-patterns-db / jsleak YAML (repeatable)")
    parser.add_argument("--refresh-secrets-db", action="store_true",
                        help="Download secrets-patterns-db (high confidence) into ~/.reconpipe")
    parser.add_argument("--skip-secrets-db", action="store_true",
                        help="Do not load bundled/user secrets-patterns-db extra regexes")
    parser.add_argument("--secrets-db-medium", action="store_true",
                        help="Also keep medium-confidence secrets-patterns-db rules")
    parser.add_argument("--skip-jsleak", action="store_true",
                        help="Do not run jsleak on discovered JavaScript URLs")
    parser.add_argument("--github-token", metavar="TOKEN",
                        help="GitHub token for code search (or env GITHUB_TOKEN)")
    parser.add_argument("--gitlab-token", metavar="TOKEN",
                        help="GitLab token for code search (or env GITLAB_TOKEN)")
    parser.add_argument("--github-org", metavar="ORG",
                        help="GitHub org to scope public code search")
    parser.add_argument("--skip-code-search", action="store_true",
                        help="Skip GitHub/GitLab public code search")
    parser.add_argument("--skip-ci-logs", action="store_true",
                        help="Skip public GitHub Actions / GitLab job logs and artifacts")
    parser.add_argument("--skip-pastes", action="store_true",
                        help="Skip Pastebin / Gist / Ghostbin paste-site search")
    parser.add_argument("--skip-docker-hub", action="store_true",
                        help="Skip Docker Hub public image search")
    parser.add_argument("--skip-image-layers", action="store_true",
                        help="Do not pull/scan public container image layers for baked-in secrets")
    parser.add_argument("--apk", metavar="FILE", action="append", default=[],
                        help="Unzip and scan an APK/XAPK/APKM (repeatable)")
    parser.add_argument("--ipa", metavar="FILE", action="append", default=[],
                        help="Unzip and scan an IPA (repeatable)")
    parser.add_argument("--package", metavar="ID", action="append", default=[],
                        help="Download an Android package (apkeep, else gplaycli) then scan it")
    parser.add_argument("--skip-buckets", action="store_true",
                        help="Do not guess/probe S3/GCS/Azure bucket names")
    parser.add_argument("--skip-openapi", action="store_true",
                        help="Do not parse OpenAPI/Swagger/Postman specs for extra URLs")
    parser.add_argument("--skip-store", action="store_true",
                        help="Do not persist findings to ~/.reconpipe/findings.db")
    parser.add_argument("--no-validation-cache", action="store_true",
                        help="Do not reuse cached provider validation results")
    parser.add_argument("--ci", action="store_true",
                        help="Shift-left: scan local --repo (cwd), skip live recon, write SARIF")
    parser.add_argument("--watch", metavar="SECONDS", type=int, default=0,
                        help="Re-run the scan on this interval (CLI loop; 0 = once)")
    parser.add_argument("--certstream-seconds", metavar="N", type=int, default=0,
                        help="Listen to certstream CT for N seconds and merge hostnames")
    parser.add_argument("--telegram-bot", metavar="TOKEN", help="Telegram bot token for alerts")
    parser.add_argument("--telegram-chat", metavar="ID", help="Telegram chat id for alerts")
    parser.add_argument("--smtp-host", metavar="HOST", help="SMTP host for email alerts")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port (default 587)")
    parser.add_argument("--smtp-user", metavar="USER", help="SMTP username")
    parser.add_argument("--smtp-password", metavar="PASS", help="SMTP password")
    parser.add_argument("--smtp-to", metavar="EMAIL", help="Alert recipient")
    parser.add_argument("--pagerduty-key", metavar="KEY", help="PagerDuty Events v2 routing key")
    parser.add_argument("--opsgenie-key", metavar="KEY", help="Opsgenie API key")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="After the scan, ask a local or cloud LLM to write remediation.md",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Do not write an LLM remediation report (overrides Settings)",
    )
    parser.add_argument(
        "--llm-provider",
        metavar="NAME",
        choices=["ollama", "openai", "anthropic", "openai_compat"],
        help="LLM provider: ollama, openai, anthropic, openai_compat",
    )
    parser.add_argument("--llm-model", metavar="NAME", help="Model name (llama3.1, gpt-4o-mini, …)")
    parser.add_argument(
        "--llm-base-url",
        metavar="URL",
        help="Ollama or OpenAI-compatible base URL (default http://127.0.0.1:11434)",
    )
    parser.add_argument("--llm-key", metavar="KEY", help="Cloud LLM API key (or env RECONPIPE_LLM_KEY)")
    parser.add_argument("--llm-timeout", metavar="SEC", type=int, help="LLM HTTP timeout (default 120)")
    parser.add_argument(
        "--llm-max-findings",
        metavar="N",
        type=int,
        help="Cap findings sent to the LLM (default 40)",
    )
    return parser


def argv_from_options(opts: Dict[str, Any]) -> List[str]:
    """
    Build a reconpipe CLI argv list from a GUI/options dict.
    Keys mirror argparse dest names (domain, skip_chaos, config, ignore_hash, …).
    """
    argv: List[str] = []
    domain = (opts.get("domain") or "").strip()
    domain_list = (opts.get("domain_list") or "").strip()
    if not domain and not domain_list:
        raise ValueError("domain is required")
    if domain:
        argv += ["-d", domain]

    mapping_flags = {
        "skip_chaos": "--skip-chaos",
        "skip_httpx": "--skip-httpx",
        "skip_gau": "--skip-gau",
        "skip_discovery": "--skip-discovery",
        "no_trufflehog": "--no-trufflehog",
        "no_validate": "--no-validate",
        "headless": "--headless",
        "no_fail_on_valid": "--no-fail-on-valid",
        "skip_intel": "--skip-intel",
        "skip_crtsh": "--skip-crtsh",
        "skip_subfinder": "--skip-subfinder",
        "no_notify": "--no-notify",
        "resume": "--resume",
        "rescan": "--rescan",
        "skip_amass": "--skip-amass",
        "amass_active": "--amass-active",
        "skip_assetfinder": "--skip-assetfinder",
        "skip_findomain": "--skip-findomain",
        "skip_dnsx": "--skip-dnsx",
        "skip_hakrawler": "--skip-hakrawler",
        "skip_paramspider": "--skip-paramspider",
        "skip_naabu": "--skip-naabu",
        "skip_whatweb": "--skip-whatweb",
        "skip_gowitness": "--skip-gowitness",
        "nuclei": "--nuclei",
        "polite": "--polite",
        "docker_fallback": "--docker-fallback",
        "iac_scan": "--iac-scan",
        "repo_shallow": "--repo-shallow",
        "skip_wayback_bodies": "--skip-wayback-bodies",
        "skip_js_history": "--skip-js-history",
        "skip_sourcemaps": "--skip-sourcemaps",
        "skip_sensitive_paths": "--skip-sensitive-paths",
        "skip_gitleaks": "--skip-gitleaks",
        "spray": "--spray",
        "skip_public_apis": "--skip-public-apis",
        "refresh_public_apis": "--refresh-public-apis",
        "refresh_secrets_db": "--refresh-secrets-db",
        "skip_secrets_db": "--skip-secrets-db",
        "secrets_db_medium": "--secrets-db-medium",
        "skip_jsleak": "--skip-jsleak",
        "skip_code_search": "--skip-code-search",
        "skip_ci_logs": "--skip-ci-logs",
        "skip_pastes": "--skip-pastes",
        "skip_docker_hub": "--skip-docker-hub",
        "skip_image_layers": "--skip-image-layers",
        "skip_buckets": "--skip-buckets",
        "skip_openapi": "--skip-openapi",
        "skip_store": "--skip-store",
        "no_validation_cache": "--no-validation-cache",
        "ci": "--ci",
        "no_default_scope": "--no-default-scope",
        "llm": "--llm",
        "skip_llm": "--skip-llm",
    }
    for key, flag in mapping_flags.items():
        if opts.get(key):
            argv.append(flag)

    value_flags = {
        "subdomains": "--subdomains",
        "files": "--files",
        "chaos_key": "--chaos-key",
        "shodan_key": "--shodan-key",
        "censys_id": "--censys-id",
        "censys_secret": "--censys-secret",
        "zoomeye_key": "--zoomeye-key",
        "output": "--output",
        "shopify_domain": "--shopify-domain",
        "sarif": "--sarif",
        "domain_list": "--domain-list",
        "exclude_pattern": "--exclude-pattern",
        "include_pattern": "--include-pattern",
        "vault_addr": "--vault-addr",
        "grafana_url": "--grafana-url",
        "n8n_url": "--n8n-url",
        "notify_webhook": "--notify-webhook",
        "proxy": "--proxy",
        "proxy_auth": "--proxy-auth",
        "credentials": "--credentials",
        "burp_import": "--burp-import",
        "nuclei_import": "--nuclei-import",
        "repo": "--repo",
        "resume_from": "--resume-from",
        "telegram_bot": "--telegram-bot",
        "telegram_chat": "--telegram-chat",
        "smtp_host": "--smtp-host",
        "smtp_user": "--smtp-user",
        "smtp_password": "--smtp-password",
        "smtp_to": "--smtp-to",
        "pagerduty_key": "--pagerduty-key",
        "opsgenie_key": "--opsgenie-key",
        "github_token": "--github-token",
        "gitlab_token": "--gitlab-token",
        "github_org": "--github-org",
        "watch": "--watch",
        "certstream_seconds": "--certstream-seconds",
        "llm_provider": "--llm-provider",
        "llm_model": "--llm-model",
        "llm_base_url": "--llm-base-url",
        "llm_key": "--llm-key",
        "llm_timeout": "--llm-timeout",
        "llm_max_findings": "--llm-max-findings",
    }
    for key, flag in value_flags.items():
        val = opts.get(key)
        if val is not None and str(val).strip() != "":
            argv += [flag, str(val).strip()]

    if opts.get("concurrency") is not None:
        argv += ["--concurrency", str(int(opts["concurrency"]))]
    if opts.get("gau_threads") is not None:
        argv += ["--gau-threads", str(int(opts["gau_threads"]))]
    if opts.get("download_workers") is not None:
        argv += ["--download-workers", str(int(opts["download_workers"]))]
    if opts.get("requests_per_second") not in (None, "", 0, "0"):
        argv += ["--requests-per-second", str(opts["requests_per_second"])]
    if opts.get("smtp_port") not in (None, ""):
        argv += ["--smtp-port", str(int(opts["smtp_port"]))]
    for hdr in opts.get("header") or []:
        if str(hdr).strip():
            argv += ["--header", str(hdr).strip()]
    for tmpl in opts.get("nuclei_templates") or []:
        if str(tmpl).strip():
            argv += ["--nuclei-templates", str(tmpl).strip()]

    for cfg in opts.get("config") or []:
        if str(cfg).strip():
            argv += ["--config", str(cfg).strip()]
    for db in opts.get("secrets_db") or []:
        if str(db).strip():
            argv += ["--secrets-db", str(db).strip()]
    for apk in opts.get("apk") or []:
        if str(apk).strip():
            argv += ["--apk", str(apk).strip()]
    for ipa in opts.get("ipa") or []:
        if str(ipa).strip():
            argv += ["--ipa", str(ipa).strip()]
    for pkg in opts.get("package") or []:
        if str(pkg).strip():
            argv += ["--package", str(pkg).strip()]
    if opts.get("js_history_max") not in (None, ""):
        argv += ["--js-history-max", str(int(opts["js_history_max"]))]
    for h in opts.get("ignore_hash") or []:
        if str(h).strip():
            argv += ["--ignore-hash", str(h).strip()]
    return argv


def _strip_flag(argv: List[str], *flags: str) -> List[str]:
    out: List[str] = []
    skip_next = False
    for i, item in enumerate(argv or []):
        if skip_next:
            skip_next = False
            continue
        if item in flags:
            # value flags take the next token unless the next is another flag
            if i + 1 < len(argv) and not str(argv[i + 1]).startswith("-"):
                skip_next = True
            continue
        out.append(item)
    return out


def load_domain_list(path: str) -> List[str]:
    rows = []
    for ln in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        text = ln.strip()
        if text and not text.startswith("#"):
            rows.append(text)
    return rows


def run_domain_list(args: Any, argv: Optional[List[str]]) -> int:
    path = Path(args.domain_list)
    if not path.is_file():
        log(f"Domain list not found: {path}", "error")
        return 1
    domains = load_domain_list(str(path))
    if not domains:
        log("Domain list is empty", "error")
        return 1
    base = _strip_flag(
        list(argv or []),
        "--domain-list", "-d", "--domain", "-o", "--output",
    )
    parent = Path(args.output) if args.output else Path(".")
    worst = 0
    for domain in domains:
        out = parent / f"recon_{domain.replace('.', '_')}"
        log(f"Multi-target: {domain} → {out}", "info")
        rc = main(base + ["-d", domain, "--output", str(out)])
        if rc:
            worst = rc
    return worst


def main(argv: Optional[List[str]] = None) -> int:
    reset_log_counters()
    parser = build_parser()
    args = parser.parse_args(argv)
    apply_saved_keys(args)
    if getattr(args, "ci", False):
        apply_ci_defaults(args)
    rp_llm.apply_llm_settings(args)
    if getattr(args, "rescan", False):
        apply_rescan_defaults(args)
        log(
            f"Rescan: output={getattr(args, 'output', None) or '(default)'} "
            f"files={getattr(args, 'files', None) or '(from output dir)'} "
            f"resume={bool(getattr(args, 'resume', False))}",
            "info",
        )

    if args.domain_list and not (args.domain or "").strip():
        return run_domain_list(args, argv)

    if not (args.domain or "").strip():
        log("Need -d/--domain or --domain-list", "error")
        return 2

    cleaned = normalize_scan_domain(args.domain)
    if not cleaned:
        log(f"Need a DNS name, not {args.domain!r}", "error")
        return 2
    if cleaned != (args.domain or "").strip():
        log(f"Normalized target {args.domain} → {cleaned}", "info")
        args.domain = cleaned

    if args.subdomains and not Path(args.subdomains).exists():
        log(f"Subdomains file not found: {args.subdomains}", "error")
        return 1
    if args.files and not Path(args.files).exists():
        log(f"URL list file not found: {args.files}", "error")
        return 1
    if args.exclude_pattern and not Path(args.exclude_pattern).exists():
        log(f"Exclude pattern file not found: {args.exclude_pattern}", "error")
        return 1
    if args.include_pattern and not Path(args.include_pattern).exists():
        log(f"Include pattern file not found: {args.include_pattern}", "error")
        return 1
    if args.domain_list and not Path(args.domain_list).exists() and (args.domain or "").strip():
        
        pass
    for cfg in args.config:
        if not Path(cfg).exists():
            log(f"Config file not found: {cfg}", "error")
            return 1

    shop_domain = _normalize_host(args.shopify_domain)

    output_dir = Path(args.output or f"recon_{args.domain.replace('.', '_')}")
    output_dir.mkdir(parents=True, exist_ok=True)

    for cfg in args.config:
        load_config_file(Path(cfg), replace=False)
        log(f"Merged config overlay: {cfg}", "info")
    if args.config:
        log(
            f"Config: {len(PATTERNS)} patterns, {len(VALIDATORS)} validators, "
            f"min_confidence={MIN_CONFIDENCE}",
            "info",
        )
    if getattr(args, "refresh_secrets_db", False):
        dest = user_data_dir() / "secrets_patterns.yml"
        try:
            dest, n = refresh_secrets_pattern_db(
                dest,
                existing_patterns=PATTERNS,
                include_medium=bool(getattr(args, "secrets_db_medium", False)),
            )
            log(f"secrets-patterns-db: refreshed {n} high-confidence rule(s) → {dest}", "success")
        except Exception as exc:
            log(f"secrets-patterns-db refresh failed: {exc}", "warn")
    db_paths: List[Path] = []
    if not getattr(args, "skip_secrets_db", False):
        db_paths.extend([bundled_secrets_db_path(), user_data_dir() / "secrets_patterns.yml"])
    for extra in getattr(args, "secrets_db", None) or []:
        db_paths.append(Path(str(extra)))
    if db_paths:
        load_secrets_pattern_db_files(
            db_paths,
            include_medium=bool(getattr(args, "secrets_db_medium", False)),
        )
    apply_scope_files(args.include_pattern, args.exclude_pattern)
    if not getattr(args, "no_default_scope", False):
        added = apply_default_target_scope(args.domain or "")
        if added:
            log(
                f"Scope: default target {', '.join(added)} "
                "(off-site URLs dropped; --no-default-scope to keep them)",
                "info",
            )
    if SCOPE_INCLUDE or SCOPE_EXCLUDE:
        log(
            f"Scope: {len(SCOPE_INCLUDE)} include / {len(SCOPE_EXCLUDE)} exclude pattern(s)",
            "info",
        )
    configure_scan_runtime(args, output_dir)
    global VALIDATION_STORE, SCAN_VALIDATION_CACHE, DOWNLOAD_ETAG_CACHE
    SCAN_VALIDATION_CACHE = not bool(getattr(args, "no_validation_cache", False))
    if VALIDATION_STORE is not None:
        try:
            VALIDATION_STORE.close()
        except Exception:
            pass
    VALIDATION_STORE = None
    if not getattr(args, "skip_store", False):
        try:
            VALIDATION_STORE = connect_store()
            log(f"Finding store: {findings_db_path()}", "info")
        except Exception as exc:
            log(f"Finding store unavailable: {exc}", "warn")
    DOWNLOAD_ETAG_CACHE = load_etag_cache(output_dir / "download_etag.json")
    if getattr(args, "refresh_public_apis", False):
        try:
            dest, n = refresh_public_apis_catalog()
            log(f"public-apis catalog: {n} apiKey service(s) → {dest.name}", "success")
        except Exception as exc:
            log(f"public-apis catalog refresh failed: {exc}", "warn")
    checkpoint = load_checkpoint(output_dir) if (args.resume or args.resume_from) else None
    resume_from = (args.resume_from or "").strip()
    if resume_from and checkpoint:
        log(f"Resume-from checkpoint stage={checkpoint.get('stage')}", "info")
    if skip_completed_stage(resume_from, "chaos") and (output_dir / "subdomains.txt").is_file():
        args.subdomains = str(output_dir / "subdomains.txt")
        log("Resume-from: reusing subdomains.txt", "info")
        args.skip_subfinder = True
        args.skip_amass = True
        args.skip_assetfinder = True
        args.skip_findomain = True
        args.skip_intel = True
        args.skip_dnsx = True
        args.skip_naabu = True
    if skip_completed_stage(resume_from, "httpx") and (output_dir / "live_hosts.txt").is_file():
        args.skip_httpx = True
        args.skip_whatweb = True
        args.skip_gowitness = True
        log("Resume-from: skipping httpx, reusing live_hosts.txt", "info")
    if skip_completed_stage(resume_from, "discovery") and (output_dir / "files_to_scan.txt").is_file():
        args.files = str(output_dir / "files_to_scan.txt")
        log("Resume-from: reusing files_to_scan.txt", "info")
    skip_scan_stage = skip_completed_stage(resume_from, "trufflehog")

    if args.ignore_hash:
        n = apply_ignore_hashes(output_dir, args.ignore_hash)
        log(
            f"Baseline: ignore_all for {n} hash(es) → {output_dir / BASELINE_FILE}",
            "success",
        )

    log(f"Target:     {C.BOLD}{args.domain}{C.RESET}", "info")
    log(f"Output dir: {C.BOLD}{output_dir}{C.RESET}", "info")

    print(f"\n{C.DIM}Tool availability:{C.RESET}")
    tools_status = probe_tools()
    httpx_bin = resolve_httpx_bin()
    python_httpx = python_httpx_on_path()
    for tool, ok in tools_status.items():
        status = f"{C.GREEN}✓ found{C.RESET}" if ok else f"{C.YELLOW}✗ not found{C.RESET}"
        extra = ""
        if tool == "httpx" and httpx_bin:
            extra = f"  {C.DIM}{httpx_bin}{C.RESET}"
        elif tool == "httpx" and python_httpx:
            extra = f"  {C.DIM}(Python httpx at {python_httpx} — skipped){C.RESET}"
        print(f"  {tool:<14} {status}{extra}")

    if not AIOHTTP_AVAILABLE:
        log("aiohttp not installed — using sync validator fallback. Run: pip3 install aiohttp", "warn")

    eta = ScanEta(output_dir)
    eta.configure(
        skip_chaos=bool(args.skip_chaos or args.subdomains),
        skip_httpx=bool(args.skip_httpx),
        skip_discovery=bool(args.skip_discovery or args.files),
        skip_gau=bool(args.skip_gau),
        skip_intel=bool(args.skip_intel),
        skip_subfinder=bool(args.skip_subfinder),
        no_trufflehog=bool(args.no_trufflehog),
        no_validate=bool(args.no_validate),
        concurrency=int(args.concurrency),
        tools=dict(tools_status),
    )
    set_scan_eta(eta)

    # Subdomains
    step_header(1, "Subdomain Acquisition (Chaos)")
    _metrics_start("chaos")
    subdomains_file = output_dir / "subdomains.txt"

    if args.subdomains:
        subdomains_file = Path(args.subdomains)
        log(f"Using existing file: {subdomains_file}", "info")
    elif args.skip_chaos:
        subdomains_file.write_text(args.domain + "\n")
        log(f"Wrote single domain as fallback: {args.domain}", "info")
    else:
        chaos_key = resolve_chaos_key(args)
        if tools_status["chaos"]:
            cmd = build_chaos_cmd(args.domain, str(subdomains_file), chaos_key)
            log(f"Running chaos -d {args.domain}...", "info")
            chaos_env = os.environ.copy()
            if chaos_key:
                chaos_env["PDCP_API_KEY"] = chaos_key
                chaos_env["CHAOS_KEY"] = chaos_key
            rc, _ = run_cmd(cmd, env=chaos_env)
            if rc != 0 and not (
                subdomains_file.is_file() and subdomains_file.stat().st_size > 0
            ):
                log("Chaos CLI exited without a host list", "warn")
        elif not chaos_key:
            log("chaos not found — using target domain only", "warn")
            log("Install: go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "warn")
        else:
            log("chaos binary missing — querying Chaos HTTP API", "info")

        cli_hosts: List[str] = []
        if subdomains_file.is_file() and subdomains_file.stat().st_size > 0:
            cli_hosts = [
                s.strip() for s in subdomains_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                if s.strip()
            ]
        if len(cli_hosts) <= 1 and chaos_key:
            http_hosts = query_chaos_http(args.domain, chaos_key)
            if http_hosts:
                log(f"Chaos HTTP API: {len(http_hosts)} host(s)", "success")
                cli_hosts = merge_host_lists(cli_hosts, http_hosts)
        if len(cli_hosts) <= 1 and not chaos_key:
            log(
                "Chaos needs a ProjectDiscovery Cloud API key "
                "(GUI: Save API keys → Chaos, or PDCP_API_KEY / CHAOS_KEY). "
                "The website is logged-in; the CLI is not.",
                "warn",
            )
        if not cli_hosts:
            log("Chaos returned no results — falling back to target domain", "warn")
            cli_hosts = [args.domain]
        subdomains_file.write_text("\n".join(cli_hosts) + "\n", encoding="utf-8")

    sub_list = [s for s in subdomains_file.read_text().splitlines() if s.strip()]
    sub_count = len(sub_list)
    log(f"Subdomains: {C.BOLD}{sub_count}{C.RESET} (pre-intel)", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count)

    if not args.skip_subfinder and tools_status.get("subfinder"):
        sf_out = output_dir / "subfinder.txt"
        log("Running subfinder...", "info")
        rc, _ = run_cmd(
            build_subfinder_cmd(args.domain, str(sf_out)),
            timeout=180,
            discard_stdout=True,
        )
        extra_sf: List[str] = []
        if sf_out.is_file():
            extra_sf = [s.strip() for s in sf_out.read_text().splitlines() if s.strip()]
        if extra_sf:
            before = len(sub_list)
            sub_list = merge_host_lists(sub_list, extra_sf)
            added = len(sub_list) - before
            merged_path = output_dir / "subdomains.txt"
            merged_path.write_text("\n".join(sub_list) + "\n")
            subdomains_file = merged_path
            log(f"subfinder: {C.BOLD}{added}{C.RESET} new host(s) → {len(sub_list)} total", "success")
        else:
            log("subfinder: no additional hosts", "info")
    elif not args.skip_subfinder:
        log("subfinder not found — Chaos/OSINT only", "warn")
        log("Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "warn")

    source_map: Dict[str, List[str]] = {"seed": list(sub_list)}

    if not args.skip_amass and tools_status.get("amass"):
        am_out = output_dir / "amass.txt"
        log("Running amass...", "info")
        rc, _ = run_tool_maybe_docker(
            "amass",
            build_amass_cmd(args.domain, str(am_out), passive_only=not args.amass_active),
            timeout=240, discard_stdout=True, mount_dir=output_dir,
        )
        extra_am = []
        if am_out.is_file():
            extra_am = [s.strip() for s in am_out.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
        source_map["amass"] = extra_am
        sub_list = merge_tool_hosts(sub_list, extra_am, "amass", output_dir)
        subdomains_file = output_dir / "subdomains.txt"
    elif not args.skip_amass:
        log("amass not found — skipping", "info")

    if not args.skip_assetfinder and tools_status.get("assetfinder"):
        log("Running assetfinder...", "info")
        rc, output = run_tool_maybe_docker(
            "assetfinder", build_assetfinder_cmd(args.domain), timeout=120, mount_dir=output_dir,
        )
        extra_af = collect_tool_stdout_lines(output) if output else []
        source_map["assetfinder"] = extra_af
        sub_list = merge_tool_hosts(sub_list, extra_af, "assetfinder", output_dir)
        subdomains_file = output_dir / "subdomains.txt"

    if not args.skip_findomain and tools_status.get("findomain"):
        fd_out = output_dir / "findomain.txt"
        log("Running findomain...", "info")
        run_tool_maybe_docker(
            "findomain", build_findomain_cmd(args.domain, str(fd_out)),
            timeout=120, discard_stdout=True, mount_dir=output_dir,
        )
        extra_fd = []
        if fd_out.is_file():
            extra_fd = [s.strip() for s in fd_out.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
        source_map["findomain"] = extra_fd
        sub_list = merge_tool_hosts(sub_list, extra_fd, "findomain", output_dir)
        subdomains_file = output_dir / "subdomains.txt"

    unique_subs, tracked = merge_subdomain_sources(source_map)
    if unique_subs:
        # Keep discovery order from merge_host_lists (sorted) plus any extras already merged
        pass
    (output_dir / "subdomain_sources.json").write_text(json.dumps(tracked, indent=2), encoding="utf-8")
    save_checkpoint(output_dir, "chaos", {"subs": len(sub_list)})
    _metrics_finish("chaos", len(sub_list))
    webhook = (args.notify_webhook or "").strip()
    if webhook:
        notify_stage_progress(webhook, "subdomains", 0.16, {"subs": len(sub_list)})

    if not args.skip_intel:
        log("Passive intel: Shodan / Censys / ZoomEye / crt.sh", "info")
        with eta_heartbeat(80):
            intel = collect_osint_hosts(
                args.domain,
                shodan_key=args.shodan_key or "",
                censys_id=args.censys_id or "",
                censys_secret=args.censys_secret or "",
                zoomeye_key=args.zoomeye_key or "",
                skip_crtsh=args.skip_crtsh,
                skip_intel=False,
            )
        extra = []
        for src, hosts in intel.items():
            extra.extend(hosts)
        if extra:
            before = len(sub_list)
            sub_list = merge_host_lists(sub_list, extra)
            added = len(sub_list) - before
            merged_path = output_dir / "subdomains.txt"
            merged_path.write_text("\n".join(sub_list) + "\n")
            subdomains_file = merged_path
            log(
                f"Intel merge: {C.BOLD}{added}{C.RESET} new host(s) → {len(sub_list)} total",
                "success",
            )
        else:
            log("Intel merge: no additional hosts", "info")
    else:
        log("Passive intel skipped (--skip-intel)", "info")

    scoped = filter_hosts_in_scope(sub_list)
    if len(scoped) != len(sub_list):
        log(
            f"Scope filter: {len(sub_list)} → {len(scoped)} host(s)",
            "info",
        )
        sub_list = scoped
        (output_dir / "subdomains.txt").write_text("\n".join(sub_list) + "\n")

    sub_count = len(sub_list)
    log(f"Subdomains: {C.BOLD}{sub_count}{C.RESET}", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count, log_now=True)

    if not args.skip_dnsx and tools_status.get("dnsx") and sub_list:
        dnsx_in = output_dir / "dnsx_input.txt"
        dnsx_out = output_dir / "dnsx.txt"
        dnsx_in.write_text("\n".join(sub_list) + "\n")
        log("Running dnsx...", "info")
        run_tool_maybe_docker(
            "dnsx", build_dnsx_cmd(str(dnsx_in), str(dnsx_out)),
            timeout=180, discard_stdout=True, mount_dir=output_dir,
        )
        if dnsx_out.is_file() and dnsx_out.stat().st_size > 0:
            resolved = [s.strip() for s in dnsx_out.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
            if resolved:
                sub_list = merge_host_lists(resolved)
                sub_count = len(sub_list)
                (output_dir / "subdomains.txt").write_text("\n".join(sub_list) + "\n")
                log(f"dnsx: {C.BOLD}{sub_count}{C.RESET} resolved host(s)", "success")

    if not args.skip_naabu and tools_status.get("naabu") and sub_list:
        naabu_in = output_dir / "subdomains.txt"
        naabu_out = output_dir / "naabu.txt"
        (output_dir / "subdomains.txt").write_text("\n".join(sub_list) + "\n")
        log("Running naabu...", "info")
        run_tool_maybe_docker(
            "naabu", build_naabu_cmd(str(naabu_in), str(naabu_out)),
            timeout=180, discard_stdout=True, mount_dir=output_dir,
        )
        if naabu_out.is_file():
            extra_ports = [s.strip() for s in naabu_out.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
            if extra_ports:
                sub_list = merge_host_lists(sub_list, extra_ports)
                sub_count = len(sub_list)
                log(f"naabu: {len(extra_ports)} host:port row(s)", "success")

    # Live hosts
    step_header(2, "Live Host Filtering (httpx)")
    _metrics_start("httpx", sub_count)
    live_hosts_file = output_dir / "live_hosts.txt"
    reuse_live = (
        skip_completed_stage(resume_from, "httpx")
        and live_hosts_file.is_file()
        and live_hosts_file.stat().st_size > 0
    )

    if reuse_live:
        log("Resume-from: reusing live_hosts.txt", "info")
    elif args.skip_httpx or not httpx_bin:
        if not args.skip_httpx:
            log_httpx_missing()
        live_hosts_file.write_text("\n".join(sub_list))
        live_count = sub_count
    else:
        # Scale wall-clock budget with list size (50 threads × ~10s per probe, + buffer)
        httpx_timeout = max(300, min(3600, (sub_count // 50) * 12 + 120))
        log(
            f"Running httpx ({httpx_bin}, timeout {httpx_timeout}s)...",
            "info",
        )
        # File input is more reliable than stdin under subprocess capture
        httpx_input = output_dir / "httpx_input.txt"
        httpx_input.write_text("\n".join(sub_list) + "\n")
        if live_hosts_file.exists():
            live_hosts_file.unlink()
        httpx_cmd = build_httpx_cmd(
            httpx_bin,
            str(httpx_input),
            str(live_hosts_file),
            threads=50,
            timeout=10,
        )
        # Results go to -o (live_hosts.txt). Capturing stdout here used to
        # buffer every host in RAM and crash the GUI websocket.
        rc, _output = run_cmd(httpx_cmd, timeout=httpx_timeout, discard_stdout=True)

        def _httpx_hosts() -> bytes:
            if live_hosts_file.is_file() and live_hosts_file.stat().st_size > 0:
                return live_hosts_file.read_bytes()
            return b""

        hosts_raw = _httpx_hosts()
        if rc == 0:
            # Empty result is valid (zero live hosts) — do not inflate to all subs
            live_hosts_file.write_bytes(hosts_raw)
        elif hosts_raw:
            kind = "timed out" if rc == CMD_TIMEOUT_RC else "exited with an error"
            log(
                f"httpx {kind} — using partial live-host results "
                "(not treating all subdomains as live)",
                "warn",
            )
            live_hosts_file.write_bytes(hosts_raw)
        elif rc == CMD_TIMEOUT_RC:
            log(
                "httpx timed out with no results — not assuming all subdomains are live",
                "error",
            )
            live_hosts_file.write_text("")
        else:
            # Wrong binary / bad flags. Treating every subdomain as live used
            # to explode Katana/waymore and crash the GUI.
            log(
                "httpx failed immediately with no results — "
                "not treating all subdomains as live (use --skip-httpx to force)",
                "error",
            )
            live_hosts_file.write_text("")

    live_list = [h for h in live_hosts_file.read_text().splitlines() if h.strip()]
    live_count = len(live_list)
    if live_count == 0 and sub_count > 0 and not args.skip_httpx and tools_status.get("httpx"):
        log(
            "No live hosts after httpx — downstream URL discovery will be empty. "
            "Re-run with --skip-httpx to force all subdomains, or increase budget.",
            "warn",
        )
    log(f"Live hosts: {C.BOLD}{live_count}{C.RESET} / {sub_count}", "success")
    if int(getattr(args, "certstream_seconds", 0) or 0) > 0:
        cs_hosts = collect_certstream_hosts(args.domain, int(args.certstream_seconds))
        if cs_hosts:
            live_list = merge_host_lists(live_list, cs_hosts)
            live_list = filter_hosts_in_scope(live_list)
            live_count = len(live_list)
            live_hosts_file.write_text("\n".join(live_list) + "\n")
            log(f"certstream: +{len(cs_hosts)} host(s) → {live_count} live", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count, live=live_count, log_now=True)
    save_checkpoint(output_dir, "httpx", {"live": live_count})
    _metrics_finish("httpx", live_count)
    if (args.notify_webhook or "").strip():
        notify_stage_progress(args.notify_webhook, "httpx", 0.32, {"live": live_count})

    if not args.skip_whatweb and tools_status.get("whatweb") and live_list:
        ww_in = output_dir / "live_hosts.txt"
        ww_out = output_dir / "whatweb.json"
        log("Running whatweb...", "info")
        run_cmd(build_whatweb_cmd(str(ww_in), str(ww_out)), timeout=180, discard_stdout=True)

    if not args.skip_gowitness and tools_status.get("gowitness") and live_list:
        gw_dir = output_dir / "screenshots"
        gw_dir.mkdir(exist_ok=True)
        log("Running gowitness...", "info")
        run_cmd(build_gowitness_cmd(str(live_hosts_file), str(gw_dir)), timeout=240, discard_stdout=True)

    # skip-httpx + skip-whatweb means live hosts are not a scan target
    # (Apps only). Do not fingerprint the workspace domain.
    if (
        not (args.skip_httpx and args.skip_whatweb)
        and tools_status.get("wappalyzer")
        and live_list
        and not skip_completed_stage(resume_from, "httpx")
    ):
        wap_out = output_dir / "wappalyzer.json"
        rows: List[str] = []
        webanalyze_bin = addons.resolve_webanalyze_bin()
        if webanalyze_bin and "webanalyze" in Path(webanalyze_bin).name.lower():
            log("Running webanalyze (Wappalyzer fingerprints)...", "info")
            hosts_in = output_dir / "webanalyze_hosts.txt"
            hosts_in.write_text(
                "\n".join(
                    (h if h.startswith("http") else f"https://{h}") for h in live_list[:80]
                )
                + "\n",
                encoding="utf-8",
            )
            rc, output = run_cmd(
                build_webanalyze_file_cmd(str(hosts_in), str(wap_out)),
                timeout=180,
            )
            rows.extend(collect_tool_stdout_lines(output))
        elif httpx_bin and httpx_has_tech_detect(httpx_bin):
            log("Running httpx -tech-detect (wappalyzergo)...", "info")
            tech_in = output_dir / "httpx_tech_input.txt"
            tech_in.write_text("\n".join(live_list[:80]) + "\n", encoding="utf-8")
            rc, _output = run_cmd(
                build_httpx_tech_cmd(httpx_bin, str(tech_in), str(wap_out)),
                timeout=180,
                discard_stdout=True,
            )
            if wap_out.is_file():
                rows = [
                    ln
                    for ln in wap_out.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if ln.strip()
                ]
        else:
            log("Running wappalyzer...", "info")
            for host in live_list[:25]:
                target = host if host.startswith("http") else f"https://{host}"
                rc, output = run_cmd(build_wappalyzer_cmd(target), timeout=30)
                rows.extend(collect_tool_stdout_lines(output))
        if rows:
            wap_out.write_text("\n".join(rows) + "\n", encoding="utf-8")
            log(f"tech detect: {len(rows)} line(s) → {wap_out.name}", "info")

    # URL discovery
    step_header(3, "URL Discovery (Katana + waymore + gospider)")
    _metrics_start("discovery", live_count)
    files_to_scan = output_dir / "files_to_scan.txt"
    file_exts = DISCOVERY_KEEP_URL_RE

    if args.files:
        files_to_scan = Path(args.files)
        log(f"Using existing URL list: {files_to_scan}", "info")
    elif args.resume and files_to_scan.is_file() and files_to_scan.stat().st_size > 0:
        log(f"Resume: reusing URL list {files_to_scan}", "info")
    elif args.skip_discovery:
        log("URL discovery skipped (--skip-discovery) — scanning live hosts directly", "warn")
        files_to_scan.write_text("\n".join(live_list))
    else:
        all_urls: Set[str] = set()
        passive_hosts = live_list[:DISCOVERY_PASSIVE_HOST_CAP]
        if live_count > DISCOVERY_PASSIVE_HOST_CAP:
            log(
                f"Passive discovery: first {DISCOVERY_PASSIVE_HOST_CAP} of "
                f"{live_count} live hosts (keeps the GUI from hanging)",
                "info",
            )

        # Katana — active crawl + JS endpoint parsing
        if tools_status["katana"]:
            log(f"Katana: active crawl + JS parsing ({live_count} hosts)...", "info")
            katana_input = output_dir / "katana_input.txt"
            katana_input.write_text("\n".join(live_list))
            katana_out_file = output_dir / "katana_urls.txt"

            jsl_available = check_tool("jsluice")

            katana_cmd = build_katana_cmd(
                str(katana_input),
                str(katana_out_file),
                headless=bool(args.headless),
                jsl=bool(jsl_available),
            )

            if katana_out_file.exists():
                katana_out_file.unlink()
            # Scale with live host count; default 600s is too short for large scopes
            katana_timeout = max(600, min(7200, live_count * 2 + 300))
            rc, _ = run_cmd(katana_cmd, timeout=katana_timeout, discard_stdout=True)
            if katana_out_file.exists() and katana_out_file.stat().st_size > 0:
                raw_katana = [
                    l.strip() for l in katana_out_file.read_text().splitlines() if l.strip()
                ]
                extend_url_set(all_urls, raw_katana)
                if rc == 0:
                    log(f"Katana raw crawl: {len(raw_katana)} total URLs", "info")
                    log(f"Katana: {len(all_urls)} URLs added", "success")
                else:
                    log(
                        f"Katana timed out/failed — using partial output "
                        f"({len(raw_katana)} URLs)",
                        "warn",
                    )
            else:
                log("Katana failed or produced no output — skipping its URLs", "warn")
        else:
            log("katana not found — skipping active crawl", "warn")
            log("Install: go install github.com/projectdiscovery/katana/cmd/katana@latest", "warn")

        # Passive archives — skipped by --skip-gau
        if url_set_full(all_urls):
            log(f"URL discovery capped at {DISCOVERY_URL_CAP} — skipping extra sources", "warn")
        elif args.skip_gau:
            log("Passive archives skipped (--skip-gau)", "info")
        elif tools_status["waymore"]:
            before = len(all_urls)
            log(f"waymore: passive archive crawl ({len(passive_hosts)} hosts)...", "info")
            waymore_dir = output_dir / "waymore_out"
            waymore_dir.mkdir(exist_ok=True)

            waymore_failures = 0
            for host in passive_hosts:
                if url_set_full(all_urls):
                    break
                clean = re.sub(r'https?://', '', host).rstrip('/')
                # -oU expects a file path (not a dir);
                waymore_out = waymore_dir / f"{clean.replace('/', '_')}.txt"
                rc, _ = run_cmd(
                    build_waymore_cmd(clean, str(waymore_out)),
                    timeout=120,
                    discard_stdout=True,
                )
                if rc != 0:
                    waymore_failures += 1
                    continue
                if waymore_out.is_file():
                    kept = [
                        line.strip()
                        for line in waymore_out.read_text().splitlines()
                        if line.strip() and file_exts.search(line)
                    ]
                    extend_url_set(all_urls, kept)
            added = len(all_urls) - before
            if waymore_failures:
                log(
                    f"waymore: {waymore_failures}/{len(passive_hosts)} hosts failed "
                    f"(+{added} URLs, total {len(all_urls)})",
                    "warn",
                )
            else:
                log(f"waymore: +{added} new URLs (total {len(all_urls)})", "success")

        elif tools_status["gau"]:
            before = len(all_urls)
            log("waymore not found — using gau as passive fallback (Wayback + CommonCrawl + OTX + VT)", "warn")
            for i, host in enumerate(passive_hosts, 1):
                if url_set_full(all_urls):
                    break
                if i % 10 == 0:
                    log(f"  gau: {i}/{len(passive_hosts)} hosts...", "info")
                rc, output = run_cmd(
                    build_gau_cmd(host, int(args.gau_threads)),
                    timeout=60,
                    discard_stdout=False,
                )
                if output:
                    kept = [
                        line.strip()
                        for line in output.decode("utf-8", errors="ignore").splitlines()
                        if line.strip() and file_exts.search(line)
                    ]
                    extend_url_set(all_urls, kept)
            log(f"gau: +{len(all_urls) - before} new URLs", "success")

        elif tools_status["waybackurls"]:
            before = len(all_urls)
            log("Using waybackurls as last-resort passive fallback", "warn")
            for host in passive_hosts:
                if url_set_full(all_urls):
                    break
                rc, output = run_cmd(build_waybackurls_cmd(host), timeout=60)
                if output:
                    kept = [
                        line.strip()
                        for line in output.decode("utf-8", errors="ignore").splitlines()
                        if line.strip() and file_exts.search(line)
                    ]
                    extend_url_set(all_urls, kept)
            log(f"waybackurls: +{len(all_urls) - before} new URLs", "success")

        else:
            log("No passive archive tools found.", "warn")
            log("Install waymore : pip3 install waymore", "warn")
            log("Install gau     : go install github.com/lc/gau/v2/cmd/gau@latest", "warn")
            log("Install waybackurls: go install github.com/tomnomnom/waybackurls@latest", "warn")

        # gospider active JS spider
        if tools_status["gospider"] and not url_set_full(all_urls):
            before = len(all_urls)
            log(f"gospider: active JS spidering ({live_count} hosts)...", "info")
            gs_input = output_dir / "gospider_input.txt"
            gs_input.write_text("\n".join(live_list))
            gs_out_dir = output_dir / "gospider_out"
            gs_out_dir.mkdir(exist_ok=True)

            run_cmd(
                build_gospider_cmd(str(gs_input), str(gs_out_dir)),
                timeout=300,
                discard_stdout=True,
            )

            url_re = re.compile(r'\[url\]\s+\[\d+\]\s+-\s+(https?://\S+)')
            js_re  = re.compile(r'https?://\S+\.(js|json|jsx|map)\b')
            extra: List[str] = []
            for gf in gs_out_dir.glob("*"):
                if url_set_full(all_urls):
                    break
                try:
                    for line in gf.read_text(errors="ignore").splitlines():
                        m = url_re.search(line)
                        if m and file_exts.search(m.group(1)):
                            extra.append(m.group(1).strip())
                        m2 = js_re.search(line)
                        if m2:
                            extra.append(m2.group(0).strip())
                except Exception:
                    pass
            extend_url_set(all_urls, extra)
            log(f"gospider: +{len(all_urls) - before} new URLs (total {len(all_urls)})", "success")
        elif not tools_status["gospider"]:
            log("gospider not found — skipping active spider layer", "warn")
            log("Install: go install github.com/jaeles-project/gospider@latest", "warn")

        if not args.skip_gau and tools_status.get("waybackurls") and not url_set_full(all_urls):
            before = len(all_urls)
            log("waybackurls: extra Wayback pass...", "info")
            for host in live_list[:DISCOVERY_PASSIVE_HOST_CAP]:
                if url_set_full(all_urls):
                    break
                rc, output = run_cmd(build_waybackurls_cmd(host), timeout=45)
                extend_url_set(
                    all_urls,
                    [line for line in collect_tool_stdout_lines(output) if file_exts.search(line)],
                )
            log(f"waybackurls extra: +{len(all_urls) - before} URLs", "info")

        if not args.skip_hakrawler and tools_status.get("hakrawler") and not url_set_full(all_urls):
            before = len(all_urls)
            log("hakrawler: form-aware crawl...", "info")
            hakrawler_misses = 0
            for host in live_list[:40]:
                if url_set_full(all_urls):
                    break
                target = host if host.startswith("http") else f"https://{host}"
                hak_cmd = build_hakrawler_cmd(target)
                rc, output = run_cmd(
                    hak_cmd,
                    timeout=60,
                    stdin_data=hakrawler_stdin(target, hak_cmd),
                )
                lines = collect_tool_stdout_lines(output)
                extend_url_set(all_urls, lines)
                if rc not in (0, None) and not lines:
                    hakrawler_misses += 1
                    if hakrawler_misses >= 2:
                        log("hakrawler failing — skipping remaining hosts", "warn")
                        break
            log(f"hakrawler: +{len(all_urls) - before} URLs", "info")

        if not args.skip_paramspider and tools_status.get("paramspider") and not url_set_full(all_urls):
            ps_dir = output_dir / "paramspider"
            ps_dir.mkdir(exist_ok=True)
            log("paramspider: parameterized URLs...", "info")
            rc, output = run_cmd(
                build_paramspider_cmd(args.domain, str(ps_dir)),
                timeout=120,
            )
            extra = [
                ln
                for ln in collect_tool_stdout_lines(output)
                if ln.startswith("http://") or ln.startswith("https://")
            ]
            result_roots = [ps_dir, Path("results"), Path.cwd() / "results"]
            seen_files = set()
            for root in result_roots:
                if not root.exists():
                    continue
                paths = [root] if root.is_file() else list(root.rglob("*.txt"))
                for gf in paths:
                    try:
                        key = str(gf.resolve())
                    except OSError:
                        key = str(gf)
                    if key in seen_files:
                        continue
                    seen_files.add(key)
                    try:
                        extra.extend(
                            line.strip()
                            for line in Path(gf).read_text(
                                encoding="utf-8", errors="ignore"
                            ).splitlines()
                            if line.strip().startswith("http")
                        )
                    except Exception:
                        pass
            extend_url_set(all_urls, extra)

        sorted_urls = dedupe_urls(sorted(all_urls))
        if len(sorted_urls) > DISCOVERY_URL_CAP:
            log(
                f"URL cap: keeping {DISCOVERY_URL_CAP} of {len(sorted_urls)} discovered URLs",
                "warn",
            )
            sorted_urls = sorted_urls[:DISCOVERY_URL_CAP]
        files_to_scan.write_text("\n".join(sorted_urls))

    url_list = [u for u in files_to_scan.read_text().splitlines() if u.strip()]
    scoped_urls = filter_urls_in_scope(url_list)
    if len(scoped_urls) != len(url_list):
        log(f"Scope filter: {len(url_list)} → {len(scoped_urls)} URL(s)", "info")
        url_list = scoped_urls
        if not args.files:
            files_to_scan.write_text("\n".join(url_list))
    extra_urls: List[str] = []
    hub_images: List[str] = []
    code_urls: List[str] = []
    repo_dir_scanned: Optional[Path] = None
    env_hits = env_like_urls(harvest_discovery_url_pool(output_dir, url_list))
    if env_hits:
        extra_urls.extend(env_hits)
        log(f".env-like URLs: {len(env_hits)}", "info")
    mcp_hits = mcp_like_urls(harvest_discovery_url_pool(output_dir, url_list))
    if mcp_hits:
        extra_urls.extend(mcp_hits)
        log(f"MCP/AI config URLs: {len(mcp_hits)}", "info")
    if getattr(args, "spray", False):
        if tools_status.get("spray"):
            extra_urls.extend(run_spray_leak_probe(live_list, output_dir))
        else:
            log(
                "spray not found — skipping (--spray is opt-in). "
                "https://github.com/chainreactors/spray",
                "warn",
            )
    if not getattr(args, "skip_sensitive_paths", False) and live_list:
        extra_urls.extend(probe_sensitive_paths(live_list, output_dir))
    if getattr(args, "burp_import", None):
        burp_path = Path(args.burp_import)
        if burp_path.is_file():
            burp_urls = parse_burp_xml(burp_path)
            extra_urls.extend(burp_urls)
            log(f"Burp import: {len(burp_urls)} URL(s)", "info")
    if getattr(args, "nuclei_import", None):
        ni = Path(args.nuclei_import)
        if ni.is_file():
            imported = parse_nuclei_output(ni)
            (output_dir / "nuclei_imported.json").write_text(json.dumps(imported, indent=2), encoding="utf-8")
            log(f"Nuclei import: {len(imported)} row(s)", "info")
    if getattr(args, "repo", None):
        repo_dir = output_dir / "repo_scan"
        ok, repo_dir = clone_repo(
            args.repo,
            repo_dir,
            timeout=300,
            shallow=bool(getattr(args, "repo_shallow", False)),
        )
        if ok:
            repo_dir_scanned = repo_dir
            repo_files = list_repo_files(repo_dir)
            if args.iac_scan:
                iac = collect_iac_files(repo_dir)
                log(f"IaC files: {len(iac)}", "info")
            for p in repo_files:
                extra_urls.append(str(p))
            mode = "shallow" if getattr(args, "repo_shallow", False) else "full history"
            log(f"Repo clone ({mode}): {len(repo_files)} file(s)", "info")
        else:
            log("git clone failed — skipping --repo", "warn")

    apk_inputs = list(getattr(args, "apk", None) or []) + list(getattr(args, "ipa", None) or [])
    pkg_ids = parse_package_ids(getattr(args, "package", None) or [])
    if pkg_ids:
        fetch_dir = output_dir / "mobile_fetch"
        try:
            fetched = fetch_android_packages(
                pkg_ids,
                fetch_dir,
                run=run_cmd,
                docker_fallback=bool(DOCKER_FALLBACK),
            )
        except Exception as exc:
            fetched = []
            log(f"package fetch: {str(exc)[:120]}", "warn")
        if fetched:
            apk_inputs.extend(str(p) for p in fetched)
            log(f"Package fetch: {len(fetched)} archive(s) via apkeep/gplaycli", "success")
        else:
            have = []
            if shutil.which("apkeep"):
                have.append("apkeep")
            if shutil.which("gplaycli"):
                have.append("gplaycli")
            if have:
                log("Package fetch: apkeep/gplaycli ran but produced no APK", "warn")
            else:
                log(
                    "Package fetch: install apkeep (preferred) or gplaycli "
                    "to download --package ids, or pass --apk with a local file",
                    "warn",
                )
    if apk_inputs:
        apk_dir = output_dir / "mobile_extract"
        apk_dir.mkdir(exist_ok=True)
        extracted_n = 0
        for archive in apk_inputs:
            ap = Path(str(archive))
            if not ap.is_file():
                log(f"Mobile archive not found: {archive}", "warn")
                continue
            dest = apk_dir / re.sub(r"[^a-zA-Z0-9._-]", "_", ap.stem)[:80]
            files = extract_mobile_archive(ap, dest)
            extra_urls.extend(str(p) for p in files)
            extracted_n += len(files)
        log(f"Mobile extract: {extracted_n} file(s) from {len(apk_inputs)} archive(s)", "info")

    if not getattr(args, "skip_code_search", False):
        gh = (getattr(args, "github_token", None) or "").strip()
        gl = (getattr(args, "gitlab_token", None) or "").strip()
        org = (getattr(args, "github_org", None) or "").strip()
        try:
            code_urls = collect_code_search_urls(
                args.domain,
                github_token=gh,
                gitlab_token=gl,
                org=org,
                extra_hosts=live_list[:15],
            )
        except Exception as exc:
            code_urls = []
            log(f"code search: {str(exc)[:120]}", "warn")
        if code_urls:
            extra_urls.extend(code_urls)
            (output_dir / "code_search_urls.txt").write_text("\n".join(code_urls) + "\n", encoding="utf-8")
            log(f"Code search: {len(code_urls)} public file URL(s)", "success")
        else:
            log("Code search: no extra URLs (set GITHUB_TOKEN for higher limits)", "info")

    if not getattr(args, "skip_ci_logs", False):
        gh_tok = (getattr(args, "github_token", None) or "").strip()
        gl_tok = (getattr(args, "gitlab_token", None) or "").strip()
        try:
            ci_targets = collect_ci_targets(
                repo_url=str(getattr(args, "repo", None) or ""),
                github_org=(getattr(args, "github_org", None) or "").strip(),
                code_urls=code_urls,
                github_token=gh_tok,
            )
            ci_dir = output_dir / "ci_logs"
            ci_files = collect_ci_log_files(
                ci_targets,
                ci_dir,
                github_token=gh_tok,
                gitlab_token=gl_tok,
            )
        except Exception as exc:
            ci_files = []
            log(f"CI logs: {str(exc)[:120]}", "warn")
        if ci_files:
            extra_urls.extend(str(p) for p in ci_files)
            (output_dir / "ci_logs.json").write_text(
                json.dumps([str(p) for p in ci_files], indent=2), encoding="utf-8"
            )
            log(f"CI logs/artifacts: {len(ci_files)} file(s) from public workflows", "success")
        else:
            log("CI logs: no public workflow logs or artifacts", "info")

    if not getattr(args, "skip_pastes", False):
        try:
            paste_dir = output_dir / "paste_sources"
            paste_files = collect_paste_files(
                args.domain,
                paste_dir,
                github_token=(getattr(args, "github_token", None) or "").strip(),
            )
        except Exception as exc:
            paste_files = []
            log(f"paste search: {str(exc)[:120]}", "warn")
        if paste_files:
            extra_urls.extend(str(p) for p in paste_files)
            (output_dir / "paste_urls.json").write_text(
                json.dumps([str(p) for p in paste_files], indent=2), encoding="utf-8"
            )
            log(f"Paste sites: {len(paste_files)} Pastebin/Gist/Ghostbin hit(s)", "success")
        else:
            log("Paste sites: no matching public pastes", "info")

    if not getattr(args, "skip_docker_hub", False):
        try:
            hub_images = collect_docker_hub_images(
                args.domain,
                extra_hosts=live_list[:8],
            )
        except Exception as exc:
            hub_images = []
            log(f"Docker Hub search: {str(exc)[:120]}", "warn")
        if hub_images:
            (output_dir / "docker_hub_images.json").write_text(
                json.dumps(hub_images, indent=2), encoding="utf-8"
            )
            log(f"Docker Hub: {len(hub_images)} public image(s)", "success")
        else:
            log("Docker Hub: no public images matched the target", "info")

    if not getattr(args, "skip_buckets", False):
        try:
            bucket_hit = probe_buckets(args.domain)
        except Exception as exc:
            bucket_hit = {"buckets": [], "urls": []}
            log(f"bucket probe: {str(exc)[:120]}", "warn")
        b_rows = bucket_hit.get("buckets") or []
        b_urls = bucket_hit.get("urls") or []
        if b_rows:
            (output_dir / "buckets.json").write_text(json.dumps(b_rows, indent=2), encoding="utf-8")
        extra_urls.extend(b_urls)
        open_n = sum(1 for r in b_rows if r.get("access") == "open")
        exist_n = sum(1 for r in b_rows if r.get("access") == "exists")
        if b_rows:
            log(
                f"Buckets: {open_n} open / {exist_n} exist-but-closed "
                f"({len(b_urls)} object URL(s))",
                "success" if open_n else "info",
            )
    js_extra = analyze_js_bundle(url_list, output_dir)
    extra_urls.extend(u for u in js_extra if u.startswith("http"))
    if tools_status.get("linkfinder"):
        js_files = extract_js_urls(url_list)[:30]
        lf_out = output_dir / "linkfinder.txt"
        lines: List[str] = []
        for js in js_files:
            rc, output = run_cmd(build_linkfinder_cmd(js), timeout=30)
            lines.extend(collect_tool_stdout_lines(output))
        if lines:
            lf_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
            extra_urls.extend(ln for ln in lines if ln.startswith("http"))
            log(f"LinkFinder: {len(lines)} line(s)", "info")
    if not getattr(args, "skip_jsleak", False) and tools_status.get("jsleak"):
        js_files = extract_js_urls(url_list)[:80]
        if js_files:
            yaml_path = bundled_secrets_db_path()
            user_yaml = user_data_dir() / "secrets_patterns.yml"
            if user_yaml.is_file():
                yaml_path = user_yaml
            extra_dbs = [Path(p) for p in (getattr(args, "secrets_db", None) or []) if Path(p).is_file()]
            if extra_dbs:
                yaml_path = extra_dbs[-1]
            use_secrets = yaml_path.is_file()
            log(f"jsleak: scanning {len(js_files)} JS URL(s)...", "info")
            stdin = ("\n".join(js_files) + "\n").encode("utf-8")
            rc, output = run_cmd(
                build_jsleak_cmd(str(yaml_path) if use_secrets else None, concurrency=12, secrets=use_secrets),
                stdin_data=stdin,
                timeout=180,
            )
            blob = (output or b"").decode("utf-8", errors="ignore")
            parsed = parse_jsleak_output(blob)
            (output_dir / "jsleak.txt").write_text(blob, encoding="utf-8")
            leak_urls = [row["url"] for row in parsed.get("links") or [] if (row.get("url") or "").startswith("http")]
            extra_urls.extend(leak_urls)
            js_hits = findings_from_jsleak(parsed.get("secrets") or [])
            if js_hits:
                (output_dir / "jsleak_secrets.json").write_text(
                    json.dumps(js_hits, indent=2), encoding="utf-8"
                )
                extra_urls.extend(str(h.get("source_url") or "") for h in js_hits if str(h.get("source_url") or "").startswith("http"))
            log(
                f"jsleak: {len(leak_urls)} link(s), {len(js_hits)} secret hit(s)",
                "success" if (leak_urls or js_hits) else "info",
            )
            # Stash hits on args for merge after secret scan starts with empty raw_findings
            args._jsleak_findings = js_hits
    if not getattr(args, "skip_openapi", False):
        spec_extra: List[str] = []
        spec_findings: List[Dict] = list(getattr(args, "_spec_findings", None) or [])
        ua_spec = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        candidates = [
            u for u in (url_list + extra_urls)
            if re.search(r"(swagger|openapi|postman)", u, re.I)
        ][:40]
        for u in candidates:
            page, _extra = _load_scan_text(u, ua_spec)
            if not page:
                continue
            spec_extra.extend(harvest_spec_urls(page, u))
            spec_findings.extend(harvest_spec_secret_findings(page, u))
        extra_urls.extend(spec_extra)
        if spec_findings:
            args._spec_findings = spec_findings  
    if extra_urls:
        url_list = dedupe_urls(url_list + extra_urls)
    scoped_extra = filter_urls_in_scope(url_list)
    if len(scoped_extra) != len(url_list):
        log(
            f"Scope filter: {len(url_list)} → {len(scoped_extra)} URL(s) "
            "(dropped off-target hosts)",
            "info",
        )
        url_list = scoped_extra
        if not args.files:
            files_to_scan.write_text("\n".join(url_list))
    elif extra_urls and not args.files:
        files_to_scan.write_text("\n".join(url_list))
    url_count = len(url_list)

    if url_count == 0:
        log("No URLs discovered — check that live_hosts.txt is populated and gau/katana are installed", "warn")
        log(f"Live hosts file: {live_hosts_file}", "warn")
        log(f"Files to scan:   {files_to_scan}", "warn")
    else:
        log(f"Total URLs to scan: {C.BOLD}{url_count}{C.RESET}", "success")
    if _ETA is not None:
        _ETA.set_work(urls=url_count, live=live_count, log_now=True)
    save_checkpoint(output_dir, "discovery", {"urls": url_count})
    _metrics_finish("discovery", url_count)
    if (args.notify_webhook or "").strip():
        notify_stage_progress(args.notify_webhook, "discovery", 0.48, {"urls": url_count})

    # Secret scanning
    step_header(4, "Secret Scanning (TruffleHog / Gitleaks / Custom)")
    _metrics_start("trufflehog", url_count)
    unique_path = output_dir / "unique_findings.json"
    unique_findings: List[Dict] = []
    exposures: List[Dict] = []
    informational: List[Dict] = []
    resumed_scan = False
    if skip_scan_stage and unique_path.is_file():
        try:
            loaded = json.loads(unique_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                unique_findings = loaded
                resumed_scan = True
                log(
                    f"Resume-from: reusing unique_findings.json ({len(unique_findings)} finding(s))",
                    "info",
                )
        except Exception:
            resumed_scan = False

    if resumed_scan:
        raw_findings = list(unique_findings)
        use_trufflehog = False
        use_gitleaks = False
    else:
        raw_findings = []
        use_trufflehog = not args.no_trufflehog and tools_status["trufflehog"]
        use_gitleaks = (
            not getattr(args, "skip_gitleaks", False)
            and bool(tools_status.get("gitleaks"))
        )
        if not getattr(args, "skip_gitleaks", False) and not tools_status.get("gitleaks"):
            log(
                "gitleaks not found — skipping "
                "(install: go install github.com/zricethezav/gitleaks/v8@latest)",
                "warn",
            )

    if not resumed_scan and (use_trufflehog or use_gitleaks):
        # Filesystem scanners need local files
        log("Downloading remote files for secret scan...", "info")
        dl_dir = output_dir / "downloaded_files"
        dl_dir.mkdir(exist_ok=True)

        to_fetch = url_list[:2000]
        workers = max(1, min(int(getattr(args, "download_workers", 16) or 16), 32))
        with eta_heartbeat(90):
            counts = download_files_parallel(
                to_fetch, dl_dir, workers=workers, timeout=8
            )
        downloaded = counts.get("downloaded", 0)
        cached = counts.get("cached", 0)
        skipped = counts.get("skipped", 0)
        wayback_n = counts.get("wayback", 0)
        ready = downloaded + cached + wayback_n
        extra = f", skipped {skipped} binary" if skipped else ""
        if wayback_n:
            extra += f", wayback {wayback_n}"
        log(
            f"Downloaded {downloaded} files ({cached} cached{extra}) → {dl_dir}",
            "success",
        )

        recon_dir = output_dir / "reconstructed_sources"
        history_diff: List[Dict] = []
        if ready > 0 and SCAN_SOURCEMAPS:
            n_maps, n_src = reconstruct_downloaded_js_maps(to_fetch, dl_dir, recon_dir)
            if n_src:
                log(
                    f"Source maps: reconstructed {n_src} original file(s) "
                    f"from {n_maps} public map(s) → {recon_dir}",
                    "success",
                )
        if ready > 0 and SCAN_JS_HISTORY:
            n_hist, history_diff = fetch_live_js_history(to_fetch, dl_dir, recon_dir)
            if n_hist:
                log(
                    f"JS history: {n_hist} distinct archived version(s) "
                    f"(≤{SCAN_JS_HISTORY_MAX}/URL, oldest first) → "
                    f"{recon_dir / '_wayback'}",
                    "success",
                )
            if history_diff:
                log(
                    f"JS history diff: {len(history_diff)} removed-line secret(s)",
                    "warn",
                )
        scan_roots: List[Path] = [dl_dir]
        if recon_dir.is_dir() and any(
            p.is_file() and p.name != "index.json" for p in recon_dir.rglob("*")
        ):
            scan_roots.append(recon_dir)
        if repo_dir_scanned and Path(repo_dir_scanned).is_dir():
            scan_roots.append(Path(repo_dir_scanned))
        ci_scan = output_dir / "ci_logs"
        if ci_scan.is_dir() and any(p.is_file() for p in ci_scan.rglob("*")):
            scan_roots.append(ci_scan)
        paste_scan = output_dir / "paste_sources"
        if paste_scan.is_dir() and any(p.is_file() for p in paste_scan.rglob("*")):
            scan_roots.append(paste_scan)

        image_layer_findings: List[Dict] = []
        if not getattr(args, "skip_image_layers", False):
            ref_pool: List[str] = list(hub_images)
            for root in list(scan_roots):
                for f_path in iter_scan_files(root, limit=250):
                    name = f_path.name.lower()
                    if not (
                        is_iac_file(f_path)
                        or name in {
                            "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                            "compose.yml", "compose.yaml",
                        }
                        or f_path.suffix.lower() in {".yml", ".yaml", ".json", ".tf"}
                    ):
                        continue
                    try:
                        ref_pool.extend(
                            extract_image_refs(
                                f_path.read_text(encoding="utf-8", errors="ignore")
                            )
                        )
                    except Exception:
                        continue
            selected = select_images_for_target(
                ref_pool, args.domain, hub_hits=hub_images
            )
            (output_dir / "image_refs.json").write_text(
                json.dumps(selected, indent=2), encoding="utf-8"
            )
            if selected:
                log(f"Image layers: scanning {len(selected)} public image(s)...", "info")
                have_docker = shutil.which("docker") is not None
                have_trivy = shutil.which("trivy") is not None
                pull_fn = (
                    wave3.docker_save_image if have_docker else (lambda _ref, _tar: None)
                )
                trivy_fn = wave3.trivy_image_secrets if have_trivy else None
                image_dir = output_dir / "image_layers"
                layer_files, image_layer_findings = scan_public_image_layers(
                    selected,
                    image_dir,
                    pull_and_save=pull_fn,
                    trivy_scan=trivy_fn,
                )
                if layer_files:
                    scan_roots.append(image_dir)
                    extra_urls.extend(str(p) for p in layer_files)
                    log(
                        f"Image layers: extracted {len(layer_files)} credential-like file(s)",
                        "success",
                    )
                elif image_layer_findings:
                    log(
                        f"Image layers: {len(image_layer_findings)} Trivy secret hit(s)",
                        "success",
                    )
                elif not have_docker and not have_trivy:
                    log(
                        "Image layers: docker/trivy not installed — recorded refs only",
                        "info",
                    )
            else:
                log("Image layers: no target-related public images", "info")

        if ready > 0:
            output = b""
            rc = 0
            if use_trufflehog:
                raw_findings = []
                any_th = False
                for root in scan_roots:
                    log(f"Running TruffleHog on {root.name}...", "info")
                    rc, output = run_cmd(
                        trufflehog_filesystem_cmd(str(root)),
                        timeout=600,
                    )
                    if output and output.strip():
                        any_th = True
                        chunk = parse_trufflehog(output)
                        annotate_wayback_findings(chunk)
                        raw_findings.extend(chunk)
                if any_th:
                    log(f"TruffleHog: {len(raw_findings)} raw findings", "success")
            if use_trufflehog and raw_findings:
                pass
            elif use_trufflehog:
                if rc not in (0, None):
                    log(
                        "TruffleHog exited before writing findings "
                        "(updater/binary replace is a common cause). "
                        "Using the built-in scanner on the downloaded files.",
                        "warn",
                    )
                else:
                    log("TruffleHog returned no findings — running custom scanner too", "warn")
                with eta_heartbeat(90):
                    raw_findings = custom_scan(str(files_to_scan), output_dir)
                for f_path in iter_scan_files(*scan_roots):
                    try:
                        content_text = f_path.read_text(errors="ignore")
                        from_source_map = (
                            is_source_map_path(str(f_path))
                            or looks_like_source_map_json(content_text)
                        )
                        if from_source_map:
                            raw_findings.append(
                                make_source_map_exposure(str(f_path), "custom_local")
                            )
                            content_text = expand_source_map_content(content_text)
                        for key_type, pattern in PATTERNS.items():
                            for m in re.finditer(pattern, content_text):
                                raw = m.group(0)
                                grp = m.group(m.lastindex) if m.lastindex else raw
                                key = grp if grp is not None else raw
                                if looks_fake(key):
                                    continue
                                if is_certificate_pin(key, content_text, m.start(), m.end(), str(f_path)):
                                    continue
                                if key_type == "mapbox_token" and not is_mapbox_token(key):
                                    continue
                                if key_type in INFORMATIONAL_TYPES:
                                    raw_findings.append({
                                        "type": key_type, "key": key,
                                        "source_url": str(f_path),
                                        "scanner": "custom_local",
                                        "tier": "informational",
                                        "note": INFORMATIONAL_NOTES.get(
                                            key_type, "Informational"
                                        ),
                                    })
                                    continue
                                needs_context = key_type in {
                                    "generic_secret", "uuid_candidate", "jwt",
                                    "discord_token", "datadog_api_key", "hashicorp_vault",
                                    "vercel_token", "netlify_pat", "algolia_api", "algolia_admin",
                                    "pagerduty_api", "trello_api", "okta_api", "clerk_secret",
                                }
                                hint = (
                                    match_public_api_hint(content_text, m.start(), m.end())
                                    if SCAN_PUBLIC_APIS
                                    else None
                                )
                                if needs_context and not has_context(
                                    content_text, m.start(), m.end()
                                ) and not hint:
                                    continue
                                if key_type == "uuid_candidate":
                                    if not has_heroku_context(
                                        content_text, m.start(), m.end(), window=100
                                    ):
                                        continue
                                    key_type = "heroku_api"
                                if key_type == "generic_secret":
                                    if entropy(key) < GENERIC_SECRET_MIN_ENTROPY:
                                        continue
                                    if is_dictionary_word(key):
                                        continue
                                jwt_meta = None
                                if key_type in {"jwt", "supabase_service", "supabase_anon", "monday_api", "onepassword_connect"}:
                                    jwt_meta = inspect_jwt(key)
                                    if not jwt_meta.get("ok"):
                                        continue
                                    if key_type == "supabase_service" and not is_supabase_service(jwt_meta):
                                        continue
                                    if key_type == "supabase_anon" and not is_supabase_anon(jwt_meta):
                                        continue
                                    if key_type == "jwt" and is_supabase_service(jwt_meta):
                                        key_type = "supabase_service"
                                    elif key_type == "jwt" and is_supabase_anon(jwt_meta):
                                        key_type = "supabase_anon"
                                    elif key_type == "jwt":
                                        kind = jwt_provider_kind(jwt_meta)
                                        if kind:
                                            key_type = kind
                                confidence = score_confidence(
                                    key_type, key, content_text, m.start(), m.end()
                                )
                                if key_type == "jwt" and jwt_meta:
                                    if jwt_meta.get("alg_none"):
                                        confidence = max(confidence, 95)
                                    elif jwt_meta.get("live"):
                                        confidence = max(confidence, 78)
                                    elif jwt_meta.get("kid") or jwt_meta.get("iss"):
                                        confidence = max(confidence, 70)
                                if key_type == "supabase_service":
                                    confidence = max(confidence, 90)
                                if key_type == "supabase_anon":
                                    confidence = max(confidence, 70)
                                if confidence < MIN_CONFIDENCE:
                                    continue
                                item = {
                                    "type": key_type, "key": key,
                                    "source_url": str(f_path),
                                    "scanner": "custom_local", "verified": False,
                                    "confidence": confidence,
                                }
                                if jwt_meta:
                                    item["jwt"] = jwt_meta
                                if from_source_map:
                                    item["from_source_map"] = True
                                if hint:
                                    attach_public_api_meta(item, hint)
                                raw_findings.append(item)
                    except Exception:
                        pass
            if SCAN_PUBLIC_APIS:
                for f_path in iter_scan_files(*scan_roots):
                    try:
                        raw_findings.extend(
                            collect_public_api_query_findings(
                                f_path.read_text(errors="ignore"),
                                str(f_path),
                            )
                        )
                    except Exception:
                        pass
            mcp_n = 0
            for f_path in iter_scan_files(*scan_roots, limit=400):
                try:
                    if not f_path.is_file() or f_path.stat().st_size > 2_000_000:
                        continue
                    text = f_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                hits = findings_from_mcp_content(text, str(f_path), scanner="mcp_config")
                if hits:
                    raw_findings.extend(hits)
                    mcp_n += len(hits)
            if mcp_n:
                log(f"AI/MCP configs: {mcp_n} credential(s)", "warn")
            if not getattr(args, "skip_openapi", False):
                spec_urls: List[str] = []
                spec_hits = 0
                for f_path in iter_scan_files(*scan_roots, limit=400):
                    try:
                        if not f_path.is_file() or f_path.stat().st_size > 2_000_000:
                            continue
                        text = f_path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    spec_urls.extend(harvest_spec_urls(text, str(f_path)))
                    extra_hits = harvest_spec_secret_findings(text, str(f_path))
                    if extra_hits:
                        raw_findings.extend(extra_hits)
                        spec_hits += len(extra_hits)
                if spec_urls:
                    extra_urls.extend(spec_urls)
                    (output_dir / "openapi_urls.txt").write_text(
                        "\n".join(merge_unique(spec_urls)) + "\n", encoding="utf-8"
                    )
                if spec_urls or spec_hits:
                    log(f"OpenAPI/Postman: {len(merge_unique(spec_urls))} URL(s), {spec_hits} example secret(s)", "info")
            if use_gitleaks:
                gl_total = 0
                for root in scan_roots:
                    report = output_dir / (
                        "gitleaks.json"
                        if root == dl_dir
                        else f"gitleaks_{root.name}.json"
                    )
                    log(f"Running Gitleaks on {root.name}...", "info")
                    gl_hits = run_gitleaks_source(root, report, git=False)
                    if gl_hits:
                        raw_findings.extend(gl_hits)
                        gl_total += len(gl_hits)
                if gl_total:
                    log(f"Gitleaks: {gl_total} finding(s)", "success")
                else:
                    log("Gitleaks: no findings", "info")
            if not use_trufflehog:
                log("Running built-in regex scanner...", "info")
                with eta_heartbeat(90):
                    raw_findings.extend(custom_scan(str(files_to_scan), output_dir))
                for f_path in iter_scan_files(*scan_roots):
                    try:
                        content_text = f_path.read_text(errors="ignore")
                        from_source_map = (
                            is_source_map_path(str(f_path))
                            or looks_like_source_map_json(content_text)
                        )
                        if from_source_map:
                            content_text = expand_source_map_content(content_text)
                        for key_type, pattern in PATTERNS.items():
                            for m in re.finditer(pattern, content_text):
                                raw = m.group(0)
                                grp = m.group(m.lastindex) if m.lastindex else raw
                                key = grp if grp is not None else raw
                                if looks_fake(key) or key_type in INFORMATIONAL_TYPES:
                                    continue
                                if is_certificate_pin(key, content_text, m.start(), m.end(), str(f_path)):
                                    continue
                                raw_findings.append({
                                    "type": key_type,
                                    "key": key,
                                    "source_url": str(f_path),
                                    "scanner": "custom_local",
                                    "verified": False,
                                    "from_source_map": bool(from_source_map),
                                    "from_reconstructed": "reconstructed_sources" in str(f_path),
                                    "from_js_history": "_wayback" in str(f_path).replace("\\", "/"),
                                })
                    except Exception:
                        pass
            if history_diff:
                raw_findings.extend(history_diff)
            if image_layer_findings:
                raw_findings.extend(image_layer_findings)
                log(
                    f"Image layers: {len(image_layer_findings)} Trivy/layer finding(s)",
                    "success",
                )
        else:
            log("No files downloaded — falling back to custom HTTP scanner", "warn")
            with eta_heartbeat(90):
                raw_findings = custom_scan(str(files_to_scan), output_dir)
            if image_layer_findings:
                raw_findings.extend(image_layer_findings)
    elif not resumed_scan:
        if not args.no_trufflehog:
            log("trufflehog not found — using built-in regex scanner", "warn")
            log("Install: https://github.com/trufflesecurity/trufflehog#installation", "warn")
        log("Running built-in regex scanner...", "info")
        with eta_heartbeat(90):
            raw_findings = custom_scan(str(files_to_scan), output_dir)

    if not resumed_scan and repo_dir_scanned and use_trufflehog:
        log("Running TruffleHog on git history...", "info")
        rc, output = run_cmd(trufflehog_git_cmd(str(repo_dir_scanned)), timeout=600)
        if output and output.strip():
            git_hits = parse_trufflehog(output)
            for item in git_hits:
                item["scanner"] = "trufflehog_git"
            raw_findings.extend(git_hits)
            log(f"TruffleHog git: {len(git_hits)} finding(s)", "success")
        else:
            log("TruffleHog git: no findings", "info")

    if not resumed_scan and repo_dir_scanned and use_gitleaks:
        log("Running Gitleaks on git history...", "info")
        gl_git = run_gitleaks_source(
            repo_dir_scanned, output_dir / "gitleaks_git.json", git=True
        )
        if gl_git:
            raw_findings.extend(gl_git)
            log(f"Gitleaks git: {len(gl_git)} finding(s)", "success")
        else:
            log("Gitleaks git: no findings", "info")

    jsleak_hits = getattr(args, "_jsleak_findings", None) or []
    if not resumed_scan and jsleak_hits:
        raw_findings.extend(jsleak_hits)
        log(f"jsleak secrets merged: {len(jsleak_hits)}", "info")
    spec_hits = getattr(args, "_spec_findings", None) or []
    if not resumed_scan and spec_hits:
        raw_findings.extend(spec_hits)
        log(f"OpenAPI/Postman secrets merged: {len(spec_hits)}", "info")
    if not resumed_scan and repo_dir_scanned:
        blamed = annotate_repo_findings(raw_findings, repo_dir_scanned)
        if blamed:
            log(f"git log -S: annotated {blamed} finding(s) with commit metadata", "info")

    if not resumed_scan:
        annotate_wayback_findings(raw_findings)
        before_scope = len(raw_findings)
        raw_findings = filter_findings_in_scope(raw_findings)
        dropped_scope = before_scope - len(raw_findings)
        if dropped_scope:
            log(
                f"Scope filter: dropped {dropped_scope} off-target finding(s)",
                "info",
            )
        raw_findings, dropped_pins = drop_certificate_pins(raw_findings)
        if dropped_pins:
            log(
                f"Dropped {dropped_pins} certificate pin(s) — public hashes, not keys",
                "info",
            )
        raw_findings, informational = split_informational(raw_findings)
        raw_findings, exposures = split_exposures(raw_findings)
        baseline = load_baseline(output_dir)
        exposures = filter_by_baseline(exposures, baseline)
        if exposures and output_dir:
            n = save_exposures(output_dir, exposures)
            if n:
                log(f"Source map exposures: {n} → source_map_exposures.json", "warn")
            for e in exposures:
                src = e.get("source_url", "")
                src_short = ("…" + src[-55:]) if len(src) > 55 else src
                log(f"{C.YELLOW}[source_map_exposure]{C.RESET} {src_short}", "find")
            record_findings_in_baseline(output_dir, exposures)
            baseline = load_baseline(output_dir)

        informational = filter_by_baseline(informational, baseline)
        if informational and output_dir:
            n = save_informational(output_dir, informational)
            if n:
                log(f"Informational: {n} public-by-design hits → informational.json", "info")
            record_findings_in_baseline(output_dir, informational)
            baseline = load_baseline(output_dir)

        before_bl = len(raw_findings)
        raw_findings = filter_by_baseline(raw_findings, baseline)
        suppressed = before_bl - len(raw_findings)
        if suppressed:
            log(f"Baseline suppressed {suppressed} known type+source hit(s)", "info")

        unique_findings = deduplicate(raw_findings)
        unique_path.write_text(json.dumps(unique_findings, indent=2), encoding="utf-8")

    log(f"Unique findings: {C.BOLD}{len(unique_findings)}{C.RESET} (from {len(raw_findings)} raw)", "success")
    save_checkpoint(output_dir, "trufflehog", {"findings": len(unique_findings)})
    _metrics_finish("trufflehog", len(unique_findings))
    if _ETA is not None:
        _ETA.set_work(findings=len(unique_findings), urls=url_count, log_now=True)

    for f in unique_findings:
        kp = f['key'][:28] + "…" if len(f['key']) > 28 else f['key']
        src = f.get('source_url', '')
        src_short = ("…" + src[-50:]) if len(src) > 50 else src
        conf = f.get('confidence', '?')
        log(f"{C.YELLOW}[{f.get('type', 'unknown')}]{C.RESET} conf={conf} {kp}  {C.DIM}{src_short}{C.RESET}", "find")

    # Validation
    step_header(5, "Key Validation (Async)")
    _metrics_start("validate", len(unique_findings))
    validated: List[Dict] = []

    if args.no_validate or not unique_findings:
        if not unique_findings:
            log("No findings to validate.", "warn")
        else:
            log("Validation skipped (--no-validate)", "warn")
        validated = unique_findings
    else:
        log(f"Validating {len(unique_findings)} keys (concurrency={args.concurrency})...", "info")
        n8n_flag = getattr(args, "n8n_url", None) or ""
        if n8n_flag:
            for f in unique_findings:
                f.setdefault("n8n_url", n8n_flag)
        with eta_heartbeat(90):
            if AIOHTTP_AVAILABLE:
                validated = asyncio.run(
                    validate_all(
                        unique_findings,
                        args.domain,
                        args.concurrency,
                        shop_domain,
                        vault_addr=args.vault_addr or "",
                        grafana_url=args.grafana_url or "",
                    )
                )
            else:
                log("Using synchronous validator (install aiohttp for async)...", "warn")
                for f in unique_findings:
                    if args.vault_addr:
                        f["vault_addr"] = args.vault_addr
                    if args.grafana_url:
                        f["grafana_url"] = args.grafana_url
                    if args.n8n_url:
                        f["n8n_url"] = args.n8n_url
                validated = validate_sync_fallback(unique_findings, args.domain, shop_domain)

        valid_count = sum(1 for f in validated if f.get("valid"))
        log(f"Results: {C.GREEN}{C.BOLD}{valid_count} VALID{C.RESET} / {len(validated)} checked", "success")

        for f in validated:
            if f.get("valid"):
                kp = f['key'][:35] + "…" if len(f['key']) > 35 else f['key']
                log(
                    f"{C.BOLD}[{f.get('type','unknown')}]{C.RESET} "
                    f"{C.GREEN}{kp}{C.RESET} | "
                    f"{f.get('note','')[:60]} | "
                    f"{C.DIM}{f.get('source_url','')[:50]}{C.RESET}",
                    "valid"
                )

    # Output
    step_header(6, "Saving Results")

    validated = annotate_severity(validated)
    exposures = annotate_severity(exposures)
    informational = annotate_severity(informational)
    validated = apply_ai_verdict(validated)
    exposures = apply_ai_verdict(exposures)
    (output_dir / "ai_verdict.json").write_text(
        json.dumps(
            [
                {
                    "type": f.get("type"),
                    "ai_verdict": f.get("ai_verdict"),
                    "ai_score": f.get("ai_score"),
                    "ai_reasons": f.get("ai_reasons") or [],
                    "valid": bool(f.get("valid")),
                    "mcp_config": bool(f.get("mcp_config")),
                    "source_url": f.get("source_url"),
                    "key": redact_key(str(f.get("key") or "")),
                }
                for f in validated
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    if VALIDATION_STORE is not None:
        try:
            stats = upsert_findings(VALIDATION_STORE, args.domain, validated)
            log(
                f"Finding store: +{stats.get('new', 0)} new / "
                f"{stats.get('newly_valid', 0)} newly valid",
                "info",
            )
        except Exception as exc:
            log(f"Finding store write failed: {exc}", "warn")

    prev_findings: List[Dict] = []
    findings_json = output_dir / "findings.json"
    if findings_json.is_file():
        try:
            loaded = json.loads(findings_json.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                prev_findings = loaded
        except Exception:
            prev_findings = []
        try:
            shutil.copy2(findings_json, output_dir / "previous_findings.json")
        except OSError:
            pass
    diff = compare_scan_runs(prev_findings, validated)
    (output_dir / "findings_diff.json").write_text(
        json.dumps(
            {
                "new_count": len(diff["new"]),
                "resolved_count": len(diff["resolved"]),
                "unchanged_count": len(diff["unchanged"]),
                "new": [
                    {
                        "type": f.get("type"),
                        "hash": f.get("hash"),
                        "severity": finding_severity(f),
                        "source_url": f.get("source_url"),
                        "key": redact_key(str(f.get("key") or "")),
                    }
                    for f in diff["new"]
                ],
                "resolved": [
                    {
                        "type": f.get("type"),
                        "hash": f.get("hash"),
                        "source_url": f.get("source_url"),
                    }
                    for f in diff["resolved"]
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if prev_findings:
        log(
            f"Run diff: {len(diff['new'])} new / {len(diff['resolved'])} gone / "
            f"{len(diff['unchanged'])} unchanged → findings_diff.json",
            "info",
        )

    findings_json.write_text(json.dumps(validated, indent=2))
    log(f"findings.json  → {findings_json}", "success")

    # Remember reported type+source so re-scans skip only those URLs
    n_bl = record_findings_in_baseline(output_dir, validated)
    if n_bl:
        log(f"Baseline updated (+{n_bl} source record(s)) → {BASELINE_FILE}", "info")

    valid_only = [f for f in validated if f.get("valid")]
    if valid_only:
        valid_json = output_dir / "valid_keys.json"
        valid_json.write_text(json.dumps(valid_only, indent=2))
        log(f"valid_keys.json → {valid_json}", "success")

    summary_file = output_dir / "summary.txt"
    with open(summary_file, "w") as sf:
        sf.write(f"ReconPipe Results — {args.domain}\n")
        sf.write(f"{'=' * 60}\n")
        sf.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        sf.write(f"Subdomains    : {sub_count}\n")
        sf.write(f"Live hosts    : {live_count}\n")
        sf.write(f"URLs scanned  : {url_count}\n")
        sf.write(f"Raw findings  : {len(raw_findings)}\n")
        sf.write(f"Unique keys   : {len(unique_findings)}\n")
        sf.write(f"Valid keys    : {len(valid_only)}\n")
        sf.write(f"Informational : {len(informational)} (public-by-design, not counted)\n")
        sf.write(f"Exposures     : {len(exposures)} (source maps; see source_map_exposures.json)\n\n")

        if exposures:
            sf.write("SOURCE MAP EXPOSURES\n")
            sf.write("-" * 60 + "\n")
            for e in exposures:
                sf.write(f"Type    : {e.get('type','source_map_exposure')}\n")
                sf.write(f"URL     : {e.get('source_url') or e.get('key','')}\n")
                sf.write(f"Note    : {e.get('note','')}\n\n")

        if valid_only:
            sf.write("CONFIRMED VALID KEYS\n")
            sf.write("-" * 60 + "\n")
            for f in valid_only:
                sf.write(f"Type    : {f.get('type','unknown')}\n")
                sf.write(f"Severity: {f.get('severity','')}\n")
                sf.write(f"Key     : {f.get('key','')}\n")
                sf.write(f"Source  : {f.get('source_url','')}\n")
                sf.write(f"Note    : {f.get('note','')}\n")
                status = f.get("status_code")
                if status is not None:
                    sf.write(f"Status  : HTTP {status}\n")
                sf.write("\n")
        elif unique_findings:
            sf.write("UNVALIDATED FINDINGS (review manually)\n")
            sf.write("-" * 60 + "\n")
            for f in unique_findings:
                sf.write(f"Type    : {f.get('type','unknown')}\n")
                sf.write(f"Key     : {f.get('key','')}\n")
                sf.write(f"Source  : {f.get('source_url','')}\n")
               
                status = f.get("status_code")
                if status is not None:
                    sf.write(f"Status  : HTTP {status}\n")
                sf.write("\n")
        else:
            sf.write("No findings.\n")

    log(f"summary.txt    → {summary_file}", "success")

    sarif_path = Path(args.sarif) if args.sarif else (output_dir / "results.sarif")
    # Include exposures as SARIF errors (leak surface) plus all validated findings
    sarif_findings = list(validated) + list(exposures)
    write_sarif(sarif_findings, sarif_path, domain=args.domain)
    log(f"results.sarif  → {sarif_path}", "success")

    extra_rep = {
        "new_count": len(diff.get("new") or []),
        "executive": executive_summary(
            args.domain, validated, len(valid_only), len(exposures)
        ),
    }
    html_path = write_html_report(
        output_dir / "report.html", args.domain, validated, exposures, informational, extra_rep
    )
    md_path = write_markdown_report(
        output_dir / "report.md", args.domain, validated, exposures, informational, extra_rep
    )
    csv_path = write_csv_report(
        output_dir / "findings.csv", validated, exposures, informational
    )
    log(f"report.html    → {html_path}", "success")
    log(f"report.md      → {md_path}", "success")
    log(f"findings.csv   → {csv_path}", "success")
    jsonld_path = write_jsonld_report(output_dir / "report.jsonld", args.domain, validated)
    log(f"report.jsonld  → {jsonld_path}", "success")
    try:
        rem_path = rp_llm.maybe_write_llm_report(
            output_dir, args.domain, validated, exposures, informational, args,
        )
        if rem_path:
            log(f"remediation.md → {rem_path}", "success")
    except Exception as exc:
        log(f"LLM remediation skipped: {exc}", "warn")
    n_tpl = write_nuclei_templates(output_dir, valid_only)
    if n_tpl:
        log(f"nuclei templates: {n_tpl}", "success")
    fp = update_global_fingerprints(validated)
    log(f"Global fingerprints: {len(fp.get('new') or [])} new / {fp.get('total')} total", "info")
    if PIPELINE_METRICS is not None:
        (output_dir / "pipeline_metrics.json").write_text(
            json.dumps(PIPELINE_METRICS.to_report(), indent=2), encoding="utf-8"
        )
    (output_dir / "export_hackerone.md").write_text(export_hackerone_markdown(validated), encoding="utf-8")
    (output_dir / "export_jira.md").write_text(export_jira_markdown(validated), encoding="utf-8")
    try:
        written = rp_reports.write_vendor_and_reports(
            output_dir,
            args.domain,
            validated,
            exposures,
            informational,
            redact=redact_key,
        )
        log(
            "Vendor dashboard + templates → "
            + ", ".join(written.keys()),
            "success",
        )
    except Exception as exc:
        log(f"Vendor/report templates skipped: {exc}", "warn")
    save_checkpoint(output_dir, "validate", {"valid": len(valid_only)})
    _metrics_finish("validate", len(valid_only))

    if args.nuclei and tools_status.get("nuclei") and url_list:
        nuc_out = output_dir / "nuclei.txt"
        log("Running nuclei...", "info")
        run_tool_maybe_docker(
            "nuclei",
            build_nuclei_cmd(str(files_to_scan), str(nuc_out), args.nuclei_templates or None),
            timeout=300, discard_stdout=True, mount_dir=output_dir,
        )

    try:
        remember_scan_target(
            args.domain,
            files=files_to_scan if Path(files_to_scan).is_file() else None,
            subdomains=subdomains_file if Path(subdomains_file).is_file() else None,
            output=output_dir,
        )
    except Exception as exc:
        log(f"Could not save target for rescan: {exc}", "warn")

    pack_items = list(validated) + list(exposures)
    if pack_items or informational:
        hits_dir = pack_hit_bundle(
            output_dir,
            validated,
            exposures=exposures,
            informational=informational,
        )
        if hits_dir:
            n_src = 0
            src_dir = hits_dir / "sources"
            if src_dir.is_dir():
                n_src = sum(1 for p in src_dir.iterdir() if p.is_file())
            log(
                f"Hit bundle: {n_src} JS/.map files + keys + summary → {hits_dir}",
                "success",
            )

    valid_count = sum(1 for f in validated if f.get("valid"))
    webhook = (args.notify_webhook or "").strip()
    if not args.no_notify or webhook:
        notify_scan_complete(
            args.domain,
            valid_only if valid_only else [f for f in validated if f.get("valid")],
            webhook=webhook,
            desktop=not args.no_notify,
        )
    send_extra_alerts(args.domain, valid_only, args)
    elapsed_txt = fmt_hms(_ETA.snapshot()["elapsed_s"]) if _ETA is not None else ""
    if _ETA is not None:
        _ETA.finish()
    print(f"\n{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"{C.BOLD}  PIPELINE COMPLETE{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"  Domain       :  {C.BOLD}{args.domain}{C.RESET}")
    if elapsed_txt:
        print(f"  Elapsed      :  {C.BOLD}{elapsed_txt}{C.RESET}")
    print(f"  Subdomains   :  {C.BOLD}{sub_count}{C.RESET}")
    print(f"  Live hosts   :  {C.BOLD}{live_count}{C.RESET}")
    print(f"  URLs scanned :  {C.BOLD}{url_count}{C.RESET}")
    print(f"  Unique keys  :  {C.BOLD}{len(unique_findings)}{C.RESET}")
    if valid_count:
        print(f"  Valid keys   :  {C.GREEN}{C.BOLD}{valid_count}{C.RESET}")
    else:
        print(f"  Valid keys   :  0")
    if exposures:
        print(f"  Exposures    :  {C.YELLOW}{C.BOLD}{len(exposures)}{C.RESET} source maps")
    print(f"  Output dir   :  {C.BOLD}{output_dir}/{C.RESET}")
    hits_dir = output_dir / "hits"
    if hits_dir.is_dir():
        print(f"  Hit bundle   :  {C.BOLD}{hits_dir}/{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}\n")

    if valid_count and not args.no_fail_on_valid:
        log(
            f"Exiting with code 1: {valid_count} valid key(s) "
            f"(use --no-fail-on-valid to disable)",
            "error",
        )
        return 1
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    watch = 0
    if "--watch" in argv:
        try:
            watch = int(argv[argv.index("--watch") + 1])
        except (IndexError, ValueError):
            watch = 0
    while True:
        rc = main(argv)
        if watch <= 0:
            sys.exit(rc)
        print(f"Watch: next scan in {watch}s (Ctrl+C to stop)", flush=True)
        try:
            time.sleep(watch)
        except KeyboardInterrupt:
            sys.exit(rc)
