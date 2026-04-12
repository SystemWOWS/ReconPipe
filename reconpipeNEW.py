#!/usr/bin/env python3
"""
ReconPipe — Automated API Key Leak Hunter
Pipeline: Chaos -> httpx -> gau/waybackurls -> TruffleHog -> Async Validator

Usage: python3 reconpipe.py -d target.com
       python3 reconpipe.py -d target.com --subdomains subs.txt
       python3 reconpipe.py -d target.com --no-trufflehog  (use built-in regex scanner)
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# ANSI Colors
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

BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗██████╗ ███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║██╔══██╗██╔════╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║██████╔╝█████╗
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═══╝ ██║██╔═══╝ ██╔══╝
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ██║██║     ███████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝     ╚══════╝
{C.RESET}{C.DIM}  Chaos → httpx → gau → TruffleHog → Async Validator | v1.0{C.RESET}
"""

# Secret Patterns (built-in fallback scanner)
PATTERNS: Dict[str, str] = {
    "google_api":       r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth":     r"ya29\.[0-9A-Za-z\-_]{20,}",
    "aws_access_key":   r"AKIA[0-9A-Z]{16}",
    "aws_secret":       r"(?i)aws.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]",
    "github_pat":       r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth":     r"gho_[0-9a-zA-Z]{36}",
    "github_app":       r"(ghu|ghs)_[0-9a-zA-Z]{36}",
    "stripe_live":      r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_test":      r"sk_test_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_(live|test)_[0-9a-zA-Z]{24,}",
    "sendgrid":         r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "mailgun":          r"key-[0-9a-zA-Z]{32}",
    "twilio_sid":       r"AC[a-z0-9]{32}",
    "twilio_token":     r"SK[0-9a-fA-F]{32}",
    "slack_token":      r"xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{10,}",
    "slack_webhook":    r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "firebase_url":     r"[a-z0-9-]+\.firebaseio\.com",
    "firebase_key":     r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "uuid_candidate":   r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
    "jwt":              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "shopify_token":    r"shpat_[a-fA-F0-9]{32}",
    "shopify_secret":   r"shpss_[a-fA-F0-9]{32}",
    "mailchimp":        r"[0-9a-f]{32}-us[0-9]{1,2}",
    "discord_token":    r"[MN][A-Za-z\d]{23}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27}",
    "discord_webhook":  r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
    "telegram_bot":     r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
    "mapbox_token":     r"pk\.eyJ1IjoiW[a-zA-Z0-9_-]{70,}",
    "generic_secret":   r"(?i)(secret|token|password|passwd|api_key|apikey|access_key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9!@#$%^&*\-_]{16,})['\"]",
}

# Validation Configs
VALIDATORS: Dict[str, Dict] = {
    "google_api": {
        "url": "https://www.googleapis.com/geolocation/v1/geolocate?key={key}",
        "method": "POST",
        "valid_codes": [200, 403],
        "invalid_codes": [400],
        "note_200": "VALID: Full access to Geolocation API",
        "note_403": "VALID (restricted): Key exists but IP/referer restricted",
    },
    "github_pat": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "headers": {"Authorization": "token {key}", "Accept": "application/vnd.github.v3+json"},
        "valid_codes": [200],
        "invalid_codes": [401],
        "note_200": "VALID: Authenticated GitHub user",
    },
    "github_oauth": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "headers": {"Authorization": "token {key}"},
        "valid_codes": [200],
        "invalid_codes": [401],
    },
    "stripe_live": {
        "url": "https://api.stripe.com/v1/charges?limit=1",
        "method": "GET",
        "headers": {"Authorization": "Bearer {key}"},
        "valid_codes": [200],
        "invalid_codes": [401],
        "note_200": "VALID LIVE KEY: Active Stripe production key",
    },
    "stripe_test": {
        "url": "https://api.stripe.com/v1/charges?limit=1",
        "method": "GET",
        "headers": {"Authorization": "Bearer {key}"},
        "valid_codes": [200],
        "invalid_codes": [401],
        "note_200": "VALID TEST KEY: Active Stripe test key",
    },
    "slack_token": {
        "url": "https://slack.com/api/auth.test",
        "method": "POST",
        "headers": {"Authorization": "Bearer {key}"},
        "valid_codes": [200],
        "check_body": True,
        "body_ok_field": "ok",
    },
    "sendgrid": {
        "url": "https://api.sendgrid.com/v3/user/profile",
        "method": "GET",
        "headers": {"Authorization": "Bearer {key}"},
        "valid_codes": [200],
        "invalid_codes": [401, 403],
    },
    "mailgun": {
        "url": "https://api.mailgun.net/v3/domains",
        "method": "GET",
        "auth": ("api", "{key}"),
        "valid_codes": [200],
        "invalid_codes": [401],
    },
    "twilio_sid": {
        "url": "https://api.twilio.com/2010-04-01/Accounts/{key}.json",
        "method": "GET",
        "valid_codes": [200, 401],
        "invalid_codes": [404],
    },
    "shopify_token": {
        "url": "https://{domain}/admin/api/2024-01/shop.json",
        "method": "GET",
        "headers": {"X-Shopify-Access-Token": "{key}"},
        "valid_codes": [200],
        "invalid_codes": [401, 403],
        "needs_domain": True,
    },
    "discord_token": {
        "url": "https://discord.com/api/v10/users/@me",
        "method": "GET",
        "headers": {"Authorization": "{key}"},
        "valid_codes": [200],
        "invalid_codes": [401],
    },
    "telegram_bot": {
        "url": "https://api.telegram.org/bot{key}/getMe",
        "method": "GET",
        "valid_codes": [200],
        "invalid_codes": [401],
    },
    "mapbox_token": {
        "url": "https://api.mapbox.com/tokens/v2?access_token={key}",
        "method": "GET",
        "valid_codes": [200],
        "invalid_codes": [401],
    },
    "uuid_candidate": {
        "url": "https://api.heroku.com/account",
        "method": "GET",
        "headers": {
            "Accept": "application/vnd.heroku+json; version=3",
            "Authorization": "Bearer {key}",
        },
        "valid_codes": [200],
        "invalid_codes": [401, 403],
        "note_200": "VALID HEROKU KEY: Full account access",
    },
}

# False-Positive Filters
STOPWORDS = {
    "example", "sample", "dummy", "placeholder", "test", "demo",
    "null", "undefined", "none", "true", "false", "localhost",
    "your_key", "your_token", "insert_key", "api_key_here",
    "00000000-0000-0000-0000-000000000000",
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
}

CONTEXT_WORDS = {
    "key", "api_key", "apikey", "token", "secret", "auth", "bearer",
    "authorization", "client_secret", "access_token", "private_key",
    "maps", "google", "firebase", "stripe", "slack", "twilio",
    "sendgrid", "mailgun", "heroku", "shopify", "discord",
}

IGNORED_PATH_PATTERNS = [
    r"\.map($|\?)",
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

BASELINE_FILE = ".reconpipe_ignore.json"

# Confidence scoring weights
CONFIDENCE = {
    "google_api":       90,
    "google_oauth":     85,
    "aws_access_key":   95,
    "aws_secret":       90,
    "github_pat":       92,
    "github_oauth":     88,
    "github_app":       88,
    "stripe_live":      97,
    "stripe_test":      85,
    "stripe_publishable": 70,
    "sendgrid":         90,
    "mailgun":          85,
    "twilio_sid":       80,
    "twilio_token":     80,
    "slack_token":      88,
    "slack_webhook":    92,
    "firebase_url":     65,
    "firebase_key":     85,
    "heroku_api":       40,
    "uuid_candidate":   20,
    "jwt":              60,
    "shopify_token":    90,
    "shopify_secret":   90,
    "mailchimp":        80,
    "discord_token":    85,
    "discord_webhook":  90,
    "telegram_bot":     88,
    "mapbox_token":     82,
    "generic_secret":   35,
}

# Minimum confidence to include in findings (lower = more noise)
MIN_CONFIDENCE = 30


# Logging
def log(msg: str, level: str = "info") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
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


# Tool helpers
def check_tool(name: str) -> bool:
    try:
        result = subprocess.run(
            [name, "--version"] if name in ("trufflehog",) else [name, "--help"],
            capture_output=True, timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def run_cmd(cmd: List[str], output_file: Optional[str] = None,
            stdin_data: Optional[bytes] = None, timeout: int = 300) -> Tuple[int, bytes]:
    try:
        proc = subprocess.run(
            cmd, input=stdin_data, capture_output=True, timeout=timeout
        )
        if output_file and proc.stdout:
            Path(output_file).write_bytes(proc.stdout)
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        log(f"Timed out: {' '.join(cmd)}", "warn")
        return -1, b""
    except (FileNotFoundError, OSError):
        log(f"Tool not found: {cmd[0]}", "error")
        return -1, b""


# Deduplication
def deduplicate(findings: List[Dict]) -> List[Dict]:
    seen: set = set()
    unique: List[Dict] = []
    for f in findings:
        h = hashlib.sha256(f.get("key", "").encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(f)
    return unique


# Custom Regex Scanner (fallback / supplement)
def path_is_noisy(path: str) -> bool:
    p = path.lower()
    return any(re.search(rx, p, re.I) for rx in IGNORED_PATH_PATTERNS)


def has_context(content: str, start: int, end: int, window: int = 100) -> bool:
    left  = max(0, start - window)
    right = min(len(content), end + window)
    chunk = content[left:right].lower()
    return any(word in chunk for word in CONTEXT_WORDS)


def looks_fake(value: str) -> bool:
    v = value.strip().lower()
    if not v or len(v) < 12:
        return True
    if v in STOPWORDS:
        return True
    # All same char (e.g. aaaaaaa)
    if len(set(v)) <= 2:
        return True
    for word in ["example", "placeholder", "dummy", "your_", "insert_", "replace_"]:
        if word in v:
            return True
    return False


def load_baseline(output_dir: Path) -> set:
    fp = output_dir / BASELINE_FILE
    if not fp.exists():
        return set()
    try:
        return set(json.loads(fp.read_text()))
    except Exception:
        return set()


def save_baseline(output_dir: Path, ignored: set) -> None:
    fp = output_dir / BASELINE_FILE
    existing = load_baseline(output_dir)
    merged = existing | ignored
    fp.write_text(json.dumps(sorted(list(merged)), indent=2))


def score_confidence(key_type: str, key: str, content: str,
                     start: int, end: int) -> int:
    base = CONFIDENCE.get(key_type, 30)

    # Boost: key appears in a meaningful context
    if has_context(content, start, end):
        base = min(base + 10, 100)

    # Boost: near assignment operators
    nearby = content[max(0, start-50):min(len(content), end+50)]
    if re.search(r'[:=]\s*["\']', nearby):
        base = min(base + 5, 100)

    # Penalty: looks like a test/example file
    if any(w in key.lower() for w in ["test", "example", "demo", "sample"]):
        base = max(base - 20, 0)

    # Penalty: very short key value
    if len(key) < 16:
        base = max(base - 15, 0)

    return base


def custom_scan(urls_file: str, output_dir: Optional[Path] = None) -> List[Dict]:
    """Context-aware scanner with confidence scoring, stopwords, path filters, and quarantine."""
    findings: List[Dict] = []
    quarantine: List[Dict] = []
    ignored_hashes: set = set()
    baseline: set = load_baseline(output_dir) if output_dir else set()

    if not Path(urls_file).exists():
        return findings

    with open(urls_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    log(f"Custom scanner: {len(urls)} URLs", "info")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i, url in enumerate(urls, 1):
        if path_is_noisy(url):
            continue

        if i % 50 == 0:
            log(f"  Progress: {i}/{len(urls)} scanned...", "info")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=8) as resp:
                page = resp.read().decode("utf-8", errors="ignore")

            for key_type, pattern in PATTERNS.items():
                for m in re.finditer(pattern, page):
                    raw = m.group(0)
                    key = m.group(m.lastindex) if m.lastindex and m.lastindex >= 2 else raw

                    # ── Stopword / fake value filter ──────────────────
                    if looks_fake(key):
                        ignored_hashes.add(hashlib.sha256(key.encode()).hexdigest())
                        continue

                    # ── Baseline filter (previously reviewed/suppressed)
                    h = hashlib.sha256(f"{key_type}:{key}".encode()).hexdigest()
                    if h in baseline:
                        continue

                    # ── Context filter for weak detector types ────────
                    needs_context = key_type in {
                        "generic_secret", "uuid_candidate", "jwt",
                        "firebase_url", "stripe_publishable",
                    }
                    if needs_context and not has_context(page, m.start(), m.end()):
                        ignored_hashes.add(hashlib.sha256(key.encode()).hexdigest())
                        quarantine.append({
                            "type": key_type,
                            "key": key[:40],
                            "source_url": url,
                            "reason": "no_context",
                        })
                        continue

                    # ── UUID/Heroku: require explicit heroku context ───
                    if key_type == "uuid_candidate":
                        nearby = page[max(0, m.start()-120):min(len(page), m.end()+120)].lower()
                        if not any(w in nearby for w in ["heroku", "bearer", "authorization"]):
                            quarantine.append({
                                "type": key_type,
                                "key": key[:40],
                                "source_url": url,
                                "reason": "uuid_no_heroku_context",
                            })
                            continue

                    # ── Confidence scoring ────────────────────────────
                    confidence = score_confidence(key_type, key, page, m.start(), m.end())
                    if confidence < MIN_CONFIDENCE:
                        quarantine.append({
                            "type": key_type,
                            "key": key[:40],
                            "source_url": url,
                            "reason": f"low_confidence_{confidence}",
                        })
                        continue

                    findings.append({
                        "type": key_type,
                        "key": key,
                        "source_url": url,
                        "scanner": "custom_regex",
                        "verified": False,
                        "confidence": confidence,
                    })

        except Exception:
            pass

    # Persist suppressions so the same junk doesn't reappear
    if output_dir:
        save_baseline(output_dir, ignored_hashes)
        if quarantine:
            qfile = output_dir / "quarantine.json"
            qfile.write_text(json.dumps(quarantine, indent=2))
            log(f"Quarantined {len(quarantine)} low-confidence matches → quarantine.json", "warn")

    log(f"Custom scanner: {len(findings)} findings (confidence ≥ {MIN_CONFIDENCE})", "success")
    return findings

def parse_trufflehog(output: bytes) -> List[Dict]:
    findings: List[Dict] = []
    type_map = {
        "googleapikey": "google_api", "googlesecrets": "google_api",
        "github":       "github_pat",
        "stripe":       "stripe_live",
        "aws":          "aws_access_key",
        "slack":        "slack_token",
        "sendgrid":     "sendgrid",
        "twilio":       "twilio_sid",
        "mailgun":      "mailgun",
        "jwt":          "jwt",
        "shopify":      "shopify_token",
        "discord":      "discord_token",
        "telegram":     "telegram_bot",
        "mapbox":       "mapbox_token",
    }

    for line in output.decode("utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            detector = data.get("DetectorName", data.get("detector_name", "unknown")).lower()

            # Extract source URL
            source_url = ""
            meta = data.get("SourceMetadata", {})
            if isinstance(meta, dict):
                d = meta.get("Data", {})
                if isinstance(d, dict):
                    source_url = (
                        d.get("Filesystem", {}).get("file", "") or
                        d.get("Git", {}).get("repository", "") or
                        d.get("Web", {}).get("url", "")
                    )

            # Map type
            key_type = "unknown"
            for k, v in type_map.items():
                if k in detector:
                    key_type = v
                    break

            raw = data.get("Raw", data.get("raw", ""))
            if raw:
                findings.append({
                    "type": key_type,
                    "detector": data.get("DetectorName", ""),
                    "key": raw.strip(),
                    "source_url": source_url,
                    "verified": data.get("Verified", data.get("verified", False)),
                    "scanner": "trufflehog",
                })
        except (json.JSONDecodeError, KeyError):
            pass

    return findings


# ──────────────────────────────────────────────────────────────
#  Async Validator
# ──────────────────────────────────────────────────────────────
async def validate_one(session, finding: Dict, semaphore: asyncio.Semaphore,
                        domain: str) -> Dict:
    result = {**finding, "validated": False, "status_code": None, "valid": False, "note": ""}
    validator = VALIDATORS.get(finding.get("type", ""))
    if not validator:
        result["note"] = "No validator for this type"
        return result

    async with semaphore:
        try:
            key = finding["key"]
            url = validator["url"].format(key=key, domain=domain)
            method = validator.get("method", "GET").lower()

            headers = {
                k: v.format(key=key)
                for k, v in validator.get("headers", {}).items()
            }
            # Referer spoofing
            if domain:
                headers.setdefault("Referer", f"https://{domain}/")
                headers.setdefault("Origin", f"https://{domain}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

            auth = None
            if "auth" in validator:
                u, p = validator["auth"]
                auth = aiohttp.BasicAuth(u, p.format(key=key))

            timeout = aiohttp.ClientTimeout(total=10)
            fn = getattr(session, method)

            async with fn(url, headers=headers, auth=auth, timeout=timeout,
                          allow_redirects=True) as resp:
                result["validated"] = True
                result["status_code"] = resp.status

                # Check JSON body for slack-style {ok: true}
                if validator.get("check_body") and resp.status == 200:
                    try:
                        body = await resp.json()
                        if body.get(validator.get("body_ok_field", "ok")):
                            result["valid"] = True
                            result["note"] = f"VALID: ok=true in response (HTTP 200)"
                        else:
                            result["note"] = f"Invalid: ok=false in response"
                    except Exception:
                        pass
                elif resp.status in validator.get("valid_codes", [200]):
                    result["valid"] = True
                    result["note"] = validator.get(f"note_{resp.status}",
                                                    f"VALID (HTTP {resp.status})")
                elif resp.status == 403:
                    result["valid"] = True
                    result["note"] = "VALID (restricted): 403 — key exists, may need Referer spoofing"
                elif resp.status in validator.get("invalid_codes", [401]):
                    result["note"] = f"Invalid/Revoked (HTTP {resp.status})"
                else:
                    result["note"] = f"Inconclusive (HTTP {resp.status})"

        except asyncio.TimeoutError:
            result["note"] = "Timeout during validation"
        except Exception as e:
            result["note"] = f"Error: {str(e)[:60]}"

        await asyncio.sleep(0.3)  # rate-limit
    return result


async def validate_all(findings: List[Dict], domain: str,
                        concurrency: int = 10) -> List[Dict]:
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [validate_one(session, f, semaphore, domain) for f in findings]
        return await asyncio.gather(*tasks)


def validate_sync_fallback(findings: List[Dict], domain: str) -> List[Dict]:
    """Basic synchronous validator when aiohttp is unavailable."""
    results = []
    for f in findings:
        result = {**f, "validated": False, "status_code": None, "valid": False}
        validator = VALIDATORS.get(f.get("type", ""))
        if not validator:
            result["note"] = "No validator for this type"
            results.append(result)
            continue
        try:
            key = f["key"]
            url = validator["url"].format(key=key, domain=domain)
            headers = {k: v.format(key=key) for k, v in validator.get("headers", {}).items()}
            if domain:
                headers.setdefault("Referer", f"https://{domain}/")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            req = urllib.request.Request(url, headers=headers,
                                          method=validator.get("method", "GET"))
            with urllib.request.urlopen(req, timeout=10) as resp:
                result["validated"] = True
                result["status_code"] = resp.status
                if resp.status in validator.get("valid_codes", [200]):
                    result["valid"] = True
                    result["note"] = f"VALID (HTTP {resp.status})"
                else:
                    result["note"] = f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            result["validated"] = True
            result["status_code"] = e.code
            if e.code == 403:
                result["valid"] = True
                result["note"] = "VALID (restricted) — 403"
            elif e.code in validator.get("invalid_codes", [401]):
                result["note"] = f"Invalid/Revoked ({e.code})"
            else:
                result["note"] = f"HTTP {e.code}"
        except Exception as e:
            result["note"] = f"Error: {str(e)[:50]}"
        results.append(result)
    return results


# Main
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="reconpipe",
        description="Automated API Key Leak Hunter — Chaos→httpx→gau→TruffleHog→Validate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 reconpipe.py -d example.com
  python3 reconpipe.py -d example.com --subdomains my_subs.txt
  python3 reconpipe.py -d example.com --no-trufflehog
  python3 reconpipe.py -d example.com --skip-chaos --skip-gau --files urls.txt
  python3 reconpipe.py -d example.com --concurrency 20 --output /tmp/scan
        """
    )
    parser.add_argument("-d", "--domain",      required=True,  help="Target domain")
    parser.add_argument("--subdomains",        metavar="FILE", help="Use existing subdomain list (skips Chaos)")
    parser.add_argument("--files",             metavar="FILE", help="Use existing URL list (skips httpx + gau)")
    parser.add_argument("--skip-chaos",        action="store_true", help="Skip Chaos step")
    parser.add_argument("--skip-httpx",        action="store_true", help="Skip httpx live-host filter")
    parser.add_argument("--skip-gau",          action="store_true", help="Skip gau/waybackurls")
    parser.add_argument("--no-trufflehog",     action="store_true", help="Use built-in regex scanner only")
    parser.add_argument("--no-validate",       action="store_true", help="Skip key validation")
    parser.add_argument("--concurrency",       type=int, default=10, help="Async validation concurrency (default: 10)")
    parser.add_argument("--chaos-key",         metavar="KEY",  help="Chaos API key (or set env CHAOS_KEY)")
    parser.add_argument("--output", "-o",      metavar="DIR",  help="Output directory (default: recon_<domain>)")
    parser.add_argument("--gau-threads",       type=int, default=5, help="gau thread count (default: 5)")
    parser.add_argument("--headless",          action="store_true", help="Enable Katana headless Chrome mode for SPAs/React/Angular")

    args = parser.parse_args()

    output_dir = Path(args.output or f"recon_{args.domain.replace('.', '_')}")
    output_dir.mkdir(parents=True, exist_ok=True)

    log(f"Target:     {C.BOLD}{args.domain}{C.RESET}", "info")
    log(f"Output dir: {C.BOLD}{output_dir}{C.RESET}", "info")

    # Check prerequisites
    print(f"\n{C.DIM}Tool availability:{C.RESET}")
    tools_status = {}
    for tool in ["chaos", "httpx", "katana", "waymore", "gospider", "gau", "waybackurls", "trufflehog"]:
        ok = check_tool(tool)
        tools_status[tool] = ok
        status = f"{C.GREEN}✓ found{C.RESET}" if ok else f"{C.YELLOW}✗ not found{C.RESET}"
        print(f"  {tool:<14} {status}")

    if not AIOHTTP_AVAILABLE:
        log("aiohttp not installed — using sync validator fallback. Run: pip3 install aiohttp", "warn")

    # Subdomain Acquisition
    step_header(1, "Subdomain Acquisition (Chaos)")
    subdomains_file = output_dir / "subdomains.txt"

    if args.subdomains:
        subdomains_file = Path(args.subdomains)
        log(f"Using existing file: {subdomains_file}", "info")
    elif args.skip_chaos or not tools_status["chaos"]:
        if not args.skip_chaos:
            log("chaos not found — using target domain only", "warn")
            log("Install: go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "warn")
        subdomains_file.write_text(args.domain + "\n")
        log(f"Wrote single domain as fallback: {args.domain}", "info")
    else:
        chaos_key = args.chaos_key or os.environ.get("CHAOS_KEY", "")
        cmd = ["chaos", "-d", args.domain, "-o", str(subdomains_file), "-silent"]
        if chaos_key:
            cmd += ["-key", chaos_key]
        log("Running chaos...", "info")
        rc, _ = run_cmd(cmd)
        if rc != 0 or not subdomains_file.exists() or subdomains_file.stat().st_size == 0:
            log("Chaos returned no results — falling back to target domain", "warn")
            subdomains_file.write_text(args.domain + "\n")

    sub_list = [s for s in subdomains_file.read_text().splitlines() if s.strip()]
    sub_count = len(sub_list)
    log(f"Subdomains: {C.BOLD}{sub_count}{C.RESET}", "success")

    # Live Host Filtering (httpx)
    step_header(2, "Live Host Filtering (httpx)")
    live_hosts_file = output_dir / "live_hosts.txt"

    if args.skip_httpx or not tools_status["httpx"]:
        if not args.skip_httpx:
            log("httpx not found — treating all subdomains as live", "warn")
            log("Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "warn")
        live_hosts_file.write_text("\n".join(sub_list))
        live_count = sub_count
    else:
        log("Running httpx (filtering live hosts)...", "info")
        stdin_data = "\n".join(sub_list).encode()
        rc, output = run_cmd(
            ["httpx", "-silent", "-threads", "50", "-timeout", "10"],
            stdin_data=stdin_data
        )
        if output:
            live_hosts_file.write_bytes(output)
        else:
            live_hosts_file.write_text("\n".join(sub_list))

    live_list = [h for h in live_hosts_file.read_text().splitlines() if h.strip()]
    live_count = len(live_list)
    log(f"Live hosts: {C.BOLD}{live_count}{C.RESET} / {sub_count}", "success")

    # URL Discovery (Katana + waymore + gospider)
    step_header(3, "URL Discovery (Katana + waymore + gospider)")
    files_to_scan = output_dir / "files_to_scan.txt"
    file_exts = re.compile(r'\.(js|json|jsx|ts|tsx|html|htm|css|env|config|conf|yml|yaml|xml|ini|php|asp|aspx)(\?|$|#)', re.I)

    if args.files:
        files_to_scan = Path(args.files)
        log(f"Using existing URL list: {files_to_scan}", "info")
    elif args.skip_gau:
        log("URL discovery skipped — scanning live hosts directly", "warn")
        files_to_scan.write_text("\n".join(live_list))
    else:
        all_urls: set = set()

        # Katana (active crawl + JS parsing)
        if tools_status["katana"]:
            log(f"Katana: active crawl + JS parsing ({live_count} hosts)...", "info")
            katana_input = output_dir / "katana_input.txt"
            katana_input.write_text("\n".join(live_list))
            katana_out_file = output_dir / "katana_urls.txt"

            # Check if jsluice is available (katana -jsl requires it separately)
            jsl_available = check_tool("jsluice")

            katana_cmd = [
                "katana",
                "-list", str(katana_input),
                "-jc",              # parse JS files for endpoints
                "-kf", "all",       # crawl robots.txt + sitemap.xml
                "-d", "3",          # crawl depth
                "-c", "20",         # concurrency
                "-rl", "150",       # rate limit (req/s)
                "-timeout", "10",   # per-request timeout
                "-o", str(katana_out_file),
            ]
            # NOTE: -em (extension match) intentionally removed — it silently
            # drops most URLs on modern sites with clean/extensionless paths.
            # We post-filter for secret-bearing file types after crawling.
            if jsl_available:
                katana_cmd.insert(3, "-jsl")    # deep JS analysis via jsluice
            if args.headless:
                katana_cmd += ["-hl", "-nos"]   # headless Chrome for SPAs

            rc, _ = run_cmd(katana_cmd, timeout=600)
            if katana_out_file.exists():
                raw_katana = [l.strip() for l in katana_out_file.read_text().splitlines() if l.strip()]
                log(f"Katana raw crawl: {len(raw_katana)} total URLs", "info")
                # Keep everything — TruffleHog/custom scanner will find secrets
                # in any file type. Don't filter here.
                for line in raw_katana:
                    all_urls.add(line)
            log(f"Katana: {len(all_urls)} URLs added", "success")
        else:
            log("katana not found — skipping active crawl", "warn")
            log("Install: go install github.com/projectdiscovery/katana/cmd/katana@latest", "warn")

        # waymore (passive archives + archived responses)
        if tools_status["waymore"]:
            before = len(all_urls)
            log(f"waymore: passive archive crawl ({live_count} hosts)...", "info")
            waymore_dir = output_dir / "waymore_out"
            waymore_dir.mkdir(exist_ok=True)

            for host in live_list:
                clean = re.sub(r'https?://', '', host).rstrip('/')
                waymore_out = waymore_dir / f"{clean.replace('/', '_')}.txt"
                run_cmd(
                    ["waymore", "-i", clean, "-mode", "U", "-oU", str(waymore_out)],
                    timeout=120
                )
                if waymore_out.exists():
                    for line in waymore_out.read_text().splitlines():
                        line = line.strip()
                        if line and file_exts.search(line):
                            all_urls.add(line)
            log(f"waymore: +{len(all_urls) - before} new URLs (total {len(all_urls)})", "success")

        elif tools_status["gau"]:
            before = len(all_urls)
            log("waymore not found — using gau as passive fallback (Wayback + CommonCrawl + OTX + VT)", "warn")
            for i, host in enumerate(live_list, 1):
                if i % 10 == 0:
                    log(f"  gau: {i}/{live_count} hosts...", "info")
                rc, output = run_cmd(["gau", "--threads", str(args.gau_threads), host], timeout=60)
                if output:
                    for line in output.decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and file_exts.search(line):
                            all_urls.add(line)
            log(f"gau: +{len(all_urls) - before} new URLs", "success")

        elif tools_status["waybackurls"]:
            before = len(all_urls)
            log("Using waybackurls as last-resort passive fallback", "warn")
            for host in live_list:
                rc, output = run_cmd(["waybackurls", host], timeout=60)
                if output:
                    for line in output.decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and file_exts.search(line):
                            all_urls.add(line)
            log(f"waybackurls: +{len(all_urls) - before} new URLs", "success")

        else:
            log("No passive archive tools found.", "warn")
            log("Install waymore : pip3 install waymore", "warn")
            log("Install gau     : go install github.com/lc/gau/v2/cmd/gau@latest", "warn")
            log("Install waybackurls: go install github.com/tomnomnom/waybackurls@latest", "warn")

        # gospider (active JS spidering + S3/subdomain extraction)
        if tools_status["gospider"]:
            before = len(all_urls)
            log(f"gospider: active JS spidering ({live_count} hosts)...", "info")
            gs_input = output_dir / "gospider_input.txt"
            gs_input.write_text("\n".join(live_list))
            gs_out_dir = output_dir / "gospider_out"
            gs_out_dir.mkdir(exist_ok=True)

            run_cmd([
                "gospider",
                "-S", str(gs_input),
                "-c", "10",         # concurrency per host
                "-d", "3",          # depth
                "--js",             # parse links from JS files
                "-t", "20",         # threads
                "--sitemap",        # parse sitemap.xml
                "--robots",         # parse robots.txt
                "-q",               # quiet mode
                "-o", str(gs_out_dir),
            ], timeout=300)

            url_re = re.compile(r'\[url\]\s+\[\d+\]\s+-\s+(https?://\S+)')
            js_re  = re.compile(r'https?://\S+\.(js|json|jsx)')
            for gf in gs_out_dir.glob("*"):
                try:
                    for line in gf.read_text(errors="ignore").splitlines():
                        m = url_re.search(line)
                        if m and file_exts.search(m.group(1)):
                            all_urls.add(m.group(1).strip())
                        m2 = js_re.search(line)
                        if m2:
                            all_urls.add(m2.group(0).strip())
                except Exception:
                    pass
            log(f"gospider: +{len(all_urls) - before} new URLs (total {len(all_urls)})", "success")
        else:
            log("gospider not found — skipping active spider layer", "warn")
            log("Install: go install github.com/jaeles-project/gospider@latest", "warn")

        sorted_urls = sorted(all_urls)
        files_to_scan.write_text("\n".join(sorted_urls))

    url_list = [u for u in files_to_scan.read_text().splitlines() if u.strip()]
    url_count = len(url_list)

    if url_count == 0:
        log("No URLs discovered — check that live_hosts.txt is populated and gau/katana are installed", "warn")
        log(f"Live hosts file: {live_hosts_file}", "warn")
        log(f"Files to scan:   {files_to_scan}", "warn")
    else:
        log(f"Total URLs to scan: {C.BOLD}{url_count}{C.RESET}", "success")
        log(f"Sample: {url_list[0]}", "info")

    # Secret Scanning
    step_header(4, "Secret Scanning (TruffleHog / Custom)")
    raw_findings: List[Dict] = []
    use_trufflehog = not args.no_trufflehog and tools_status["trufflehog"]

    if use_trufflehog:
        # TruffleHog filesystem mode needs LOCAL files — download them first
        log("Downloading remote files for TruffleHog scan...", "info")
        dl_dir = output_dir / "downloaded_files"
        dl_dir.mkdir(exist_ok=True)

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        downloaded = 0
        for url in url_list[:2000]:  # cap at 2000 files
            try:
                import hashlib as _hl
                fname = _hl.md5(url.encode()).hexdigest() + "_" + url.split("/")[-1].split("?")[0]
                fname = re.sub(r'[^a-zA-Z0-9._-]', '_', fname)[:120]
                out_path = dl_dir / fname
                if out_path.exists():
                    downloaded += 1
                    continue
                req = urllib.request.Request(url, headers={"User-Agent": ua})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    out_path.write_bytes(resp.read())
                    downloaded += 1
                if downloaded % 50 == 0:
                    log(f"  Downloaded: {downloaded}/{min(len(url_list),2000)} files...", "info")
            except Exception:
                pass

        log(f"Downloaded {downloaded} files → {dl_dir}", "success")

        if downloaded > 0:
            log("Running TruffleHog on downloaded files...", "info")
            rc, output = run_cmd(
                ["trufflehog", "filesystem",
                 "--path", str(dl_dir),
                 "--json", "--no-update"],
                timeout=600
            )
            if output and output.strip():
                raw_findings = parse_trufflehog(output)
                log(f"TruffleHog: {len(raw_findings)} raw findings", "success")
            else:
                log("TruffleHog returned no findings — running custom scanner too", "warn")
                raw_findings = custom_scan(str(files_to_scan), output_dir)
                # Also run custom scanner over downloaded files for double coverage
                for f_path in dl_dir.iterdir():
                    try:
                        content_text = f_path.read_text(errors="ignore")
                        for key_type, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content_text)
                            for match in matches:
                                key = match[-1] if isinstance(match, tuple) else match
                                if len(key) > 8:
                                    raw_findings.append({
                                        "type": key_type, "key": key,
                                        "source_url": str(f_path),
                                        "scanner": "custom_local", "verified": False,
                                    })
                    except Exception:
                        pass
        else:
            log("No files downloaded — falling back to custom HTTP scanner", "warn")
            raw_findings = custom_scan(str(files_to_scan), output_dir)
    else:
        if not args.no_trufflehog:
            log("trufflehog not found — using built-in regex scanner", "warn")
            log("Install: https://github.com/trufflesecurity/trufflehog#installation", "warn")
        log("Running built-in regex scanner...", "info")
        raw_findings = custom_scan(str(files_to_scan), output_dir)

    # Deduplicate
    unique_findings = deduplicate(raw_findings)
    log(f"Unique findings: {C.BOLD}{len(unique_findings)}{C.RESET} (from {len(raw_findings)} raw)", "success")

    for f in unique_findings:
        kp = f['key'][:28] + "…" if len(f['key']) > 28 else f['key']
        src = f.get('source_url', '')
        src_short = ("…" + src[-50:]) if len(src) > 50 else src
        conf = f.get('confidence', '?')
        log(f"{C.YELLOW}[{f.get('type', 'unknown')}]{C.RESET} conf={conf} {kp}  {C.DIM}{src_short}{C.RESET}", "find")

    # Key Validation
    step_header(5, "Key Validation (Async)")
    validated: List[Dict] = []

    if args.no_validate or not unique_findings:
        if not unique_findings:
            log("No findings to validate.", "warn")
        else:
            log("Validation skipped (--no-validate)", "warn")
        validated = unique_findings
    else:
        log(f"Validating {len(unique_findings)} keys (concurrency={args.concurrency})...", "info")
        if AIOHTTP_AVAILABLE:
            validated = asyncio.run(validate_all(unique_findings, args.domain, args.concurrency))
        else:
            log("Using synchronous validator (install aiohttp for async)...", "warn")
            validated = validate_sync_fallback(unique_findings, args.domain)

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

    # Save Results
    step_header(6, "Saving Results")

    # JSON
    findings_json = output_dir / "findings.json"
    findings_json.write_text(json.dumps(validated, indent=2))
    log(f"findings.json  → {findings_json}", "success")

    # Valid keys only
    valid_only = [f for f in validated if f.get("valid")]
    if valid_only:
        valid_json = output_dir / "valid_keys.json"
        valid_json.write_text(json.dumps(valid_only, indent=2))
        log(f"valid_keys.json → {valid_json}", "success")

    # Summary
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
        sf.write(f"Valid keys    : {len(valid_only)}\n\n")

        if valid_only:
            sf.write("CONFIRMED VALID KEYS\n")
            sf.write("-" * 60 + "\n")
            for f in valid_only:
                sf.write(f"Type    : {f.get('type','unknown')}\n")
                sf.write(f"Key     : {f.get('key','')}\n")
                sf.write(f"Source  : {f.get('source_url','')}\n")
                sf.write(f"Note    : {f.get('note','')}\n")
                sf.write(f"Status  : HTTP {f.get('status_code','N/A')}\n\n")
        elif unique_findings:
            sf.write("UNVALIDATED FINDINGS (review manually)\n")
            sf.write("-" * 60 + "\n")
            for f in unique_findings:
                sf.write(f"Type    : {f.get('type','unknown')}\n")
                sf.write(f"Key     : {f.get('key','')}\n")
                sf.write(f"Source  : {f.get('source_url','')}\n\n")
        else:
            sf.write("No findings.\n")

    log(f"summary.txt    → {summary_file}", "success")

    # Final stats banner
    valid_count = sum(1 for f in validated if f.get("valid"))
    print(f"\n{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"{C.BOLD}  PIPELINE COMPLETE{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"  Domain       :  {C.BOLD}{args.domain}{C.RESET}")
    print(f"  Subdomains   :  {C.BOLD}{sub_count}{C.RESET}")
    print(f"  Live hosts   :  {C.BOLD}{live_count}{C.RESET}")
    print(f"  URLs scanned :  {C.BOLD}{url_count}{C.RESET}")
    print(f"  Unique keys  :  {C.BOLD}{len(unique_findings)}{C.RESET}")
    if valid_count:
        print(f"  Valid keys   :  {C.GREEN}{C.BOLD}{valid_count}{C.RESET}")
    else:
        print(f"  Valid keys   :  0")
    print(f"  Output dir   :  {C.BOLD}{output_dir}/{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}\n")


if __name__ == "__main__":
    main()