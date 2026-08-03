import argparse
import asyncio
import base64
import hmac
import json
import math
import os
import random
import re
import subprocess
import sys
import hashlib
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False

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
    ClientError = Exception  # type: ignore
    BotoCoreError = Exception  # type: ignore

# Colors
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

_VALIDATOR_FIELD_NAMES = {f.name for f in fields(ValidatorSpec)}


def _coerce_validator(raw: Dict[str, Any]) -> ValidatorSpec:
    data = dict(raw or {})
    # Legacy note_200 / notes: {"200": "..."} → notes: {200: "..."}
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

    if replace:
        PATTERNS = {}
        VALIDATORS = {}
        CONFIDENCE = {}
        INFORMATIONAL_NOTES = {}
        EXPOSURE_NOTES = {}

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

# Plain words that pass length checks but are not secrets (generic_secret gate)
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
    "openai", "anthropic", "gitlab", "mapbox", "npm", "pypi", "digitalocean",
    "aws_session", "session_token",
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

# .map files are scanned (not ignored) — exposure is its own severity bucket
SOURCE_MAP_PATH_RE = re.compile(r"\.map(?:$|\?|#)", re.I)

BASELINE_FILE = ".reconpipe_ignore.json"

load_default_config()



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
    """True if the binary is on PATH (exit code of --help/--version is ignored)."""
    try:
        subprocess.run(
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
        "email", "preferred_username", "cid", "client_id",
    )
    info["claims"] = {k: payload[k] for k in keep if k in payload}
    return info


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


def custom_scan(urls_file: str, output_dir: Optional[Path] = None) -> List[Dict]:
    """HTTP regex scanner with confidence scoring, baseline suppression, and quarantine."""
    findings: List[Dict] = []
    informational: List[Dict] = []
    exposures: List[Dict] = []
    quarantine: List[Dict] = []
    # In-run dedup is per (hash, source) so the same key on a new URL still surfaces
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

        if i % 50 == 0:
            log(f"  Progress: {i}/{len(urls)} scanned...", "info")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=8) as resp:
                page = resp.read().decode("utf-8", errors="ignore")

            # Source maps: report exposure, then scan unminified sourcesContent
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

                    # Mapbox: require JSON-decodable payload (not literal eyJ1Ijoi)
                    if key_type == "mapbox_token" and not is_mapbox_token(key):
                        baseline_record(baseline, h, key_type, url)
                        continue

                    # Public-by-design — record, don't treat as a leak
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

                    # Weak detectors need nearby credential context
                    needs_context = key_type in {
                        "generic_secret", "uuid_candidate", "jwt",
                        "discord_token",
                    }
                    if needs_context and not has_context(page, m.start(), m.end()):
                        baseline_record(baseline, h, key_type, url)
                        quarantine.append({
                            "type": key_type,
                            "key": key[:40],
                            "source_url": url,
                            "reason": "no_context",
                        })
                        continue

                    # UUID + Heroku markers → heroku_api; else quarantine (feeder only)
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

                    # generic_secret: Shannon entropy + dictionary-word gate
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
                    if key_type == "jwt":
                        jwt_meta = inspect_jwt(key)
                        if not jwt_meta.get("ok"):
                            baseline_record(baseline, h, key_type, url)
                            quarantine.append({
                                "type": "jwt",
                                "key": key[:40],
                                "source_url": url,
                                "reason": f"jwt_{jwt_meta.get('error', 'decode_failed')}",
                            })
                            continue

                    confidence = score_confidence(key_type, key, page, m.start(), m.end())
                    if key_type == "jwt" and jwt_meta:
                        if jwt_meta.get("alg_none"):
                            confidence = max(confidence, 95)
                        elif jwt_meta.get("live"):
                            confidence = max(confidence, 78)
                        elif jwt_meta.get("kid") or jwt_meta.get("iss"):
                            confidence = max(confidence, 70)
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
                    findings.append(finding)

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
    """Host for cross-file pairing (URL host, or parent path for local files)."""
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

    # Global fallback: exactly one of each half across the whole scan
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
    return findings


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
        "github":       "github_pat",
        "gitlab":       "gitlab_pat",
        "stripe":       "stripe_live",
        "openai":       "openai_key",
        "anthropic":    "anthropic_key",
        "sendgrid":     "sendgrid",
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
            meta = data.get("SourceMetadata", {})
            if isinstance(meta, dict):
                d = meta.get("Data", {})
                if isinstance(d, dict):
                    source_url = (
                        d.get("Filesystem", {}).get("file", "") or
                        d.get("Git", {}).get("repository", "") or
                        d.get("Web", {}).get("url", "")
                    )

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
                    findings.append({
                        "type": "aws_access_key",
                        "detector": detector_name,
                        "key": access,
                        "aws_secret": secret or None,
                        "source_url": source_url,
                        "verified": verified,
                        "scanner": "trufflehog",
                    })
                if secret:
                    findings.append({
                        "type": "aws_secret",
                        "detector": detector_name,
                        "key": secret,
                        "aws_access_key": access or None,
                        "source_url": source_url,
                        "verified": verified,
                        "scanner": "trufflehog",
                    })
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
                findings.append({
                    "type": key_type,
                    "detector": data.get("DetectorName", ""),
                    "key": value,
                    "source_url": source_url,
                    "verified": data.get("Verified", data.get("verified", False)),
                    "scanner": "trufflehog",
                })
        except Exception:
            pass

    return findings


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


def _validator_domain(validator: ValidatorSpec, domain: str, shop_domain: str = "") -> Optional[str]:
    """Pick the host for this validator, or None if a required store domain is missing."""
    if validator.needs_domain:
        return shop_domain or None
    return domain


def _apply_http_verdict(
    result: Dict,
    validator: ValidatorSpec,
    status: int,
    body_text: str,
    original_url: str,
    final_url: str,
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
        return

    is_valid, note = classify_http_status(
        validator, status, body_text, original_url, final_url
    )
    result["valid"] = is_valid
    result["note"] = note


async def validate_one(session, finding: Dict, limiter: "DomainRateLimiter",
                        domain: str, shop_domain: str = "") -> Dict:
    result = {**finding, "validated": False, "status_code": None, "valid": False, "note": ""}
    validator = VALIDATORS.get(finding.get("type", ""))
    if not validator:
        result["note"] = "No validator for this type"
        return result
    if validator.skip_reason:
        result["note"] = validator.skip_reason
        return result

    # JWT — local header/payload inspection (no remote call)
    if validator.jwt_inspect:
        result.update(validate_jwt_inspect(finding.get("key") or ""))
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

    host = _validator_domain(validator, domain, shop_domain)
    if validator.needs_domain and not host:
        result["note"] = "Skipped: pass --shopify-domain <store.myshopify.com>"
        return result

    key = finding["key"]
    url = validator.url.format(key=key, domain=host)
    limit_host = _host_from_url(url)
    method = (validator.method or "GET").lower()
    max_attempts = 4  # 1 try + up to 3 retries on 429

    dsem = await limiter.acquire(limit_host)
    try:
        try:
            headers = {
                k: v.format(key=key)
                for k, v in validator.headers.items()
            }
            if host:
                headers.setdefault("Referer", f"https://{host}/")
                headers.setdefault("Origin", f"https://{host}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

            auth = None
            if validator.auth:
                u, p = validator.auth
                auth = aiohttp.BasicAuth(u, p.format(key=key))

            timeout = aiohttp.ClientTimeout(total=10)
            for attempt in range(max_attempts):
                req_kwargs = {
                    "headers": headers,
                    "auth": auth,
                    "timeout": timeout,
                    "allow_redirects": True,
                }
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
                    result, validator, status, body_text, url, final_url
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
                        shop_domain: str = "") -> List[Dict]:
    findings = pair_credential_findings(findings)
    per_domain = max(1, min(3, concurrency // 3 or 1))
    limiter = DomainRateLimiter(global_limit=concurrency, per_domain=per_domain)
    async with aiohttp.TCPConnector(limit=concurrency, limit_per_host=per_domain) as connector:
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                validate_one(session, f, limiter, domain, shop_domain)
                for f in findings
            ]
            return await asyncio.gather(*tasks)


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

        if validator.jwt_inspect:
            result.update(validate_jwt_inspect(f.get("key") or ""))
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

        host = _validator_domain(validator, domain, shop_domain)
        if validator.needs_domain and not host:
            result["note"] = "Skipped: pass --shopify-domain <store.myshopify.com>"
            results.append(result)
            continue

        key = f["key"]
        url = validator.url.format(key=key, domain=host)
        max_attempts = 4
        try:
            headers = {k: v.format(key=key) for k, v in validator.headers.items()}
            if host:
                headers.setdefault("Referer", f"https://{host}/")
                headers.setdefault("Origin", f"https://{host}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            if validator.auth:
                user, passwd = validator.auth
                creds = f"{user.format(key=key)}:{passwd.format(key=key)}"
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
                    result, validator, status, body_text, url, final_url
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
  python3 reconpipe.py -d example.com --config engagement.example.yaml
  python3 reconpipe.py -d example.com --files urls.txt --sarif out.sarif
        """
    )
    parser.add_argument("-d", "--domain",      required=True,  help="Target domain")
    parser.add_argument("--subdomains",        metavar="FILE", help="Use existing subdomain list (skips Chaos)")
    parser.add_argument("--files",             metavar="FILE", help="Use existing URL list (skips httpx + gau)")
    parser.add_argument("--skip-chaos",        action="store_true", help="Skip Chaos step")
    parser.add_argument("--skip-httpx",        action="store_true", help="Skip httpx live-host filter")
    parser.add_argument("--skip-gau",          action="store_true",
                        help="Skip passive archives only (waymore/gau/waybackurls); katana/gospider still run")
    parser.add_argument("--skip-discovery",    action="store_true",
                        help="Skip all URL discovery (katana/waymore/gau/gospider); scan live hosts only")
    parser.add_argument("--no-trufflehog",     action="store_true", help="Use built-in regex scanner only")
    parser.add_argument("--no-validate",       action="store_true", help="Skip key validation")
    parser.add_argument("--concurrency",       type=int, default=10, help="Async validation concurrency (default: 10)")
    parser.add_argument("--chaos-key",         metavar="KEY",  help="Chaos API key (or set env CHAOS_KEY)")
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

    args = parser.parse_args()

    if args.subdomains and not Path(args.subdomains).exists():
        log(f"Subdomains file not found: {args.subdomains}", "error")
        sys.exit(1)
    if args.files and not Path(args.files).exists():
        log(f"URL list not found: {args.files}", "error")
        sys.exit(1)
    for cfg in args.config:
        if not Path(cfg).exists():
            log(f"Config file not found: {cfg}", "error")
            sys.exit(1)

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

    if args.ignore_hash:
        n = apply_ignore_hashes(output_dir, args.ignore_hash)
        log(
            f"Baseline: ignore_all for {n} hash(es) → {output_dir / BASELINE_FILE}",
            "success",
        )

    log(f"Target:     {C.BOLD}{args.domain}{C.RESET}", "info")
    log(f"Output dir: {C.BOLD}{output_dir}{C.RESET}", "info")

    print(f"\n{C.DIM}Tool availability:{C.RESET}")
    tools_status = {}
    for tool in ["chaos", "httpx", "katana", "waymore", "gospider", "gau", "waybackurls", "trufflehog"]:
        ok = check_tool(tool)
        tools_status[tool] = ok
        status = f"{C.GREEN}✓ found{C.RESET}" if ok else f"{C.YELLOW}✗ not found{C.RESET}"
        print(f"  {tool:<14} {status}")

    if not AIOHTTP_AVAILABLE:
        log("aiohttp not installed — using sync validator fallback. Run: pip3 install aiohttp", "warn")

    # Subdomains
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

    # Live hosts
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

    # URL discovery
    step_header(3, "URL Discovery (Katana + waymore + gospider)")
    files_to_scan = output_dir / "files_to_scan.txt"
    file_exts = re.compile(r'\.(js|json|jsx|ts|tsx|map|html|htm|css|env|config|conf|yml|yaml|xml|ini|php|asp|aspx)(\?|$|#)', re.I)

    if args.files:
        files_to_scan = Path(args.files)
        log(f"Using existing URL list: {files_to_scan}", "info")
    elif args.skip_discovery:
        log("URL discovery skipped (--skip-discovery) — scanning live hosts directly", "warn")
        files_to_scan.write_text("\n".join(live_list))
    else:
        all_urls: set = set()

        # Katana — active crawl + JS endpoint parsing
        if tools_status["katana"]:
            log(f"Katana: active crawl + JS parsing ({live_count} hosts)...", "info")
            katana_input = output_dir / "katana_input.txt"
            katana_input.write_text("\n".join(live_list))
            katana_out_file = output_dir / "katana_urls.txt"

            jsl_available = check_tool("jsluice")

            katana_cmd = [
                "katana",
                "-list", str(katana_input),
                "-jc",              # parse JS for endpoints
                "-kf", "all",       # robots.txt + sitemap.xml
                "-d", "3",          # depth
                "-c", "20",         # concurrency
                "-rl", "150",       # rate limit (req/s)
                "-timeout", "10",
                "-o", str(katana_out_file),
            ]
            # -em drops extensionless SPA paths; filter after crawl instead
            if jsl_available:
                katana_cmd.insert(3, "-jsl")  # deep JS via jsluice
            if args.headless:
                katana_cmd += ["-hl", "-nos"]  # headless Chrome for SPAs

            if katana_out_file.exists():
                katana_out_file.unlink()
            rc, _ = run_cmd(katana_cmd, timeout=600)
            if rc == 0 and katana_out_file.exists():
                raw_katana = [l.strip() for l in katana_out_file.read_text().splitlines() if l.strip()]
                log(f"Katana raw crawl: {len(raw_katana)} total URLs", "info")
                # Keep all URLs — scanners find secrets in any content type
                for line in raw_katana:
                    all_urls.add(line)
                log(f"Katana: {len(all_urls)} URLs added", "success")
            else:
                log("Katana failed or produced no output — skipping its URLs", "warn")
        else:
            log("katana not found — skipping active crawl", "warn")
            log("Install: go install github.com/projectdiscovery/katana/cmd/katana@latest", "warn")

        # Passive archives — skipped by --skip-gau
        if args.skip_gau:
            log("Passive archives skipped (--skip-gau)", "info")
        elif tools_status["waymore"]:
            before = len(all_urls)
            log(f"waymore: passive archive crawl ({live_count} hosts)...", "info")
            waymore_dir = output_dir / "waymore_out"
            waymore_dir.mkdir(exist_ok=True)

            waymore_failures = 0
            for host in live_list:
                clean = re.sub(r'https?://', '', host).rstrip('/')
                # -oU expects a file path (not a dir);
                waymore_out = waymore_dir / f"{clean.replace('/', '_')}.txt"
                rc, _ = run_cmd(
                    ["waymore", "-i", clean, "-mode", "U", "-oU", str(waymore_out)],
                    timeout=120
                )
                if rc != 0:
                    waymore_failures += 1
                    continue
                if waymore_out.is_file():
                    for line in waymore_out.read_text().splitlines():
                        line = line.strip()
                        if line and file_exts.search(line):
                            all_urls.add(line)
            added = len(all_urls) - before
            if waymore_failures:
                log(
                    f"waymore: {waymore_failures}/{live_count} hosts failed "
                    f"(+{added} URLs, total {len(all_urls)})",
                    "warn",
                )
            else:
                log(f"waymore: +{added} new URLs (total {len(all_urls)})", "success")

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

        # gospider active JS spider
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
                "-c", "10",
                "-d", "3",
                "--js",
                "-t", "20",
                "--sitemap",
                "--robots",
                "-q",
                "-o", str(gs_out_dir),
            ], timeout=300)

            url_re = re.compile(r'\[url\]\s+\[\d+\]\s+-\s+(https?://\S+)')
            js_re  = re.compile(r'https?://\S+\.(js|json|jsx|map)\b')
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

    # Secret scanning
    step_header(4, "Secret Scanning (TruffleHog / Custom)")
    raw_findings: List[Dict] = []
    use_trufflehog = not args.no_trufflehog and tools_status["trufflehog"]

    if use_trufflehog:
        # TruffleHog filesystem mode needs local files
        log("Downloading remote files for TruffleHog scan...", "info")
        dl_dir = output_dir / "downloaded_files"
        dl_dir.mkdir(exist_ok=True)

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        downloaded = 0
        cached = 0
        for url in url_list[:2000]:
            try:
                fname = hashlib.md5(url.encode()).hexdigest() + "_" + url.split("/")[-1].split("?")[0]
                fname = re.sub(r'[^a-zA-Z0-9._-]', '_', fname)[:120]
                out_path = dl_dir / fname
                if out_path.exists():
                    cached += 1
                    continue
                req = urllib.request.Request(url, headers={"User-Agent": ua})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    out_path.write_bytes(resp.read())
                    downloaded += 1
                if downloaded % 50 == 0:
                    log(f"  Downloaded: {downloaded}/{min(len(url_list),2000)} files...", "info")
            except Exception:
                pass

        ready = downloaded + cached
        if cached:
            log(f"Downloaded {downloaded} files ({cached} cached) → {dl_dir}", "success")
        else:
            log(f"Downloaded {downloaded} files → {dl_dir}", "success")

        if ready > 0:
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
                for f_path in dl_dir.iterdir():
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
                                    "discord_token",
                                }
                                if needs_context and not has_context(
                                    content_text, m.start(), m.end()
                                ):
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
                                if key_type == "jwt":
                                    jwt_meta = inspect_jwt(key)
                                    if not jwt_meta.get("ok"):
                                        continue
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
                                raw_findings.append(item)
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
    log(f"Unique findings: {C.BOLD}{len(unique_findings)}{C.RESET} (from {len(raw_findings)} raw)", "success")

    for f in unique_findings:
        kp = f['key'][:28] + "…" if len(f['key']) > 28 else f['key']
        src = f.get('source_url', '')
        src_short = ("…" + src[-50:]) if len(src) > 50 else src
        conf = f.get('confidence', '?')
        log(f"{C.YELLOW}[{f.get('type', 'unknown')}]{C.RESET} conf={conf} {kp}  {C.DIM}{src_short}{C.RESET}", "find")

    # Validation
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
            validated = asyncio.run(
                validate_all(unique_findings, args.domain, args.concurrency, shop_domain)
            )
        else:
            log("Using synchronous validator (install aiohttp for async)...", "warn")
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

    findings_json = output_dir / "findings.json"
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
                # --no-validate / no status_code → omit Status line
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
    if exposures:
        print(f"  Exposures    :  {C.YELLOW}{C.BOLD}{len(exposures)}{C.RESET} source maps")
    print(f"  Output dir   :  {C.BOLD}{output_dir}/{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}\n")

    # Merge gate: live-validated secrets fail the process (CI can block merges)
    if valid_count and not args.no_fail_on_valid:
        log(
            f"Exiting with code 1: {valid_count} valid key(s) "
            f"(use --no-fail-on-valid to disable)",
            "error",
        )
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
