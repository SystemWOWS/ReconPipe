import argparse
import asyncio
import base64
import hmac
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
from contextlib import contextmanager, nullcontext
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  
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
    ClientError = Exception  
    BotoCoreError = Exception

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
    google_api_spray: bool = False

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
    """
    Nmap-like scan clock: elapsed, % done, ETC, remaining.
    Budgets are expected times (not hard timeouts) and shrink as stages finish.
    """

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
    """Pulse remaining-time logs during a long blocking tool."""
    if _ETA is None or int(timeout) < 45:
        return nullcontext()
    return _ETA.heartbeat()


# Saved keys / targets live in ~/.reconpipe (override with RECONPIPE_HOME).
USER_KEY_FIELDS = (
    ("chaos", "chaos_key", ("CHAOS_KEY", "PDCP_API_KEY")),
    ("shodan", "shodan_key", ("SHODAN_API_KEY",)),
    ("censys_id", "censys_id", ("CENSYS_API_ID",)),
    ("censys_secret", "censys_secret", ("CENSYS_API_SECRET",)),
    ("zoomeye", "zoomeye_key", ("ZOOMEYE_API_KEY", "ZOOMEYE_KEY")),
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


def remember_scan_target(
    domain: str,
    *,
    files: Optional[Path] = None,
    subdomains: Optional[Path] = None,
    output: Optional[Path] = None,
) -> Dict[str, str]:
    """Persist domain + URL list so the next scan can skip discovery."""
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
    return entry


def download_filename(url: str) -> str:
    tail = (url or "").split("/")[-1].split("?")[0]
    fname = hashlib.md5((url or "").encode()).hexdigest() + "_" + tail
    return re.sub(r"[^a-zA-Z0-9._-]", "_", fname)[:120]


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
        "summary.txt",
        "results.sarif",
        "files_to_scan.txt",
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
    "chaos", "httpx", "katana", "waymore", "gospider", "gau", "waybackurls", "trufflehog",
]


def _cmd_blob(path: str, *args: str) -> str:
    try:
        proc = subprocess.run(
            [path, *args], capture_output=True, timeout=6
        )
        return ((proc.stdout or b"") + (proc.stderr or b"")).decode(
            "utf-8", errors="replace"
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


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
        "/usr/local/bin",
        "/usr/bin",
        str(Path.home() / ".local" / "bin"),
    ]
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


def check_tool(name: str) -> bool:
    """True if the binary is on PATH (exit code of --help/--version is ignored)."""
    if name == "httpx":
        return resolve_httpx_bin() is not None
    try:
        # --no-update first: `trufflehog --version` otherwise tries to replace its binary
        argv = (
            [name, "--no-update", "--version"]
            if name == "trufflehog"
            else [name, "--help"]
        )
        subprocess.run(argv, capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


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


def build_chaos_cmd(
    domain: str,
    output_file: str,
    api_key: str = "",
    help_blob: Optional[str] = None,
) -> List[str]:
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

        if i % 200 == 0:
            log(f"  Progress: {i}/{len(urls)} scanned...", "info")
            if _ETA is not None:
                _ETA.set_work(progress=i / max(len(urls), 1), log_now=True)

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


# Cheap Google key checks from keyhacks (Maps JSON) + Gemini models list.
# Do not call Static Maps / Street View / Distance Matrix (large billed payloads).
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
    return (template or "").format(key=key, domain=host or "", dc=_key_datacenter(key))


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

    if validator.google_api_spray:
        spray = await validate_google_api_spray_async(
            session, finding.get("key") or "", limiter
        )
        result.update(spray)
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
            if host:
                headers.setdefault("Referer", f"https://{host}/")
                headers.setdefault("Origin", f"https://{host}")
            headers.setdefault("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

            auth = None
            if validator.auth:
                u, p = validator.auth
                auth = aiohttp.BasicAuth(
                    _format_tpl(u, key, host), _format_tpl(p, key, host)
                )

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
        url = _format_tpl(validator.url, key, host)
        max_attempts = 4
        try:
            headers = {k: _format_tpl(v, key, host) for k, v in validator.headers.items()}
            if host:
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
    else:
        shodan = "off"
    if (censys_id or "").strip() and (censys_secret or "").strip():
        censys = "key"
    elif os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET"):
        censys = "env"
    else:
        censys = "off"
    if (zoomeye_key or "").strip():
        zoomeye = "key"
    elif os.environ.get("ZOOMEYE_API_KEY") or os.environ.get("ZOOMEYE_KEY"):
        zoomeye = "env"
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
    parser.add_argument("-d", "--domain",      required=True,  help="Target domain")
    parser.add_argument("--subdomains",        metavar="FILE", help="Use existing subdomain list (skips Chaos)")
    parser.add_argument("--files",             metavar="FILE",
                        help="Use existing URL list (skips URL discovery: katana/waymore/gau/gospider)")
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
    return parser


def argv_from_options(opts: Dict[str, Any]) -> List[str]:
    """
    Build a reconpipe CLI argv list from a GUI/options dict.
    Keys mirror argparse dest names (domain, skip_chaos, config, ignore_hash, …).
    """
    argv: List[str] = []
    domain = (opts.get("domain") or "").strip()
    if not domain:
        raise ValueError("domain is required")
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
    }
    for key, flag in value_flags.items():
        val = opts.get(key)
        if val is not None and str(val).strip() != "":
            argv += [flag, str(val).strip()]

    if opts.get("concurrency") is not None:
        argv += ["--concurrency", str(int(opts["concurrency"]))]
    if opts.get("gau_threads") is not None:
        argv += ["--gau-threads", str(int(opts["gau_threads"]))]

    for cfg in opts.get("config") or []:
        if str(cfg).strip():
            argv += ["--config", str(cfg).strip()]
    for h in opts.get("ignore_hash") or []:
        if str(h).strip():
            argv += ["--ignore-hash", str(h).strip()]
    return argv


def main(argv: Optional[List[str]] = None) -> int:
    reset_log_counters()
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args(argv)
    apply_saved_keys(args)

    if args.subdomains and not Path(args.subdomains).exists():
        log(f"Subdomains file not found: {args.subdomains}", "error")
        return 1
    if args.files and not Path(args.files).exists():
        log(f"URL list file not found: {args.files}", "error")
        return 1
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
        no_trufflehog=bool(args.no_trufflehog),
        no_validate=bool(args.no_validate),
        concurrency=int(args.concurrency),
        tools=dict(tools_status),
    )
    set_scan_eta(eta)

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
        cmd = build_chaos_cmd(args.domain, str(subdomains_file), chaos_key)
        log("Running chaos...", "info")
        rc, _ = run_cmd(cmd)
        if rc != 0 or not subdomains_file.exists() or subdomains_file.stat().st_size == 0:
            log("Chaos returned no results — falling back to target domain", "warn")
            subdomains_file.write_text(args.domain + "\n")

    sub_list = [s for s in subdomains_file.read_text().splitlines() if s.strip()]
    sub_count = len(sub_list)
    log(f"Subdomains: {C.BOLD}{sub_count}{C.RESET} (pre-intel)", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count)

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

    sub_count = len(sub_list)
    log(f"Subdomains: {C.BOLD}{sub_count}{C.RESET}", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count, log_now=True)

    # Live hosts
    step_header(2, "Live Host Filtering (httpx)")
    live_hosts_file = output_dir / "live_hosts.txt"

    if args.skip_httpx or not httpx_bin:
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
        rc, output = run_cmd(httpx_cmd, timeout=httpx_timeout)

        def _httpx_hosts() -> bytes:
            if live_hosts_file.is_file() and live_hosts_file.stat().st_size > 0:
                return live_hosts_file.read_bytes()
            return output or b""

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
            # Instant crash (bad flags, wrong binary, etc.) — keep recon moving
            log(
                "httpx failed immediately with no results — "
                "continuing with unverified subdomains (same as --skip-httpx)",
                "error",
            )
            live_hosts_file.write_text("\n".join(sub_list) + "\n")

    live_list = [h for h in live_hosts_file.read_text().splitlines() if h.strip()]
    live_count = len(live_list)
    if live_count == 0 and sub_count > 0 and not args.skip_httpx and tools_status.get("httpx"):
        log(
            "No live hosts after httpx — downstream URL discovery will be empty. "
            "Re-run with --skip-httpx to force all subdomains, or increase budget.",
            "warn",
        )
    log(f"Live hosts: {C.BOLD}{live_count}{C.RESET} / {sub_count}", "success")
    if _ETA is not None:
        _ETA.set_work(subs=sub_count, live=live_count, log_now=True)

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
            if rc == 0 and katana_out_file.exists():
                raw_katana = [l.strip() for l in katana_out_file.read_text().splitlines() if l.strip()]
                log(f"Katana raw crawl: {len(raw_katana)} total URLs", "info")
                # Keep all URLs — scanners find secrets in any content type
                for line in raw_katana:
                    all_urls.add(line)
                log(f"Katana: {len(all_urls)} URLs added", "success")
            elif katana_out_file.exists() and katana_out_file.stat().st_size > 0:
                raw_katana = [l.strip() for l in katana_out_file.read_text().splitlines() if l.strip()]
                for line in raw_katana:
                    all_urls.add(line)
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
                    build_waymore_cmd(clean, str(waymore_out)),
                    timeout=120,
                    discard_stdout=True,
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
                rc, output = run_cmd(
                    build_gau_cmd(host, int(args.gau_threads)),
                    timeout=60,
                )
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

            run_cmd(
                build_gospider_cmd(str(gs_input), str(gs_out_dir)),
                timeout=300,
                discard_stdout=True,
            )

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
    if _ETA is not None:
        _ETA.set_work(urls=url_count, live=live_count, log_now=True)

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
        to_fetch = url_list[:2000]
        with eta_heartbeat(90):
            for i, url in enumerate(to_fetch, 1):
                try:
                    fname = download_filename(url)
                    out_path = dl_dir / fname
                    if out_path.exists():
                        cached += 1
                        continue
                    req = urllib.request.Request(url, headers={"User-Agent": ua})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        out_path.write_bytes(resp.read())
                        downloaded += 1
                    if downloaded % 100 == 0:
                        log(f"  Downloaded: {downloaded}/{len(to_fetch)} files...", "info")
                        if _ETA is not None:
                            _ETA.set_work(
                                progress=min(0.55, i / max(len(to_fetch), 1) * 0.55)
                            )
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
                trufflehog_filesystem_cmd(str(dl_dir)),
                timeout=600,
            )
            if output and output.strip():
                raw_findings = parse_trufflehog(output)
                log(f"TruffleHog: {len(raw_findings)} raw findings", "success")
            else:
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
            with eta_heartbeat(90):
                raw_findings = custom_scan(str(files_to_scan), output_dir)
    else:
        if not args.no_trufflehog:
            log("trufflehog not found — using built-in regex scanner", "warn")
            log("Install: https://github.com/trufflesecurity/trufflehog#installation", "warn")
        log("Running built-in regex scanner...", "info")
        with eta_heartbeat(90):
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
    validated: List[Dict] = []

    if args.no_validate or not unique_findings:
        if not unique_findings:
            log("No findings to validate.", "warn")
        else:
            log("Validation skipped (--no-validate)", "warn")
        validated = unique_findings
    else:
        log(f"Validating {len(unique_findings)} keys (concurrency={args.concurrency})...", "info")
        with eta_heartbeat(90):
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

    # Merge gate: live-validated secrets fail the process (CI can block merges)
    if valid_count and not args.no_fail_on_valid:
        log(
            f"Exiting with code 1: {valid_count} valid key(s) "
            f"(use --no-fail-on-valid to disable)",
            "error",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
