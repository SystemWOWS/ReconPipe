#!/usr/bin/env python3
"""
ReconPipe Professional GUI — NiceGUI frontend for reconpipe.py

Linux-ready localhost web UI:
  python3 reconpipegui.py

Exposes every CLI option, streams pipeline output, browses artifacts,
and re-tests findings with ReconPipe's configured validators only.
"""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from nicegui import app, ui
except ImportError:
    print(
        "NiceGUI is required for the GUI.\n"
        "  pip3 install nicegui\n"
        "  or: pip3 install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

import reconpipe as rp

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
ARTIFACT_FILES = [
    "findings.json",
    "valid_keys.json",
    "informational.json",
    "source_map_exposures.json",
    "quarantine.json",
    "summary.txt",
    "results.sarif",
    "subdomains.txt",
    "live_hosts.txt",
    "files_to_scan.txt",
]

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def redact_secret(value: str, reveal: bool = False) -> str:
    if not value:
        return ""
    if reveal or len(value) <= 8:
        return value if reveal else ("*" * len(value))
    return f"{value[:4]}…{value[-4:]}" if not reveal else value


def load_json_list(path: Path) -> List[Dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        return sum(1 for line in path.read_text(errors="ignore").splitlines() if line.strip())
    except Exception:
        return 0


def default_output_dir(domain: str) -> Path:
    safe = (domain or "target").replace(".", "_")
    return HERE / f"recon_{safe}"


def guess_key_types(key: str) -> List[str]:
    """Return pattern types that match a pasted key (longest / most specific first)."""
    text = (key or "").strip()
    if not text:
        return []
    hits: List[tuple] = []
    for name, pattern in rp.PATTERNS.items():
        try:
            m = re.search(pattern, text)
        except re.error:
            continue
        if m:
            hits.append((len(m.group(0)), name))
    hits.sort(reverse=True)
    return [name for _, name in hits]


def validator_type_options() -> List[str]:
    return sorted(rp.VALIDATORS.keys())


def validate_form(opts: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    domain = (opts.get("domain") or "").strip()
    if not domain:
        errors.append("Target domain is required.")
    elif not DOMAIN_RE.match(domain):
        errors.append(f"Invalid domain syntax: {domain}")

    for label, key in (("Subdomains file", "subdomains"), ("URL list", "files")):
        path = (opts.get(key) or "").strip()
        if path and not Path(path).expanduser().is_file():
            errors.append(f"{label} not found: {path}")

    for cfg in opts.get("config") or []:
        cfg = str(cfg).strip()
        if cfg and not Path(cfg).expanduser().is_file():
            errors.append(f"Config overlay not found: {cfg}")

    try:
        conc = int(opts.get("concurrency", 10))
        if conc < 1 or conc > 200:
            errors.append("Concurrency must be between 1 and 200.")
    except (TypeError, ValueError):
        errors.append("Concurrency must be an integer.")

    try:
        gt = int(opts.get("gau_threads", 5))
        if gt < 1 or gt > 100:
            errors.append("gau threads must be between 1 and 100.")
    except (TypeError, ValueError):
        errors.append("gau threads must be an integer.")

    out = (opts.get("output") or "").strip()
    if out:
        try:
            Path(out).expanduser()
        except Exception:
            errors.append(f"Invalid output directory: {out}")

    return errors

# Pipeline worker (subprocess — safe cancel / isolation)

class PipelineRunner:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.running = False
        self.exit_code: Optional[int] = None
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.command: List[str] = []
        self.output_dir: Optional[Path] = None
        self.domain: str = ""
        self._lock = threading.Lock()

    def start(self, opts: Dict[str, Any]) -> None:
        with self._lock:
            if self.running:
                raise RuntimeError("A scan is already running.")

            argv = rp.argv_from_options(opts)
            domain = opts["domain"].strip()
            out = (opts.get("output") or "").strip()
            self.output_dir = Path(out).expanduser() if out else default_output_dir(domain)
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if not out:
                argv += ["--output", str(self.output_dir)]

            cmd = [sys.executable, str(HERE / "reconpipe.py"), *argv]
            self.command = cmd
            self.domain = domain
            self.exit_code = None
            self.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.finished_at = None
            self.running = True

            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            # Prefer UTF-8 console on Windows / Linux
            env.setdefault("PYTHONIOENCODING", "utf-8")

            self.proc = subprocess.Popen(
                cmd,
                cwd=str(HERE),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                start_new_session=True,
            )
            self.thread = threading.Thread(target=self._reader, daemon=True)
            self.thread.start()
            self.log_q.put(f"[gui] Started: {' '.join(cmd)}")
            self.log_q.put(f"[gui] Output directory: {self.output_dir}")

    def _reader(self) -> None:
        assert self.proc is not None
        try:
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self.log_q.put(strip_ansi(line.rstrip("\n")))
        except Exception as exc:
            self.log_q.put(f"[gui] Log reader error: {exc}")
        finally:
            code = self.proc.wait()
            self.exit_code = code
            self.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.running = False
            self.log_q.put(f"[gui] Pipeline finished with exit code {code}")

    def stop(self) -> None:
        with self._lock:
            if not self.proc or not self.running:
                return
            self.log_q.put("[gui] Stopping pipeline…")
            try:
                if os.name == "nt":
                    self.proc.terminate()
                else:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def drain_logs(self) -> List[str]:
        lines: List[str] = []
        while True:
            try:
                lines.append(self.log_q.get_nowait())
            except queue.Empty:
                break
        return lines

# UI state

class GuiState:
    def __init__(self) -> None:
        self.runner = PipelineRunner()
        self.log_lines: List[str] = []
        self.history: List[Dict[str, Any]] = []
        self.findings: List[Dict] = []
        self.informational: List[Dict] = []
        self.exposures: List[Dict] = []
        self.revealed: set = set()
        self.selected_idx: Optional[int] = None
        self.last_test_note: str = ""
        self.workspace: Optional[Path] = None
        self.domain: str = ""
        self.shopify_domain: str = ""
        self.config_overlays: List[str] = []
        self.filter_type: str = "All"
        self.filter_status: str = "All"
        self.filter_tier: str = "All"
        self.filter_query: str = ""
        self.min_confidence: int = 0


STATE = GuiState()


# Build UI
def build_ui() -> None:
    ui.dark_mode().enable()
    ui.colors(
        primary="#e85d04",
        secondary="#3a3a3a",
        accent="#e85d04",
        dark="#1a1a1a",
        positive="#6aa84f",
        negative="#c62828",
        warning="#f9a825",
        info="#5c6b73",
    )
    ui.add_head_html(
        """
        <style>
          :root {
            --rp-bg: #161616;
            --rp-panel: #222222;
            --rp-panel-2: #2a2a2a;
            --rp-border: #3a3a3a;
            --rp-orange: #e85d04;
            --rp-text: #d6d6d6;
            --rp-muted: #8a8a8a;
            --rp-green: #6aa84f;
            --rp-red: #c62828;
          }
          html, body, .q-layout, .q-page, .nicegui-content {
            background: var(--rp-bg) !important;
            color: var(--rp-text) !important;
            font-family: "Segoe UI", Tahoma, sans-serif !important;
          }
          body::before {
            content: "";
            position: fixed; inset: 0; pointer-events: none; z-index: 0;
            background:
              linear-gradient(180deg, rgba(232,93,4,0.05) 0 36px, transparent 36px),
              repeating-linear-gradient(
                0deg, transparent, transparent 3px, rgba(255,255,255,0.012) 4px
              );
          }
          .q-header {
            background: #111111 !important;
            border-bottom: 2px solid var(--rp-orange) !important;
            box-shadow: none !important;
            min-height: 40px;
          }
          .q-tab {
            text-transform: none !important;
            font-size: 12.5px !important;
            color: #bdbdbd !important;
            min-height: 36px;
          }
          .q-tab--active { color: #fff !important; }
          .q-tab__indicator { background: var(--rp-orange) !important; height: 2px !important; }
          .q-tabs { background: #1c1c1c; border-bottom: 1px solid var(--rp-border); }
          .q-card, .rp-card {
            background: var(--rp-panel) !important;
            border: 1px solid var(--rp-border) !important;
            border-radius: 0 !important;
            box-shadow: none !important;
          }
          .q-field--outlined .q-field__control {
            border-radius: 0 !important;
            background: #1a1a1a !important;
          }
          .q-btn { border-radius: 0 !important; font-weight: 600; letter-spacing: 0.02em; }
          .rp-console {
            font-family: Consolas, "Lucida Console", ui-monospace, monospace;
            font-size: 12.5px; line-height: 1.4;
            background: #0c0c0c; color: #9ccc65;
            border: 1px solid #2a2a2a;
            padding: 10px 12px; height: 440px; overflow: auto; white-space: pre-wrap;
          }
          .rp-title {
            font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
            color: #fff;
          }
          .rp-brand-mark {
            width: 10px; height: 10px; background: var(--rp-orange);
            display: inline-block; margin-right: 10px;
          }
          .rp-section {
            font-size: 11px; font-weight: 700; letter-spacing: 0.14em;
            text-transform: uppercase; color: var(--rp-orange);
            border-bottom: 1px solid var(--rp-border); padding-bottom: 6px; margin-bottom: 8px;
          }
          .rp-badge-ok { color: var(--rp-green); font-weight: 700; }
          .rp-badge-miss { color: #f9a825; font-weight: 700; }
          .rp-secret { font-family: Consolas, monospace; }
          .rp-status-dot {
            width: 8px; height: 8px; border-radius: 50%; display: inline-block;
            background: var(--rp-muted); margin-right: 8px;
          }
          .rp-status-dot.live { background: var(--rp-green); box-shadow: 0 0 6px var(--rp-green); }
          .rp-status-dot.run { background: var(--rp-orange); box-shadow: 0 0 6px var(--rp-orange); }
          .rp-status-dot.dead { background: var(--rp-red); }
          .rp-stat-grid {
            display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 10px;
          }
          .rp-stat {
            background: #1a1a1a; border: 1px solid var(--rp-border); padding: 8px 10px;
          }
          .rp-stat .k { font-size: 10px; color: var(--rp-muted); letter-spacing: 0.1em; text-transform: uppercase; }
          .rp-stat .v { font-size: 16px; font-weight: 700; color: #eee; font-family: Consolas, monospace; }
          .rp-footer {
            background: #111 !important; border-top: 1px solid var(--rp-border) !important;
            color: #9a9a9a; font-size: 11.5px; min-height: 26px;
          }
          .rp-verdict {
            font-family: Consolas, monospace; font-size: 18px; font-weight: 700;
            letter-spacing: 0.16em; padding: 12px; border: 1px solid var(--rp-border);
            background: #141414;
          }
          .rp-verdict.live { color: var(--rp-green); border-color: #3d5c2f; }
          .rp-verdict.dead { color: var(--rp-red); border-color: #5c1f1f; }
          .rp-verdict.skip { color: #f9a825; border-color: #5c4a16; }
        </style>
        """
    )

    with ui.header().classes("items-center px-4"):
        with ui.row().classes("items-center no-wrap"):
            ui.element("span").classes("rp-brand-mark")
            ui.label("ReconPipe").classes("rp-title text-base")

    with ui.tabs().classes("w-full") as tabs:
        tab_scan = ui.tab("Scan")
        tab_console = ui.tab("Console")
        tab_findings = ui.tab("Findings")
        tab_tester = ui.tab("Key Tester")
        tab_artifacts = ui.tab("Artifacts")
        tab_history = ui.tab("History")

    with ui.tab_panels(tabs, value=tab_scan).classes("w-full px-3 pb-10"):
        # Scan 
        with ui.tab_panel(tab_scan):
            with ui.row().classes("w-full gap-3 items-stretch"):
                with ui.column().classes("w-full lg:w-7/12 gap-3"):
                    with ui.card().classes("w-full rp-card"):
                        ui.label("Target & I/O").classes("rp-section")
                        domain_in = ui.input(
                            "Target domain (-d)",
                            placeholder="example.com",
                        ).classes("w-full").props("outlined dense")
                        with ui.row().classes("w-full gap-2"):
                            sub_in = ui.input(
                                "Subdomains file (--subdomains)",
                                placeholder="/path/to/subs.txt",
                            ).classes("flex-1").props("outlined dense")
                            files_in = ui.input(
                                "URL list (--files)",
                                placeholder="/path/to/urls.txt",
                            ).classes("flex-1").props("outlined dense")
                        with ui.row().classes("w-full gap-2"):
                            out_in = ui.input(
                                "Output directory (-o)",
                                placeholder="recon_example_com",
                            ).classes("flex-1").props("outlined dense")
                            sarif_in = ui.input(
                                "SARIF path (--sarif)",
                                placeholder="optional override",
                            ).classes("flex-1").props("outlined dense")
                        chaos_in = ui.input(
                            "Chaos API key (--chaos-key)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or set CHAOS_KEY / PDCP_API_KEY in env",
                        ).classes("w-full").props("outlined dense")
                        shopify_in = ui.input(
                            "Shopify store host (--shopify-domain)",
                            placeholder="store.myshopify.com",
                        ).classes("w-full").props("outlined dense")
                        config_in = ui.textarea(
                            "Config overlays (--config, one path per line)",
                            placeholder="engagement.example.yaml",
                        ).classes("w-full").props("outlined dense")
                        ignore_in = ui.textarea(
                            "Ignore hashes (--ignore-hash, one SHA256 per line)",
                            placeholder="paste finding hashes to suppress",
                        ).classes("w-full").props("outlined dense")

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Pipeline options").classes("rp-section")
                        with ui.row().classes("w-full flex-wrap gap-4"):
                            skip_chaos = ui.checkbox("Skip Chaos (--skip-chaos)")
                            skip_httpx = ui.checkbox("Skip httpx (--skip-httpx)")
                            skip_gau = ui.checkbox("Skip passive archives (--skip-gau)")
                            skip_discovery = ui.checkbox(
                                "Skip all URL discovery (--skip-discovery)"
                            )
                            no_trufflehog = ui.checkbox(
                                "Built-in scanner only (--no-trufflehog)"
                            )
                            no_validate = ui.checkbox("Skip validation (--no-validate)")
                            headless = ui.checkbox("Katana headless Chrome (--headless)")
                            no_fail = ui.checkbox(
                                "Do not fail on valid keys (--no-fail-on-valid)"
                            )
                        with ui.row().classes("w-full gap-4"):
                            conc_in = ui.number(
                                "Validation concurrency", value=10, min=1, max=200
                            ).classes("w-40")
                            gau_in = ui.number(
                                "gau threads", value=5, min=1, max=100
                            ).classes("w-40")

                    form_error = ui.label("").classes("text-red-400 text-sm")

                    def collect_opts() -> Dict[str, Any]:
                        configs = [
                            ln.strip()
                            for ln in (config_in.value or "").splitlines()
                            if ln.strip()
                        ]
                        hashes = [
                            ln.strip()
                            for ln in (ignore_in.value or "").splitlines()
                            if ln.strip()
                        ]
                        return {
                            "domain": (domain_in.value or "").strip(),
                            "subdomains": (sub_in.value or "").strip() or None,
                            "files": (files_in.value or "").strip() or None,
                            "output": (out_in.value or "").strip() or None,
                            "sarif": (sarif_in.value or "").strip() or None,
                            "chaos_key": (chaos_in.value or "").strip() or None,
                            "shopify_domain": (shopify_in.value or "").strip() or None,
                            "config": configs,
                            "ignore_hash": hashes,
                            "skip_chaos": bool(skip_chaos.value),
                            "skip_httpx": bool(skip_httpx.value),
                            "skip_gau": bool(skip_gau.value),
                            "skip_discovery": bool(skip_discovery.value),
                            "no_trufflehog": bool(no_trufflehog.value),
                            "no_validate": bool(no_validate.value),
                            "headless": bool(headless.value),
                            "no_fail_on_valid": bool(no_fail.value),
                            "concurrency": int(conc_in.value or 10),
                            "gau_threads": int(gau_in.value or 5),
                        }

                    def preview_cmd() -> None:
                        opts = collect_opts()
                        errs = validate_form(opts)
                        if errs:
                            form_error.text = " · ".join(errs)
                            cmd_preview.set_text("")
                            return
                        form_error.text = ""
                        try:
                            argv = rp.argv_from_options(opts)
                            cmd_preview.set_text(
                                "python3 reconpipe.py " + " ".join(argv)
                            )
                        except Exception as exc:
                            form_error.text = str(exc)

                    def start_scan() -> None:
                        opts = collect_opts()
                        errs = validate_form(opts)
                        if errs:
                            form_error.text = " · ".join(errs)
                            ui.notify("Fix form errors before starting", type="negative")
                            return
                        form_error.text = ""
                        try:
                            STATE.runner.start(opts)
                        except Exception as exc:
                            ui.notify(str(exc), type="negative")
                            return
                        STATE.domain = opts["domain"]
                        STATE.shopify_domain = opts.get("shopify_domain") or ""
                        STATE.config_overlays = list(opts.get("config") or [])
                        STATE.workspace = STATE.runner.output_dir
                        STATE.log_lines.clear()
                        STATE.findings.clear()
                        STATE.informational.clear()
                        STATE.exposures.clear()
                        STATE.revealed.clear()
                        status_label.set_text("RUNNING")
                        status_dot.classes(replace="rp-status-dot run")
                        ui.notify("Pipeline started", type="positive")
                        tabs.set_value(tab_console)
                        update_stats()

                    def stop_scan() -> None:
                        STATE.runner.stop()
                        ui.notify("Stop signal sent", type="warning")

                    with ui.row().classes("gap-2"):
                        ui.button("Start scan", on_click=start_scan, color="primary").props(
                            "unelevated"
                        )
                        ui.button("Stop", on_click=stop_scan, color="negative").props(
                            "outline"
                        )
                        ui.button(
                            "Preview CLI", on_click=preview_cmd, color="secondary"
                        ).props("flat")
                    cmd_preview = ui.label("").classes(
                        "text-xs text-gray-500 font-mono break-all"
                    )

                with ui.column().classes("w-full lg:w-5/12 gap-3"):
                    with ui.card().classes("w-full rp-card"):
                        with ui.row().classes("w-full justify-between items-center"):
                            ui.label("Tool preflight").classes("rp-section w-full")
                        ui.button(
                            "Refresh", on_click=lambda: refresh_tools(), color="secondary"
                        ).props("flat dense")
                        tools_box = ui.column().classes("w-full gap-1")

                        def refresh_tools() -> None:
                            tools_box.clear()
                            status = rp.probe_tools()
                            extras = {"jsluice": rp.check_tool("jsluice")}
                            with tools_box:
                                for name, ok in {**status, **extras}.items():
                                    with ui.row().classes("w-full justify-between"):
                                        ui.label(name).classes("font-mono text-sm")
                                        if ok:
                                            ui.label("FOUND").classes(
                                                "text-xs rp-badge-ok"
                                            )
                                        else:
                                            ui.label("MISSING").classes(
                                                "text-xs rp-badge-miss"
                                            )
                                ui.separator()
                                ui.label(
                                    f"aiohttp  {'ok' if rp.AIOHTTP_AVAILABLE else 'missing'}"
                                    f"   ·   {len(rp.VALIDATORS)} validators"
                                    f"   ·   {len(rp.PATTERNS)} patterns"
                                ).classes("text-xs text-gray-500")

                        refresh_tools()

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Run status").classes("rp-section")
                        with ui.row().classes("items-center no-wrap"):
                            status_dot = ui.element("span").classes("rp-status-dot")
                            status_label = ui.label("IDLE").classes(
                                "font-mono font-bold tracking-widest"
                            )
                        stats_html = ui.html("", sanitize=False).classes("w-full")

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Load workspace").classes("rp-section")
                        load_in = ui.input(
                            "Output directory",
                            placeholder="recon_example_com",
                        ).classes("w-full").props("outlined dense")
                        load_domain = ui.input(
                            "Domain context (for re-test)",
                            placeholder="example.com",
                        ).classes("w-full").props("outlined dense")

                        def load_workspace() -> None:
                            path = Path((load_in.value or "").strip()).expanduser()
                            if not path.is_dir():
                                ui.notify(f"Not a directory: {path}", type="negative")
                                return
                            STATE.workspace = path
                            STATE.domain = (load_domain.value or domain_in.value or "").strip()
                            STATE.shopify_domain = (shopify_in.value or "").strip()
                            STATE.config_overlays = [
                                ln.strip()
                                for ln in (config_in.value or "").splitlines()
                                if ln.strip()
                            ]
                            reload_findings()
                            update_stats()
                            ui.notify("Workspace loaded", type="positive")
                            tabs.set_value(tab_findings)

                        ui.button(
                            "Load findings", on_click=load_workspace, color="secondary"
                        ).props("outline")

        # ---------------- Console ----------------
        with ui.tab_panel(tab_console):
            with ui.card().classes("w-full rp-card"):
                with ui.row().classes("w-full justify-between items-center"):
                    ui.label("Console").classes("rp-section w-full")
                    ui.button(
                        "Clear",
                        on_click=lambda: (STATE.log_lines.clear(), console.set_content("")),
                        color="secondary",
                    ).props("flat dense")
                console = ui.html("", sanitize=False).classes("rp-console w-full")

                stage_labels: Dict[int, Any] = {}
                with ui.row().classes("gap-3 flex-wrap mt-2"):
                    for num, title in (
                        (1, "1 Subdomains"),
                        (2, "2 Live hosts"),
                        (3, "3 URL discovery"),
                        (4, "4 Secret scan"),
                        (5, "5 Validation"),
                        (6, "6 Save results"),
                    ):
                        stage_labels[num] = ui.label(title).classes(
                            "text-xs text-slate-500"
                        )

        # Findings
        with ui.tab_panel(tab_findings):
            with ui.card().classes("w-full rp-card"):
                ui.label("Findings").classes("rp-section")
                ui.label(
                    "Keys are redacted until Reveal. Inspect a finding to re-test it, "
                    "or use the Key Tester tab for a pasted credential."
                ).classes("text-xs text-gray-500 mb-2")

                with ui.row().classes("w-full gap-2 flex-wrap items-end"):
                    f_type = ui.select(
                        ["All"], value="All", label="Key type"
                    ).classes("w-48").props("dense outlined")
                    f_status = ui.select(
                        ["All", "Valid", "Invalid", "Unchecked", "Error/Skipped"],
                        value="All",
                        label="Validation",
                    ).classes("w-44").props("dense outlined")
                    f_tier = ui.select(
                        ["All", "actionable", "informational", "exposure"],
                        value="All",
                        label="Tier",
                    ).classes("w-40").props("dense outlined")
                    f_query = ui.input("Search source / note / hash").classes(
                        "flex-1"
                    ).props("dense outlined")
                    f_conf = ui.number(
                        "Min confidence", value=0, min=0, max=100
                    ).classes("w-36").props("dense")

                    def apply_filters() -> None:
                        STATE.filter_type = f_type.value or "All"
                        STATE.filter_status = f_status.value or "All"
                        STATE.filter_tier = f_tier.value or "All"
                        STATE.filter_query = (f_query.value or "").strip().lower()
                        STATE.min_confidence = int(f_conf.value or 0)
                        render_findings()

                    ui.button("Apply", on_click=apply_filters, color="primary").props(
                        "unelevated dense"
                    )
                    ui.button(
                        "Reload files", on_click=lambda: reload_findings(), color="secondary"
                    ).props("outline dense")

                findings_meta = ui.label("0 findings").classes("text-sm text-slate-400")
                findings_host = ui.column().classes("w-full gap-2 mt-2")
                detail_host = ui.card().classes("w-full rp-card mt-2")
                with detail_host:
                    ui.label("Select a finding to inspect / re-test.").classes(
                        "text-slate-400 text-sm"
                    )

                def filtered_rows() -> List[Dict]:
                    rows: List[Dict] = []
                    for f in STATE.findings:
                        rows.append({**f, "_tier": "actionable"})
                    for f in STATE.informational:
                        rows.append({**f, "_tier": "informational"})
                    for f in STATE.exposures:
                        rows.append({**f, "_tier": "exposure"})

                    out: List[Dict] = []
                    for f in rows:
                        if STATE.filter_tier != "All" and f.get("_tier") != STATE.filter_tier:
                            continue
                        if STATE.filter_type != "All" and f.get("type") != STATE.filter_type:
                            continue
                        conf = f.get("confidence")
                        try:
                            if conf is not None and int(conf) < STATE.min_confidence:
                                continue
                        except (TypeError, ValueError):
                            pass
                        valid = f.get("valid")
                        validated = f.get("validated")
                        status = STATE.filter_status
                        if status == "Valid" and not valid:
                            continue
                        if status == "Invalid" and not (validated and valid is False):
                            continue
                        if status == "Unchecked" and validated:
                            continue
                        if status == "Error/Skipped":
                            note = (f.get("note") or "").lower()
                            if not any(
                                x in note
                                for x in ("skip", "error", "timeout", "no validator")
                            ):
                                continue
                        q = STATE.filter_query
                        if q:
                            blob = " ".join(
                                str(f.get(k, ""))
                                for k in (
                                    "type",
                                    "source_url",
                                    "note",
                                    "hash",
                                    "key",
                                )
                            ).lower()
                            if q not in blob:
                                continue
                        out.append(f)
                    return out

                def render_findings() -> None:
                    rows = filtered_rows()
                    findings_meta.set_text(
                        f"{len(rows)} shown · {len(STATE.findings)} actionable · "
                        f"{len(STATE.informational)} informational · "
                        f"{len(STATE.exposures)} exposures"
                    )
                    types = sorted(
                        {
                            str(f.get("type") or "unknown")
                            for f in (
                                STATE.findings
                                + STATE.informational
                                + STATE.exposures
                            )
                        }
                    )
                    f_type.options = ["All", *types]
                    findings_host.clear()
                    with findings_host:
                        if not rows:
                            ui.label("No findings match the current filters.").classes(
                                "text-slate-500 text-sm"
                            )
                            return
                        for idx, f in enumerate(rows):
                            key = str(f.get("key") or "")
                            fid = f.get("hash") or f"{f.get('type')}:{key[:24]}:{idx}"
                            revealed = fid in STATE.revealed
                            valid = f.get("valid")
                            badge = (
                                "VALID"
                                if valid
                                else (
                                    "checked"
                                    if f.get("validated")
                                    else f.get("_tier", "finding")
                                )
                            )
                            color = (
                                "text-emerald-400"
                                if valid
                                else (
                                    "text-amber-300"
                                    if f.get("_tier") == "exposure"
                                    else "text-slate-300"
                                )
                            )
                            with ui.card().classes("w-full bg-slate-900/60 border border-slate-800"):
                                with ui.row().classes(
                                    "w-full justify-between items-start gap-2"
                                ):
                                    with ui.column().classes("gap-0 flex-1"):
                                        ui.label(
                                            f"[{f.get('type', 'unknown')}]  conf={f.get('confidence', '—')}  ·  {badge}"
                                        ).classes(f"font-semibold {color}")
                                        ui.label(
                                            redact_secret(key, reveal=revealed)
                                        ).classes("rp-secret text-sm text-slate-200")
                                        src = f.get("source_url") or ""
                                        ui.label(src).classes(
                                            "text-xs text-slate-500 break-all"
                                        )
                                        if f.get("note"):
                                            ui.label(str(f.get("note"))).classes(
                                                "text-xs text-slate-400"
                                            )
                                    with ui.column().classes("gap-1"):
                                        def make_select(i=idx, row=f, id_=fid):
                                            def _sel():
                                                STATE.selected_idx = i
                                                show_detail(row, id_)

                                            return _sel

                                        def make_reveal(id_=fid):
                                            def _rev():
                                                if id_ in STATE.revealed:
                                                    STATE.revealed.discard(id_)
                                                else:
                                                    STATE.revealed.add(id_)
                                                render_findings()

                                            return _rev

                                        ui.button(
                                            "Inspect",
                                            on_click=make_select(),
                                            color="primary",
                                        ).props("dense unelevated")
                                        ui.button(
                                            "Reveal" if not revealed else "Hide",
                                            on_click=make_reveal(),
                                            color="secondary",
                                        ).props("dense flat")

                def show_detail(finding: Dict, fid: str) -> None:
                    detail_host.clear()
                    with detail_host:
                        ui.label(
                            f"Detail · {finding.get('type', 'unknown')}"
                        ).classes("rp-section")
                        revealed = fid in STATE.revealed
                        ui.label(
                            "Key: " + redact_secret(str(finding.get("key") or ""), revealed)
                        ).classes("rp-secret text-sm")
                        ui.label(f"Source: {finding.get('source_url', '')}").classes(
                            "text-xs text-slate-400 break-all"
                        )
                        ui.label(f"Hash: {finding.get('hash', '—')}").classes(
                            "text-xs text-slate-500"
                        )
                        ui.label(
                            f"Valid: {finding.get('valid')} · Status: {finding.get('status_code')} · "
                            f"Note: {finding.get('note', '')}"
                        ).classes("text-sm text-slate-300 mt-1")
                        if finding.get("jwt"):
                            ui.code(json.dumps(finding["jwt"], indent=2)).classes("w-full")

                        can_test = finding.get("_tier") == "actionable" and (
                            finding.get("type") in rp.VALIDATORS
                        )
                        test_note = ui.label(STATE.last_test_note).classes(
                            "text-sm text-slate-400 mt-2"
                        )

                        async def retest() -> None:
                            if not STATE.domain:
                                ui.notify(
                                    "Set domain context (scan form or Load workspace)",
                                    type="negative",
                                )
                                return
                            if finding.get("type") not in rp.VALIDATORS:
                                ui.notify(
                                    "No configured validator for this type",
                                    type="warning",
                                )
                                return
                            ui.notify("Running configured validator…", type="info")
                            try:
                                result = await ui.run_io_bound(
                                    rp.validate_finding_configured_sync,
                                    dict(finding),
                                    STATE.domain,
                                    STATE.shopify_domain,
                                    STATE.config_overlays,
                                )
                            except Exception as exc:
                                ui.notify(f"Validation error: {exc}", type="negative")
                                return
                            # Merge into actionable findings list
                            updated = False
                            for i, existing in enumerate(STATE.findings):
                                if (
                                    existing.get("hash")
                                    and existing.get("hash") == result.get("hash")
                                ) or (
                                    existing.get("type") == result.get("type")
                                    and existing.get("key") == result.get("key")
                                    and existing.get("source_url")
                                    == result.get("source_url")
                                ):
                                    STATE.findings[i] = result
                                    updated = True
                                    break
                            if not updated and result.get("_tier") != "informational":
                                STATE.findings.append(result)
                            # Persist back to findings.json when possible
                            if STATE.workspace:
                                path = STATE.workspace / "findings.json"
                                try:
                                    path.write_text(
                                        json.dumps(STATE.findings, indent=2),
                                        encoding="utf-8",
                                    )
                                    valid_only = [
                                        x for x in STATE.findings if x.get("valid")
                                    ]
                                    if valid_only:
                                        (STATE.workspace / "valid_keys.json").write_text(
                                            json.dumps(valid_only, indent=2),
                                            encoding="utf-8",
                                        )
                                except Exception as exc:
                                    ui.notify(
                                        f"Could not write findings.json: {exc}",
                                        type="warning",
                                    )
                            stamp = datetime.now().strftime("%H:%M:%S")
                            STATE.last_test_note = (
                                f"[{stamp}] valid={result.get('valid')} "
                                f"status={result.get('status_code')} "
                                f"note={result.get('note', '')}"
                            )
                            test_note.set_text(STATE.last_test_note)
                            render_findings()
                            show_detail(result, fid)
                            ui.notify("Re-test complete", type="positive")

                        with ui.row().classes("gap-2 mt-3"):
                            if can_test:
                                ui.button(
                                    "Test key (live check)",
                                    on_click=retest,
                                    color="positive",
                                ).props("unelevated")
                            else:
                                ui.label(
                                    "No live validator configured for this tier/type."
                                ).classes("text-sm text-slate-500")

                def reload_findings() -> None:
                    if not STATE.workspace:
                        ui.notify("No workspace selected", type="warning")
                        return
                    STATE.findings = load_json_list(STATE.workspace / "findings.json")
                    STATE.informational = load_json_list(
                        STATE.workspace / "informational.json"
                    )
                    STATE.exposures = load_json_list(
                        STATE.workspace / "source_map_exposures.json"
                    )
                    render_findings()
                    update_stats()
                    ui.notify(
                        f"Loaded {len(STATE.findings)} findings from {STATE.workspace}",
                        type="info",
                    )

                # bind for outer timers
                build_ui.reload_findings = reload_findings  # type: ignore[attr-defined]
                build_ui.render_findings = render_findings  # type: ignore[attr-defined]

        # Key Tester
        with ui.tab_panel(tab_tester):
            with ui.card().classes("w-full rp-card"):
                ui.label("Key Tester").classes("rp-section")
                ui.label(
                    "Paste a discovered API key and run ReconPipe’s configured provider "
                    "check. LIVE means the credential is accepted by the provider API."
                ).classes("text-xs text-gray-500 mb-3")

                with ui.row().classes("w-full gap-2 flex-wrap"):
                    tester_type = ui.select(
                        validator_type_options(),
                        value=validator_type_options()[0] if validator_type_options() else None,
                        label="Key type",
                    ).classes("w-56").props("dense outlined")
                    tester_domain = ui.input(
                        "Target domain (Referer / Shopify host context)",
                        value="",
                        placeholder="example.com",
                    ).classes("flex-1").props("dense outlined")
                    tester_shop = ui.input(
                        "Shopify store (if testing shpat_)",
                        placeholder="store.myshopify.com",
                    ).classes("flex-1").props("dense outlined")

                tester_key = ui.textarea(
                    "API key / token",
                    placeholder="paste credential",
                ).classes("w-full").props("outlined dense")

                with ui.row().classes("w-full gap-2"):
                    tester_secret = ui.input(
                        "Paired secret (AWS secret / Twilio auth token)",
                        password=True,
                        password_toggle_button=True,
                    ).classes("flex-1").props("outlined dense")
                    tester_session = ui.input(
                        "AWS session token (ASIA keys)",
                        password=True,
                        password_toggle_button=True,
                    ).classes("flex-1").props("outlined dense")

                guess_label = ui.label("").classes("text-xs text-gray-500")
                tester_verdict = ui.html(
                    '<div class="rp-verdict skip">NO TEST YET</div>',
                    sanitize=False,
                ).classes("w-full mt-2")
                tester_detail = ui.label("").classes(
                    "text-sm text-gray-400 font-mono mt-2 whitespace-pre-wrap"
                )

                def apply_guess() -> None:
                    hits = guess_key_types(tester_key.value or "")
                    if not hits:
                        guess_label.set_text("")
                        return
                    preferred = [h for h in hits if h in rp.VALIDATORS] or hits
                    guess_label.set_text("Detected: " + ", ".join(hits[:6]))
                    if preferred[0] in validator_type_options():
                        tester_type.set_value(preferred[0])

                tester_key.on("blur", lambda: apply_guess())

                async def run_manual_test() -> None:
                    key = (tester_key.value or "").strip()
                    ktype = tester_type.value
                    if not key:
                        ui.notify("Paste an API key first", type="warning")
                        return
                    if not ktype:
                        ui.notify("Select a key type", type="warning")
                        return
                    if ktype not in rp.VALIDATORS:
                        ui.notify(f"No configured validator for {ktype}", type="warning")
                        return
                    domain = (
                        (tester_domain.value or "").strip()
                        or STATE.domain
                        or "example.com"
                    )
                    shop = (
                        (tester_shop.value or "").strip()
                        or STATE.shopify_domain
                    )
                    finding: Dict[str, Any] = {
                        "type": ktype,
                        "key": key,
                        "source_url": "gui://key-tester",
                    }
                    secret = (tester_secret.value or "").strip()
                    session = (tester_session.value or "").strip()
                    if secret:
                        if ktype == "aws_access_key":
                            finding["aws_secret"] = secret
                        if ktype in ("twilio_sid", "twilio_token"):
                            finding["twilio_token"] = secret
                    if session:
                        finding["aws_session_token"] = session
                    ui.notify(f"Testing {ktype}…", type="info")
                    try:
                        result = await ui.run_io_bound(
                            rp.validate_finding_configured_sync,
                            finding,
                            domain,
                            shop,
                            STATE.config_overlays,
                        )
                    except Exception as exc:
                        tester_verdict.set_content(
                            '<div class="rp-verdict dead">ERROR</div>'
                        )
                        tester_detail.set_text(str(exc))
                        ui.notify(f"Validation error: {exc}", type="negative")
                        return
                    valid = bool(result.get("valid"))
                    validated = bool(result.get("validated"))
                    note = str(result.get("note") or "")
                    skipped = note.lower().startswith("skip") or (
                        "no validator" in note.lower()
                    )
                    if valid:
                        cls, label = "live", "LIVE"
                    elif skipped:
                        cls, label = "skip", "SKIPPED"
                    elif validated:
                        cls, label = "dead", "DEAD"
                    else:
                        cls, label = "skip", "INCONCLUSIVE"
                    tester_verdict.set_content(
                        f'<div class="rp-verdict {cls}">{label}</div>'
                    )
                    stamp = datetime.now().strftime("%H:%M:%S")
                    tester_detail.set_text(
                        f"[{stamp}] type={result.get('type')}\n"
                        f"valid={result.get('valid')}  validated={result.get('validated')}  "
                        f"http={result.get('status_code')}\n"
                        f"note={note}"
                    )
                    footer_status.set_text(f"LAST TEST  {label}")
                    ui.notify(f"Key test: {label}", type="positive" if valid else "warning")

                with ui.row().classes("gap-2 mt-3"):
                    ui.button(
                        "Detect type", on_click=apply_guess, color="secondary"
                    ).props("outline")
                    ui.button(
                        "Test key", on_click=run_manual_test, color="primary"
                    ).props("unelevated")

        # Artifacts 
        with ui.tab_panel(tab_artifacts):
            with ui.card().classes("w-full rp-card"):
                ui.label("Artifacts").classes("rp-section")
                ui.label(
                    "These files may contain live secrets. Handle according to your "
                    "engagement rules; do not share them casually."
                ).classes("text-xs text-amber-400 mb-2")
                artifacts_host = ui.column().classes("w-full gap-2")
                preview = ui.code("").classes("w-full max-h-96 overflow-auto")

                def refresh_artifacts() -> None:
                    artifacts_host.clear()
                    ws = STATE.workspace or STATE.runner.output_dir
                    with artifacts_host:
                        if not ws or not Path(ws).is_dir():
                            ui.label("No output directory yet.").classes(
                                "text-slate-500 text-sm"
                            )
                            return
                        ui.label(str(ws)).classes("text-xs text-slate-400 break-all mb-2")
                        for name in ARTIFACT_FILES:
                            path = Path(ws) / name
                            exists = path.is_file()
                            with ui.row().classes(
                                "w-full justify-between items-center border-b border-slate-800 py-1"
                            ):
                                ui.label(name).classes(
                                    "font-mono text-sm "
                                    + ("text-slate-200" if exists else "text-slate-600")
                                )
                                with ui.row().classes("gap-1"):
                                    if exists:
                                        size = path.stat().st_size

                                        def make_preview(p=path):
                                            def _p():
                                                try:
                                                    text = p.read_text(
                                                        encoding="utf-8", errors="replace"
                                                    )
                                                    if len(text) > 20000:
                                                        text = text[:20000] + "\n… truncated …"
                                                    preview.set_content(text)
                                                except Exception as exc:
                                                    preview.set_content(str(exc))

                                            return _p

                                        ui.label(f"{size} B").classes(
                                            "text-xs text-slate-500"
                                        )
                                        ui.button(
                                            "Preview",
                                            on_click=make_preview(),
                                            color="secondary",
                                        ).props("flat dense")
                                    else:
                                        ui.label("missing").classes(
                                            "text-xs text-slate-600"
                                        )

                ui.button(
                    "Refresh artifact list",
                    on_click=refresh_artifacts,
                    color="primary",
                ).props("unelevated")
                build_ui.refresh_artifacts = refresh_artifacts  # type: ignore[attr-defined]

        # History 
        with ui.tab_panel(tab_history):
            with ui.card().classes("w-full rp-card"):
                ui.label("History").classes("rp-section")
                history_host = ui.column().classes("w-full gap-2")

                def render_history() -> None:
                    history_host.clear()
                    with history_host:
                        if not STATE.history:
                            ui.label("No completed runs in this session yet.").classes(
                                "text-slate-500 text-sm"
                            )
                            return
                        for item in reversed(STATE.history):
                            with ui.card().classes("w-full bg-slate-900/50"):
                                ui.label(
                                    f"{item.get('domain')} · exit {item.get('exit_code')} · "
                                    f"{item.get('started_at')} → {item.get('finished_at')}"
                                ).classes("text-sm text-slate-200")
                                ui.label(str(item.get("output_dir"))).classes(
                                    "text-xs text-slate-500 break-all"
                                )

                build_ui.render_history = render_history  # type: ignore[attr-defined]
                render_history()

    footer_status = ui.label("IDLE").classes("font-mono")
    with ui.footer().classes("rp-footer items-center justify-between px-4"):
        with ui.row().classes("items-center gap-4"):
            footer_status
            footer_target = ui.label("").classes("font-mono")
        footer_path = ui.label("").classes("font-mono truncate")

    def update_stats() -> None:
        ws = STATE.workspace or STATE.runner.output_dir
        running = STATE.runner.running
        if running:
            status_label.set_text("RUNNING")
            status_dot.classes(replace="rp-status-dot run")
            footer_status.set_text("RUNNING")
        elif STATE.runner.exit_code is not None:
            code = STATE.runner.exit_code
            status_label.set_text(f"DONE  exit {code}")
            status_dot.classes(
                replace="rp-status-dot live" if code == 0 else "rp-status-dot dead"
            )
            footer_status.set_text(f"DONE  {code}")
        else:
            status_label.set_text("IDLE")
            status_dot.classes(replace="rp-status-dot")
            footer_status.set_text("IDLE")

        if STATE.domain:
            footer_target.set_text(STATE.domain)
        if not ws:
            stats_html.set_content("")
            footer_path.set_text("")
            return
        ws = Path(ws)
        footer_path.set_text(str(ws))
        subs = count_lines(ws / "subdomains.txt")
        live = count_lines(ws / "live_hosts.txt")
        urls = count_lines(ws / "files_to_scan.txt")
        findings_n = len(STATE.findings) or len(load_json_list(ws / "findings.json"))
        stats_html.set_content(
            "<div class='rp-stat-grid'>"
            f"<div class='rp-stat'><div class='k'>Subs</div><div class='v'>{subs}</div></div>"
            f"<div class='rp-stat'><div class='k'>Live</div><div class='v'>{live}</div></div>"
            f"<div class='rp-stat'><div class='k'>URLs</div><div class='v'>{urls}</div></div>"
            f"<div class='rp-stat'><div class='k'>Keys</div><div class='v'>{findings_n}</div></div>"
            "</div>"
        )

    def detect_stage(line: str) -> None:
        m = re.search(r"\[(\d)/6\]", line)
        if not m:
            return
        n = int(m.group(1))
        for i, lbl in stage_labels.items():
            if i < n:
                lbl.classes(replace="text-xs font-bold")
                lbl.style("color: #6aa84f")
            elif i == n:
                lbl.classes(replace="text-xs font-bold")
                lbl.style("color: #e85d04")
            else:
                lbl.classes(replace="text-xs")
                lbl.style("color: #8a8a8a")

    def on_tick() -> None:
        lines = STATE.runner.drain_logs()
        if lines:
            STATE.log_lines.extend(lines)
            if len(STATE.log_lines) > 5000:
                STATE.log_lines = STATE.log_lines[-4000:]
            # Keep console readable
            text = "\n".join(STATE.log_lines[-800:])
            escaped = (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            console.set_content(f"<pre style='margin:0'>{escaped}</pre>")
            for ln in lines:
                detect_stage(ln)

        if STATE.runner.running:
            update_stats()
        elif STATE.runner.finished_at and STATE.runner.exit_code is not None:
            # Finalize once
            code = STATE.runner.exit_code
            if not STATE.history or STATE.history[-1].get("finished_at") != STATE.runner.finished_at:
                STATE.history.append(
                    {
                        "domain": STATE.runner.domain,
                        "output_dir": str(STATE.runner.output_dir),
                        "exit_code": code,
                        "started_at": STATE.runner.started_at,
                        "finished_at": STATE.runner.finished_at,
                        "command": " ".join(STATE.runner.command),
                    }
                )
                STATE.workspace = STATE.runner.output_dir
                try:
                    build_ui.reload_findings()  # type: ignore[attr-defined]
                except Exception:
                    pass
                try:
                    build_ui.refresh_artifacts()  # type: ignore[attr-defined]
                except Exception:
                    pass
                try:
                    build_ui.render_history()  # type: ignore[attr-defined]
                except Exception:
                    pass
            update_stats()

    ui.timer(0.4, on_tick)


def main() -> None:
    host = os.environ.get("RECONPIPE_GUI_HOST", "127.0.0.1")
    port = int(os.environ.get("RECONPIPE_GUI_PORT", "8088"))
    show = os.environ.get("RECONPIPE_GUI_SHOW", "1").strip() not in {"0", "false", "False"}
    print(f"ReconPipe GUI → http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    ui.run(
        title="ReconPipe",
        host=host,
        port=port,
        reload=False,
        show=show,
        favicon="🔑",
    )


if __name__ in {"__main__", "__mp_main__"}:
    build_ui()
    main()
