from __future__ import annotations

import argparse
import inspect
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import asyncio

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

try:
    from nicegui import run as nicegui_run
except Exception:
    nicegui_run = None  


async def run_io_bound(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a blocking function off the UI loop (NiceGUI 1.x–3.x)."""
    bound = getattr(ui, "run_io_bound", None)
    if callable(bound):
        return await bound(func, *args, **kwargs)
    io_bound = getattr(nicegui_run, "io_bound", None) if nicegui_run is not None else None
    if callable(io_bound):
        return await io_bound(func, *args, **kwargs)
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
    return await loop.run_in_executor(None, func, *args)

import reconpipe as rp

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FINDINGS_RENDER_CAP = 80
CONSOLE_PUSH_CHARS = 800
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
    "scan_status.json",
    "hits/summary.txt",
    "hits/findings.json",
    "hits/valid_keys.json",
    "hits/INDEX.txt",
    "report.html",
    "report.md",
    "findings.csv",
    "findings_diff.json",
    "report.jsonld",
    "pipeline_metrics.json",
    "js_endpoints.json",
    "js_secrets.json",
    "unique_findings.json",
    "checkpoint.json",
    "export_hackerone.md",
    "export_jira.md",
    "findings_stream.jsonl",
    "wayback_sources.json",
    "reconstructed_sources.json",
    "js_history.json",
    "js_history_removed.json",
    "sensitive_paths.txt",
    "docker_hub_images.json",
    "image_refs.json",
    "ai_verdict.json",
    "gitleaks.json",
    "gitleaks_git.json",
    "spray_urls.txt",
    "jsleak.txt",
    "jsleak_secrets.json",
    "code_search_urls.txt",
    "ci_logs.json",
    "paste_urls.json",
    "buckets.json",
    "openapi_urls.txt",
    "download_etag.json",
    "remediation.md",
    "llm_report.json",
    "vendors.json",
    "vendors.html",
    "report_pentest.md",
    "report_executive.md",
    "report_executive.html",
    "findings_report.html",
]
ARTIFACT_ZIP_NAME = "reconpipe_artifacts.zip"


def _artifact_rel_ok(rel: str) -> bool:
    name = (rel or "").replace("\\", "/").lstrip("/")
    if not name or name.startswith("../") or "/../" in f"/{name}/" or name.endswith("/.."):
        return False
    allowed = {n.replace("\\", "/") for n in ARTIFACT_FILES}
    allowed.add(ARTIFACT_ZIP_NAME)
    return name in allowed


def resolve_workspace_file(workspace: Path, rel: str) -> Optional[Path]:
    """Return an existing artifact under workspace, or None if off-limits/missing."""
    name = (rel or "").replace("\\", "/").lstrip("/")
    if not _artifact_rel_ok(name):
        return None
    try:
        ws = Path(workspace).expanduser().resolve()
        path = (ws / name).resolve()
        path.relative_to(ws)
    except (OSError, ValueError):
        return None
    return path if path.is_file() else None


def existing_artifact_files(workspace: Path) -> List[Tuple[str, Path]]:
    ws = Path(workspace)
    rows: List[Tuple[str, Path]] = []
    for name in ARTIFACT_FILES:
        path = resolve_workspace_file(ws, name)
        if path is not None:
            rows.append((name.replace("\\", "/"), path))
    return rows


def write_artifacts_zip(workspace: Path) -> Optional[Path]:
    """Zip existing report artifacts (not downloaded_files/)."""
    files = existing_artifact_files(workspace)
    if not files:
        return None
    dest = Path(workspace) / ARTIFACT_ZIP_NAME
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, path in files:
            zf.write(path, arcname=name)
    return dest if dest.is_file() else None


def trigger_browser_download(path: Path, filename: Optional[str] = None) -> bool:
    """Send a workspace file to the browser (NiceGUI 1.x–3.x)."""
    if not path.is_file():
        ui.notify(f"File not found: {path.name}", type="negative")
        return False
    name = filename or path.name
    download = getattr(ui, "download", None)
    if download is None:
        ui.notify("Download is not available in this NiceGUI build", type="negative")
        return False
    file_fn = getattr(download, "file", None)
    try:
        if callable(file_fn):
            try:
                file_fn(path, filename=name)
            except TypeError:
                file_fn(path)
        elif callable(download):
            try:
                download(path, filename=name)
            except TypeError:
                download(path.read_bytes(), name)
        else:
            ui.notify("Download is not available in this NiceGUI build", type="negative")
            return False
        ui.notify(f"Downloading {name}", type="positive")
        return True
    except Exception as exc:
        ui.notify(f"Download failed: {exc}", type="negative")
        return False

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
    return data if isinstance(data, list) else []


def load_jsonl_list(path: Path, limit: int = 2500) -> List[Dict]:
    if not path.is_file():
        return []
    rows: List[Dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        if limit and len(lines) > limit:
            lines = lines[-limit:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    except Exception:
        return []
    return rows


def finding_identity(row: Dict) -> Tuple[Any, Any, Any]:
    return (row.get("hash"), row.get("type"), row.get("key"))


def merge_finding_rows(dst: List[Dict], incoming: Iterable[Dict]) -> int:
    """Upsert streamed/workspace findings. Returns new + updated count."""
    if not incoming:
        return 0
    index = {finding_identity(f): i for i, f in enumerate(dst)}
    changed = 0
    for item in incoming:
        if not isinstance(item, dict):
            continue
        ident = finding_identity(item)
        if ident in index and (ident[0] or ident[2]):
            i = index[ident]
            merged = dict(dst[i])
            merged.update(item)
            if merged != dst[i]:
                dst[i] = merged
                changed += 1
            continue
        dst.append(item)
        index[ident] = len(dst) - 1
        changed += 1
    return changed


def workspace_file_sig(path: Path) -> Tuple[int, int]:
    try:
        st = path.stat()
        return (int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))), int(st.st_size))
    except OSError:
        return (0, 0)


def ingest_workspace_findings(workspace: Path) -> int:
    """Merge live stream + JSON artifacts into STATE. Returns how many rows changed."""
    ws = Path(workspace)
    n = 0
    n += merge_finding_rows(STATE.findings, load_jsonl_list(ws / "findings_stream.jsonl"))
    n += merge_finding_rows(STATE.findings, load_json_list(ws / "unique_findings.json"))
    n += merge_finding_rows(STATE.findings, load_json_list(ws / "findings.json"))
    n += merge_finding_rows(STATE.informational, load_json_list(ws / "informational.json"))
    n += merge_finding_rows(STATE.exposures, load_json_list(ws / "source_map_exposures.json"))
    return n


def load_scan_status(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


_LINE_CACHE: Dict[str, tuple] = {}


def count_lines(path: Path) -> int:
    """Count non-empty lines, cached by size+mtime so the GUI can poll cheaply."""
    try:
        st = path.stat()
    except OSError:
        return 0
    key = str(path)
    stamp = (int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))), st.st_size)
    cached = _LINE_CACHE.get(key)
    if cached and cached[0] == stamp:
        return cached[1]
    n = 0
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                n += chunk.count(b"\n")
    except OSError:
        return 0
    _LINE_CACHE[key] = (stamp, n)
    return n


def default_output_dir(domain: str) -> Path:
    safe = (domain or "target").replace(".", "_")
    env = (os.environ.get("RECONPIPE_WORKDIR") or "").strip()
    root = Path(env) if env else HERE
    return root / f"recon_{safe}"


APK_SUFFIXES = (".apk", ".xapk", ".apkm")
IPA_SUFFIXES = (".ipa",)


def work_root() -> Path:
    env = (os.environ.get("RECONPIPE_WORKDIR") or "").strip()
    return Path(env) if env else HERE


def running_in_docker() -> bool:
    if (os.environ.get("RECONPIPE_WORKDIR") or "").strip():
        return True
    try:
        return Path("/.dockerenv").exists()
    except OSError:
        return False


def classify_mobile_path(raw: str) -> str:
    path = (raw or "").strip().strip('"').strip("'")
    low = path.lower()
    if low.endswith(IPA_SUFFIXES):
        return "ipa"
    if low.endswith(APK_SUFFIXES):
        return "apk"
    return ""


def parse_mobile_paths(text: str) -> Tuple[List[str], List[str]]:
    apk: List[str] = []
    ipa: List[str] = []
    for ln in (text or "").splitlines():
        raw = ln.strip().strip('"').strip("'")
        if not raw:
            continue
        kind = classify_mobile_path(raw)
        if kind == "apk":
            apk.append(raw)
        elif kind == "ipa":
            ipa.append(raw)
    return apk, ipa


def split_mobile_file_list(paths: List[str]) -> Tuple[List[str], List[str]]:
    apk: List[str] = []
    ipa: List[str] = []
    for raw in paths or []:
        kind = classify_mobile_path(raw)
        if kind == "apk":
            apk.append(raw.strip().strip('"').strip("'"))
        elif kind == "ipa":
            ipa.append(raw.strip().strip('"').strip("'"))
    return apk, ipa


def sanitize_upload_name(name: str) -> str:
    base = Path(name or "app.bin").name
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", base).strip("._") or "app.bin"
    return cleaned[:180]


def upload_event_name(e: Any) -> str:
    """Filename from NiceGUI 2 (e.name) or 3 (e.file.name)."""
    file_obj = getattr(e, "file", None)
    raw = getattr(file_obj, "name", None) or getattr(e, "name", None) or ""
    return str(raw).strip()


async def read_upload_bytes(e: Any) -> bytes:
    """File bytes from NiceGUI 2 (e.content) or 3 (await e.file.read())."""
    file_obj = getattr(e, "file", None)
    if file_obj is not None:
        read = getattr(file_obj, "read", None)
        if callable(read):
            data = read()
            if inspect.isawaitable(data):
                data = await data
            return data or b""
    content = getattr(e, "content", None)
    if content is not None and hasattr(content, "read"):
        try:
            content.seek(0)
        except Exception:
            pass
        return content.read() or b""
    return b""


def stage_mobile_bytes(filename: str, data: bytes) -> Path:
    dest_dir = work_root() / "mobile_uploads"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sanitize_upload_name(filename)
    dest.write_bytes(data or b"")
    return dest


def mobile_path_missing_hint(path: str) -> str:
    msg = f"App package not found: {path}"
    if running_in_docker():
        msg += (
            " — this GUI is in Docker and cannot see host paths. "
            "Upload the file on the Apps tab, or copy it into scans/ and use /work/<filename>."
        )
    return msg


def fmt_bytes(n: int) -> str:
    """Human size for the CPU/RAM meter (1024-based)."""
    n = max(0, int(n or 0))
    for unit, size in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            val = n / size
            return f"{val:.1f} {unit}" if val < 10 else f"{val:.0f} {unit}"
    return f"{n} B"


def parse_proc_stat_cpu_ticks(line: str) -> int:
    """utime+stime from a /proc/<pid>/stat line (field 14+15)."""
    rpar = (line or "").rfind(")")
    if rpar < 0:
        return 0
    fields = line[rpar + 1 :].split()
    if len(fields) < 13:
        return 0
    try:
        return int(fields[11]) + int(fields[12])
    except (TypeError, ValueError):
        return 0


def parse_status_vmrss_bytes(text: str) -> int:
    for raw in (text or "").splitlines():
        if raw.startswith("VmRSS:"):
            parts = raw.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1]) * 1024
                except ValueError:
                    return 0
    return 0


def parse_meminfo_bytes(text: str) -> tuple:
    """Return (MemTotal, MemAvailable) in bytes from /proc/meminfo."""
    total = 0
    avail = 0
    for raw in (text or "").splitlines():
        if raw.startswith("MemTotal:"):
            parts = raw.split()
            if len(parts) >= 2:
                total = int(parts[1]) * 1024
        elif raw.startswith("MemAvailable:"):
            parts = raw.split()
            if len(parts) >= 2:
                avail = int(parts[1]) * 1024
    return total, avail


def usage_html(snap: Dict[str, Any]) -> str:
    cpu = float(snap.get("cpu_pct") or 0.0)
    rss = int(snap.get("rss_bytes") or 0)
    total = int(snap.get("host_total") or 0)
    cpu_w = max(0, min(100, int(round(cpu))))
    ram_w = 0
    if total > 0:
        ram_w = max(0, min(100, int(round(rss / total * 100.0))))
    ram = fmt_bytes(rss)
    if total:
        ram = f"{ram} / {fmt_bytes(total)}"
    cpu_cls = "hot" if cpu >= 85 else "ok"
    ram_cls = "hot" if ram_w >= 85 else "ok"
    pids = int(snap.get("pids") or 0)
    return (
        f'<div class="rp-usage" title="ReconPipe GUI + scan tools ({pids} processes)">'
        f'<div class="rp-usage-item"><span class="k">CPU</span>'
        f'<span class="bar"><span class="{cpu_cls}" style="width:{cpu_w}%"></span></span>'
        f'<span class="v">{cpu:.0f}%</span></div>'
        f'<div class="rp-usage-item"><span class="k">RAM</span>'
        f'<span class="bar"><span class="{ram_cls}" style="width:{ram_w}%"></span></span>'
        f'<span class="v">{ram}</span></div></div>'
    )


class ResourceMonitor:
    """CPU % of the machine and RSS for this GUI + the scan process tree."""

    _PID_CAP = 400

    def __init__(self) -> None:
        self._prev_t = 0.0
        self._prev_cpu = 0.0
        self._ncpu = max(1, os.cpu_count() or 1)
        self._clk = 100.0
        try:
            self._clk = float(os.sysconf("SC_CLK_TCK")) or 100.0
        except (AttributeError, ValueError, OSError):
            pass
        self._linux = Path("/proc/self/stat").is_file()
        self._win = os.name == "nt"

    def snapshot(self, extra_pid: Optional[int] = None) -> Dict[str, Any]:
        pids = self._tree_pids(os.getpid())
        if extra_pid:
            try:
                pids.update(self._tree_pids(int(extra_pid)))
            except (TypeError, ValueError):
                pass
        cpu_sec = 0.0
        rss = 0
        for pid in pids:
            cpu_sec += self._cpu_seconds(pid)
            rss += self._rss_bytes(pid)
        now = time.monotonic()
        cpu_pct = 0.0
        if self._prev_t and now > self._prev_t:
            dcpu = max(0.0, cpu_sec - self._prev_cpu)
            cpu_pct = (dcpu / (now - self._prev_t)) / self._ncpu * 100.0
            cpu_pct = max(0.0, min(100.0, cpu_pct))
        self._prev_t = now
        self._prev_cpu = cpu_sec
        host_total, host_avail = self._host_ram()
        return {
            "cpu_pct": cpu_pct,
            "rss_bytes": rss,
            "host_total": host_total,
            "host_avail": host_avail,
            "pids": len(pids),
        }

    def _tree_pids(self, root: int) -> Set[int]:
        found: Set[int] = set()
        if root <= 0:
            return found
        stack = [root]
        while stack and len(found) < self._PID_CAP:
            pid = stack.pop()
            if pid in found:
                continue
            found.add(pid)
            for child in self._children(pid):
                if child not in found:
                    stack.append(child)
        return found

    def _children(self, pid: int) -> List[int]:
        if self._linux:
            return self._linux_children(pid)
        if self._win:
            return self._win_children(pid)
        return []

    def _linux_children(self, pid: int) -> List[int]:
        kids: List[int] = []
        task = Path(f"/proc/{pid}/task")
        try:
            for tid_dir in task.iterdir():
                try:
                    text = (tid_dir / "children").read_text(encoding="ascii", errors="ignore")
                except OSError:
                    continue
                for tok in text.split():
                    try:
                        kids.append(int(tok))
                    except ValueError:
                        pass
        except OSError:
            pass
        return kids

    def _win_children(self, pid: int) -> List[int]:
        try:
            import ctypes
            from ctypes import wintypes
        except Exception:
            return []
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        k32 = ctypes.windll.kernel32
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == -1 or snap == 0xFFFFFFFF:
            return []
        kids: List[int] = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not k32.Process32FirstW(snap, ctypes.byref(entry)):
                return []
            while True:
                if int(entry.th32ParentProcessID) == int(pid):
                    kids.append(int(entry.th32ProcessID))
                if not k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        finally:
            k32.CloseHandle(snap)
        return kids

    def _cpu_seconds(self, pid: int) -> float:
        if self._linux:
            try:
                line = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return 0.0
            return parse_proc_stat_cpu_ticks(line) / self._clk
        if self._win:
            return self._win_cpu_seconds(pid)
        return 0.0

    def _rss_bytes(self, pid: int) -> int:
        if self._linux:
            try:
                text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return 0
            return parse_status_vmrss_bytes(text)
        if self._win:
            return self._win_rss_bytes(pid)
        return 0

    def _host_ram(self) -> tuple:
        if self._linux:
            try:
                text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return 0, 0
            return parse_meminfo_bytes(text)
        if self._win:
            return self._win_host_ram()
        return 0, 0

    def _win_cpu_seconds(self, pid: int) -> float:
        try:
            import ctypes
            from ctypes import wintypes
        except Exception:
            return 0.0
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return 0.0
        create = wintypes.FILETIME()
        exit_t = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        try:
            if not k32.GetProcessTimes(
                handle,
                ctypes.byref(create),
                ctypes.byref(exit_t),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return 0.0
            def _sec(ft: Any) -> float:
                val = (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)
                return val / 10_000_000.0
            return _sec(kernel) + _sec(user)
        finally:
            k32.CloseHandle(handle)

    def _win_rss_bytes(self, pid: int) -> int:
        try:
            import ctypes
            from ctypes import wintypes
        except Exception:
            return 0
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        k32 = ctypes.windll.kernel32

        class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            return 0
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        try:
            psapi = ctypes.windll.psapi
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        except Exception:
            return 0
        finally:
            k32.CloseHandle(handle)
        return 0

    def _win_host_ram(self) -> tuple:
        try:
            import ctypes
            from ctypes import wintypes
        except Exception:
            return 0, 0

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]

        info = MEMORYSTATUSEX()
        info.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
            return 0, 0
        return int(info.ullTotalPhys), int(info.ullAvailPhys)


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
    names = [name for _, name in hits]
    refined = rp.refine_secret_type(names[0] if names else "", text)
    if refined:
        names = [refined] + [n for n in names if n != refined]
    return names


def validator_type_options() -> List[str]:
    return sorted(rp.VALIDATORS.keys())


def validate_form(opts: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    domain = (opts.get("domain") or "").strip()
    domain_list = (opts.get("domain_list") or "").strip()
    if not domain and not domain_list:
        errors.append("Target domain is required.")
    elif domain and not DOMAIN_RE.match(domain):
        errors.append(f"Invalid domain syntax: {domain}")

    for label, key in (
        ("Subdomains file", "subdomains"),
        ("URL list", "files"),
        ("Domain list", "domain_list"),
        ("Exclude patterns", "exclude_pattern"),
        ("Include patterns", "include_pattern"),
    ):
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

    for key, label in (("apk", "APK"), ("ipa", "IPA")):
        for raw in opts.get(key) or []:
            path = str(raw or "").strip()
            if not path:
                continue
            if not Path(path).expanduser().is_file():
                errors.append(mobile_path_missing_hint(path))

    return errors

# Pipeline worker

class PipelineRunner:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.log_q: "queue.Queue[str]" = queue.Queue(maxsize=400)
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
            domain = (opts.get("domain") or "").strip() or "multi"
            out = (opts.get("output") or "").strip()
            work = Path(os.environ.get("RECONPIPE_WORKDIR") or HERE)
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
            
            env.setdefault("PYTHONIOENCODING", "utf-8")

            self.proc = subprocess.Popen(
                cmd,
                cwd=str(work),
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

    def _offer_log(self, line: str) -> None:
        text = strip_ansi((line or "").rstrip("\n"))
        if not rp.console_keep_line(text):
            return
        try:
            self.log_q.put_nowait(text)
        except queue.Full:
            return

    def _reader(self) -> None:
        assert self.proc is not None
        try:
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self._offer_log(line)
        except Exception as exc:
            self._offer_log(f"[gui] Log reader error: {exc}")
        finally:
            code = self.proc.wait()
            self.exit_code = code
            self.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.running = False
            self._offer_log(f"[gui] Pipeline finished with exit code {code}")

    def stop(self) -> None:
        with self._lock:
            if not self.proc or not self.running:
                return
            self._offer_log("[gui] Stopping pipeline…")
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
        while len(lines) < 20:
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
        self.filter_severity: str = "All"
        self.filter_company: str = "All"
        self.filter_file: str = ""
        self.scan_queue: List[str] = []
        self.mobile_paths: List[str] = []
        self.dark_on: bool = True
        self.preview_artifact: str = ""
        self.llm_widgets: Dict[str, Any] = {}


STATE = GuiState()


def _widget_text(widget: Any) -> str:
    if widget is None:
        return ""
    return str(getattr(widget, "value", "") or "").strip()


def llm_scan_opts() -> Dict[str, Any]:
    """Flags for the next scan, from the Settings widgets or saved disk config."""
    w = STATE.llm_widgets
    if w:
        enabled = bool(w["enabled"].value)
        auto = bool(w["auto"].value)
        provider = str(w["provider"].value or "ollama")
        return {
            "llm": enabled and auto,
            "skip_llm": not (enabled and auto),
            "llm_provider": provider,
            "llm_model": _widget_text(w.get("model")),
            "llm_base_url": _widget_text(w.get("base_url")),
            "llm_key": _widget_text(w.get("api_key")),
            "llm_timeout": int(w["timeout"].value or 120),
            "llm_max_findings": int(w["max_findings"].value or 40),
        }
    saved = rp.rp_llm.load_app_settings()
    on = bool(saved.get("enabled") and saved.get("auto"))
    return {
        "llm": on,
        "skip_llm": not on,
        "llm_provider": saved.get("provider"),
        "llm_model": saved.get("model"),
        "llm_base_url": saved.get("base_url"),
        "llm_key": rp.rp_llm.load_llm_key() or None,
        "llm_timeout": saved.get("timeout"),
        "llm_max_findings": saved.get("max_findings"),
    }


def llm_args_from_opts(opts: Optional[Dict[str, Any]] = None) -> Any:
    opts = opts or llm_scan_opts()

    class _Args:
        pass

    args = _Args()
    args.llm = True
    args.skip_llm = False
    args.ci = False
    args.llm_provider = opts.get("llm_provider") or "ollama"
    args.llm_model = opts.get("llm_model") or ""
    args.llm_base_url = opts.get("llm_base_url") or ""
    args.llm_key = opts.get("llm_key") or rp.rp_llm.load_llm_key()
    args.llm_timeout = opts.get("llm_timeout") or 120
    args.llm_max_findings = opts.get("llm_max_findings") or 40
    return rp.rp_llm.apply_llm_settings(args)


# Build UI
def build_ui() -> None:
    saved_ui = rp.rp_llm.load_app_settings()
    STATE.dark_on = bool(saved_ui.get("dark", True))
    dark_mode = ui.dark_mode()
    if STATE.dark_on:
        dark_mode.enable()
    else:
        dark_mode.disable()
    ui.colors(
        primary="#e8620a",
        secondary="#5b6673",
        accent="#e8620a",
        dark="#0d1117",
        positive="#2ea043",
        negative="#e5484d",
        warning="#d29922",
        info="#58a6ff",
    )
    ui.add_head_html(
        """
        <style>
          /* ---- Dark theme (default)  */
          :root {
            --rp-bg: #0d1117;
            --rp-bg-2: #10151c;
            --rp-panel: #161b22;
            --rp-panel-2: #1b212b;
            --rp-border: #2a313c;
            --rp-border-soft: #20262f;
            --rp-orange: #f0781f;
            --rp-orange-soft: rgba(240,120,31,0.12);
            --rp-text: #c9d1d9;
            --rp-text-strong: #f0f3f6;
            --rp-muted: #8b949e;
            --rp-green: #3fb950;
            --rp-red: #f85149;
            --rp-amber: #d29922;
            --rp-input-bg: #0f141b;
            --rp-shadow: 0 1px 2px rgba(0,0,0,0.45), 0 4px 14px rgba(0,0,0,0.30);
            --rp-radius: 10px;
            --rp-radius-sm: 7px;
          }
          /* ---- Light theme (Dark/Light toggle)  */
          body.body--light {
            --rp-bg: #f3f4f6;
            --rp-bg-2: #eceef1;
            --rp-panel: #ffffff;
            --rp-panel-2: #f4f6f8;
            --rp-border: #dde1e6;
            --rp-border-soft: #e7eaee;
            --rp-orange: #d95b00;
            --rp-orange-soft: rgba(217,91,0,0.10);
            --rp-text: #313a45;
            --rp-text-strong: #10151b;
            --rp-muted: #6b7683;
            --rp-green: #1a7f37;
            --rp-red: #cf222e;
            --rp-amber: #9a6700;
            --rp-input-bg: #ffffff;
            --rp-shadow: 0 1px 2px rgba(140,149,159,0.16), 0 3px 12px rgba(140,149,159,0.12);
          }
          html, body, .q-layout, .q-page, .nicegui-content {
            background: var(--rp-bg) !important;
            color: var(--rp-text) !important;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
            -webkit-font-smoothing: antialiased;
          }
          ::selection { background: var(--rp-orange-soft); }
          /* Thin, refined scrollbars for a polished feel. */
          * { scrollbar-width: thin; scrollbar-color: var(--rp-border) transparent; }
          ::-webkit-scrollbar { width: 10px; height: 10px; }
          ::-webkit-scrollbar-track { background: transparent; }
          ::-webkit-scrollbar-thumb {
            background: var(--rp-border); border-radius: 10px;
            border: 2px solid transparent; background-clip: padding-box;
          }
          ::-webkit-scrollbar-thumb:hover { background: var(--rp-muted); }

          .q-header {
            background: var(--rp-panel) !important;
            border-bottom: 1px solid var(--rp-border) !important;
            box-shadow: var(--rp-shadow) !important;
            min-height: 52px;
            backdrop-filter: saturate(1.1);
          }
          .q-tabs {
            background: transparent;
            border-bottom: 1px solid var(--rp-border);
            padding: 0 6px;
          }
          .q-tab {
            text-transform: none !important;
            font-size: 13px !important; font-weight: 600;
            color: var(--rp-muted) !important;
            min-height: 42px; border-radius: var(--rp-radius-sm) var(--rp-radius-sm) 0 0;
            transition: color .15s ease, background .15s ease;
          }
          .q-tab:hover { color: var(--rp-text) !important; background: var(--rp-orange-soft); }
          .q-tab--active { color: var(--rp-text-strong) !important; }
          .q-tab__indicator { background: var(--rp-orange) !important; height: 2.5px !important; border-radius: 3px; }

          .q-card, .rp-card {
            background: var(--rp-panel) !important;
            border: 1px solid var(--rp-border) !important;
            border-radius: var(--rp-radius) !important;
            box-shadow: var(--rp-shadow) !important;
            transition: border-color .15s ease;
          }
          .rp-card { padding: 16px !important; }
          .q-field--outlined .q-field__control {
            border-radius: var(--rp-radius-sm) !important;
            background: var(--rp-input-bg) !important;
          }
          .q-field--outlined .q-field__control:before { border-color: var(--rp-border) !important; }
          .q-field--outlined.q-field--focused .q-field__control:after {
            border-color: var(--rp-orange) !important;
          }
          .q-btn {
            border-radius: var(--rp-radius-sm) !important;
            font-weight: 600; letter-spacing: 0.01em; text-transform: none;
            transition: transform .08s ease, box-shadow .15s ease, background .15s ease;
          }
          .q-btn:active { transform: translateY(1px); }
          .q-btn.q-btn--unelevated { box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
          .q-btn.q-btn--unelevated:hover { box-shadow: var(--rp-shadow); }

          .rp-console {
            font-family: "Cascadia Code", Consolas, "Lucida Console", ui-monospace, monospace;
            font-size: 12.5px; line-height: 1.5;
            background: #0a0d12; color: #8fd67a;
            border: 1px solid var(--rp-border);
            border-radius: var(--rp-radius-sm);
            padding: 12px 14px; height: 460px; overflow: auto; white-space: pre-wrap;
            contain: content;
          }
          .rp-title {
            font-weight: 700; letter-spacing: 0.02em; font-size: 17px;
            color: var(--rp-text-strong);
          }
          .rp-brand-mark {
            width: 22px; height: 22px; border-radius: 6px;
            background: linear-gradient(135deg, var(--rp-orange), #b8410a);
            display: inline-flex; align-items: center; justify-content: center;
            margin-right: 12px; box-shadow: 0 0 0 1px rgba(240,120,31,0.25), 0 2px 6px rgba(0,0,0,0.4);
          }
          .rp-brand-mark::after { content: "\\1F511"; font-size: 12px; line-height: 1; }
          .rp-section {
            font-size: 11px; font-weight: 700; letter-spacing: 0.12em;
            text-transform: uppercase; color: var(--rp-orange);
            border-bottom: 1px solid var(--rp-border); padding-bottom: 8px; margin-bottom: 12px;
          }
          .rp-badge-ok { color: var(--rp-green); font-weight: 700; }
          .rp-badge-miss { color: var(--rp-amber); font-weight: 700; }
          .rp-secret {
            font-family: Consolas, ui-monospace, monospace;
            background: var(--rp-panel-2); padding: 1px 6px; border-radius: 4px;
          }
          .rp-status-dot {
            width: 9px; height: 9px; border-radius: 50%; display: inline-block;
            background: var(--rp-muted); margin-right: 9px;
          }
          .rp-status-dot.live { background: var(--rp-green); box-shadow: 0 0 8px var(--rp-green); }
          .rp-status-dot.run {
            background: var(--rp-orange); box-shadow: 0 0 8px var(--rp-orange);
            animation: rp-pulse 1.3s ease-in-out infinite;
          }
          .rp-status-dot.dead { background: var(--rp-red); }
          @keyframes rp-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
          .rp-stat-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(88px, 1fr)); gap: 10px; margin-top: 12px;
          }
          .rp-stat {
            background: var(--rp-panel-2); border: 1px solid var(--rp-border-soft);
            border-radius: var(--rp-radius-sm); padding: 10px 12px; text-align: center;
          }
          .rp-stat .k { font-size: 10px; color: var(--rp-muted); letter-spacing: 0.12em; text-transform: uppercase; }
          .rp-stat .v { font-size: 20px; font-weight: 700; color: var(--rp-text-strong); font-family: Consolas, monospace; margin-top: 2px; }
          .rp-footer {
            background: var(--rp-panel) !important; border-top: 1px solid var(--rp-border) !important;
            color: var(--rp-muted); font-size: 11.5px; min-height: 30px;
          }
          .rp-verdict {
            font-family: Consolas, monospace; font-size: 18px; font-weight: 700;
            letter-spacing: 0.12em; padding: 14px 16px; border: 1px solid var(--rp-border);
            border-radius: var(--rp-radius-sm); background: var(--rp-panel-2);
            color: var(--rp-muted);
          }
          .rp-verdict.live { color: var(--rp-green); border-color: rgba(63,185,80,0.4); background: rgba(63,185,80,0.08); }
          .rp-verdict.dead { color: var(--rp-red); border-color: rgba(248,81,73,0.4); background: rgba(248,81,73,0.07); }
          .rp-verdict.skip { color: var(--rp-amber); border-color: rgba(210,153,34,0.4); background: rgba(210,153,34,0.07); }
          .rp-header-meta {
            font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase;
            color: var(--rp-muted); margin-left: 14px;
          }
          .rp-chip {
            font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
            text-transform: uppercase; padding: 3px 9px; border-radius: 999px;
            border: 1px solid var(--rp-border); color: var(--rp-text);
          }
          .rp-chip.on { color: var(--rp-green); border-color: rgba(63,185,80,0.45); background: rgba(63,185,80,0.08); }
          .rp-chip.off { color: var(--rp-muted); }
          .rp-ver-chip {
            font-family: Consolas, monospace; font-size: 10.5px; color: var(--rp-muted);
            border: 1px solid var(--rp-border); border-radius: 999px; padding: 2px 9px;
          }
          .rp-usage {
            display: flex; align-items: center; gap: 14px;
            font-family: Consolas, ui-monospace, monospace;
          }
          .rp-usage-item { display: flex; align-items: center; gap: 7px; }
          .rp-usage .k {
            font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase;
            color: var(--rp-muted); font-weight: 700;
          }
          .rp-usage .v {
            font-size: 11.5px; color: var(--rp-text-strong); white-space: nowrap;
          }
          .rp-usage .bar {
            width: 52px; height: 6px; border-radius: 99px;
            background: var(--rp-border); overflow: hidden; display: inline-block;
          }
          .rp-usage .bar > span { display: block; height: 100%; width: 0; background: var(--rp-orange); }
          .rp-usage .bar > span.hot { background: var(--rp-red); }
          .rp-subcard {
            background: var(--rp-panel-2) !important;
            border: 1px solid var(--rp-border-soft) !important;
            border-radius: var(--rp-radius-sm) !important;
            box-shadow: none !important;
            transition: border-color .15s ease;
          }
          .rp-subcard:hover { border-color: var(--rp-orange) !important; }
          .rp-opt-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
            gap: 2px 10px;
            width: 100%;
          }
          .rp-expansion {
            width: 100%;
            border: 1px solid var(--rp-border-soft) !important;
            border-radius: var(--rp-radius-sm) !important;
            background: var(--rp-panel-2) !important;
            margin: 0 0 8px 0;
          }
          .rp-expansion .q-expansion-item__container {
            border-radius: var(--rp-radius-sm);
          }
          .rp-expansion .q-item {
            min-height: 40px;
            padding: 6px 12px;
          }
          .rp-expansion .q-item__label { font-weight: 650; font-size: 13px; color: var(--rp-text-strong); }
          .rp-expansion .q-expansion-item__content { padding: 4px 12px 12px 12px; }
          .rp-hint { font-size: 11.5px; color: var(--rp-muted); margin: 0 0 8px 0; }
          .rp-gl-table td code { font-size: 12px; }
          .body--dark .rp-secret-pill { background: #7f1d1d; color: #fecaca; }
          .body--dark .rp-secret-pill.live { background: #14532d; color: #bbf7d0; }
        </style>
        """
    )

    with ui.header().classes("items-center justify-between px-4 no-wrap"):
        with ui.row().classes("items-center no-wrap"):
            ui.element("span").classes("rp-brand-mark")
            ui.label("ReconPipe").classes("rp-title")
        with ui.row().classes("items-center gap-3"):
            usage_html_el = ui.html(
                usage_html({"cpu_pct": 0, "rss_bytes": 0, "host_total": 0, "pids": 1}),
                sanitize=False,
            )
            def toggle_dark() -> None:
                STATE.dark_on = not STATE.dark_on
                if STATE.dark_on:
                    dark_mode.enable()
                else:
                    dark_mode.disable()

            ui.button(
                "Dark/Light", on_click=toggle_dark, color="secondary", icon="dark_mode"
            ).props("flat dense")
            ui.label("v1.3").classes("rp-ver-chip")

    with ui.tabs().classes("w-full") as tabs:
        tab_scan = ui.tab("Scan")
        tab_apps = ui.tab("Apps")
        tab_console = ui.tab("Console")
        tab_findings = ui.tab("Findings")
        tab_vendors = ui.tab("Vendors")
        tab_tester = ui.tab("Key Tester")
        tab_artifacts = ui.tab("Artifacts")
        tab_history = ui.tab("History")
        tab_settings = ui.tab("Settings")

    scan_actions: Dict[str, Any] = {}
    mobile_package_fields: List[Any] = []

    with ui.tab_panels(tabs, value=tab_scan).classes("w-full px-4 pt-4 pb-12"):
        # Scan 
        with ui.tab_panel(tab_scan):
            with ui.row().classes("w-full gap-3 items-stretch"):
                with ui.column().classes("w-full lg:w-7/12 gap-3"):
                    with ui.card().classes("w-full rp-card"):
                        ui.label("Target & I/O").classes("rp-section")
                        with ui.row().classes("w-full gap-2 items-end"):
                            target_select = ui.select(
                                [],
                                label="Saved targets",
                            ).classes("flex-1").props("dense outlined")
                            targets_hint = ui.label("").classes(
                                "text-xs text-slate-500"
                            )

                        def refresh_target_select() -> None:
                            rows = rp.list_saved_targets()
                            names = [r.get("name") or r.get("domain") or "" for r in rows]
                            names = [n for n in names if n]
                            target_select.options = names
                            target_select.update()
                            n = len(names)
                            targets_hint.set_text(
                                f"{n} saved · lists in {rp.user_data_dir() / 'lists'}"
                                if n
                                else f"Save a target to rescan without re-crawling"
                            )

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
                        domain_list_in = ui.input(
                            "Domain list (--domain-list)",
                            placeholder="/path/to/domains.txt",
                        ).classes("w-full").props("outlined dense")
                        with ui.row().classes("w-full gap-2"):
                            include_in = ui.input(
                                "Include hosts (--include-pattern)",
                                placeholder="*.api.example.com file",
                            ).classes("flex-1").props("outlined dense")
                            exclude_in = ui.input(
                                "Exclude hosts (--exclude-pattern)",
                                placeholder="*.cdn.example.com file",
                            ).classes("flex-1").props("outlined dense")

                        with ui.expansion(
                            "Advanced target (Shopify, Vault, notify, config)",
                            icon="tune",
                        ).classes("rp-expansion"):
                            shopify_in = ui.input(
                                "Shopify store host (--shopify-domain)",
                                placeholder="store.myshopify.com",
                            ).classes("w-full").props("outlined dense")
                            with ui.row().classes("w-full gap-2"):
                                vault_in = ui.input(
                                    "Vault address (--vault-addr)",
                                    placeholder="https://vault.example.com",
                                ).classes("flex-1").props("outlined dense")
                                grafana_in = ui.input(
                                    "Grafana host (--grafana-url)",
                                    placeholder="grafana.example.com",
                                ).classes("flex-1").props("outlined dense")
                            n8n_in = ui.input(
                                "n8n instance (--n8n-url)",
                                placeholder="https://tenant.app.n8n.cloud",
                            ).classes("w-full").props("outlined dense")
                            webhook_in = ui.input(
                                "Notify webhook (--notify-webhook)",
                                placeholder="Slack/Discord/custom URL",
                            ).classes("w-full").props("outlined dense")
                            config_in = ui.textarea(
                                "Config overlays (--config, one path per line)",
                                placeholder="engagement.example.yaml",
                            ).classes("w-full").props("outlined dense")
                            ignore_in = ui.textarea(
                                "Ignore hashes (--ignore-hash, one SHA256 per line)",
                                placeholder="paste finding hashes to suppress",
                            ).classes("w-full").props("outlined dense")

                        def apply_target(row: Dict[str, Any]) -> None:
                            domain_in.set_value(row.get("domain") or "")
                            files_in.set_value(row.get("files") or "")
                            sub_in.set_value(row.get("subdomains") or "")
                            out_in.set_value(row.get("output") or "")

                        def load_selected_target() -> None:
                            name = (target_select.value or "").strip()
                            row = next(
                                (r for r in rp.list_saved_targets() if r.get("name") == name),
                                None,
                            )
                            if not row:
                                ui.notify("Select a saved target", type="warning")
                                return
                            apply_target(row)
                            ui.notify(f"Loaded {name}", type="positive")

                        def save_current_target() -> None:
                            domain = (domain_in.value or "").strip()
                            if not domain:
                                ui.notify("Enter a domain first", type="warning")
                                return
                            try:
                                rp.upsert_saved_target(
                                    {
                                        "name": domain,
                                        "domain": domain,
                                        "files": (files_in.value or "").strip(),
                                        "subdomains": (sub_in.value or "").strip(),
                                        "output": (out_in.value or "").strip(),
                                    }
                                )
                            except Exception as exc:
                                ui.notify(str(exc), type="negative")
                                return
                            refresh_target_select()
                            target_select.set_value(domain)
                            ui.notify(f"Saved target {domain}", type="positive")

                        def delete_selected_target() -> None:
                            name = (target_select.value or "").strip()
                            if not name:
                                ui.notify("Select a saved target", type="warning")
                                return
                            rp.delete_saved_target(name)
                            refresh_target_select()
                            target_select.set_value(None)
                            ui.notify(f"Deleted {name}", type="warning")

                        with ui.row().classes("w-full gap-2"):
                            ui.button(
                                "Load target", on_click=load_selected_target, color="secondary"
                            ).props("outline dense")
                            ui.button(
                                "Save target", on_click=save_current_target, color="primary"
                            ).props("unelevated dense")
                            ui.button(
                                "Rescan", on_click=lambda: rescan_saved_target(), color="primary"
                            ).props("unelevated dense")
                            ui.button(
                                "Delete", on_click=delete_selected_target, color="negative"
                            ).props("flat dense")
                        refresh_target_select()
                        build_ui.refresh_targets = refresh_target_select  

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Passive intel").classes("rp-section")
                        ui.label(
                            "Saved to ~/.reconpipe/keys.yaml so you do not re-enter them. "
                            "That file stays on this machine (chmod 600)."
                        ).classes("rp-hint")
                        chaos_in = ui.input(
                            "Chaos API key (--chaos-key)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or set CHAOS_KEY / PDCP_API_KEY in env",
                        ).classes("w-full").props("outlined dense")
                        shodan_in = ui.input(
                            "Shodan API key (--shodan-key)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or SHODAN_API_KEY",
                        ).classes("w-full").props("outlined dense")
                        with ui.row().classes("w-full gap-2"):
                            censys_id_in = ui.input(
                                "Censys API ID (--censys-id)",
                                placeholder="or CENSYS_API_ID",
                            ).classes("flex-1").props("outlined dense")
                            censys_secret_in = ui.input(
                                "Censys API secret (--censys-secret)",
                                password=True,
                                password_toggle_button=True,
                                placeholder="or CENSYS_API_SECRET",
                            ).classes("flex-1").props("outlined dense")
                        zoomeye_in = ui.input(
                            "ZoomEye API key (--zoomeye-key)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or ZOOMEYE_API_KEY",
                        ).classes("w-full").props("outlined dense")
                        github_token_in = ui.input(
                            "GitHub token (--github-token)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or GITHUB_TOKEN (code search)",
                        ).classes("w-full").props("outlined dense")
                        gitlab_token_in = ui.input(
                            "GitLab token (--gitlab-token)",
                            password=True,
                            password_toggle_button=True,
                            placeholder="or GITLAB_TOKEN",
                        ).classes("w-full").props("outlined dense")
                        with ui.row().classes("w-full flex-wrap gap-4"):
                            skip_intel = ui.checkbox("Skip all intel (--skip-intel)")
                            skip_crtsh = ui.checkbox("Skip crt.sh (--skip-crtsh)")
                        keys_hint = ui.label("").classes("text-xs text-slate-500")

                        def fill_saved_keys() -> None:
                            saved = rp.load_user_keys()
                            if saved.get("chaos"):
                                chaos_in.set_value(saved["chaos"])
                            if saved.get("shodan"):
                                shodan_in.set_value(saved["shodan"])
                            if saved.get("censys_id"):
                                censys_id_in.set_value(saved["censys_id"])
                            if saved.get("censys_secret"):
                                censys_secret_in.set_value(saved["censys_secret"])
                            if saved.get("zoomeye"):
                                zoomeye_in.set_value(saved["zoomeye"])
                            if saved.get("github"):
                                github_token_in.set_value(saved["github"])
                            if saved.get("gitlab"):
                                gitlab_token_in.set_value(saved["gitlab"])
                            if saved.get("notify_webhook"):
                                webhook_in.set_value(saved["notify_webhook"])
                            n = sum(1 for ok in rp.saved_keys_status().values() if ok)
                            keys_hint.set_text(
                                f"{n} key(s) on disk · {rp.user_data_dir() / 'keys.yaml'}"
                                if n
                                else "No keys saved yet"
                            )

                        def save_intel_keys() -> None:
                            path = rp.save_user_keys(
                                {
                                    "chaos": (chaos_in.value or "").strip(),
                                    "shodan": (shodan_in.value or "").strip(),
                                    "censys_id": (censys_id_in.value or "").strip(),
                                    "censys_secret": (censys_secret_in.value or "").strip(),
                                    "zoomeye": (zoomeye_in.value or "").strip(),
                                    "github": (github_token_in.value or "").strip(),
                                    "gitlab": (gitlab_token_in.value or "").strip(),
                                    "notify_webhook": (webhook_in.value or "").strip(),
                                }
                            )
                            fill_saved_keys()
                            ui.notify(f"Saved API keys to {path}", type="positive")

                        with ui.row().classes("w-full gap-2"):
                            ui.button(
                                "Save API keys", on_click=save_intel_keys, color="primary"
                            ).props("unelevated dense")
                            ui.button(
                                "Reload saved keys", on_click=fill_saved_keys, color="secondary"
                            ).props("outline dense")
                        fill_saved_keys()

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Pipeline options").classes("rp-section")
                        ui.label(
                            "Common skips are grouped. Open a section only when you need it."
                        ).classes("rp-hint")

                        with ui.expansion("Discovery", icon="travel_explore", value=True).classes(
                            "rp-expansion"
                        ):
                            ui.label("Subdomains, live hosts, and URL collection.").classes("rp-hint")
                            with ui.element("div").classes("rp-opt-grid"):
                                skip_chaos = ui.checkbox("Skip Chaos (--skip-chaos)")
                                skip_subfinder = ui.checkbox("Skip subfinder (--skip-subfinder)")
                                skip_amass = ui.checkbox("Skip amass (--skip-amass)")
                                skip_httpx = ui.checkbox("Skip httpx (--skip-httpx)")
                                skip_gau = ui.checkbox("Skip passive archives (--skip-gau)")
                                skip_discovery = ui.checkbox(
                                    "Skip all URL discovery (--skip-discovery)"
                                )
                                skip_wayback = ui.checkbox(
                                    "Skip Wayback bodies (--skip-wayback-bodies)"
                                )
                                skip_js_history = ui.checkbox(
                                    "Skip historical live JS (--skip-js-history)"
                                )
                                skip_sourcemaps = ui.checkbox(
                                    "Skip source map reconstruct (--skip-sourcemaps)"
                                )
                                headless = ui.checkbox("Katana headless Chrome (--headless)")
                            with ui.row().classes("w-full gap-4 mt-2"):
                                gau_in = ui.number(
                                    "gau threads", value=5, min=1, max=100
                                ).classes("w-40")
                                js_history_max_in = ui.number(
                                    "JS history versions / URL (--js-history-max)",
                                    value=15,
                                    min=1,
                                    max=200,
                                ).classes("w-64")

                        with ui.expansion("Secret engines", icon="vpn_key").classes("rp-expansion"):
                            ui.label("How secrets are detected after files are collected.").classes(
                                "rp-hint"
                            )
                            with ui.element("div").classes("rp-opt-grid"):
                                no_trufflehog = ui.checkbox(
                                    "Built-in scanner only (--no-trufflehog)"
                                )
                                skip_gitleaks = ui.checkbox("Skip Gitleaks (--skip-gitleaks)")
                                skip_jsleak = ui.checkbox("Skip jsleak (--skip-jsleak)")
                                skip_secrets_db = ui.checkbox(
                                    "Skip secrets-patterns-db (--skip-secrets-db)"
                                )
                                skip_public_apis = ui.checkbox(
                                    "Skip public-apis catalog (--skip-public-apis)"
                                )
                                no_validate = ui.checkbox("Skip validation (--no-validate)")
                            with ui.row().classes("w-full gap-4 mt-2"):
                                conc_in = ui.number(
                                    "Validation concurrency", value=10, min=1, max=200
                                ).classes("w-40")

                        with ui.expansion("Extra leak surfaces", icon="public").classes(
                            "rp-expansion"
                        ):
                            ui.label(
                                "Optional probes on top of the main crawl. APK/IPA is on the Apps tab."
                            ).classes("rp-hint")
                            with ui.element("div").classes("rp-opt-grid"):
                                skip_code_search = ui.checkbox(
                                    "Skip GitHub/GitLab code search (--skip-code-search)"
                                )
                                skip_ci_logs = ui.checkbox(
                                    "Skip public Actions / GitLab logs (--skip-ci-logs)"
                                )
                                skip_pastes = ui.checkbox(
                                    "Skip Pastebin / Gist / Ghostbin (--skip-pastes)"
                                )
                                skip_docker_hub = ui.checkbox(
                                    "Skip Docker Hub image search (--skip-docker-hub)"
                                )
                                skip_image_layers = ui.checkbox(
                                    "Skip public image layer scan (--skip-image-layers)"
                                )
                                skip_buckets = ui.checkbox(
                                    "Skip cloud bucket probe (--skip-buckets)"
                                )
                                skip_openapi = ui.checkbox(
                                    "Skip OpenAPI/Postman parse (--skip-openapi)"
                                )
                                skip_sens = ui.checkbox(
                                    "Skip leak-path probe (--skip-sensitive-paths)"
                                )
                                spray_on = ui.checkbox("Run spray leak paths (--spray)")
                                nuclei_on = ui.checkbox("Run nuclei (--nuclei)")
                            github_org_in = ui.input(
                                "GitHub org for code search and CI logs (--github-org)"
                            ).classes("w-full").props("outlined dense")
                            burp_in = ui.input(
                                "Burp XML (--burp-import)"
                            ).classes("w-full").props("outlined dense")
                            repo_in = ui.input(
                                "Git repo to clone (--repo)"
                            ).classes("w-full").props("outlined dense")
                            package_in = ui.input(
                                "Android package ids (--package)",
                                placeholder="com.example.app  (needs apkeep or gplaycli)",
                            ).classes("w-full").props("outlined dense")
                            mobile_package_fields.append(package_in)
                            creds_in = ui.input(
                                "Scan credentials YAML (--credentials)"
                            ).classes("w-full").props("outlined dense")
                            with ui.element("div").classes("rp-opt-grid"):
                                repo_shallow = ui.checkbox("Shallow git clone (--repo-shallow)")
                                ci_on = ui.checkbox("CI / local-repo mode (--ci)")

                        with ui.expansion("Runtime", icon="settings").classes("rp-expansion"):
                            ui.label("Speed, resume, proxy, and fail behavior.").classes("rp-hint")
                            with ui.element("div").classes("rp-opt-grid"):
                                resume_on = ui.checkbox("Resume previous output (--resume)")
                                polite = ui.checkbox("Polite mode (--polite)")
                                docker_fb = ui.checkbox("Docker fallback (--docker-fallback)")
                                no_fail = ui.checkbox(
                                    "Do not fail on valid keys (--no-fail-on-valid)"
                                )
                                no_notify = ui.checkbox("No desktop notify (--no-notify)")
                                no_default_scope = ui.checkbox(
                                    "Allow off-target URLs (--no-default-scope)"
                                )
                            proxy_in = ui.input(
                                "Proxy (--proxy)", placeholder="http://127.0.0.1:8080"
                            ).classes("w-full").props("outlined dense")
                            proxy_auth_in = ui.input(
                                "Proxy auth (--proxy-auth)", password=True
                            ).classes("w-full").props("outlined dense")
                            header_in = ui.textarea(
                                "Extra headers (-H), one NAME: VALUE per line"
                            ).classes("w-full").props("outlined dense")

                    with ui.card().classes("w-full rp-card"):
                        ui.label("Queue & profiles").classes("rp-section")
                        ui.label(
                            "Queue several domains, or save the current option set as a named profile."
                        ).classes("rp-hint")
                        with ui.row().classes("w-full gap-2"):
                            queue_in = ui.input("Queue domain").classes("flex-1").props("outlined dense")
                            queue_box = ui.column().classes("w-full")

                            def render_queue() -> None:
                                queue_box.clear()
                                with queue_box:
                                    if not STATE.scan_queue:
                                        ui.label("Queue empty").classes("text-xs text-slate-500")
                                        return
                                    for d in STATE.scan_queue:
                                        ui.label(d).classes("font-mono text-sm")

                            def add_queue() -> None:
                                d = (queue_in.value or "").strip()
                                if d:
                                    STATE.scan_queue.append(d)
                                    queue_in.set_value("")
                                    render_queue()

                            def run_queue() -> None:
                                if not STATE.scan_queue:
                                    ui.notify("Queue is empty", type="warning")
                                    return
                                domain = STATE.scan_queue.pop(0)
                                domain_in.set_value(domain)
                                render_queue()
                                start_scan()

                            ui.button("Add to queue", on_click=add_queue, color="secondary").props("dense outline")
                            ui.button("Run next queued", on_click=run_queue, color="primary").props("dense unelevated")
                        render_queue()
                        profile_in = ui.input("Scan profile name").classes("w-full").props("outlined dense")

                        def save_profile() -> None:
                            name = (profile_in.value or "").strip()
                            if not name:
                                ui.notify("Name the profile", type="warning")
                                return
                            path = rp.user_data_dir() / "profiles.yaml"
                            rp.save_scan_profile(path, name, collect_opts())
                            ui.notify(f"Saved profile {name}", type="positive")

                        def load_profile() -> None:
                            name = (profile_in.value or "").strip()
                            path = rp.user_data_dir() / "profiles.yaml"
                            profiles = rp.load_scan_profiles(path)
                            opts = profiles.get(name)
                            if not opts:
                                ui.notify("Profile not found", type="warning")
                                return
                            if opts.get("domain"):
                                domain_in.set_value(opts["domain"])
                            ui.notify(f"Loaded profile {name}", type="positive")

                        with ui.row().classes("gap-2"):
                            ui.button("Save profile", on_click=save_profile, color="secondary").props("dense outline")
                            ui.button("Load profile", on_click=load_profile, color="secondary").props("dense outline")

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
                            "shodan_key": (shodan_in.value or "").strip() or None,
                            "censys_id": (censys_id_in.value or "").strip() or None,
                            "censys_secret": (censys_secret_in.value or "").strip() or None,
                            "zoomeye_key": (zoomeye_in.value or "").strip() or None,
                            "shopify_domain": (shopify_in.value or "").strip() or None,
                            "domain_list": (domain_list_in.value or "").strip() or None,
                            "exclude_pattern": (exclude_in.value or "").strip() or None,
                            "include_pattern": (include_in.value or "").strip() or None,
                            "vault_addr": (vault_in.value or "").strip() or None,
                            "grafana_url": (grafana_in.value or "").strip() or None,
                            "n8n_url": (n8n_in.value or "").strip() or None,
                            "notify_webhook": (webhook_in.value or "").strip() or None,
                            "config": configs,
                            "ignore_hash": hashes,
                            "skip_chaos": bool(skip_chaos.value),
                            "skip_subfinder": bool(skip_subfinder.value),
                            "skip_httpx": bool(skip_httpx.value),
                            "skip_gau": bool(skip_gau.value),
                            "skip_discovery": bool(skip_discovery.value),
                            "no_trufflehog": bool(no_trufflehog.value),
                            "no_validate": bool(no_validate.value),
                            "headless": bool(headless.value),
                            "no_fail_on_valid": bool(no_fail.value),
                            "no_notify": bool(no_notify.value),
                            "skip_amass": bool(skip_amass.value),
                            "polite": bool(polite.value),
                            "nuclei": bool(nuclei_on.value),
                            "docker_fallback": bool(docker_fb.value),
                            "resume": bool(resume_on.value),
                            "skip_wayback_bodies": bool(skip_wayback.value),
                            "skip_js_history": bool(skip_js_history.value),
                            "js_history_max": int(js_history_max_in.value or 15),
                            "skip_sourcemaps": bool(skip_sourcemaps.value),
                            "skip_sensitive_paths": bool(skip_sens.value),
                            "skip_gitleaks": bool(skip_gitleaks.value),
                            "spray": bool(spray_on.value),
                            "skip_public_apis": bool(skip_public_apis.value),
                            "skip_secrets_db": bool(skip_secrets_db.value),
                            "skip_jsleak": bool(skip_jsleak.value),
                            "skip_code_search": bool(skip_code_search.value),
                            "skip_ci_logs": bool(skip_ci_logs.value),
                            "skip_pastes": bool(skip_pastes.value),
                            "skip_docker_hub": bool(skip_docker_hub.value),
                            "skip_image_layers": bool(skip_image_layers.value),
                            "skip_buckets": bool(skip_buckets.value),
                            "skip_openapi": bool(skip_openapi.value),
                            "ci": bool(ci_on.value),
                            "no_default_scope": bool(no_default_scope.value),
                            "github_token": (github_token_in.value or "").strip() or None,
                            "gitlab_token": (gitlab_token_in.value or "").strip() or None,
                            "github_org": (github_org_in.value or "").strip() or None,
                            "repo_shallow": bool(repo_shallow.value),
                            "proxy": (proxy_in.value or "").strip() or None,
                            "proxy_auth": (proxy_auth_in.value or "").strip() or None,
                            "burp_import": (burp_in.value or "").strip() or None,
                            "repo": (repo_in.value or "").strip() or None,
                            "package": rp.parse_package_ids(
                                [w.value or "" for w in mobile_package_fields]
                            ),
                            "apk": split_mobile_file_list(STATE.mobile_paths)[0],
                            "ipa": split_mobile_file_list(STATE.mobile_paths)[1],
                            "credentials": (creds_in.value or "").strip() or None,
                            "header": [
                                ln.strip()
                                for ln in (header_in.value or "").splitlines()
                                if ln.strip()
                            ],
                            "skip_intel": bool(skip_intel.value),
                            "skip_crtsh": bool(skip_crtsh.value),
                            "concurrency": int(conc_in.value or 10),
                            "gau_threads": int(gau_in.value or 5),
                            **llm_scan_opts(),
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

                    def launch_from_opts(opts: Dict[str, Any]) -> bool:
                        errs = validate_form(opts)
                        if errs:
                            form_error.text = " · ".join(errs)
                            ui.notify("Fix form errors before starting", type="negative")
                            return False
                        form_error.text = ""
                        try:
                            STATE.runner.start(opts)
                        except Exception as exc:
                            ui.notify(str(exc), type="negative")
                            return False
                        STATE.domain = opts["domain"]
                        STATE.shopify_domain = opts.get("shopify_domain") or ""
                        STATE.config_overlays = list(opts.get("config") or [])
                        STATE.workspace = STATE.runner.output_dir
                        STATE.log_lines.clear()
                        STATE.findings.clear()
                        STATE.informational.clear()
                        STATE.exposures.clear()
                        STATE.revealed.clear()
                        STATE._finalized_at = None
                        STATE._finding_sigs = None
                        STATE._dash_sig = None  
                        try:
                            console.clear()
                        except Exception:
                            pass
                        status_label.set_text("RUNNING")
                        status_dot.classes(replace="rp-status-dot run")
                        ui.notify("Pipeline started", type="positive")
                        tabs.set_value(tab_console)
                        update_stats(force=True)
                        return True

                    def start_scan() -> None:
                        launch_from_opts(collect_opts())

                    scan_actions["collect"] = collect_opts
                    scan_actions["launch"] = launch_from_opts
                    scan_actions["domain_in"] = domain_in

                    def fill_from_saved(row: Dict[str, Any]) -> None:
                        apply_target(row)
                        out = (row.get("output") or row.get("output_dir") or "").strip()
                        if out:
                            out_in.set_value(out)
                            load_in.set_value(out)
                        files = (row.get("files") or "").strip()
                        if files:
                            files_in.set_value(files)
                        subs = (row.get("subdomains") or "").strip()
                        if subs:
                            sub_in.set_value(subs)

                    def rescan_saved_target() -> None:
                        name = (target_select.value or domain_in.value or "").strip()
                        row = next(
                            (r for r in rp.list_saved_targets() if r.get("name") == name),
                            None,
                        )
                        if not row:
                            row = rp.find_saved_target(name)  
                        if not row:
                            ui.notify("Load or save a target first", type="warning")
                            return
                        fill_from_saved(row)
                        resume_on.set_value(True)
                        start_scan()

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
                            extras = {
                                "jsluice": rp.check_tool("jsluice"),
                                "apkeep": rp.check_tool("apkeep"),
                                "gplaycli": rp.check_tool("gplaycli"),
                            }
                            intel = rp.osint_source_status(
                                shodan_key=shodan_in.value or "",
                                censys_id=censys_id_in.value or "",
                                censys_secret=censys_secret_in.value or "",
                                zoomeye_key=zoomeye_in.value or "",
                                skip_crtsh=bool(skip_crtsh.value),
                                skip_intel=bool(skip_intel.value),
                            )
                            with tools_box:
                                httpx_bin = rp.resolve_httpx_bin()
                                python_httpx = rp.python_httpx_on_path()
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
                                if not status.get("httpx") and python_httpx:
                                    ui.label(
                                        f"PATH httpx is the Python client ({python_httpx}), "
                                        "not ProjectDiscovery. Set HTTPX_BIN or put "
                                        "$HOME/go/bin ahead of ~/.local/bin."
                                    ).classes("text-xs text-amber-400")
                                elif httpx_bin:
                                    ui.label(httpx_bin).classes(
                                        "text-xs text-gray-500 font-mono break-all"
                                    )
                                ui.separator()
                                ui.label("PASSIVE INTEL").classes(
                                    "text-xs text-gray-500 tracking-widest"
                                )
                                labels = {
                                    "shodan": "Shodan",
                                    "censys": "Censys",
                                    "zoomeye": "ZoomEye",
                                    "crtsh": "crt.sh",
                                }
                                for key, title in labels.items():
                                    st = intel.get(key, "off")
                                    chip = (
                                        "on" if st in ("key", "env", "on") else "off"
                                    )
                                    with ui.row().classes("w-full justify-between"):
                                        ui.label(title).classes("font-mono text-sm")
                                        ui.label(st.upper()).classes(
                                            f"text-xs rp-chip {chip}"
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
                        eta_label = ui.label("").classes(
                            "text-xs text-slate-400 font-mono mt-1"
                        )
                        stats_html = ui.html("", sanitize=False).classes("w-full")
                        ui.button(
                            "Download reports (.zip)",
                            on_click=lambda: (
                                build_ui.download_all_artifacts()  
                                if callable(getattr(build_ui, "download_all_artifacts", None))
                                else ui.notify("Open the Artifacts tab first", type="warning")
                            ),
                            color="primary",
                        ).props("unelevated dense").classes("mt-2")

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
                            update_stats(force=True)
                            refresh = getattr(build_ui, "refresh_artifacts", None)
                            if callable(refresh):
                                refresh()
                            ui.notify("Workspace loaded", type="positive")
                            tabs.set_value(tab_findings)

                        ui.button(
                            "Load findings", on_click=load_workspace, color="secondary"
                        ).props("outline")

        # Apps (APK / IPA)
        with ui.tab_panel(tab_apps):
            with ui.row().classes("w-full gap-3 items-stretch"):
                with ui.column().classes("w-full lg:w-7/12 gap-3"):
                    with ui.card().classes("w-full rp-card"):
                        ui.label("APK / IPA scanner").classes("rp-section")
                        ui.label(
                            "Unzip the app, keep JS/JSON/XML/plist/.env, strings-dump binaries, "
                            "then run the same secret scanners. Fetch by Play package id "
                            "(--package, needs apkeep or gplaycli) or upload a file. In Docker, "
                            "upload here instead of a host path like /home/.../Downloads."
                        ).classes("text-sm text-slate-500 mb-2")
                        app_domain_in = ui.input(
                            "App / backend domain (-d)",
                            placeholder="example.com",
                        ).classes("w-full").props("outlined dense")
                        app_path_in = ui.input(
                            "Add a file path",
                            placeholder="/work/app.apk  or  C:\\Users\\...\\app.apk",
                        ).classes("w-full").props("outlined dense")
                        app_package_in = ui.input(
                            "Or fetch by package id (--package)",
                            placeholder="com.example.app",
                        ).classes("w-full").props("outlined dense")
                        mobile_package_fields.append(app_package_in)
                        app_files_box = ui.column().classes("w-full gap-1")

                        def render_app_files() -> None:
                            app_files_box.clear()
                            with app_files_box:
                                if not STATE.mobile_paths:
                                    ui.label("No packages queued.").classes(
                                        "text-xs text-slate-500"
                                    )
                                    return
                                for idx, path in enumerate(list(STATE.mobile_paths)):
                                    exists = Path(path).expanduser().is_file()
                                    with ui.row().classes(
                                        "w-full items-center justify-between gap-2"
                                    ):
                                        ui.label(path).classes(
                                            "font-mono text-xs break-all flex-1"
                                        )
                                        ui.label(
                                            "ready" if exists else "missing"
                                        ).classes(
                                            "text-xs rp-badge-ok"
                                            if exists
                                            else "text-xs rp-badge-miss"
                                        )

                                        def _drop(i: int = idx) -> None:
                                            if 0 <= i < len(STATE.mobile_paths):
                                                STATE.mobile_paths.pop(i)
                                            render_app_files()

                                        ui.button(
                                            "Remove", on_click=_drop, color="secondary"
                                        ).props("flat dense")

                        def add_app_path(raw: str, *, copy_into_work: bool = False) -> None:
                            path = (raw or "").strip().strip('"').strip("'")
                            if not path:
                                ui.notify("Enter or upload an APK/IPA first", type="warning")
                                return
                            if not classify_mobile_path(path):
                                ui.notify(
                                    "Use .apk, .xapk, .apkm, or .ipa",
                                    type="warning",
                                )
                                return
                            src = Path(path).expanduser()
                            staged_root = work_root() / "mobile_uploads"
                            already = False
                            try:
                                already = src.resolve().is_relative_to(staged_root.resolve())
                            except (OSError, ValueError):
                                already = False
                            if src.is_file() and not already and (
                                copy_into_work or running_in_docker()
                            ):
                                try:
                                    staged = stage_mobile_bytes(src.name, src.read_bytes())
                                    path = str(staged)
                                except OSError as exc:
                                    ui.notify(f"Could not stage file: {exc}", type="negative")
                                    return
                            if path not in STATE.mobile_paths:
                                STATE.mobile_paths.append(path)
                            app_path_in.set_value("")
                            render_app_files()
                            if not Path(path).expanduser().is_file():
                                ui.notify(mobile_path_missing_hint(path), type="warning")
                            else:
                                ui.notify(f"Queued {Path(path).name}", type="positive")

                        async def on_app_upload(e: Any) -> None:
                            try:
                                raw_name = upload_event_name(e)
                                name = sanitize_upload_name(raw_name or "app.bin")
                                if not classify_mobile_path(name):
                                    ui.notify(
                                        f"Upload an .apk, .xapk, .apkm, or .ipa (got {raw_name or name})",
                                        type="warning",
                                    )
                                    return
                                data = await read_upload_bytes(e)
                                if not data:
                                    ui.notify("Upload was empty", type="negative")
                                    return
                                dest = stage_mobile_bytes(name, data)
                            except Exception as exc:
                                ui.notify(f"Upload failed: {exc}", type="negative")
                                return
                            add_app_path(str(dest))

                        with ui.row().classes("w-full gap-2 flex-wrap"):
                            ui.button(
                                "Add path",
                                on_click=lambda: add_app_path(app_path_in.value or ""),
                                color="secondary",
                            ).props("outline dense")
                            ui.upload(
                                on_upload=on_app_upload,
                                auto_upload=True,
                                max_file_size=200_000_000,
                                label="Upload APK / IPA",
                            ).props(
                                'accept=".apk,.xapk,.apkm,.ipa" dense'
                            ).classes("flex-1")
                        render_app_files()

                    with ui.card().classes("w-full rp-card"):
                        ui.label("How to scan").classes("rp-section")
                        app_only = ui.checkbox(
                            "Apps only — skip live recon (no subdomain/URL crawl)"
                        )
                        app_only.value = True
                        app_no_validate = ui.checkbox(
                            "Skip key validation (--no-validate)"
                        )
                        app_no_validate.value = True
                        ui.label(
                            "Apps-only still needs a domain for reports. "
                            "Untick it to attach the package to a full Scan-tab run."
                        ).classes("text-xs text-slate-500")
                        app_error = ui.label("").classes("text-red-400 text-sm")

                        def start_app_scan() -> None:
                            collect = scan_actions.get("collect")
                            launch = scan_actions.get("launch")
                            domain_widget = scan_actions.get("domain_in")
                            if not callable(collect) or not callable(launch):
                                ui.notify("Scan form is not ready", type="negative")
                                return
                            apk, ipa = split_mobile_file_list(STATE.mobile_paths)
                            packages = rp.parse_package_ids(
                                [w.value or "" for w in mobile_package_fields]
                            )
                            if not apk and not ipa and not packages:
                                app_error.text = (
                                    "Add an APK/IPA or a Play package id (--package)."
                                )
                                ui.notify(app_error.text, type="warning")
                                return
                            domain = (app_domain_in.value or "").strip()
                            if not domain and domain_widget is not None:
                                domain = (domain_widget.value or "").strip()
                            if domain and domain_widget is not None and not (
                                domain_widget.value or ""
                            ).strip():
                                domain_widget.set_value(domain)
                            opts = collect()
                            if domain:
                                opts["domain"] = domain
                            opts["apk"] = apk
                            opts["ipa"] = ipa
                            opts["package"] = packages
                            if bool(app_only.value):
                                opts["skip_chaos"] = True
                                opts["skip_subfinder"] = True
                                opts["skip_httpx"] = True
                                opts["skip_gau"] = True
                                opts["skip_discovery"] = True
                                opts["skip_intel"] = True
                                opts["skip_amass"] = True
                                opts["skip_buckets"] = True
                                opts["skip_code_search"] = True
                                opts["skip_ci_logs"] = True
                                opts["skip_pastes"] = True
                                opts["skip_docker_hub"] = True
                                opts["skip_image_layers"] = True
                                opts["skip_openapi"] = True
                                opts["skip_sensitive_paths"] = True
                                opts["spray"] = False
                            if bool(app_no_validate.value):
                                opts["no_validate"] = True
                            app_error.text = ""
                            launch(opts)

                        with ui.row().classes("gap-2 mt-2"):
                            ui.button(
                                "Scan apps",
                                on_click=start_app_scan,
                                color="primary",
                            ).props("unelevated")
                            ui.button(
                                "Open Scan tab",
                                on_click=lambda: tabs.set_value(tab_scan),
                                color="secondary",
                            ).props("flat")

                with ui.column().classes("w-full lg:w-5/12 gap-3"):
                    with ui.card().classes("w-full rp-card"):
                        ui.label("What this does").classes("rp-section")
                        ui.label(
                            "Accepts .apk, .xapk, .apkm (APKMirror), and .ipa. "
                            "Extracts into recon_<domain>/mobile_extract/. "
                            "Findings show on Findings / Artifacts. "
                            "In Docker, uploads land in /work/mobile_uploads/."
                        ).classes("text-sm text-slate-500")

        # Console
        with ui.tab_panel(tab_console):
            with ui.card().classes("w-full rp-card"):
                with ui.row().classes("w-full justify-between items-center"):
                    ui.label("Console").classes("rp-section w-full")
                    ui.button(
                        "Clear",
                        on_click=lambda: (STATE.log_lines.clear(), console.clear()),
                        color="secondary",
                    ).props("flat dense")
                
                console = ui.log(max_lines=120).classes("rp-console w-full")

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
                ui.label("Security Findings").classes("rp-section")
                ui.label(
                    "Live Gitleaks-style report: company, where the key was found, "
                    "redacted secret. Rows fill in while a scan runs. Reveal before copy."
                ).classes("text-xs text-gray-500 mb-2")

                with ui.row().classes("w-full gap-2 flex-wrap items-end"):
                    f_type = ui.select(
                        ["All"], value="All", label="Filter by Rule"
                    ).classes("w-48").props("dense outlined")
                    f_company = ui.select(
                        ["All"], value="All", label="Filter by Company"
                    ).classes("w-52").props("dense outlined")
                    f_file = ui.input("Filter by File").classes("w-64").props(
                        "dense outlined placeholder='URL, path, or filename'"
                    )
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
                    f_sev = ui.select(
                        ["All", "critical", "high", "medium", "low"],
                        value="All",
                        label="Severity",
                    ).classes("w-36").props("dense outlined")
                    f_query = ui.input("Search source / note / hash").classes(
                        "flex-1"
                    ).props("dense outlined")
                    f_conf = ui.number(
                        "Min confidence", value=0, min=0, max=100
                    ).classes("w-36").props("dense")

                    def apply_filters() -> None:
                        STATE.filter_type = f_type.value or "All"
                        STATE.filter_company = f_company.value or "All"
                        STATE.filter_file = (f_file.value or "").strip().lower()
                        STATE.filter_status = f_status.value or "All"
                        STATE.filter_tier = f_tier.value or "All"
                        STATE.filter_severity = f_sev.value or "All"
                        STATE.filter_query = (f_query.value or "").strip().lower()
                        STATE.min_confidence = int(f_conf.value or 0)
                        render_findings()

                    def reset_filters() -> None:
                        f_type.set_value("All")
                        f_company.set_value("All")
                        f_file.set_value("")
                        f_status.set_value("All")
                        f_tier.set_value("All")
                        f_sev.set_value("All")
                        f_query.set_value("")
                        f_conf.set_value(0)
                        apply_filters()

                    ui.button("Apply", on_click=apply_filters, color="primary").props(
                        "unelevated dense"
                    )
                    ui.button("Reset Filters", on_click=reset_filters, color="secondary").props(
                        "outline dense"
                    )
                    ui.button(
                        "Reload files", on_click=lambda: reload_findings(), color="secondary"
                    ).props("outline dense")

                    def export_h1() -> None:
                        text = rp.export_hackerone_markdown(STATE.findings)
                        ui.notify("HackerOne markdown generated — see Artifacts", type="positive")
                        preview_path = (STATE.workspace or STATE.runner.output_dir)
                        if preview_path:
                            Path(preview_path).mkdir(parents=True, exist_ok=True)
                            (Path(preview_path) / "export_hackerone.md").write_text(text, encoding="utf-8")

                    def export_jira() -> None:
                        text = rp.export_jira_markdown(STATE.findings)
                        preview_path = (STATE.workspace or STATE.runner.output_dir)
                        if preview_path:
                            Path(preview_path).mkdir(parents=True, exist_ok=True)
                            (Path(preview_path) / "export_jira.md").write_text(text, encoding="utf-8")
                        ui.notify("Jira markdown generated", type="positive")

                    report_tpl = ui.select(
                        {
                            "pentest": "Pentest / bug bounty (HackerOne, Bugcrowd, Intigriti)",
                            "executive": "Executive briefing (CEO / CTO / board)",
                        },
                        value="pentest",
                        label="Report template",
                    ).classes("w-96").props("dense outlined")

                    def generate_template_report() -> None:
                        ws = STATE.workspace or STATE.runner.output_dir
                        if not ws:
                            ui.notify("Load or finish a scan first", type="warning")
                            return
                        ws_path = Path(ws)
                        findings = list(STATE.findings or [])
                        exposures = list(STATE.exposures or [])
                        informational = list(STATE.informational or [])
                        if not findings and not exposures and not informational:
                            findings = load_json_list(ws_path / "findings.json")
                            informational = load_json_list(ws_path / "informational.json")
                            exposures = load_json_list(ws_path / "source_map_exposures.json")
                        domain = STATE.domain or "scan"
                        tid = str(report_tpl.value or "pentest")
                        written = rp.rp_reports.write_vendor_and_reports(
                            ws_path,
                            domain,
                            findings,
                            exposures,
                            informational,
                            redact=rp.redact_key,
                        )
                        dest = written.get(
                            "report_executive.md" if tid == "executive" else "report_pentest.md"
                        )
                        try:
                            build_ui.render_vendors()  
                        except Exception:
                            pass
                        try:
                            build_ui.refresh_artifacts()  
                        except Exception:
                            pass
                        name = dest.name if dest is not None else "report"
                        ui.notify(
                            f"Wrote {name} (and vendor dashboard) — open Artifacts to download",
                            type="positive",
                        )

                    ui.button(
                        "Generate report",
                        on_click=generate_template_report,
                        color="primary",
                    ).props("unelevated dense")
                    ui.button("Export HackerOne", on_click=export_h1, color="secondary").props("flat dense")
                    ui.button("Export Jira", on_click=export_jira, color="secondary").props("flat dense")

                findings_html = ui.html(
                    "<p class='text-slate-500 text-sm'>Run a scan or load a workspace — "
                    "the live report fills in here.</p>",
                    sanitize=False,
                )
                with ui.row().classes("w-full gap-2 flex-wrap items-end mt-2"):
                    inspect_select = ui.select(
                        {"_": "Select a finding to inspect"},
                        value="_",
                        label="Inspect row",
                    ).classes("flex-1").props("dense outlined")
                    inspect_btns = ui.row().classes("gap-1")

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
                        if STATE.filter_severity != "All" and str(f.get("severity") or "").lower() != STATE.filter_severity:
                            continue
                        if STATE.filter_type != "All" and f.get("type") != STATE.filter_type:
                            continue
                        company_want = STATE.filter_company
                        if company_want and company_want != "All":
                            vid, _prod = rp.rp_reports.vendor_for_type(str(f.get("type") or ""))
                            rec = rp.rp_reports.vendor_record(vid)
                            if rec.get("name") != company_want and vid != company_want:
                                continue
                        file_q = STATE.filter_file
                        if file_q:
                            loc = rp.rp_reports.finding_source_location(f).lower()
                            if file_q not in loc:
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
                            vid, _prod = rp.rp_reports.vendor_for_type(str(f.get("type") or ""))
                            company = rp.rp_reports.vendor_record(vid).get("name") or ""
                            blob = " ".join(
                                str(f.get(k, ""))
                                for k in (
                                    "type",
                                    "source_url",
                                    "note",
                                    "hash",
                                    "scanner",
                                    "detector",
                                )
                            ).lower()
                            blob = f"{blob} {company.lower()}"
                            if q not in blob:
                                continue
                        out.append(f)
                    return out

                def render_findings() -> None:
                    rows = filtered_rows()
                    shown = rows[:FINDINGS_RENDER_CAP]
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
                    companies = sorted(
                        {
                            rp.rp_reports.vendor_record(
                                rp.rp_reports.vendor_for_type(str(f.get("type") or ""))[0]
                            )["name"]
                            for f in (
                                STATE.findings
                                + STATE.informational
                                + STATE.exposures
                            )
                        }
                    )
                    type_opts = ["All", *types]
                    company_opts = ["All", *companies]
                    if list(f_type.options or []) != type_opts:
                        f_type.options = type_opts
                    if list(f_company.options or []) != company_opts:
                        f_company.options = company_opts

                    reports = rp.rp_reports
                    enriched = []
                    inspect_opts = {"_": "Select a finding to inspect"}
                    id_map: Dict[str, Dict] = {}
                    for idx, f in enumerate(shown):
                        key = str(f.get("key") or "")
                        fid = str(f.get("hash") or f"{f.get('type')}:{key[:24]}:{idx}")
                        row = reports.enrich_finding_row(
                            f,
                            tier=str(f.get("_tier") or "actionable"),
                            redact=rp.redact_key,
                            reveal=fid in STATE.revealed,
                        )
                        row["_id"] = fid
                        enriched.append(row)
                        loc = row.get("source_short") or "unknown"
                        inspect_opts[fid] = (
                            f"{row.get('rule')} · {row.get('company')} · {loc}"
                        )
                        id_map[fid] = f
                    STATE._inspect_map = id_map
                    stats = reports.findings_report_stats(
                        STATE.findings, STATE.exposures, STATE.informational
                    )
                    live = bool(STATE.runner.running)
                    mode = "Live scan" if live else "ReconPipe"
                    generated = (
                        "Updating as hits arrive"
                        if live
                        else datetime.now().strftime("%b %d, %Y %H:%M:%S")
                    )
                    dash = reports.findings_dashboard_html(
                        STATE.domain or "scan",
                        enriched,
                        stats=stats,
                        generated=generated,
                        scan_mode=mode,
                        live=live,
                        fragment=True,
                        cap=FINDINGS_RENDER_CAP,
                        total=len(rows),
                    )
                    sig = (
                        dash,
                        tuple(inspect_opts.items()),
                        live,
                    )
                    if getattr(STATE, "_dash_sig", None) != sig:
                        STATE._dash_sig = sig
                        findings_html.set_content(dash)
                        prev = inspect_select.value
                        inspect_select.options = inspect_opts
                        if prev in inspect_opts:
                            inspect_select.set_value(prev)
                        elif inspect_select.value not in inspect_opts:
                            inspect_select.set_value("_")

                        inspect_btns.clear()
                        with inspect_btns:
                            def _selected_row() -> Tuple[Optional[Dict], str]:
                                fid = str(inspect_select.value or "_")
                                row = (getattr(STATE, "_inspect_map", {}) or {}).get(fid)
                                return row, fid

                            def do_inspect() -> None:
                                row, fid = _selected_row()
                                if not row or fid == "_":
                                    ui.notify("Select a finding first", type="warning")
                                    return
                                show_detail(row, fid)

                            def do_reveal() -> None:
                                row, fid = _selected_row()
                                if not row or fid == "_":
                                    ui.notify("Select a finding first", type="warning")
                                    return
                                if fid in STATE.revealed:
                                    STATE.revealed.discard(fid)
                                else:
                                    STATE.revealed.add(fid)
                                STATE._dash_sig = None
                                render_findings()
                                show_detail(row, fid)

                            async def do_copy() -> None:
                                row, fid = _selected_row()
                                if not row or fid == "_":
                                    ui.notify("Select a finding first", type="warning")
                                    return
                                val = str(row.get("key") or "")
                                try:
                                    await ui.run_javascript(
                                        f"navigator.clipboard.writeText({json.dumps(val)})"
                                    )
                                except Exception:
                                    pass
                                ui.notify("Copied to clipboard", type="positive")

                            ui.button("Inspect", on_click=do_inspect, color="primary").props(
                                "dense unelevated"
                            )
                            _row, fid = _selected_row()
                            revealed = fid in STATE.revealed and fid != "_"
                            ui.button(
                                "Hide" if revealed else "Reveal",
                                on_click=do_reveal,
                                color="secondary",
                            ).props("dense flat")
                            ui.button("Copy", on_click=do_copy, color="secondary").props(
                                "dense flat"
                            )

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
                        vid, product = rp.rp_reports.vendor_for_type(
                            str(finding.get("type") or "")
                        )
                        company = rp.rp_reports.vendor_record(vid).get("name") or vid
                        ui.label(f"Company: {company} · {product}").classes(
                            "text-sm text-slate-300"
                        )
                        loc = rp.rp_reports.finding_source_location(finding)
                        line = rp.rp_reports.finding_line_number(finding)
                        line_bit = f" · line {line}" if line else ""
                        ui.label(f"Where found: {loc}{line_bit}").classes(
                            "text-xs text-slate-400 break-all"
                        )
                        if finding.get("scanner"):
                            ui.label(f"Scanner: {finding.get('scanner')}").classes(
                                "text-xs text-slate-500"
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
                                result = await run_io_bound(
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
                    STATE._dash_sig = None
                    STATE._finding_sigs = None
                    render_findings()
                    try:
                        build_ui.render_vendors()  
                    except Exception:
                        pass
                    update_stats(force=True)
                    ui.notify(
                        f"Loaded {len(STATE.findings)} findings from {STATE.workspace}",
                        type="info",
                    )

                # bind for outer timers
                build_ui.reload_findings = reload_findings  
                build_ui.render_findings = render_findings
                for _w in (f_type, f_company, f_status, f_tier, f_sev):
                    _w.on("update:model-value", lambda *_: apply_filters())
                f_file.on("blur", lambda *_: apply_filters())
                f_file.on("keydown.enter", lambda *_: apply_filters())
                render_findings()  

        # Vendors
        with ui.tab_panel(tab_vendors):
            with ui.card().classes("w-full rp-card"):
                ui.label("Vendors & API keys").classes("rp-section")
                ui.label(
                    "Companies whose credentials showed up in this scan, with a short "
                    "description of the vendor. Fingerprints only — full secrets stay redacted."
                ).classes("text-xs text-gray-500 mb-2")
                vendors_meta = ui.label("No vendors yet").classes("text-sm text-slate-400")
                vendors_host = ui.column().classes("w-full gap-3 mt-2")

                def render_vendors() -> None:
                    groups = rp.rp_reports.group_findings_by_vendor(
                        STATE.findings,
                        STATE.exposures,
                        STATE.informational,
                        redact=rp.redact_key,
                    )
                    live_n = sum(int(g.get("live") or 0) for g in groups)
                    vendors_meta.set_text(
                        f"{len(groups)} compan{'y' if len(groups) == 1 else 'ies'} · "
                        f"{live_n} live key(s)"
                    )
                    vendors_host.clear()
                    with vendors_host:
                        if not groups:
                            ui.label(
                                "Run a scan or load a workspace — vendors appear from findings."
                            ).classes("text-slate-500 text-sm")
                            return
                        for g in groups:
                            with ui.card().classes("w-full rp-subcard"):
                                with ui.row().classes("w-full items-center justify-between"):
                                    ui.label(str(g.get("name") or "")).classes("text-base font-semibold")
                                    ui.label(
                                        f"LIVE {g.get('live')}/{g.get('total')}"
                                        if g.get("live")
                                        else f"{g.get('total')} seen"
                                    ).classes("text-xs text-slate-400")
                                ui.label(
                                    f"{g.get('category') or ''} · {g.get('website') or ''}"
                                ).classes("text-xs text-slate-500")
                                ui.label(str(g.get("about") or "")).classes(
                                    "text-sm text-slate-300 mt-1"
                                )
                                for k in g.get("keys") or []:
                                    live = "LIVE" if k.get("valid") else "—"
                                    ui.label(
                                        f"{k.get('product')}  `{k.get('type')}`  {live}  "
                                        f"{k.get('fingerprint')}  {str(k.get('source_url') or '')[:60]}"
                                    ).classes("text-xs font-mono text-slate-400 break-all")

                ui.button("Refresh", on_click=render_vendors, color="secondary").props(
                    "outline dense"
                )
                render_vendors()
                build_ui.render_vendors = render_vendors  

        # Key Tester
        with ui.tab_panel(tab_tester):
            with ui.card().classes("w-full rp-card"):
                ui.label("Key Tester").classes("rp-section")
                ui.label(
                    "Paste one or more API keys (one per line) and run the configured "
                    "provider check (keyhacks-style). Google AIza keys are sprayed across "
                    "cheap Maps JSON, YouTube, and Gemini models-list probes — not billed "
                    "image APIs. LIVE means the credential is accepted. Batch mode fills the table below."
                ).classes("text-xs text-gray-500 mb-3")

                with ui.row().classes("w-full gap-2 flex-wrap"):
                    tester_type = ui.select(
                        validator_type_options(),
                        value=validator_type_options()[0] if validator_type_options() else None,
                        label="Key type",
                    ).classes("w-56").props("dense outlined")
                    tester_domain = ui.input(
                        "Target domain (Referer / Shopify / n8n instance)",
                        value="",
                        placeholder="example.com or https://tenant.app.n8n.cloud",
                    ).classes("flex-1").props("dense outlined")
                    tester_shop = ui.input(
                        "Shopify store (if testing shpat_)",
                        placeholder="store.myshopify.com",
                    ).classes("flex-1").props("dense outlined")

                tester_key = ui.textarea(
                    "API key / token (one per line for batch)",
                    placeholder="paste credential(s), one per line",
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
                tester_batch = ui.column().classes("w-full gap-1 mt-2")

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
                    keys = rp.split_tester_keys(tester_key.value or "")
                    ktype = tester_type.value
                    if not keys:
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
                    secret = (tester_secret.value or "").strip()
                    session = (tester_session.value or "").strip()
                    ui.notify(f"Testing {len(keys)} {ktype} key(s)…", type="info")
                    rows: List[Dict[str, Any]] = []
                    last_result: Dict[str, Any] = {}
                    last_label = "INCONCLUSIVE"
                    last_valid = False
                    for key in keys:
                        hits = guess_key_types(key)
                        use_type = ktype
                        if len(keys) > 1 and hits:
                            preferred = [h for h in hits if h in rp.VALIDATORS]
                            if preferred:
                                use_type = preferred[0]
                        finding: Dict[str, Any] = {
                            "type": use_type,
                            "key": key,
                            "source_url": "gui://key-tester",
                        }
                        if use_type in {"grafana_token"}:
                            finding["grafana_url"] = domain
                        if use_type in {"n8n_api", "jwt"}:
                            inst = (tester_domain.value or "").strip()
                            if inst and inst.lower() not in {"example.com"}:
                                finding["n8n_url"] = inst
                        if use_type in {"hashicorp_vault"}:
                            finding["vault_addr"] = domain
                        if secret:
                            if use_type == "aws_access_key":
                                finding["aws_secret"] = secret
                            if use_type in ("twilio_sid", "twilio_token"):
                                finding["twilio_token"] = secret
                        if session:
                            finding["aws_session_token"] = session
                        try:
                            result = await run_io_bound(
                                rp.validate_finding_configured_sync,
                                finding,
                                domain,
                                shop,
                                STATE.config_overlays,
                            )
                        except Exception as exc:
                            result = {
                                "type": use_type,
                                "key": key,
                                "valid": False,
                                "validated": False,
                                "note": str(exc),
                            }
                        rows.append(result)
                        last_result = result
                    tester_batch.clear()
                    with tester_batch:
                        if len(rows) > 1:
                            with ui.row().classes("w-full text-xs text-slate-500"):
                                ui.label("type").classes("w-40")
                                ui.label("verdict").classes("w-24")
                                ui.label("key").classes("flex-1")
                                ui.label("note").classes("flex-1")
                            for r in rows:
                                valid = bool(r.get("valid"))
                                note = str(r.get("note") or "")
                                skipped = note.lower().startswith("skip")
                                label = (
                                    "LIVE"
                                    if valid
                                    else ("SKIP" if skipped else "DEAD")
                                )
                                with ui.row().classes("w-full items-center gap-2"):
                                    ui.label(str(r.get("type") or "")).classes(
                                        "w-40 font-mono text-xs"
                                    )
                                    ui.label(label).classes(
                                        "w-24 text-emerald-400"
                                        if valid
                                        else "w-24 text-amber-300"
                                    )
                                    ui.label(
                                        redact_secret(str(r.get("key") or ""), False)
                                    ).classes("flex-1 rp-secret text-xs")
                                    ui.label(note[:80]).classes(
                                        "flex-1 text-xs text-slate-400"
                                    )
                    valid = bool(last_result.get("valid"))
                    validated = bool(last_result.get("validated"))
                    note = str(last_result.get("note") or "")
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
                    last_label = label
                    last_valid = valid
                    tester_verdict.set_content(
                        f'<div class="rp-verdict {cls}">{label}'
                        + (f" · {len(rows)} keys" if len(rows) > 1 else "")
                        + "</div>"
                    )
                    stamp = datetime.now().strftime("%H:%M:%S")
                    services = last_result.get("google_services")
                    extra = ""
                    if isinstance(services, dict) and services:
                        extra = "\nservices=" + ", ".join(
                            f"{k}:{v}" for k, v in services.items()
                        )
                    scopes = last_result.get("github_scopes")
                    if scopes:
                        extra += "\nscopes=" + ",".join(str(s) for s in scopes)
                    tester_detail.set_text(
                        f"[{stamp}] type={last_result.get('type')}\n"
                        f"valid={last_result.get('valid')}  validated={last_result.get('validated')}  "
                        f"http={last_result.get('status_code')}\n"
                        f"note={note}{extra}"
                    )
                    footer_status.set_text(f"LAST TEST  {last_label}")
                    live_n = sum(1 for r in rows if r.get("valid"))
                    ui.notify(
                        f"Key test: {live_n}/{len(rows)} LIVE"
                        if len(rows) > 1
                        else f"Key test: {last_label}",
                        type="positive" if last_valid or live_n else "warning",
                    )

                with ui.row().classes("gap-2 mt-3"):
                    ui.button(
                        "Detect type", on_click=apply_guess, color="secondary"
                    ).props("outline")
                    ui.button(
                        "Test key(s)", on_click=run_manual_test, color="primary"
                    ).props("unelevated")

        # Artifacts 
        with ui.tab_panel(tab_artifacts):
            with ui.card().classes("w-full rp-card"):
                ui.label("Artifacts").classes("rp-section")
                ui.label(
                    "These files may contain live secrets. Handle according to your "
                    "engagement rules; do not share them casually. After a scan, "
                    "remediation.md is the verify-and-fix writeup (Settings → LLM)."
                ).classes("text-xs text-amber-400 mb-2")

                def current_workspace() -> Optional[Path]:
                    ws = STATE.workspace or STATE.runner.output_dir
                    return Path(ws) if ws else None

                def download_named(rel: str) -> None:
                    ws = current_workspace()
                    if ws is None:
                        ui.notify("No output directory yet", type="warning")
                        return
                    path = resolve_workspace_file(ws, rel)
                    if path is None:
                        ui.notify(f"Not available: {rel}", type="warning")
                        return
                    trigger_browser_download(path, Path(rel).name)

                def download_previewed() -> None:
                    rel = STATE.preview_artifact
                    if not rel:
                        ui.notify("Preview a file first", type="warning")
                        return
                    download_named(rel)

                def download_all_artifacts() -> None:
                    ws = current_workspace()
                    if ws is None or not ws.is_dir():
                        ui.notify("No output directory yet", type="warning")
                        return
                    dest = write_artifacts_zip(ws)
                    if dest is None:
                        ui.notify("No report files to zip yet", type="warning")
                        return
                    trigger_browser_download(dest, dest.name)

                with ui.row().classes("gap-2 mb-3"):
                    ui.button(
                        "Download all reports (.zip)",
                        on_click=download_all_artifacts,
                        color="primary",
                    ).props("unelevated")
                    ui.button(
                        "Refresh artifact list",
                        on_click=lambda: refresh_artifacts(),
                        color="secondary",
                    ).props("outline")

                artifacts_host = ui.column().classes("w-full gap-2")
                with ui.row().classes("w-full justify-between items-center mt-4"):
                    preview_title = ui.label("Preview — pick a file").classes(
                        "text-sm text-slate-400"
                    )
                    ui.button(
                        "Download this file",
                        on_click=download_previewed,
                        color="primary",
                    ).props("unelevated dense")
                preview = ui.code("").classes("w-full max-h-96 overflow-auto")

                def show_preview(rel: str) -> None:
                    ws = current_workspace()
                    path = resolve_workspace_file(ws, rel) if ws is not None else None
                    if path is None:
                        preview.set_content("")
                        preview_title.set_text("Preview — file missing")
                        STATE.preview_artifact = ""
                        ui.notify(f"Not available: {rel}", type="warning")
                        return
                    STATE.preview_artifact = rel
                    preview_title.set_text(f"Preview — {rel}")
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                        if len(text) > 20000:
                            text = text[:20000] + "\n… truncated …"
                        preview.set_content(text)
                    except Exception as exc:
                        preview.set_content(str(exc))

                def refresh_artifacts() -> None:
                    artifacts_host.clear()
                    ws = current_workspace()
                    with artifacts_host:
                        if not ws or not ws.is_dir():
                            ui.label("No output directory yet.").classes(
                                "text-slate-500 text-sm"
                            )
                            return
                        ui.label(str(ws)).classes("text-xs text-slate-400 break-all mb-2")
                        present = existing_artifact_files(ws)
                        ui.label(
                            f"{len(present)} file(s) ready to download"
                            if present
                            else "Reports appear here when the scan finishes."
                        ).classes("text-xs text-slate-500 mb-1")
                        for name in ARTIFACT_FILES:
                            path = resolve_workspace_file(ws, name)
                            exists = path is not None
                            with ui.row().classes(
                                "w-full justify-between items-center border-b border-slate-800 py-1"
                            ):
                                ui.label(name).classes(
                                    "font-mono text-sm "
                                    + ("text-slate-200" if exists else "text-slate-600")
                                )
                                with ui.row().classes("gap-1"):
                                    if exists and path is not None:
                                        ui.label(fmt_bytes(path.stat().st_size)).classes(
                                            "text-xs text-slate-500"
                                        )
                                        ui.button(
                                            "Preview",
                                            on_click=lambda n=name: show_preview(n),
                                            color="secondary",
                                        ).props("flat dense")
                                        ui.button(
                                            "Download",
                                            on_click=lambda n=name: download_named(n),
                                            color="primary",
                                        ).props("flat dense")
                                    else:
                                        ui.label("missing").classes(
                                            "text-xs text-slate-600"
                                        )

                build_ui.refresh_artifacts = refresh_artifacts  
                build_ui.download_all_artifacts = download_all_artifacts  

        # History 
        with ui.tab_panel(tab_history):
            with ui.card().classes("w-full rp-card"):
                ui.label("History").classes("rp-section")
                ui.label(
                    "Past scans from this machine (or docker-home). "
                    "Open reviews findings; Rescan reuses the URL list and output folder."
                ).classes("text-xs text-gray-500 mb-2")
                history_host = ui.column().classes("w-full gap-2")

                def open_history_item(item: Dict[str, Any]) -> None:
                    path = Path(str(item.get("output_dir") or item.get("output") or "")).expanduser()
                    if not path.is_dir():
                        ui.notify(f"Output folder not found: {path}", type="negative")
                        return
                    load_in.set_value(str(path))
                    load_domain.set_value(str(item.get("domain") or ""))
                    domain_in.set_value(str(item.get("domain") or ""))
                    load_workspace()

                def rescan_history_item(item: Dict[str, Any]) -> None:
                    domain = str(item.get("domain") or "").strip()
                    if not domain:
                        ui.notify("History row has no domain", type="warning")
                        return
                    domain_in.set_value(domain)
                    fill_from_saved(item)
                    resume_on.set_value(True)
                    start_scan()

                def render_history() -> None:
                    history_host.clear()
                    rows = rp.load_scan_history()
                    STATE.history = rows
                    with history_host:
                        if not rows:
                            ui.label("No saved scans yet. Finish a run to see it here.").classes(
                                "text-slate-500 text-sm"
                            )
                            return
                        for item in rows:
                            with ui.card().classes("w-full rp-subcard"):
                                ui.label(
                                    f"{item.get('domain')} · "
                                    f"{item.get('finished_at') or item.get('started_at') or ''}"
                                ).classes("text-sm")
                                ui.label(str(item.get("output_dir") or "")).classes(
                                    "text-xs text-slate-500 break-all"
                                )
                                with ui.row().classes("gap-2 mt-1"):
                                    ui.button(
                                        "Open",
                                        on_click=lambda it=item: open_history_item(it),
                                        color="secondary",
                                    ).props("flat dense")
                                    ui.button(
                                        "Rescan",
                                        on_click=lambda it=item: rescan_history_item(it),
                                        color="primary",
                                    ).props("unelevated dense")

                build_ui.render_history = render_history 
                render_history()

        with ui.tab_panel(tab_settings):
            saved_llm = rp.rp_llm.load_app_settings()
            with ui.card().classes("w-full rp-card"):
                ui.label("Settings").classes("rp-section")
                ui.label(
                    "Saved under ~/.reconpipe (or RECONPIPE_HOME). LLM reports run after a "
                    "scan when enabled + auto, or from the button below on a finished workspace. "
                    "Only redacted fingerprints are sent to the model."
                ).classes("text-xs text-gray-500 mb-3")
                ui.label(
                    f"Data directory: {rp.user_data_dir()}"
                ).classes("text-xs text-slate-500 mb-3")

                ui.label("Appearance").classes("rp-section")
                dark_default = ui.checkbox(
                    "Start in dark mode",
                    value=bool(saved_llm.get("dark", True)),
                )

                ui.label("LLM remediation").classes("rp-section")
                llm_enabled = ui.checkbox(
                    "Enable LLM reports",
                    value=bool(saved_llm.get("enabled")),
                )
                llm_auto = ui.checkbox(
                    "Run automatically when a scan finishes",
                    value=bool(saved_llm.get("auto", True)),
                )
                llm_provider = ui.select(
                    {
                        "ollama": "Local — Ollama",
                        "openai_compat": "Local — OpenAI-compatible (LM Studio / vLLM / llama.cpp)",
                        "openai": "Cloud — OpenAI",
                        "anthropic": "Cloud — Anthropic",
                    },
                    value=saved_llm.get("provider") or "ollama",
                    label="Provider",
                ).classes("w-full").props("dense outlined")
                llm_model = ui.input(
                    "Model",
                    value=str(saved_llm.get("model") or ""),
                    placeholder="llama3.1  ·  gpt-4o-mini  ·  claude-3-5-haiku-latest",
                ).classes("w-full").props("outlined dense")
                llm_base = ui.input(
                    "Base URL (Ollama / local OpenAI-compatible)",
                    value=str(saved_llm.get("base_url") or ""),
                    placeholder="http://127.0.0.1:11434",
                ).classes("w-full").props("outlined dense")
                llm_key_in = ui.input(
                    "API key (cloud providers; stored in keys.yaml)",
                    value=rp.rp_llm.load_llm_key(),
                    password=True,
                    password_toggle_button=True,
                    placeholder="or RECONPIPE_LLM_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY",
                ).classes("w-full").props("outlined dense")
                with ui.row().classes("w-full gap-2"):
                    llm_timeout = ui.number(
                        "Timeout (sec)",
                        value=int(saved_llm.get("timeout") or 120),
                        min=10,
                        max=600,
                    ).classes("flex-1").props("dense outlined")
                    llm_max = ui.number(
                        "Max findings sent to the model",
                        value=int(saved_llm.get("max_findings") or 40),
                        min=1,
                        max=200,
                    ).classes("flex-1").props("dense outlined")
                llm_status = ui.label("").classes("text-sm text-slate-400 mt-1")

                STATE.llm_widgets = {
                    "enabled": llm_enabled,
                    "auto": llm_auto,
                    "provider": llm_provider,
                    "model": llm_model,
                    "base_url": llm_base,
                    "api_key": llm_key_in,
                    "timeout": llm_timeout,
                    "max_findings": llm_max,
                    "dark": dark_default,
                }

                def _provider_defaults() -> None:
                    name = str(llm_provider.value or "ollama")
                    if not (llm_model.value or "").strip():
                        llm_model.set_value(rp.rp_llm.DEFAULT_MODELS.get(name, ""))
                    cur = (llm_base.value or "").strip()
                    if not cur or cur in rp.rp_llm.DEFAULT_BASE_URLS.values():
                        llm_base.set_value(rp.rp_llm.DEFAULT_BASE_URLS.get(name, ""))

                llm_provider.on("update:model-value", lambda *_: _provider_defaults())

                def save_settings() -> None:
                    path = rp.rp_llm.save_app_settings(
                        {
                            "enabled": bool(llm_enabled.value),
                            "auto": bool(llm_auto.value),
                            "provider": str(llm_provider.value or "ollama"),
                            "model": (llm_model.value or "").strip(),
                            "base_url": (llm_base.value or "").strip(),
                            "timeout": int(llm_timeout.value or 120),
                            "max_findings": int(llm_max.value or 40),
                            "dark": bool(dark_default.value),
                        },
                        llm_key=(llm_key_in.value or "").strip(),
                    )
                    STATE.dark_on = bool(dark_default.value)
                    if STATE.dark_on:
                        dark_mode.enable()
                    else:
                        dark_mode.disable()
                    ui.notify(f"Saved {path}", type="positive")

                async def test_llm() -> None:
                    llm_status.set_text("Checking…")
                    ok, msg = await run_io_bound(
                        rp.rp_llm.ping_llm,
                        provider=str(llm_provider.value or "ollama"),
                        model=(llm_model.value or "").strip(),
                        base_url=(llm_base.value or "").strip(),
                        api_key=(llm_key_in.value or "").strip() or rp.rp_llm.load_llm_key(),
                    )
                    llm_status.set_text(("OK — " if ok else "Failed — ") + msg)
                    ui.notify(msg, type="positive" if ok else "negative")

                def _load_scan_findings(ws: Path) -> Tuple[List[Dict], List[Dict]]:
                    findings: List[Dict] = []
                    exposures: List[Dict] = []
                    fj = ws / "findings.json"
                    if fj.is_file():
                        try:
                            data = json.loads(fj.read_text(encoding="utf-8"))
                            if isinstance(data, list):
                                findings = data
                        except Exception:
                            findings = []
                    ex = ws / "source_map_exposures.json"
                    if ex.is_file():
                        try:
                            data = json.loads(ex.read_text(encoding="utf-8"))
                            if isinstance(data, list):
                                exposures = data
                        except Exception:
                            exposures = []
                    return findings, exposures

                async def generate_llm_now() -> None:
                    ws = Path(STATE.workspace or STATE.runner.output_dir or "")
                    if not ws or not ws.is_dir():
                        ui.notify("Load a finished scan workspace first (Artifacts / History)", type="warning")
                        return
                    findings, exposures = _load_scan_findings(ws)
                    domain = STATE.domain or ws.name
                    llm_status.set_text("Writing remediation.md…")
                    args = llm_args_from_opts()
                    try:
                        dest = await run_io_bound(
                            rp.rp_llm.maybe_write_llm_report,
                            ws,
                            domain,
                            findings,
                            exposures,
                            [],
                            args,
                            force=True,
                        )
                    except Exception as exc:
                        llm_status.set_text(f"Failed — {exc}")
                        ui.notify(str(exc), type="negative")
                        return
                    if dest:
                        llm_status.set_text(f"Wrote {dest}")
                        ui.notify(f"Wrote {dest.name}", type="positive")
                        try:
                            build_ui.refresh_artifacts()  
                        except Exception:
                            pass
                    else:
                        llm_status.set_text("No report written")
                        ui.notify("No report written", type="warning")

                with ui.row().classes("w-full gap-2 flex-wrap mt-2"):
                    ui.button("Save settings", on_click=save_settings, color="primary").props(
                        "unelevated dense"
                    )
                    ui.button("Test LLM", on_click=test_llm, color="secondary").props(
                        "outline dense"
                    )
                    ui.button(
                        "Generate report from finished scan",
                        on_click=generate_llm_now,
                        color="secondary",
                    ).props("outline dense")

                ui.label(
                    "Local: install Ollama, run `ollama pull llama3.1`, leave Base URL as "
                    "http://127.0.0.1:11434. LM Studio uses openai_compat and usually "
                    "http://127.0.0.1:1234/v1. Cloud: pick OpenAI or Anthropic and paste a key."
                ).classes("text-xs text-gray-500 mt-3")

    footer_status = ui.label("IDLE").classes("font-mono")
    footer_usage = ui.label("CPU —  ·  RAM —").classes("font-mono")
    with ui.footer().classes("rp-footer items-center justify-between px-4"):
        with ui.row().classes("items-center gap-4"):
            footer_status
            footer_target = ui.label("").classes("font-mono")
            footer_usage
        footer_path = ui.label("").classes("font-mono truncate")

    ui_cache: Dict[str, Any] = {}
    last_stats_at = 0.0
    usage_monitor = ResourceMonitor()
    last_usage_html = ""
    last_usage_snap: Dict[str, Any] = {}

    def _text(el: Any, key: str, value: str) -> None:
        if ui_cache.get(key) == value:
            return
        ui_cache[key] = value
        el.set_text(value)

    def update_usage() -> None:
        nonlocal last_usage_html
        extra = None
        proc = STATE.runner.proc
        if proc is not None:
            try:
                if proc.poll() is None:
                    extra = proc.pid
            except Exception:
                extra = None
        try:
            snap = usage_monitor.snapshot(extra_pid=extra)
        except Exception:
            return
        last_usage_snap.clear()
        last_usage_snap.update(snap)
        html = usage_html(snap)
        if html != last_usage_html:
            last_usage_html = html
            try:
                usage_html_el.set_content(html)
            except Exception:
                pass
        cpu = float(snap.get("cpu_pct") or 0.0)
        ram = fmt_bytes(int(snap.get("rss_bytes") or 0))
        total = int(snap.get("host_total") or 0)
        if total:
            ram = f"{ram} / {fmt_bytes(total)}"
        _text(footer_usage, "usage", f"CPU {cpu:.0f}%  ·  RAM {ram}")

    def update_stats(*, force: bool = False) -> None:
        nonlocal last_stats_at
        now = time.monotonic()
        running = STATE.runner.running
        if running and not force and (now - last_stats_at) < 2.5:
            return
        last_stats_at = now

        ws = STATE.workspace or STATE.runner.output_dir
        if running:
            if ui_cache.get("dot") != "run":
                ui_cache["dot"] = "run"
                status_dot.classes(replace="rp-status-dot run")
        elif STATE.runner.exit_code is not None:
            code = STATE.runner.exit_code
            _text(status_label, "status", f"DONE  exit {code}")
            dot = "live" if code == 0 else "dead"
            if ui_cache.get("dot") != dot:
                ui_cache["dot"] = dot
                status_dot.classes(
                    replace="rp-status-dot live" if code == 0 else "rp-status-dot dead"
                )
            _text(footer_status, "footer_status", f"DONE  {code}")
            _text(eta_label, "eta", "")
        else:
            _text(status_label, "status", "IDLE")
            if ui_cache.get("dot") != "idle":
                ui_cache["dot"] = "idle"
                status_dot.classes(replace="rp-status-dot")
            _text(footer_status, "footer_status", "IDLE")
            _text(eta_label, "eta", "")

        if STATE.domain:
            _text(footer_target, "target", STATE.domain)
        if not ws:
            if ui_cache.get("stats"):
                ui_cache["stats"] = ""
                stats_html.set_content("")
            _text(footer_path, "path", "")
            if running:
                _text(status_label, "status", "RUNNING")
                _text(footer_status, "footer_status", "RUNNING")
            return
        ws = Path(ws)
        _text(footer_path, "path", str(ws))
        st = load_scan_status(ws / "scan_status.json") if running else {}
        if running:
            pct = int(st.get("pct") or 0)
            left_s = int(st.get("remaining_s") or 0)
            stage = str(st.get("stage_name") or "")
            if st:
                left = rp.fmt_remaining_short(left_s)
                _text(status_label, "status", f"RUNNING  {pct}%")
                _text(footer_status, "footer_status", f"RUNNING  ~{left}")
                _text(
                    eta_label,
                    "eta",
                    f"{st.get('timing') or f'About {pct}% done'}  {stage}",
                )
            else:
                _text(status_label, "status", "RUNNING")
                _text(footer_status, "footer_status", "RUNNING")
                _text(eta_label, "eta", "Estimating remaining time…")
        subs = count_lines(ws / "subdomains.txt")
        live = count_lines(ws / "live_hosts.txt")
        urls = count_lines(ws / "files_to_scan.txt")
        findings_n = len(STATE.findings)
        if not running and findings_n == 0:
            findings_n = len(load_json_list(ws / "findings.json"))
        html = (
            "<div class='rp-stat-grid'>"
            f"<div class='rp-stat'><div class='k'>Subs</div><div class='v'>{subs}</div></div>"
            f"<div class='rp-stat'><div class='k'>Live</div><div class='v'>{live}</div></div>"
            f"<div class='rp-stat'><div class='k'>URLs</div><div class='v'>{urls}</div></div>"
            f"<div class='rp-stat'><div class='k'>Keys</div><div class='v'>{findings_n}</div></div>"
            f"<div class='rp-stat'><div class='k'>CPU</div><div class='v'>"
            f"{float(last_usage_snap.get('cpu_pct') or 0):.0f}%</div></div>"
            f"<div class='rp-stat'><div class='k'>RAM</div><div class='v'>"
            f"{fmt_bytes(int(last_usage_snap.get('rss_bytes') or 0))}</div></div>"
            "</div>"
        )
        if ui_cache.get("stats") != html:
            ui_cache["stats"] = html
            stats_html.set_content(html)

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
        try:
            update_usage()
        except Exception:
            pass
        lines = STATE.runner.drain_logs()
        if lines:
            STATE.log_lines.extend(lines)
            if len(STATE.log_lines) > 400:
                STATE.log_lines = STATE.log_lines[-300:]

            if lines:
                text = "\n".join(lines)
                if len(text) > CONSOLE_PUSH_CHARS:
                    text = text[-CONSOLE_PUSH_CHARS:]
                try:
                    console.push(text)
                except Exception:
                    pass
            for ln in lines:
                if "[/" in ln or "/6]" in ln:
                    detect_stage(ln)

        if STATE.runner.running:
            update_stats()
            ws = Path(STATE.workspace or STATE.runner.output_dir or "")
            if str(ws):
                sigs = (
                    workspace_file_sig(ws / "findings_stream.jsonl"),
                    workspace_file_sig(ws / "unique_findings.json"),
                    workspace_file_sig(ws / "findings.json"),
                    workspace_file_sig(ws / "informational.json"),
                    workspace_file_sig(ws / "source_map_exposures.json"),
                )
                if sigs != getattr(STATE, "_finding_sigs", None):
                    STATE._finding_sigs = sigs
                    try:
                        ingest_workspace_findings(ws)
                    except Exception:
                        pass
                    STATE._dash_sig = None
                    try:
                        build_ui.render_findings()
                    except Exception:
                        pass
                    try:
                        build_ui.render_vendors()
                    except Exception:
                        pass

        elif STATE.runner.finished_at and STATE.runner.exit_code is not None:
            # Finalize once
            if getattr(STATE, "_finalized_at", None) != STATE.runner.finished_at:
                STATE._finalized_at = STATE.runner.finished_at
                STATE.workspace = STATE.runner.output_dir
                try:
                    STATE.history = rp.load_scan_history()
                except Exception:
                    pass
                try:
                    build_ui.reload_findings()  
                except Exception:
                    pass
                try:
                    build_ui.refresh_artifacts()  
                except Exception:
                    pass
                try:
                    build_ui.render_history()  
                except Exception:
                    pass
                try:
                    build_ui.refresh_targets()  
                except Exception:
                    pass
                try:
                    ui.notify(
                        "Scan finished — reports are in Artifacts (including remediation.md if LLM is on)",
                        type="positive",
                    )
                except Exception:
                    pass
            update_stats(force=True)

    try:
        update_usage()
    except Exception:
        pass
    ui.timer(1.0, on_tick)


def _quiet_interrupt_hook(exc_type, exc, tb) -> None:
    if issubclass(exc_type, (KeyboardInterrupt, asyncio.CancelledError, SystemExit)):
        return
    sys.__excepthook__(exc_type, exc, tb)


def _stop_pipeline_quietly() -> None:
    try:
        STATE.runner.stop()
    except Exception:
        pass


class _DropNiceguiBanner:
    """Hide NiceGUI's 'ready to go' line; keep our own startup prints."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, data):
        if isinstance(data, str) and data.startswith("NiceGUI ready to go"):
            return len(data)
        return self._stream.write(data)

    def flush(self):
        return self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _ui_run(**kwargs: Any) -> None:
    """Call ui.run with only kwargs this NiceGUI version accepts."""
    params = inspect.signature(ui.run).parameters
    accepted = {
        key: value
        for key, value in kwargs.items()
        if key in params and params[key].kind != inspect.Parameter.VAR_KEYWORD
    }
    wrap_stdout = "show_welcome_message" not in params
    old = sys.stdout
    if wrap_stdout:
        sys.stdout = _DropNiceguiBanner(old)
    try:
        ui.run(**accepted)
    finally:
        sys.stdout = old


def native_backend_available() -> bool:
    """True if pywebview can be imported (GTK WebKit on Linux)."""
    try:
        import webview  # noqa: F401
        return True
    except Exception:
        return False


def has_graphical_display() -> bool:
    if os.name == "nt":
        return True
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def want_native_window(
    native_flag: bool = False,
    browser_flag: bool = False,
) -> bool:
    """
    Desktop window vs Firefox/localhost.
    Env RECONPIPE_GUI_NATIVE=0 forces browser (used by tests).
    """
    if browser_flag:
        return False
    if native_flag:
        return True
    raw = (os.environ.get("RECONPIPE_GUI_NATIVE") or "").strip().lower()
    if raw in {"0", "false", "no", "browser", "off"}:
        return False
    if raw in {"1", "true", "yes", "native", "on"}:
        return True
    return has_graphical_display()


def parse_gui_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconpipegui",
        description="ReconPipe GUI — desktop window by default (no Firefox).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--native",
        action="store_true",
        help="Open a desktop window (WebKit), not Firefox",
    )
    mode.add_argument(
        "--browser",
        action="store_true",
        help="Serve on localhost for a web browser",
    )
    parser.add_argument("--host", default=None, help="Bind address (browser mode)")
    parser.add_argument("--port", type=int, default=None, help="Bind port")
    args, unknown = parser.parse_known_args(argv)
    if argv is None:
        sys.argv[:] = [sys.argv[0], *unknown]
    return args


def _native_install_hint() -> str:
    return (
        "Native window needs pywebview + WebKit:\n"
        "  pip3 install pywebview\n"
        "  sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1"
    )


def main() -> None:
    sys.excepthook = _quiet_interrupt_hook
    cli = parse_gui_args()
    host = cli.host or os.environ.get("RECONPIPE_GUI_HOST", "127.0.0.1")
    port = int(cli.port or os.environ.get("RECONPIPE_GUI_PORT", "8088"))
    show = os.environ.get("RECONPIPE_GUI_SHOW", "0").strip() in {"1", "true", "True"}

    native = want_native_window(cli.native, cli.browser)
    if native and not native_backend_available():
        if cli.native or (os.environ.get("RECONPIPE_GUI_NATIVE") or "").strip().lower() in {
            "1", "true", "yes", "native", "on",
        }:
            print(_native_install_hint(), file=sys.stderr)
            raise SystemExit(2)
        print("pywebview not installed — using localhost instead of a desktop window.", file=sys.stderr)
        print(_native_install_hint(), file=sys.stderr)
        native = False

    if native:
        show = False
        print("ReconPipe GUI — desktop window (not Firefox)")
        print("Close the window or press Ctrl+C to stop.")
    else:
        print(f"ReconPipe GUI → http://{host}:{port}")
        print("Press Ctrl+C to stop.")


    run_kwargs: Dict[str, Any] = dict[str, Any](
        title="ReconPipe",
        host="127.0.0.1" if native else host,
        reload=False,
        show=show,
        native=native,
        favicon="assets/reconpipe.ico",
        dark=True,
        prod_js=True,
        show_welcome_message=False,
        uvicorn_logging_level="warning",
        binding_refresh_interval=2.0,
        message_history_length=0,
        reconnect_timeout=30.0,
    )
    if native:
        run_kwargs["window_size"] = (1440, 900)
        run_kwargs["frameless"] = False

    else:
        run_kwargs["port"] = port

    try:
        _ui_run(**run_kwargs)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        _stop_pipeline_quietly()
        print("Stopped.")


if __name__ in {"__main__", "__mp_main__"}:
    try:
        build_ui()
        main()
    except (KeyboardInterrupt, asyncio.CancelledError):
        _stop_pipeline_quietly()
        print("Stopped.")
        raise SystemExit(0) from None
