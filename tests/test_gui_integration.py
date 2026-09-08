#!/usr/bin/env python3
"""Integration checks for ReconPipe GUI ↔ CLI wiring (no long network scan)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import reconpipe as rp  # noqa: E402


def _make_fixtures(base: Path) -> dict:
    base.mkdir(parents=True, exist_ok=True)
    subs = base / "subs.txt"
    urls = base / "urls.txt"
    subs.write_text("example.com\n", encoding="utf-8")
    urls.write_text(
        "https://example.com/\nhttps://example.com/robots.txt\n",
        encoding="utf-8",
    )
    return {"subs": subs, "urls": urls, "out": base / "out"}


def test_api():
    argv = rp.argv_from_options(
        {
            "domain": "example.com",
            "skip_httpx": True,
            "no_trufflehog": True,
            "no_validate": True,
            "no_fail_on_valid": True,
            "concurrency": 4,
            "gau_threads": 3,
            "headless": False,
        }
    )
    args = rp.build_parser().parse_args(argv)
    assert args.domain == "example.com"
    assert args.no_trufflehog and args.no_validate and args.skip_httpx
    assert args.concurrency == 4
    tools = rp.probe_tools()
    assert "httpx" in tools and "chaos" in tools
    print("[ok] build_parser / argv_from_options / probe_tools")


def test_jwt_retest():
    assert "jwt" in rp.VALIDATORS
    finding = {
        "type": "jwt",
        "key": (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
        "source_url": "https://example.com/app.js",
        "hash": "testhash",
        "confidence": 80,
    }
    result = rp.validate_finding_configured_sync(finding, "example.com")
    assert result.get("type") == "jwt"
    assert result.get("validated") is True or result.get("note")
    print("[ok] validate_finding_configured_sync (jwt)", result.get("note") or result.get("valid"))


def test_pipeline_subprocess():
    tmp = Path(tempfile.mkdtemp(prefix="reconpipe_gui_"))
    try:
        fx = _make_fixtures(tmp)
        cmd = [
            sys.executable,
            str(ROOT / "reconpipe.py"),
            *rp.argv_from_options(
                {
                    "domain": "example.com",
                    "subdomains": str(fx["subs"]),
                    "files": str(fx["urls"]),
                    "output": str(fx["out"]),
                    "skip_httpx": True,
                    "no_trufflehog": True,
                    "no_validate": True,
                    "no_fail_on_valid": True,
                }
            ),
        ]
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        assert proc.returncode == 0, (proc.stdout[-800:] + proc.stderr[-800:])
        findings_path = fx["out"] / "findings.json"
        assert findings_path.is_file()
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        print("[ok] GUI-style subprocess pipeline exit", proc.returncode, "findings", len(data))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_gui_module_compiles_and_helpers():
    src = (ROOT / "reconpipegui.py").read_text(encoding="utf-8")
    compile(src, "reconpipegui.py", "exec")
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "reconpipegui_testmod", ROOT / "reconpipegui.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    assert mod.validate_form({"domain": ""})
    assert not mod.validate_form(
        {"domain": "example.com", "concurrency": 10, "gau_threads": 5}
    )
    assert mod.validate_form(
        {"domain": "bad domain", "concurrency": 10, "gau_threads": 5}
    )
    redacted = mod.redact_secret("sk_live_1234567890abcdef", reveal=False)
    assert "…" in redacted and "sk_l" in redacted
    assert mod.redact_secret("sk_live_1234567890abcdef", reveal=True).startswith("sk_live")
    hits = mod.guess_key_types("sk_live_abcdefghijklmnopqrstuvwx")
    assert "stripe_live" in hits
    assert "github_pat" in mod.validator_type_options()
    status_path = Path(tempfile.mkdtemp()) / "scan_status.json"
    status_path.write_text(
        '{"pct": 40, "remaining_s": 600, "timing": "About 40% done", "stage_name": "URL discovery"}',
        encoding="utf-8",
    )
    st = mod.load_scan_status(status_path)
    assert st.get("pct") == 40 and st.get("remaining_s") == 600
    assert rp.fmt_remaining_short(600) == "10m"
    assert "google_api" in mod.validator_type_options()
    assert "firebase_key" in mod.validator_type_options()
    assert "mailchimp" in mod.validator_type_options()
    runner = mod.PipelineRunner()
    runner._offer_log("https://cdn.example.com/app.js?x=1")
    runner._offer_log("found endpoint /api/v1/users")
    runner._offer_log("[gui] Started: test")
    runner._offer_log("  [3/6] URL DISCOVERY")
    drained = runner.drain_logs()
    assert "[gui] Started: test" in drained
    assert any("/6]" in ln for ln in drained)
    assert not any(ln.startswith("https://") for ln in drained)
    assert mod.want_native_window(browser_flag=True) is False
    assert mod.want_native_window(native_flag=True) is True
    prev_native = os.environ.get("RECONPIPE_GUI_NATIVE")
    os.environ["RECONPIPE_GUI_NATIVE"] = "0"
    try:
        assert mod.want_native_window() is False
        args = mod.parse_gui_args(["--browser", "--port", "9999"])
        assert args.browser and args.port == 9999 and not args.native
    finally:
        if prev_native is None:
            os.environ.pop("RECONPIPE_GUI_NATIVE", None)
        else:
            os.environ["RECONPIPE_GUI_NATIVE"] = prev_native
    assert (ROOT / "reconpipe-gui").is_file()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "hosts.txt"
        p.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
        n1 = mod.count_lines(p)
        n2 = mod.count_lines(p)
        assert n1 == n2 == 2
        p.write_text("a.example.com\n", encoding="utf-8")
        assert mod.count_lines(p) == 1
    src = (ROOT / "reconpipegui.py").read_text(encoding="utf-8")
    assert "Passive intel" in src
    assert "--shodan-key" in src and "--zoomeye-key" in src and "--censys-id" in src
    assert "Save API keys" in src and "Save target" in src
    print("[ok] reconpipegui import + form validation helpers")


def test_gui_server_smoke():
    """Start GUI briefly and hit HTTP root."""
    import socket
    import time
    import urllib.request

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["RECONPIPE_GUI_HOST"] = "127.0.0.1"
    env["RECONPIPE_GUI_PORT"] = str(port)
    env["RECONPIPE_GUI_SHOW"] = "0"
    env["RECONPIPE_GUI_NATIVE"] = "0"

    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "reconpipegui.py")],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        url = f"http://127.0.0.1:{port}/"
        ok = False
        last_err = None
        for _ in range(40):
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                raise AssertionError(f"GUI exited early code={proc.returncode}\n{out[:2000]}")
            try:
                with urllib.request.urlopen(url, timeout=1.5) as resp:
                    body = resp.read(200)
                    if resp.status == 200 and body:
                        ok = True
                        break
            except Exception as exc:
                last_err = exc
                time.sleep(0.35)
        assert ok, f"GUI did not respond on {url}: {last_err}"
        print(f"[ok] GUI HTTP smoke test on {url}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    test_api()
    test_jwt_retest()
    test_pipeline_subprocess()
    test_gui_module_compiles_and_helpers()
    test_gui_server_smoke()
    print("\nALL GUI INTEGRATION TESTS PASSED")
