#!/usr/bin/env python3
"""LLM settings, redaction, and remediation-report helpers."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402
import reconpipe_llm as llm  # noqa: E402


class LlmSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.patcher = patch.dict(os.environ, {"RECONPIPE_HOME": str(self.home)})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_settings_roundtrip(self):
        path = llm.save_app_settings(
            {
                "enabled": True,
                "auto": False,
                "provider": "openai",
                "model": "gpt-4o-mini",
                "base_url": "https://api.openai.com/v1",
                "timeout": 90,
                "max_findings": 12,
                "dark": False,
            },
            llm_key="sk-test-not-real",
        )
        self.assertTrue(path.is_file())
        saved = llm.load_app_settings()
        self.assertTrue(saved["enabled"])
        self.assertFalse(saved["auto"])
        self.assertEqual(saved["provider"], "openai")
        self.assertEqual(saved["model"], "gpt-4o-mini")
        self.assertFalse(saved["dark"])
        self.assertEqual(llm.load_llm_key(), "sk-test-not-real")
        keys = rp.load_user_keys()
        self.assertEqual(keys.get("llm"), "sk-test-not-real")

    def test_default_auto_is_off(self):
        saved = llm.default_llm_settings()
        self.assertFalse(saved["auto"])
        self.assertFalse(saved["enabled"])
        loaded = llm.load_app_settings()
        self.assertFalse(loaded["auto"])

    def test_ci_skips_llm_unless_forced(self):
        llm.save_app_settings({"enabled": True, "auto": True, "provider": "ollama"})
        args = rp.build_parser().parse_args(["-d", "example.com", "--ci"])
        rp.apply_ci_defaults(args)
        llm.apply_llm_settings(args)
        self.assertFalse(args.llm)
        self.assertTrue(args.skip_llm)
        args2 = rp.build_parser().parse_args(["-d", "example.com", "--ci", "--llm"])
        rp.apply_ci_defaults(args2)
        llm.apply_llm_settings(args2)
        self.assertTrue(args2.llm)

    def test_saved_auto_off_skips_scan_hook(self):
        llm.save_app_settings({"enabled": True, "auto": False, "provider": "ollama"})
        args = rp.build_parser().parse_args(["-d", "example.com"])
        llm.apply_llm_settings(args)
        self.assertFalse(args.llm)

    def test_argv_includes_llm_flags(self):
        argv = rp.argv_from_options(
            {
                "domain": "example.com",
                "llm": True,
                "llm_provider": "ollama",
                "llm_model": "llama3.1",
                "llm_base_url": "http://127.0.0.1:11434",
            }
        )
        self.assertIn("--llm", argv)
        self.assertIn("--llm-provider", argv)
        self.assertIn("ollama", argv)


class RemediationReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.patcher = patch.dict(os.environ, {"RECONPIPE_HOME": str(self.home)})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_prompt_redacts_secret(self):
        secret = "sk_live_" + "A" * 40
        rows = llm.findings_for_prompt(
            [
                {
                    "type": "stripe_live",
                    "key": secret,
                    "source_url": "https://cdn.example.com/app.js",
                    "valid": True,
                    "severity": "critical",
                    "note": "VALID",
                }
            ],
            redact_key=rp.redact_key,
        )
        blob = json.dumps(rows)
        self.assertNotIn(secret, blob)
        self.assertIn("sk_l", blob)
        prompt = llm.build_user_prompt("example.com", rows)
        self.assertNotIn(secret, prompt)
        self.assertIn("exploit", llm.SYSTEM_PROMPT.lower() or "do not write exploit")
        self.assertIn("Do not write exploit", llm.SYSTEM_PROMPT)

    def test_fallback_has_verify_and_fix(self):
        rows = llm.findings_for_prompt(
            [
                {
                    "type": "hubspot_api",
                    "key": "pat-na1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "source_url": "https://example.com/app.js",
                    "valid": True,
                    "severity": "high",
                    "note": "VALID: HubSpot",
                    "revocation": "https://app.hubspot.com/private-apps",
                }
            ],
            redact_key=rp.redact_key,
        )
        md = llm.build_fallback_markdown("example.com", rows)
        self.assertIn("**Verify**", md)
        self.assertIn("**Fix**", md)
        self.assertIn("hubspot_api", md)
        self.assertNotIn("pat-na1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", md)

    def test_write_uses_llm_text_when_enabled(self):
        out = Path(self.tmp.name) / "scan"
        out.mkdir()
        secret = "ghp_" + "x" * 36
        args = SimpleNamespace(
            llm=True,
            skip_llm=False,
            ci=False,
            llm_provider="ollama",
            llm_model="llama3.1",
            llm_base_url="http://127.0.0.1:11434",
            llm_key="",
            llm_timeout=30,
            llm_max_findings=10,
        )
        with patch.object(llm, "chat_completion", return_value="# Remediation\n\nRotate the token.\n"):
            dest = llm.maybe_write_llm_report(
                out,
                "example.com",
                [{"type": "github_pat", "key": secret, "valid": True, "source_url": "https://ex.com/a.js"}],
                args=args,
            )
        self.assertIsNotNone(dest)
        text = dest.read_text(encoding="utf-8")
        self.assertIn("Rotate the token", text)
        self.assertNotIn(secret, text)
        meta = json.loads((out / "llm_report.json").read_text(encoding="utf-8"))
        self.assertTrue(meta["llm_used"])
        self.assertTrue(meta["redacted"])

    def test_write_falls_back_when_llm_fails(self):
        out = Path(self.tmp.name) / "scan2"
        out.mkdir()
        args = SimpleNamespace(
            llm=True,
            skip_llm=False,
            ci=False,
            llm_provider="ollama",
            llm_model="llama3.1",
            llm_base_url="http://127.0.0.1:11434",
            llm_key="",
            llm_timeout=5,
            llm_max_findings=10,
        )
        with patch.object(llm, "chat_completion", side_effect=OSError("connection refused")):
            dest = llm.maybe_write_llm_report(
                out,
                "example.com",
                [{"type": "openai_key", "key": "sk-proj-not-a-real-key-value", "valid": True}],
                args=args,
                force=True,
            )
        self.assertIsNotNone(dest)
        text = dest.read_text(encoding="utf-8")
        self.assertIn("LLM unavailable", text)
        self.assertIn("**Fix**", text)
        self.assertNotIn("sk-proj-not-a-real-key-value", text)

    def test_disabled_skips_file(self):
        out = Path(self.tmp.name) / "scan3"
        out.mkdir()
        args = SimpleNamespace(
            llm=False,
            skip_llm=True,
            ci=False,
            llm_provider="ollama",
            llm_model="llama3.1",
            llm_base_url="http://127.0.0.1:11434",
            llm_key="",
            llm_timeout=5,
            llm_max_findings=10,
        )
        dest = llm.maybe_write_llm_report(out, "example.com", [], args=args)
        self.assertIsNone(dest)
        self.assertFalse((out / "remediation.md").is_file())


if __name__ == "__main__":
    unittest.main()
