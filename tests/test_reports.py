#!/usr/bin/env python3
"""Vendor dashboard and pentest / executive report templates."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402
import reconpipe_reports as reports  # noqa: E402


class VendorDashboardTests(unittest.TestCase):
    def test_groups_by_company_and_redacts(self):
        secret = "sk_live_" + "A" * 24
        groups = reports.group_findings_by_vendor(
            [
                {
                    "type": "stripe_live",
                    "key": secret,
                    "valid": True,
                    "severity": "critical",
                    "source_url": "https://cdn.example.com/app.js",
                    "note": "VALID",
                },
                {
                    "type": "stripe_test",
                    "key": "sk_test_" + "B" * 24,
                    "valid": False,
                    "severity": "medium",
                    "source_url": "https://cdn.example.com/app.js",
                },
            ],
            redact=rp.redact_key,
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["name"], "Stripe")
        self.assertEqual(groups[0]["live"], 1)
        self.assertEqual(groups[0]["total"], 2)
        blob = json.dumps(groups)
        self.assertNotIn(secret, blob)
        self.assertIn("sk_l", blob)
        html = reports.vendor_dashboard_html("example.com", groups)
        self.assertIn("Stripe", html)
        self.assertNotIn(secret, html)

    def test_hubspot_maps_to_crm(self):
        groups = reports.group_findings_by_vendor(
            [{"type": "hubspot_api", "key": "pat-na1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "valid": True}],
            redact=rp.redact_key,
        )
        self.assertEqual(groups[0]["id"], "hubspot")
        self.assertIn("CRM", groups[0]["category"])


class ReportTemplateTests(unittest.TestCase):
    def test_pentest_has_bounty_sections(self):
        groups = reports.group_findings_by_vendor(
            [
                {
                    "type": "openai_key",
                    "key": "sk-proj-not-a-real-openai-key-value",
                    "valid": True,
                    "severity": "high",
                    "source_url": "https://example.com/.env",
                    "revocation": "https://platform.openai.com/api-keys",
                }
            ],
            redact=rp.redact_key,
        )
        md = reports.export_pentest_markdown("example.com", groups)
        self.assertIn("Steps to reproduce", md)
        self.assertIn("Impact", md)
        self.assertIn("Remediation", md)
        self.assertIn("CWE-798", md)
        self.assertIn("Key Tester", md)
        self.assertNotIn("sk-proj-not-a-real-openai-key-value", md)
        self.assertNotIn("exploit PoC", md.lower())

    def test_executive_is_plain_language(self):
        groups = reports.group_findings_by_vendor(
            [
                {
                    "type": "aws_access_key",
                    "key": "AKIAIOSFODNN7EXAMPLE",
                    "valid": True,
                    "severity": "critical",
                    "source_url": "https://example.com/config.js",
                }
            ],
            redact=rp.redact_key,
        )
        md = reports.export_executive_markdown("example.com", groups)
        self.assertIn("Bottom line", md)
        self.assertIn("Amazon Web Services", md)
        self.assertIn("What this means", md)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", md)
        html = reports.export_executive_html("example.com", groups)
        self.assertIn("Leadership briefing", html)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", html)

    def test_render_template_picker(self):
        groups = reports.group_findings_by_vendor([], redact=rp.redact_key)
        pentest = reports.render_report_template("pentest", "ex.com", groups)
        execu = reports.render_report_template("executive", "ex.com", groups)
        self.assertIn("CWE-798", pentest)
        self.assertIn("Security briefing", execu)

    def test_write_all_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            written = reports.write_vendor_and_reports(
                out,
                "example.com",
                [{"type": "groq_api", "key": "gsk_" + "A" * 20, "valid": True, "severity": "high"}],
                redact=rp.redact_key,
            )
            for name in (
                "vendors.json",
                "vendors.html",
                "report_pentest.md",
                "report_executive.md",
                "report_executive.html",
            ):
                self.assertIn(name, written)
                self.assertTrue((out / name).is_file(), name)
            data = json.loads((out / "vendors.json").read_text(encoding="utf-8"))
            self.assertEqual(data["vendors"][0]["id"], "groq")


class NewPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rp.load_default_config()

    def test_new_prefix_types_loaded(self):
        for name in (
            "groq_api",
            "xai_api",
            "perplexity_api",
            "fireworks_api",
            "slack_app_token",
            "figma_token",
            "databricks_token",
            "postman_api",
            "sonar_token",
            "cloudinary_url",
            "razorpay_key",
            "flutterwave_secret",
        ):
            self.assertIn(name, rp.PATTERNS, name)
            self.assertIn(name, rp.VALIDATORS, name)

    def test_samples_match_and_classify(self):
        samples = {
            "groq_api": "gsk_" + "A" * 20,
            "figma_token": "figd_" + "B" * 40,
            "postman_api": "PMAK-" + "a" * 24 + "-" + "b" * 34,
            "razorpay_key": "rzp_live_" + "C" * 14,
            "cloudinary_url": "cloudinary://abc:secretpass@demo-cloud",
            "xai_api": "xai-" + "D" * 20,
            "slack_app_token": "xapp-1-" + "E" * 20,
        }
        for name, sample in samples.items():
            self.assertTrue(rp.re.search(rp.PATTERNS[name], sample), name)
            self.assertEqual(rp.classify_secret_type(sample), name, name)

    def test_scanner_picks_prefix_keys_from_js_line(self):
        groq = "gsk_" + "F" * 20
        figma = "figd_" + "G" * 40
        line = f"const cfg = {{ groq: '{groq}', figma: '{figma}' }};"
        hits = rp.findings_from_removed_js_lines(
            [line], js_url="https://example.com/app.js", old_ts="20200101", new_ts="live"
        )
        types = {h["type"] for h in hits}
        self.assertIn("groq_api", types)
        self.assertIn("figma_token", types)
        self.assertTrue(any(h["key"] == groq for h in hits))


if __name__ == "__main__":
    unittest.main()
