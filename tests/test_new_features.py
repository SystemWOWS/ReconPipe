#!/usr/bin/env python3
"""New detectors, reports, scope, downloads, alerting helpers."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import base64 as b64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402


class NewPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rp.load_default_config()

    def test_validators_present(self):
        for name in (
            "cloudflare_api",
            "azure_sas",
            "huggingface_token",
            "notion_token",
            "grafana_token",
            "hashicorp_vault",
            "datadog_api_key",
            "gcp_service_acct",
            "linear_api_key",
            "supabase_service",
        ):
            self.assertIn(name, rp.PATTERNS)
            self.assertIn(name, rp.VALIDATORS)

    def test_stripe_uses_account_endpoint(self):
        self.assertIn("/v1/account", rp.VALIDATORS["stripe_live"].url)
        self.assertIn("/v1/account", rp.VALIDATORS["stripe_test"].url)
        self.assertIn("/v1/account", rp.VALIDATORS["stripe_restricted"].url)
        self.assertEqual(rp.VALIDATORS["stripe_live"].restricted_codes, [403])

    def test_azure_sas_live_and_expired(self):
        live = (
            "sv=2021-08-06&ss=b&sp=r&se=2099-12-31T00:00:00Z"
            "&sig=abcdefghijklmnopqrstuv"
        )
        out = rp.validate_azure_sas(live)
        self.assertTrue(out["valid"])
        self.assertIn("LIVE", out["note"])
        dead = (
            "sv=2021-08-06&ss=b&sp=r&se=2001-01-01T00:00:00Z"
            "&sig=abcdefghijklmnopqrstuv"
        )
        out2 = rp.validate_azure_sas(dead)
        self.assertFalse(out2["valid"])
        self.assertIn("expired", out["note"].lower() + out2["note"].lower())

    def test_gcp_service_account_inspect(self):
        blob = (
            '{"type":"service_account","project_id":"demo",'
            '"private_key":"-----BEGIN PRIVATE KEY-----\\nMII\\n-----END PRIVATE KEY-----\\n",'
            '"client_email":"foo@demo.iam.gserviceaccount.com"}'
        )
        out = rp.validate_gcp_service_account(blob)
        self.assertTrue(out["valid"])
        self.assertIn("foo@demo", out["note"])

    def test_supabase_jwt_reclassify(self):
        header = b64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        payload = b64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "https://xyzcompany.supabase.co/auth/v1",
                    "role": "service_role",
                    "ref": "xyzcompany",
                    "exp": 9999999999,
                }
            ).encode()
        ).decode().rstrip("=")
        token = f"{header}.{payload}.sig"
        meta = rp.inspect_jwt(token)
        self.assertTrue(rp.is_supabase_service(meta))
        generic = rp.inspect_jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertFalse(rp.is_supabase_service(generic))


class ScopeAndCliTests(unittest.TestCase):
    def test_host_scope_globs(self):
        inc = ["*.api.example.com", "example.com"]
        exc = ["*.cdn.example.com"]
        self.assertTrue(rp.host_in_scope("api.example.com", inc, exc))
        self.assertTrue(rp.host_in_scope("foo.api.example.com", inc, exc))
        self.assertFalse(rp.host_in_scope("static.cdn.example.com", inc, exc))
        self.assertFalse(rp.host_in_scope("other.com", inc, exc))

    def test_apply_scope_files(self):
        rp.SCOPE_INCLUDE = []
        rp.SCOPE_EXCLUDE = []
        with tempfile.TemporaryDirectory() as td:
            inc = Path(td) / "inc.txt"
            exc = Path(td) / "exc.txt"
            inc.write_text("*.api.example.com\n", encoding="utf-8")
            exc.write_text("*.cdn.example.com\n", encoding="utf-8")
            rp.apply_scope_files(str(inc), str(exc))
            self.assertTrue(rp.host_in_scope("a.api.example.com"))
            self.assertFalse(rp.host_in_scope("x.cdn.example.com"))
        rp.SCOPE_INCLUDE = []
        rp.SCOPE_EXCLUDE = []

    def test_default_target_scope_drops_other_domains(self):
        rp.SCOPE_INCLUDE = []
        rp.SCOPE_EXCLUDE = []
        added = rp.apply_default_target_scope("google.com")
        self.assertIn("google.com", added)
        self.assertIn("*.google.com", added)
        self.assertTrue(rp.host_in_scope("www.google.com"))
        self.assertTrue(rp.host_in_scope("mail.google.com"))
        self.assertFalse(rp.host_in_scope("yahoo.com"))
        urls = rp.filter_urls_in_scope(
            [
                "https://www.google.com/app.js",
                "https://yahoo.com/ads.js",
                "https://web.archive.org/web/20200101000000/https://google.com/x.js",
                "/work/recon_google_com/downloaded_files/local.js",
            ]
        )
        self.assertIn("https://www.google.com/app.js", urls)
        self.assertNotIn("https://yahoo.com/ads.js", urls)
        self.assertTrue(any("web.archive.org" in u for u in urls))
        self.assertTrue(any(u.endswith("local.js") for u in urls))
        off = {"type": "generic", "source_url": "https://yahoo.com/x.js", "key": "x"}
        on = {"type": "generic", "source_url": "https://google.com/x.js", "key": "y"}
        kept = rp.filter_findings_in_scope([off, on])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["source_url"], "https://google.com/x.js")
        rp.SCOPE_INCLUDE = []
        rp.SCOPE_EXCLUDE = []

    def test_default_scope_skips_when_include_already_set(self):
        rp.SCOPE_INCLUDE = ["*.api.example.com"]
        rp.SCOPE_EXCLUDE = []
        self.assertEqual(rp.apply_default_target_scope("example.com"), [])
        self.assertEqual(rp.SCOPE_INCLUDE, ["*.api.example.com"])
        rp.SCOPE_INCLUDE = []

    def test_no_default_scope_flag(self):
        args = rp.build_parser().parse_args(["-d", "example.com", "--no-default-scope"])
        self.assertTrue(args.no_default_scope)
        argv = rp.argv_from_options({"domain": "example.com", "no_default_scope": True})
        self.assertIn("--no-default-scope", argv)

    def test_subfinder_and_gospider_delay(self):
        sf = rp.build_subfinder_cmd(
            "example.com", "out.txt", help_blob="-d string\n-o string\n-silent"
        )
        self.assertEqual(sf[0], "subfinder")
        self.assertIn("-d", sf)
        self.assertIn("-silent", sf)
        gs = rp.build_gospider_cmd(
            "hosts.txt",
            "out",
            help_blob=(
                "  -S, --sites string\n  --delay int\n  -q, --quiet\n"
                "  --js\n  --robots\n  -o, --output\n  -c\n  -d\n  -t"
            ),
        )
        self.assertIn("--delay", gs)
        gau = rp.build_gau_cmd("example.com", 5, help_blob="--threads\n--timeout")
        self.assertIn("--timeout", gau)

    def test_parser_domain_list_and_flags(self):
        p = rp.build_parser()
        args = p.parse_args(
            [
                "--domain-list",
                "domains.txt",
                "--exclude-pattern",
                "exc.txt",
                "--notify-webhook",
                "https://example.com/hook",
                "--skip-subfinder",
            ]
        )
        self.assertEqual(args.domain_list, "domains.txt")
        self.assertTrue(args.skip_subfinder)
        self.assertEqual(args.notify_webhook, "https://example.com/hook")
        argv = rp.argv_from_options(
            {
                "domain": "example.com",
                "skip_subfinder": True,
                "notify_webhook": "https://hooks.example/x",
                "exclude_pattern": "exc.txt",
            }
        )
        self.assertIn("--skip-subfinder", argv)
        self.assertIn("--notify-webhook", argv)
        self.assertIn("--exclude-pattern", argv)


class ReportAndDiffTests(unittest.TestCase):
    def test_severity_tiers(self):
        self.assertEqual(
            rp.finding_severity({"type": "aws_access_key"}), "critical"
        )
        self.assertEqual(rp.finding_severity({"type": "github_pat"}), "high")
        self.assertEqual(rp.finding_severity({"type": "stripe_test"}), "medium")
        self.assertEqual(rp.finding_severity({"type": "jwt"}), "low")
        self.assertEqual(
            rp.finding_severity({"type": "sendgrid", "note": "VALID (restricted)"}),
            "medium",
        )

    def test_reports_and_diff(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            findings = [
                {
                    "type": "github_pat",
                    "key": "ghp_" + "a" * 36,
                    "source_url": "https://example.com/a.js",
                    "valid": True,
                    "note": "VALID",
                    "hash": "aaa",
                }
            ]
            rp.write_html_report(out / "report.html", "example.com", findings)
            rp.write_markdown_report(out / "report.md", "example.com", findings)
            rp.write_csv_report(out / "findings.csv", findings)
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("github_pat", html)
            self.assertIn("ghp_…", html)
            md = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Severity", md)
            csv_text = (out / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("severity", csv_text)
            prev = [{"type": "openai_key", "key": "sk-old", "hash": "bbb"}]
            diff = rp.compare_scan_runs(prev, findings)
            self.assertEqual(len(diff["new"]), 1)
            self.assertEqual(len(diff["resolved"]), 1)

    def test_split_tester_keys(self):
        keys = rp.split_tester_keys("a\n b \n\nc,\n")
        self.assertEqual(keys, ["a", "b", "c"])

    def test_github_scopes_header(self):
        result = {"note": "VALID: Authenticated GitHub user", "type": "github_pat"}
        rp.attach_github_scopes(result, {"X-OAuth-Scopes": "repo, admin:org"})
        self.assertEqual(result["github_scopes"], ["repo", "admin:org"])
        self.assertIn("scopes=", result["note"])

    def test_content_type_gating(self):
        self.assertTrue(rp.content_type_allowed("application/javascript"))
        self.assertTrue(rp.content_type_allowed("application/json; charset=utf-8"))
        self.assertFalse(rp.content_type_allowed("image/png"))
        self.assertFalse(rp.content_type_allowed("video/mp4"))
        self.assertTrue(rp.content_type_allowed(""))

    def test_download_resume_and_skip(self):
        with tempfile.TemporaryDirectory() as td:
            dl = Path(td)
            url = "https://example.com/app.js"
            dest = dl / rp.download_filename(url)
            dest.write_text("cached", encoding="utf-8")
            status = rp.download_url_file(url, dl, "test-ua")
            self.assertEqual(status, "cached")

    def test_notify_webhook_redacts(self):
        captured = {}

        def fake_urlopen(req, timeout=12):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())

            class Resp:
                status = 204

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return Resp()

        with patch("urllib.request.urlopen", fake_urlopen):
            ok = rp.notify_webhook(
                "https://discord.com/api/webhooks/1/abc",
                {"text": "2 valid key(s) on example.com", "keys": [{"key": "ghp_…aaaa"}]},
            )
        self.assertTrue(ok)
        self.assertIn("content", captured["body"])

    def test_load_domain_list(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "d.txt"
            p.write_text("a.com\n# skip\nb.com\n", encoding="utf-8")
            self.assertEqual(rp.load_domain_list(str(p)), ["a.com", "b.com"])


if __name__ == "__main__":
    unittest.main()
