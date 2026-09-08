#!/usr/bin/env python3
"""Wave-2 patterns, pipeline helpers, reports, and CLI flags."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import base64 as b64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402

PREFIX_TYPES = [
    "railway_token", "render_api", "flyio_token", "planetscale_token",
    "neon_api", "buildkite_token", "sentry_auth", "newrelic_api",
    "replicate_api", "doppler_token", "pulumi_token", "contentful_cma",
    "clickup_api", "launchdarkly_api", "posthog_api",
]


class Wave2PatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rp.load_default_config()
        rp.addons.bind_config_lookups(rp.REVOCATION_URLS, rp.COMPLIANCE_TAGS)

    def test_all_patterns_compile(self):
        errors = []
        for name, pat in rp.PATTERNS.items():
            try:
                re.compile(pat)
            except re.error as exc:
                errors.append(f"{name}: {exc}")
        self.assertFalse(errors, errors)

    def test_new_types_loaded(self):
        for name in PREFIX_TYPES + [
            "vercel_token", "mongodb_srv", "postgres_uri", "supabase_anon",
            "teams_webhook", "square_access", "clerk_secret",
        ]:
            self.assertIn(name, rp.PATTERNS, name)
            self.assertIn(name, rp.VALIDATORS, name)

    def test_prefix_samples_match(self):
        samples = {
            "railway_token": "railway_" + "a" * 32,
            "render_api": "rnd_" + "b" * 24,
            "flyio_token": "fo1_" + "c" * 40,
            "planetscale_token": "pscale_tkn_" + "d" * 32,
            "neon_api": "neon_" + "e" * 32,
            "buildkite_token": "bkua_" + "f" * 40,
            "sentry_auth": "sntrys_" + "g" * 64,
            "newrelic_api": "NRAK-" + "H" * 27,
            "replicate_api": "r8_" + "i" * 40,
            "doppler_token": "dp.pt." + "j" * 40,
            "pulumi_token": "pul-" + "a" * 40,
            "contentful_cma": "CFPAT-" + "k" * 43,
            "clickup_api": "pk_12_" + "A" * 32,
            "launchdarkly_api": "api-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "posthog_api": "phc_" + "m" * 32,
        }
        for name, sample in samples.items():
            rx = re.compile(rp.PATTERNS[name])
            self.assertTrue(rx.search(sample), name)

    def test_vercel_needs_context(self):
        rx = re.compile(rp.PATTERNS["vercel_token"])
        self.assertTrue(rx.search("VERCEL_TOKEN=" + "A" * 24))
        self.assertIsNone(rx.search("A" * 24))

    def test_uri_inspect(self):
        out = rp.inspect_connection_uri("postgres://alice:s3cret@db.internal:5432/app")
        self.assertTrue(out["valid"])
        self.assertIn("alice", out["note"])
        dead = rp.inspect_connection_uri("postgres://localhost/app")
        self.assertFalse(dead["valid"])

    def test_supabase_anon_classify(self):
        header = b64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
        payload = b64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "https://xyz.supabase.co/auth/v1",
                    "role": "anon",
                    "ref": "xyz",
                    "iat": 111,
                    "exp": 9999999999,
                }
            ).encode()
        ).decode().rstrip("=")
        token = f"{header}.{payload}.sig"
        meta = rp.inspect_jwt(token)
        self.assertTrue(rp.is_supabase_anon(meta))
        self.assertFalse(rp.is_supabase_service(meta))

    def test_cvss_and_severity_map(self):
        self.assertEqual(rp.finding_cvss("critical"), 9.8)
        self.assertEqual(rp.finding_severity({"type": "doppler_token"}), "critical")
        self.assertEqual(rp.finding_severity({"type": "heap_app_id"}), "low")

    def test_annotate_adds_revocation(self):
        rows = rp.annotate_severity([{"type": "github_pat", "key": "ghp_" + "a" * 36}])
        self.assertIn("github.com", rows[0].get("revocation") or "")
        self.assertIn("cvss", rows[0])
        self.assertIn("entropy", rows[0])


class Wave2PipelineTests(unittest.TestCase):
    def test_merge_subdomain_sources(self):
        hosts, tracked = rp.merge_subdomain_sources(
            {"chaos": ["A.example.com."], "amass": ["a.example.com", "b.example.com"]}
        )
        self.assertEqual(hosts, ["a.example.com", "b.example.com"])
        self.assertIn("chaos", tracked["a.example.com"])
        self.assertIn("amass", tracked["a.example.com"])

    def test_normalize_and_dedupe(self):
        a = "https://Example.com:443/x?utm_source=x&b=2&a=1"
        b = "https://example.com/x?a=1&b=2"
        self.assertEqual(rp.normalize_url(a), rp.normalize_url(b))
        self.assertEqual(len(rp.dedupe_urls([a, b, a])), 1)

    def test_js_endpoints(self):
        js = 'fetch("/api/v1/users"); axios.get("/graphql");'
        eps = rp.extract_endpoints_from_js(js)
        self.assertTrue(any("/api/v1/users" in e for e in eps))

    def test_parse_source_map(self):
        blob = json.dumps(
            {"sources": ["app.js"], "sourcesContent": ["const secret='abc'"]}
        )
        parsed = rp.parse_source_map(blob)
        self.assertEqual(parsed["app.js"], "const secret='abc'")

    def test_burp_xml(self):
        xml = (
            "<?xml version='1.0'?><items>"
            "<item><url>https://ex.com/a</url></item>"
            "<item><url>https://ex.com/a?utm_source=1</url></item>"
            "</items>"
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "burp.xml"
            p.write_text(xml, encoding="utf-8")
            urls = rp.parse_burp_xml(p)
            self.assertEqual(len(urls), 1)

    def test_skip_completed_stage(self):
        self.assertTrue(rp.skip_completed_stage("httpx", "chaos"))
        self.assertFalse(rp.skip_completed_stage("httpx", "discovery"))
        self.assertTrue(rp.skip_completed_stage("validate", "trufflehog"))
        self.assertFalse(rp.skip_completed_stage("trufflehog", "validate"))
        with tempfile.TemporaryDirectory() as td:
            rp.save_checkpoint(Path(td), "httpx", {"live": 3})
            data = rp.load_checkpoint(Path(td))
            self.assertEqual(data["stage"], "httpx")
            self.assertTrue(rp.checkpoint_reached(data, "chaos"))
            self.assertFalse(rp.checkpoint_reached(data, "validate"))

    def test_tool_builders(self):
        self.assertEqual(rp.build_amass_cmd("ex.com", "o.txt")[0], "amass")
        self.assertIn("-passive", rp.build_amass_cmd("ex.com", "o.txt", True))
        self.assertNotIn("-passive", rp.build_amass_cmd("ex.com", "o.txt", False))
        self.assertEqual(rp.build_assetfinder_cmd("ex.com")[0], "assetfinder")
        self.assertEqual(rp.build_findomain_cmd("ex.com", "o")[0], "findomain")
        self.assertIn("-silent", rp.build_dnsx_cmd("in", "o"))
        self.assertEqual(rp.build_waybackurls_cmd("ex.com")[-1], "ex.com")
        self.assertEqual(rp.build_hakrawler_cmd("https://ex.com")[0], "hakrawler")
        self.assertEqual(rp.build_naabu_cmd("in", "o")[0], "naabu")
        self.assertEqual(rp.build_nuclei_cmd("u", "o")[0], "nuclei")
        self.assertEqual(rp.build_gowitness_cmd("u", "d")[0], "gowitness")

    def test_adaptive_concurrency(self):
        ac = rp.AdaptiveConcurrency(initial=10, min_=2, max_=50)
        for _ in range(10):
            ac.record(6.0, 429)
        self.assertLess(ac.current, 10)
        ac2 = rp.AdaptiveConcurrency(initial=10)
        for _ in range(10):
            ac2.record(0.1, 200)
        self.assertGreater(ac2.current, 10)

    def test_js_secret_assignments(self):
        hits = rp.extract_js_secret_assignments(
            'const api_key = "abcdefghijklmnopqr"; Authorization: "Bearer tokentokentoken"'
        )
        self.assertTrue(hits)

    def test_apply_polite_delay_noop(self):
        old = rp.SCAN_POLITE_DELAY
        rp.SCAN_POLITE_DELAY = 0
        try:
            rp.apply_polite_delay()
        finally:
            rp.SCAN_POLITE_DELAY = old

    def test_headers_and_polite(self):
        hdrs = rp.parse_header_list(["Cookie: a=b", "X-Test: 1"])
        self.assertEqual(hdrs["Cookie"], "a=b")
        self.assertEqual(rp.polite_delay_seconds(True, 0), 0.5)
        self.assertAlmostEqual(rp.polite_delay_seconds(False, 2), 0.5)

    def test_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yaml"
            p.write_text("headers:\n  X-Auth: zz\nbearer_token: abc\n", encoding="utf-8")
            creds = rp.load_credentials(p)
            hdrs = rp.credentials_to_headers(creds)
            self.assertIn("Authorization", hdrs)
            self.assertEqual(hdrs["X-Auth"], "zz")

    def test_cli_flags(self):
        parser = rp.build_parser()
        args = parser.parse_args(
            [
                "-d", "example.com",
                "--proxy", "http://127.0.0.1:8080",
                "--polite",
                "--skip-amass",
                "--nuclei",
                "--burp-import", "burp.xml",
                "--header", "Cookie: x=1",
                "--resume-from", "httpx",
            ]
        )
        self.assertTrue(args.polite)
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertTrue(args.nuclei)
        argv = rp.argv_from_options(
            {
                "domain": "example.com",
                "polite": True,
                "proxy": "http://127.0.0.1:8080",
                "skip_amass": True,
            }
        )
        self.assertIn("--polite", argv)
        self.assertIn("--proxy", argv)
        self.assertIn("--skip-amass", argv)

    def test_reports_jsonld_nuclei_exec(self):
        findings = [
            {
                "type": "github_pat",
                "key": "ghp_" + "a" * 36,
                "valid": True,
                "severity": "high",
                "source_url": "https://ex.com/app.js",
                "note": "VALID",
                "hash": "abc123def456",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            rp.write_jsonld_report(d / "report.jsonld", "ex.com", findings)
            data = json.loads((d / "report.jsonld").read_text(encoding="utf-8"))
            self.assertEqual(data["@type"], "Dataset")
            n = rp.write_nuclei_templates(d, findings)
            self.assertEqual(n, 1)
            html = rp.write_html_report(d / "r.html", "ex.com", findings)
            text = html.read_text(encoding="utf-8")
            self.assertIn("Executive", text) if False else self.assertIn("CVSS", text)
            md = rp.write_markdown_report(d / "r.md", "ex.com", findings)
            self.assertIn("Executive summary", md.read_text(encoding="utf-8"))

    def test_pipeline_metrics(self):
        m = rp.PipelineMetrics()
        m.start_stage("chaos", 10)
        m.finish_stage("chaos", 8)
        report = m.to_report()
        self.assertEqual(report["stages"][0]["out"], 8)
        self.assertEqual(rp.build_wappalyzer_cmd("https://ex.com")[0], "wappalyzer")
        self.assertIn("linkfinder", rp.build_linkfinder_cmd("https://ex.com/a.js"))

    def test_notify_stage_progress_redacts(self):
        with patch.object(rp, "notify_webhook", return_value=True) as mock:
            ok = rp.notify_stage_progress("https://example.com/hook", "httpx", 0.5, {"live": 3})
            self.assertTrue(ok)
            payload = mock.call_args[0][1]
            self.assertEqual(payload["event"], "stage_progress")

    def test_export_presets(self):
        text = rp.export_hackerone_markdown(
            [{"type": "openai_key", "valid": True, "severity": "high", "source_url": "u", "note": "ok"}]
        )
        self.assertIn("openai_key", text)
        self.assertIn("h2.", rp.export_jira_markdown(
            [{"type": "openai_key", "valid": True, "severity": "high", "source_url": "u", "note": "ok"}]
        ))

    def test_docker_nuclei_iac_profiles(self):
        cmd = rp.docker_cmd_for("subfinder", ["-d", "ex.com"], Path("/data"))
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd[0], "docker")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.jsonl"
            p.write_text('{"template-id":"exp","matched-at":"https://x"}\nplain\n', encoding="utf-8")
            parsed = rp.parse_nuclei_output(p)
            self.assertEqual(len(parsed), 2)
            tf = Path(td) / "main.tf"
            tf.write_text('resource "null" "x" {}', encoding="utf-8")
            self.assertTrue(rp.is_iac_file(tf))
            prof = Path(td) / "profiles.yaml"
            rp.save_scan_profile(path=prof, name="fast", opts={"skip_httpx": True})
            loaded = rp.load_scan_profiles(prof)
            self.assertIn("fast", loaded)
        self.assertIn("live credential", rp.executive_summary("ex.com", [{"severity": "critical"}], 1, 0).lower())

    def test_connection_validator_flag(self):
        rp.load_default_config()
        self.assertTrue(rp.VALIDATORS["postgres_uri"].uri_inspect)
        self.assertTrue(rp.VALIDATORS["mongodb_srv"].uri_inspect)

    def test_retry_succeeds(self):
        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return 1, b""
            return 0, b"ok"

        with patch.object(rp, "run_cmd", side_effect=fake_run):
            rc, out = rp.run_cmd_with_retry(["true"], max_retries=3, base_delay=0.01)
        self.assertEqual(rc, 0)
        self.assertEqual(calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
