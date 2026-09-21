#!/usr/bin/env python3
"""Wave-2 patterns, pipeline helpers, reports, and CLI flags."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import base64 as b64
import yaml

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

    def test_source_mapping_url_and_reconstruct(self):
        js = "void 0;\n//# sourceMappingURL=app.js.map\n"
        self.assertEqual(rp.extract_source_mapping_url(js), "app.js.map")
        cands = rp.source_map_url_candidates("https://cdn.example.com/static/app.js", js)
        self.assertIn("https://cdn.example.com/static/app.js.map", cands)
        inline = (
            "x();\n//# sourceMappingURL=data:application/json;base64,"
            + b64.b64encode(
                json.dumps(
                    {
                        "version": 3,
                        "sources": ["src/app.ts"],
                        "sourcesContent": ["const k='sk_live_abcdefghijklmnopqrstuvwx'"],
                        "mappings": "AAAA",
                    }
                ).encode()
            ).decode()
            + "\n"
        )
        self.assertTrue(rp.extract_source_mapping_url(inline).startswith("data:"))
        decoded = rp.decode_source_map_data_url(rp.extract_source_mapping_url(inline))
        self.assertIn("sk_live_", decoded)
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "recon"
            written = rp.write_reconstructed_sources(decoded, dest, prefix="m1")
            self.assertTrue(written)
            self.assertTrue(any("sk_live_" in p.read_text(encoding="utf-8") for p in written))
            escaped = rp.safe_source_relpath("webpack:///../secret.ts")
            self.assertNotIn("..", escaped.split("/"))

    def test_reconstruct_downloaded_js_maps_writes_tree(self):
        mmap = json.dumps(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["webpack:///src/keys.ts"],
                "sourcesContent": ["export const k = 'AKIAIOSFODNN7EXAMPLE';"],
                "mappings": "AAAA",
            }
        )
        js = "console.log(1);\n//# sourceMappingURL=app.js.map\n"
        url = "https://cdn.example.com/app.js"
        with tempfile.TemporaryDirectory() as td:
            dl = Path(td) / "downloaded_files"
            dest = Path(td) / "reconstructed_sources"
            dl.mkdir()
            (dl / rp.download_filename(url)).write_text(js, encoding="utf-8")

            def fake_get(u, timeout=10):
                self.assertTrue(str(u).endswith(".map"))
                return mmap.encode()

            with patch.object(rp, "_http_get_bytes", side_effect=fake_get):
                n_maps, n_files = rp.reconstruct_downloaded_js_maps([url], dl, dest)
            self.assertEqual(n_maps, 1)
            self.assertGreaterEqual(n_files, 1)
            blob = "\n".join(p.read_text(encoding="utf-8") for p in dest.rglob("*") if p.is_file() and p.suffix != ".json")
            self.assertIn("AKIAIOSFODNN7EXAMPLE", blob)

    def test_parse_cdx_rows_and_history_skip_same_hash(self):
        data = [
            ["timestamp", "original", "statuscode", "mimetype", "digest"],
            ["20200101120000", "https://ex.com/app.js", "200", "application/javascript", "abc"],
            ["20240101120000", "https://ex.com/app.js", "200", "application/javascript", "def"],
            ["20240101120000", "https://ex.com/app.js", "200", "application/javascript", "def"],
        ]
        rows = rp.parse_cdx_rows(data)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["timestamp"], "20200101120000")
        text_rows = rp.parse_cdx_text(
            "https://ex.com/app.js 20200101120000\n"
            "https://ex.com/app.js 20240101120000\n"
            "https://ex.com/app.js 20240101120000\n"
        )
        self.assertEqual(len(text_rows), 2)
        digested = rp.parse_cdx_text(
            "https://ex.com/app.js 20180101120000 sha1:aaaa\n"
            "https://ex.com/app.js 20200101120000 sha1:bbbb\n"
            "https://ex.com/app.js 20240101120000 sha1:cccc\n"
        )
        oldest = rp.select_oldest_snapshots(digested, 1)
        self.assertEqual(oldest[0]["timestamp"], "20180101120000")
        self.assertEqual(
            rp.diff_removed_lines("keep\nsecret=1\n", "keep\n"),
            ["secret=1"],
        )
        live = b"current-bundle"
        old = b"const k='sk_live_abcdefghijklmnopqrstuvwx';\ncurrent-bundle"
        url = "https://ex.com/app.js"
        with tempfile.TemporaryDirectory() as td:
            dl = Path(td) / "dl"
            dest = Path(td) / "reconstructed_sources"
            dl.mkdir()
            (dl / rp.download_filename(url)).write_bytes(live)
            snaps = [
                {
                    "timestamp": "20200101120000",
                    "original": url,
                    "archive_url": "https://web.archive.org/web/20200101120000id_/https://ex.com/app.js",
                },
                {
                    "timestamp": "20240101120000",
                    "original": url,
                    "archive_url": "https://web.archive.org/web/20240101120000id_/https://ex.com/app.js",
                },
            ]

            class _Resp:
                def __init__(self, body: bytes):
                    self._body = body
                    self.headers = {}

                def read(self):
                    return self._body

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

            def fake_open(req, timeout=15):
                url_s = getattr(req, "full_url", None) or str(req)
                if "20200101" in url_s:
                    return _Resp(old)
                return _Resp(live)

            with patch.object(rp, "list_cdx_snapshots", return_value=snaps):
                with patch("urllib.request.urlopen", side_effect=fake_open):
                    n, diffs = rp.fetch_live_js_history([url], dl, dest)
            self.assertEqual(n, 1)
            wb = dest / "_wayback"
            bodies = [
                p for p in wb.iterdir() if p.is_file() and p.name != "index.json"
            ]
            self.assertEqual(len(bodies), 1)
            self.assertEqual(bodies[0].read_bytes(), old)
            self.assertTrue(any(d.get("scanner") == "js_history_diff" for d in diffs))
            self.assertTrue((Path(td) / "js_history.json").is_file())
            self.assertTrue((Path(td) / "js_history_removed.json").is_file())

            many = snaps + [
                {
                    "timestamp": "20220101120000",
                    "original": url,
                    "digest": "mid",
                    "archive_url": "https://web.archive.org/web/20220101120000id_/https://ex.com/app.js",
                }
            ]
            opened: list = []

            def fake_open_count(req, timeout=15):
                opened.append(getattr(req, "full_url", None) or str(req))
                url_s = opened[-1]
                if "20200101" in url_s:
                    return _Resp(old)
                return _Resp(b"other-unique-body-" + url_s.encode())

            with patch.object(rp, "list_cdx_snapshots", return_value=many):
                with patch("urllib.request.urlopen", side_effect=fake_open_count):
                    n_cap, _diffs = rp.fetch_live_js_history(
                        [url], dl, dest, max_versions=1
                    )
            self.assertEqual(n_cap, 1)
            self.assertEqual(len(opened), 1)
            self.assertIn("20200101", opened[0])

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
        modern = rp.build_hakrawler_cmd("https://ex.com")
        self.assertNotIn("-url", modern)
        self.assertIn("-d", modern)
        self.assertEqual(rp.hakrawler_stdin("https://ex.com", modern), b"https://ex.com\n")
        old_hak = rp.build_hakrawler_cmd(
            "https://ex.com", help_blob="-url string\n-depth int\n-plain"
        )
        self.assertEqual(old_hak[1:3], ["-url", "https://ex.com"])
        self.assertIsNone(rp.hakrawler_stdin("https://ex.com", old_hak))
        ps = rp.build_paramspider_cmd("ex.com", "/tmp/ps")
        self.assertEqual(ps[:3], ["paramspider", "-d", "ex.com"])
        self.assertIn("-s", ps)
        self.assertNotIn("--output", ps)
        old_ps = rp.build_paramspider_cmd(
            "ex.com", "/tmp/ps", help_blob="--output DIR\n--level high"
        )
        self.assertIn("--output", old_ps)
        self.assertIn("--level", old_ps)
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
                "--skip-wayback-bodies",
                "--skip-js-history",
                "--js-history-max", "8",
                "--skip-sourcemaps",
                "--skip-sensitive-paths",
                "--repo-shallow",
                "--skip-gitleaks",
                "--spray",
                "--skip-public-apis",
                "--skip-secrets-db",
                "--skip-jsleak",
            ]
        )
        self.assertTrue(args.polite)
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertTrue(args.nuclei)
        self.assertTrue(args.skip_wayback_bodies)
        self.assertTrue(args.skip_js_history)
        self.assertEqual(args.js_history_max, 8)
        self.assertTrue(args.skip_sourcemaps)
        self.assertTrue(args.skip_sensitive_paths)
        self.assertTrue(args.repo_shallow)
        self.assertTrue(args.skip_gitleaks)
        self.assertTrue(args.spray)
        self.assertTrue(args.skip_public_apis)
        self.assertTrue(args.skip_secrets_db)
        self.assertTrue(args.skip_jsleak)
        argv = rp.argv_from_options(
            {
                "domain": "example.com",
                "polite": True,
                "proxy": "http://127.0.0.1:8080",
                "skip_amass": True,
                "skip_wayback_bodies": True,
                "skip_js_history": True,
                "js_history_max": 8,
                "skip_sourcemaps": True,
                "repo_shallow": True,
                "skip_gitleaks": True,
                "spray": True,
                "skip_public_apis": True,
                "skip_secrets_db": True,
                "skip_jsleak": True,
            }
        )
        self.assertIn("--polite", argv)
        self.assertIn("--proxy", argv)
        self.assertIn("--skip-amass", argv)
        self.assertIn("--skip-wayback-bodies", argv)
        self.assertIn("--skip-js-history", argv)
        self.assertIn("--js-history-max", argv)
        self.assertIn("8", argv)
        self.assertIn("--skip-sourcemaps", argv)
        self.assertIn("--repo-shallow", argv)
        self.assertIn("--skip-gitleaks", argv)
        self.assertIn("--spray", argv)
        self.assertIn("--skip-public-apis", argv)
        self.assertIn("--skip-secrets-db", argv)
        self.assertIn("--skip-jsleak", argv)

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
        cmd0 = Path(rp.build_wappalyzer_cmd("https://ex.com")[0]).name.lower()
        self.assertIn(cmd0, ("webanalyze", "wappalyzer"))
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

    def test_wayback_cdx_and_id_url(self):
        rows = [
            ["timestamp", "original", "statuscode", "mimetype"],
            ["20200101120000", "https://ex.com/old.js", "200", "application/javascript"],
            ["20240101120000", "https://ex.com/old.js", "200", "application/javascript"],
        ]
        snap = rp.pick_cdx_snapshot(rows)
        self.assertEqual(snap["timestamp"], "20240101120000")
        self.assertIn("id_/", rp.wayback_id_url(snap["timestamp"], snap["original"]))
        self.assertIn("20240101120000", rp.wayback_id_url(snap["timestamp"], snap["original"]))
        self.assertIsNone(rp.pick_cdx_snapshot([]))
        self.assertIsNone(rp.cdx_lookup("https://web.archive.org/web/1/https://ex.com"))

    def test_annotate_wayback_findings(self):
        rp.WAYBACK_BY_FILE.clear()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "abc_app.js"
            p.write_text("x", encoding="utf-8")
            rp.remember_wayback_file(
                p,
                {
                    "original": "https://ex.com/app.js",
                    "archive_url": "https://web.archive.org/web/20240101120000id_/https://ex.com/app.js",
                },
            )
            findings = [{"type": "openai_key", "source_url": str(p), "key": "sk"}]
            rp.annotate_wayback_findings(findings)
            self.assertTrue(findings[0]["from_wayback"])
            self.assertEqual(findings[0]["source_url"], "https://ex.com/app.js")
        rp.WAYBACK_BY_FILE.clear()

    def test_sensitive_paths_and_html_shell(self):
        urls = rp.sensitive_urls_for_hosts(["example.com", "https://api.example.com/app"], limit_hosts=5)
        self.assertTrue(any(u.endswith("/.env") for u in urls))
        self.assertTrue(any(u.endswith("/.git/config") for u in urls))
        self.assertIn("https://example.com/.env", urls)
        self.assertTrue(rp.looks_like_html_shell(b"<!DOCTYPE html><html>login</html>"))
        self.assertFalse(rp.looks_like_html_shell(b"AWS_SECRET_ACCESS_KEY=abc"))
        self.assertEqual(rp.origin_from_host("127.0.0.1:8080"), "http://127.0.0.1:8080")

        class _Resp:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def read(self, n=0):
                return b"SECRET_KEY=abcdefghijklmnop"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=_Resp()):
            self.assertTrue(rp.probe_sensitive_url("https://ex.com/.env"))

        class _Html:
            status = 200
            headers = {"Content-Type": "text/html"}

            def read(self, n=0):
                return b"<!DOCTYPE html><html><body>Not found</body></html>"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=_Html()):
            self.assertFalse(rp.probe_sensitive_url("https://ex.com/.env"))

    def test_git_clone_and_trufflehog_git_cmd(self):
        cmd = rp.build_clone_cmd("https://github.com/x/y", "/tmp/y", shallow=False)
        self.assertEqual(cmd[:2], ["git", "clone"])
        self.assertNotIn("--depth", cmd)
        self.assertIn("--depth", rp.build_clone_cmd("https://github.com/x/y", "/tmp/y", shallow=True))
        git_cmd = rp.trufflehog_git_cmd("https://github.com/x/y")
        self.assertEqual(git_cmd[:4], ["trufflehog", "--no-update", "--json", "git"])
        self.assertTrue(rp.trufflehog_git_cmd("/tmp/repo")[-1].startswith("file:"))

    def test_gitleaks_spray_and_env_helpers(self):
        cmd = rp.build_gitleaks_cmd("/tmp/src", "/tmp/gitleaks.json", git=False)
        self.assertEqual(cmd[:2], ["gitleaks", "dir"])
        self.assertIn("--exit-code", cmd)
        self.assertIn("0", cmd)
        self.assertEqual(
            rp.build_gitleaks_cmd("/tmp/repo", "/tmp/g.json", git=True)[:2],
            ["gitleaks", "git"],
        )
        detect = rp.build_gitleaks_detect_cmd("/tmp/src", "/tmp/g.json", git=False)
        self.assertIn("detect", detect)
        self.assertIn("--no-git", detect)
        self.assertNotIn(
            "--no-git",
            rp.build_gitleaks_detect_cmd("/tmp/repo", "/tmp/g.json", git=True),
        )
        spray = rp.build_spray_cmd("urls.txt", "dict.txt")
        self.assertEqual(spray[:3], ["spray", "-l", "urls.txt"])
        self.assertIn("--bak", spray)
        self.assertIn("--common", spray)
        self.assertIn("gitleaks", rp.PIPELINE_TOOLS)
        self.assertIn("spray", rp.PIPELINE_TOOLS)
        self.assertTrue(any(p.endswith(".env.staging") for p in rp.SENSITIVE_PATHS))
        self.assertTrue(any(p.endswith("/.cursor/mcp.json") for p in rp.SENSITIVE_PATHS))
        self.assertTrue(any("application_default_credentials.json" in p for p in rp.SENSITIVE_PATHS))
        self.assertTrue(rp.leak_wordlist_path().is_file())
        self.assertTrue(rp.DISCOVERY_KEEP_URL_RE.search("https://ex.com/.env.local"))
        self.assertTrue(rp.DISCOVERY_KEEP_URL_RE.search("https://ex.com/.cursor/mcp.json"))
        self.assertTrue(rp.DISCOVERY_KEEP_URL_RE.search("https://ex.com/backup.env"))
        self.assertTrue(rp.DISCOVERY_KEEP_URL_RE.search("https://ex.com/app.js"))
        env_hits = rp.env_like_urls(
            [
                "https://ex.com/app.js",
                "https://ex.com/.env.production",
                "https://cdn.ex.com/.env.bak",
                "https://ex.com/.env.production",
            ]
        )
        self.assertEqual(
            env_hits,
            ["https://ex.com/.env.production", "https://cdn.ex.com/.env.bak"],
        )
        extracted = rp.collect_http_urls_from_text(
            "noise\nhttps://ex.com/.env\n[200] https://ex.com/backup.sql extra"
        )
        self.assertIn("https://ex.com/.env", extracted)
        self.assertTrue(any(u.startswith("https://ex.com/backup.sql") for u in extracted))
        self.assertEqual(rp.gitleaks_type_for("github-pat", "ghp_abc"), "github_pat")
        self.assertEqual(
            rp.gitleaks_type_for("github-pat", "github_pat_abc"),
            "github_fine_pat",
        )
        self.assertEqual(rp.gitleaks_type_for("unknown-rule", "x"), "generic_secret")

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "waymore_out").mkdir()
            (d / "waymore_out" / "ex.com.txt").write_text(
                "https://ex.com/.env.staging\nhttps://ex.com/app.js\n",
                encoding="utf-8",
            )
            pool = rp.harvest_discovery_url_pool(d, ["https://ex.com/app.js"])
            self.assertIn("https://ex.com/.env.staging", pool)

            pat = "ghp_" + "A" * 36
            stripe = "sk_test_" + "b" * 24
            report = d / "gitleaks.json"
            report.write_text(
                json.dumps(
                    [
                        {
                            "RuleID": "github-pat",
                            "Secret": pat,
                            "File": "app.js",
                            "Commit": "deadbeef",
                            "Description": "GitHub PAT",
                        },
                        {
                            "RuleID": "generic-api-key",
                            "Secret": "xxxxxxxx",
                            "File": "fake.js",
                        },
                        {
                            "RuleID": "stripe-access-token",
                            "Secret": stripe,
                            "File": "pay.js",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            rows = rp.parse_gitleaks_report(report)
            self.assertEqual(len(rows), 3)
            findings = rp.findings_from_gitleaks(rows)
            types = {item["type"] for item in findings}
            self.assertIn("github_pat", types)
            self.assertIn("stripe_test", types)
            self.assertNotIn("generic_secret", types)
            gh = next(item for item in findings if item["type"] == "github_pat")
            self.assertEqual(gh["git_commit"], "deadbeef")
            self.assertEqual(gh["scanner"], "gitleaks")
            self.assertEqual(gh["key"], pat)

            aws_id = "AKIABCDEFGHIJKLMNOPQ"
            wrapped = d / "wrapped.json"
            wrapped.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "RuleID": "aws-access-token",
                                "Secret": aws_id,
                                "File": "aws.env",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            aws_rows = rp.parse_gitleaks_report(wrapped)
            aws_hits = rp.findings_from_gitleaks(aws_rows)
            self.assertEqual(aws_hits[0]["type"], "aws_access_key")

            jsonl = d / "jsonl.json"
            jsonl.write_text(
                json.dumps({"RuleID": "openai", "Secret": "sk-proj-" + "c" * 20, "File": "a"})
                + "\n"
                + json.dumps({"RuleID": "jwt", "Secret": "aaaaaaaa", "File": "b"})
                + "\n",
                encoding="utf-8",
            )
            jsonl_rows = rp.parse_gitleaks_report(jsonl)
            self.assertEqual(len(jsonl_rows), 2)
            openai_hits = rp.findings_from_gitleaks(jsonl_rows)
            self.assertTrue(any(item["type"] == "openai_key" for item in openai_hits))
            self.assertFalse(any(item["key"] == "aaaaaaaa" for item in openai_hits))

            src = d / "src"
            src.mkdir()
            out = d / "from_run.json"
            sample = [
                {"RuleID": "github-pat", "Secret": "ghp_" + "C" * 36, "File": "x.js"}
            ]

            def fake_gitleaks(cmd, **kwargs):
                self.assertEqual(cmd[0], "gitleaks")
                out.write_text(json.dumps(sample), encoding="utf-8")
                return 0, b""

            with patch.object(rp, "run_cmd", side_effect=fake_gitleaks):
                hits = rp.run_gitleaks_source(src, out, git=False)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["type"], "github_pat")
            self.assertEqual(hits[0]["scanner"], "gitleaks")

            def fake_spray(cmd, **kwargs):
                self.assertEqual(cmd[0], "spray")
                return 0, b"https://ex.com/.env.bak\n"

            with patch.object(rp, "run_cmd", side_effect=fake_spray):
                spray_urls = rp.run_spray_leak_probe(["ex.com"], d)
            self.assertIn("https://ex.com/.env.bak", spray_urls)
            self.assertTrue((d / "spray_urls.txt").is_file())
            self.assertTrue((d / "spray_targets.txt").is_file())

    def test_gitleaks_binary_scans_fixture(self):
        if not shutil.which("gitleaks"):
            self.skipTest("gitleaks not on PATH")
        self.assertTrue(rp.check_tool("gitleaks"))
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "app.js").write_text(
                'const t = "ghp_abcdefghijklmnopqrstuvwxyzABCD123456";\n',
                encoding="utf-8",
            )
            report = Path(td) / "gitleaks.json"
            hits = rp.run_gitleaks_source(src, report, git=False)
            self.assertTrue(report.is_file() and report.stat().st_size > 0)
            self.assertTrue(hits, "gitleaks should report the fixture GitHub PAT")
            self.assertTrue(any(item["type"] == "github_pat" for item in hits))
            self.assertTrue(any(item["scanner"] == "gitleaks" for item in hits))

    def test_public_apis_catalog_helpers(self):
        sample = (ROOT / "tests" / "fixtures" / "public_apis_sample.md").read_text(
            encoding="utf-8"
        )
        entries = rp.parse_public_apis_markdown(sample)
        names = {e["name"] for e in entries}
        self.assertIn("OpenWeatherMap", names)
        self.assertIn("Cats", names)
        self.assertNotIn("Cat Facts", names)
        self.assertNotIn("AniList", names)
        owm = next(e for e in entries if e["name"] == "OpenWeatherMap")
        self.assertIn("openweathermap.org", owm["hosts"])
        cats = next(e for e in entries if e["name"] == "Cats")
        self.assertTrue(any("thecatapi.com" in h for h in cats["hosts"]))
        adopt = next(e for e in entries if e["name"] == "AdoptAPet")
        self.assertTrue(adopt["hosts"])

        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / "public_apis.json"
            dest, n = rp.refresh_public_apis_catalog(path=catalog, markdown=sample)
            self.assertEqual(dest, catalog)
            self.assertEqual(n, len(entries))
            idx = rp.load_public_apis_index(catalog)
            hit = rp.lookup_public_api_host("api.openweathermap.org", idx)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["name"], "OpenWeatherMap")
            self.assertIsNone(rp.lookup_public_api_host("github.com", idx))
            js = (
                'fetch("https://api.openweathermap.org/data/2.5/weather'
                '?appid=abcdef1234567890abcdef12")'
            )
            qhits = rp.public_api_query_secrets(js, idx)
            self.assertTrue(qhits)
            self.assertEqual(qhits[0]["type"], "public_api_key")
            self.assertEqual(qhits[0]["likely_service"], "OpenWeatherMap")
            self.assertEqual(qhits[0]["key"], "abcdef1234567890abcdef12")
            nearby = 'const api_key = "AbCdEfGhIjKlMnOp1234"; // openweathermap.org'
            hint = rp.match_public_api_hint(nearby, 16, 36, index=idx)
            self.assertIsNotNone(hint)
            self.assertEqual(hint["name"], "OpenWeatherMap")
            generic = rp.public_api_query_secrets(
                "https://api.internal.example/v1?api_key=ZzYyXxWwVvUuTtSs1234",
                idx,
            )
            self.assertTrue(generic)
            self.assertEqual(generic[0]["type"], "generic_secret")
            skip_key = rp.public_api_query_secrets(
                "https://cdn.example.com/app.js?key=not-a-real-vendor-token1",
                idx,
            )
            self.assertFalse(skip_key)

        bundled = rp.load_public_apis_index(force=True)
        self.assertGreaterEqual(len(bundled.get("entries") or []), 20)
        self.assertIsNotNone(rp.lookup_public_api_host("openweathermap.org", bundled))
        old = rp.SCAN_PUBLIC_APIS
        try:
            rp.SCAN_PUBLIC_APIS = True
            findings = rp.collect_public_api_query_findings(
                'u="https://api.openweathermap.org/data/2.5/weather?appid=abcdef1234567890abcdef12"',
                "https://ex.com/app.js",
            )
            self.assertTrue(any(f["type"] == "public_api_key" for f in findings))
            rp.SCAN_PUBLIC_APIS = False
            self.assertEqual(
                rp.collect_public_api_query_findings(
                    'u="https://api.openweathermap.org/data/2.5/weather?appid=abcdef1234567890abcdef12"',
                    "https://ex.com/app.js",
                ),
                [],
            )
        finally:
            rp.SCAN_PUBLIC_APIS = old
            rp.reset_public_apis_index()

    def test_secrets_db_and_jsleak_helpers(self):
        sample = yaml.safe_load(
            (ROOT / "tests" / "fixtures" / "secrets_patterns_sample.yml").read_text(
                encoding="utf-8"
            )
        )
        rows = rp.iter_secrets_pattern_entries(sample)
        names = {row["name"] for row in rows}
        self.assertIn("AWS AppSync GraphQL Key", names)
        filtered = rp.filter_secrets_db_entries(rows, dict(rp.PATTERNS))
        kept = {row["name"] for row in filtered}
        self.assertIn("AWS AppSync GraphQL Key", kept)
        self.assertIn("Adafruit IO Key", kept)
        self.assertNotIn("AWS API Key", kept)
        self.assertNotIn("AWS API Gateway", kept)
        self.assertNotIn("Generic Password", kept)
        self.assertNotIn("Medium Token", kept)
        with_medium = rp.filter_secrets_db_entries(
            rows, dict(rp.PATTERNS), include_medium=True
        )
        self.assertTrue(any(row["name"] == "Medium Token" for row in with_medium))

        old_patterns = dict(rp.PATTERNS)
        old_conf = dict(rp.CONFIDENCE)
        try:
            added = rp.apply_secrets_pattern_entries(filtered)
            self.assertGreaterEqual(added, 1)
            self.assertIn("spd_aws_appsync_graphql_key", rp.PATTERNS)
            self.assertTrue(re.search(rp.PATTERNS["spd_aws_appsync_graphql_key"], "da2-" + "a" * 26))
        finally:
            rp.PATTERNS = old_patterns
            rp.CONFIDENCE = old_conf

        parsed = rp.parse_jsleak_output(
            "[+] Found [Adafruit IO Key] [aio_abcdefghijklmnopqrstuvwx1234] "
            "[https://ex.com/app.js]\n"
            "[+] Found link: [https://cdn.ex.com/api.js] in [https://ex.com/app.js]\n"
        )
        self.assertEqual(parsed["secrets"][0]["name"], "Adafruit IO Key")
        self.assertTrue(parsed["secrets"][0]["secret"].startswith("aio_"))
        self.assertEqual(parsed["links"][0]["url"], "https://cdn.ex.com/api.js")
        cmd = rp.build_jsleak_cmd("/tmp/p.yml", concurrency=8)
        self.assertEqual(cmd[0], "jsleak")
        self.assertIn("-s", cmd)
        self.assertIn("-l", cmd)
        self.assertIn("-e", cmd)
        self.assertIn("jsleak", rp.PIPELINE_TOOLS)
        links = rp.extract_jsleak_links(
            'const u = "/api/v1/users"; fetch("https://cdn.example.com/x.js");'
        )
        self.assertTrue(any("api/v1/users" in item or item.startswith("https://") or item.startswith("/") for item in links))
        self.assertTrue(rp.bundled_secrets_db_path().is_file())

        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "filtered.yml"
            sample_text = (ROOT / "tests" / "fixtures" / "secrets_patterns_sample.yml").read_text(
                encoding="utf-8"
            )
            out, n = rp.refresh_secrets_pattern_db(
                dest,
                existing_patterns=dict(rp.PATTERNS),
                yaml_text=sample_text,
            )
            self.assertEqual(out, dest)
            self.assertGreaterEqual(n, 1)
            self.assertTrue(dest.is_file())


class ToolPreflightTests(unittest.TestCase):
    def _exe(self, directory: Path, name: str) -> Path:
        if os.name == "nt":
            path = directory / f"{name}.exe"
            path.write_bytes(b"MZ")
        else:
            path = directory / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
        return path

    def test_check_tool_uses_gobin_and_aliases(self):
        with tempfile.TemporaryDirectory() as td:
            gobin = Path(td) / "gobin"
            gobin.mkdir()
            self._exe(gobin, "webanalyze")
            self._exe(gobin, "whatweb")
            self._exe(gobin, "jsluice")
            self._exe(gobin, "gowitness")
            self._exe(gobin, "apkeep")
            self._exe(gobin, "gplaycli")
            env = {"GOBIN": str(gobin), "PATH": str(Path(td) / "empty")}
            (Path(td) / "empty").mkdir()
            with patch.dict(os.environ, env, clear=False):
                self.assertTrue(rp.check_tool("webanalyze"))
                self.assertTrue(rp.check_tool("wappalyzer"))
                self.assertTrue(rp.check_tool("whatweb"))
                self.assertTrue(rp.check_tool("jsluice"))
                self.assertTrue(rp.check_tool("gowitness"))
                self.assertTrue(rp.check_tool("apkeep"))
                self.assertTrue(rp.check_tool("gplaycli"))
                self.assertFalse(rp.check_tool("definitely_missing_reconpipe_tool"))


if __name__ == "__main__":
    unittest.main()

