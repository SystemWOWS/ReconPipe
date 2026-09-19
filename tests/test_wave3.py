#!/usr/bin/env python3
"""Wave-3: code search, OpenAPI, APK, buckets, SQLite, ETag, CI, pairing."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import zipfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402
import reconpipe_wave3 as w3  # noqa: E402


class Wave3HelperTests(unittest.TestCase):
    def test_github_queries_and_raw_url(self):
        qs = w3.github_search_queries("example.com", org="acme", extra_hosts=["api.example.com"])
        self.assertTrue(any("example.com" in q for q in qs))
        self.assertTrue(any(q.startswith("org:acme") for q in qs))
        raw = w3.github_raw_url(
            "https://github.com/acme/app/blob/main/src/config.js"
        )
        self.assertEqual(
            raw,
            "https://raw.githubusercontent.com/acme/app/main/src/config.js",
        )

    def test_parse_github_and_gitlab_payloads(self):
        gh = {
            "items": [
                {
                    "html_url": "https://github.com/acme/app/blob/abc/file.env",
                    "path": "file.env",
                    "sha": "abc",
                    "repository": {"full_name": "acme/app"},
                }
            ]
        }
        rows = w3.parse_github_search_payload(gh)
        self.assertEqual(len(rows), 1)
        self.assertIn("raw.githubusercontent.com", rows[0]["raw_url"])
        gl = [{
            "filename": "a.env",
            "project_id": "1",
            "web_url": "https://gitlab.com/g/p/-/blob/main/a.env",
            "ref": "main",
        }]
        grows = w3.parse_gitlab_search_payload(gl)
        self.assertIn("/-/raw/", grows[0]["raw_url"])

    def test_code_search_injectable_fetch(self):
        def fake_fetch(url, headers=None, timeout=20):
            self.assertIn("api.github.com/search/code", url)
            return {"items": [{
                "html_url": "https://github.com/x/y/blob/main/.env",
                "path": ".env",
                "sha": "1",
                "repository": {"full_name": "x/y"},
            }]}

        urls = w3.collect_code_search_urls("example.com", fetch_json=fake_fetch)
        self.assertTrue(urls)
        self.assertTrue(urls[0].startswith("https://raw.githubusercontent.com/"))

    def test_openapi_and_postman(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {"/users": {}, "/orders": {}},
            "components": {
                "securitySchemes": {
                    "ApiKey": {"type": "apiKey", "example": "sk_live_examplekeyvalue99"}
                }
            },
        }
        parsed = w3.parse_openapi_spec(spec, "https://example.com/openapi.json")
        self.assertTrue(any("/users" in u for u in parsed["urls"]))
        self.assertTrue(any("sk_live" in s["value"] for s in parsed["secrets"]))
        self.assertTrue(w3.looks_like_openapi(json.dumps(spec)))

        postman = {
            "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [{
                "request": {
                    "url": {"raw": "https://api.example.com/v2/me"},
                    "header": [{"key": "X-Api-Key", "value": "postman-secret-key-12345"}],
                }
            }],
            "variable": [{"key": "api_token", "value": "variable-secret-value1"}],
        }
        pm = w3.parse_postman_collection(postman)
        self.assertIn("https://api.example.com/v2/me", pm["urls"])
        self.assertTrue(pm["secrets"])
        self.assertTrue(w3.looks_like_postman(json.dumps(postman)))
        findings = w3.harvest_spec_secret_findings(json.dumps(spec), "https://ex.com/openapi.json")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["scanner"], "openapi")

    def test_apk_extract_and_strings(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            apk = td_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("assets/config.json", '{"apiKey":"AIzaSyDummyKeyValue000000000000000000"}')
                zf.writestr("res/values/strings.xml", "<string name='k'>aio_abcdefghijklmnopqrstuvwx1234</string>")
                zf.writestr("lib/arm.so", b"XXXX" + b"sk_live_abcdefghijklmnopqrstuv" + b"\x00\x01")
            out = td_path / "out"
            files = w3.extract_mobile_archive(apk, out)
            names = {p.name for p in files}
            self.assertIn("config.json", names)
            self.assertTrue(any(p.name == "_apk_strings.txt" for p in files))
            strings = (out / "_apk_strings.txt").read_text(encoding="utf-8")
            self.assertIn("sk_live_", strings)

    def test_apkm_nested_apk_extract(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            inner = td_path / "base.apk"
            with zipfile.ZipFile(inner, "w") as zf:
                zf.writestr("assets/google-services.json", '{"api_key":"AIzaSyNestedKey00000000000000000000"}')
            apkm = td_path / "app.apkm"
            with zipfile.ZipFile(apkm, "w") as zf:
                zf.write(inner, arcname="base.apk")
            out = td_path / "out"
            files = w3.extract_mobile_archive(apkm, out)
            names = {p.name for p in files}
            self.assertIn("google-services.json", names)

    def test_package_id_and_apkeep_fetch(self):
        self.assertEqual(w3.parse_package_id("com.example.app"), "com.example.app")
        self.assertEqual(w3.parse_package_id("com.example.app@1.2.3"), "com.example.app@1.2.3")
        self.assertEqual(w3.parse_package_id("not a package"), "")
        dest = Path("out")
        self.assertEqual(
            w3.apkeep_cmd("com.example.app", dest),
            ["apkeep", "-a", "com.example.app", str(dest)],
        )
        self.assertEqual(
            w3.gplaycli_cmd("com.example.app@9", dest),
            ["gplaycli", "-d", "com.example.app", "-y", "-f", str(dest)],
        )
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)

            def fake_which(name: str):
                return "/usr/bin/apkeep" if name == "apkeep" else None

            def fake_run(cmd, timeout=180):
                out = Path(cmd[-1])
                (out / "com.example.app.apk").write_bytes(b"PK\x03\x04fake")
                return 0, b""

            files = w3.fetch_android_packages(
                ["com.example.app", "not valid"],
                dest,
                run=fake_run,
                which=fake_which,
            )
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].name.endswith(".apk"))

            def none_which(_name: str):
                return None

            empty = w3.fetch_android_packages(
                ["com.example.app"],
                dest / "empty",
                run=lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no network")),
                which=none_which,
            )
            self.assertEqual(empty, [])

    def test_bucket_candidates_and_listing(self):
        names = w3.bucket_name_candidates("www.example.com")
        self.assertIn("example", names)
        self.assertIn("example-assets", names)
        keys = w3.parse_s3_listing("<ListBucketResult><Contents><Key>config.json</Key></Contents></ListBucketResult>")
        self.assertEqual(keys, ["config.json"])
        self.assertEqual(
            w3.classify_bucket_response(200, "<ListBucketResult></ListBucketResult>"),
            "open",
        )
        self.assertEqual(w3.classify_bucket_response(403, "AccessDenied"), "exists")
        self.assertEqual(w3.classify_bucket_response(404, ""), "missing")
        urls = w3.bucket_object_urls("s3", "example", ["config.json", "photo.jpg", ".env"])
        self.assertTrue(any(u.endswith("config.json") for u in urls))
        self.assertTrue(any(".env" in u for u in urls))
        self.assertFalse(any(u.endswith("photo.jpg") for u in urls))

    def test_probe_buckets_injected(self):
        def fake_fetch(url, timeout=8):
            if "s3.amazonaws.com" in url and "example.s3" in url.replace("https://", ""):
                return 200, "<ListBucketResult><Key>app.js</Key></ListBucketResult>", {}
            if "storage.googleapis.com" in url:
                return 404, "", {}
            if "blob.core.windows.net" in url:
                return 403, "denied", {}
            return 404, "", {}

        hit = w3.probe_buckets("example.com", fetch=fake_fetch)
        self.assertTrue(any(r["access"] == "open" for r in hit["buckets"]))
        self.assertTrue(any(r["kind"] == "azure" and r["access"] == "exists" for r in hit["buckets"]))
        self.assertTrue(any("app.js" in u for u in hit["urls"]))

    def test_etag_headers(self):
        h = w3.etag_request_headers({"etag": '"abc"', "last_modified": "Wed, 01 Jan 2020 00:00:00 GMT"})
        self.assertEqual(h["If-None-Match"], '"abc"')
        self.assertIn("If-Modified-Since", h)
        updated = w3.etag_cache_update({}, {"etag": '"xyz"', "last-modified": "Thu"})
        self.assertEqual(updated["etag"], '"xyz"')

    def test_sqlite_store_and_cache(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "f.db"
            conn = w3.connect_store(db)
            f1 = {"hash": "aaa", "type": "github_pat", "key": "ghp_x", "source_url": "https://a", "valid": False, "note": "no"}
            stats = w3.upsert_findings(conn, "example.com", [f1])
            self.assertEqual(stats["new"], 1)
            f1["valid"] = True
            f1["note"] = "ok"
            stats = w3.upsert_findings(conn, "example.com", [f1])
            self.assertEqual(stats["newly_valid"], 1)
            w3.cache_put(conn, "kh1", {"type": "github_pat", "valid": True, "status_code": 200, "note": "VALID"})
            cached = w3.cache_get(conn, "kh1")
            self.assertTrue(cached["from_cache"])
            self.assertTrue(cached["valid"])
            conn.close()

    def test_generic_pairing_and_proximity(self):
        findings = [
            {"type": "paypal_client_id", "key": "A" * 80, "source_url": "https://ex.com/a.js"},
            {"type": "paypal_secret", "key": "E" * 80, "source_url": "https://ex.com/a.js"},
        ]
        out = w3.pair_generic_findings(findings)
        self.assertTrue(out[0].get("paired"))
        self.assertEqual(out[0]["paypal_secret"], "E" * 80)
        blob = "id=" + "A" * 20 + "...." + "secret=" + "B" * 20
        self.assertTrue(w3.proximity_partners(blob, "A" * 20, "B" * 20, window=40))
        self.assertFalse(w3.proximity_partners("A" * 20 + ("." * 300) + "B" * 20, "A" * 20, "B" * 20, window=40))

    def test_ci_defaults_and_cli_flags(self):
        parser = rp.build_parser()
        args = parser.parse_args([
            "-d", "example.com",
            "--skip-code-search",
            "--skip-buckets",
            "--skip-openapi",
            "--ci",
            "--apk", "app.apk",
            "--package", "com.example.app",
            "--github-org", "acme",
        ])
        self.assertTrue(args.skip_code_search)
        self.assertTrue(args.ci)
        self.assertEqual(args.apk, ["app.apk"])
        self.assertEqual(args.package, ["com.example.app"])
        args2 = parser.parse_args(["--ci"])
        rp.apply_ci_defaults(args2)
        self.assertTrue(args2.skip_chaos)
        self.assertTrue(args2.skip_code_search)
        self.assertTrue(args2.skip_ci_logs)
        self.assertTrue(args2.skip_pastes)
        self.assertTrue(args2.skip_buckets)
        self.assertTrue(args2.no_notify)
        self.assertEqual(args2.domain, "local")
        self.assertTrue(args2.repo)
        self.assertEqual(args2.sarif, "results.sarif")
        argv = rp.argv_from_options({
            "domain": "example.com",
            "skip_code_search": True,
            "skip_ci_logs": True,
            "skip_pastes": True,
            "skip_buckets": True,
            "ci": True,
            "apk": ["app.apk"],
            "package": ["com.example.app"],
            "github_org": "acme",
        })
        self.assertIn("--skip-code-search", argv)
        self.assertIn("--skip-ci-logs", argv)
        self.assertIn("--skip-pastes", argv)
        self.assertIn("--ci", argv)
        self.assertIn("--apk", argv)
        self.assertIn("--package", argv)
        self.assertIn("com.example.app", argv)

    def test_certstream_and_crtsh_parsers(self):
        hosts = w3.crtsh_hosts_from_payload([
            {"name_value": "*.api.example.com\nwww.example.com"},
            {"common_name": "cdn.example.com"},
        ])
        self.assertIn("api.example.com", hosts)
        msg = {
            "message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": ["*.shop.example.com", "other.net"]}},
        }
        names = w3.certstream_domains_from_message(msg)
        matched = w3.hosts_matching_domain(names, "example.com")
        self.assertEqual(matched, ["shop.example.com"])

    def test_pair_credential_calls_generic(self):
        findings = [
            {"type": "woocommerce_key", "key": "ck_" + "a" * 40, "source_url": "https://ex.com/x"},
            {"type": "woocommerce_secret", "key": "cs_" + "b" * 40, "source_url": "https://ex.com/x"},
        ]
        out = rp.pair_credential_findings(findings)
        self.assertTrue(out[0].get("paired"))


if __name__ == "__main__":
    unittest.main()
