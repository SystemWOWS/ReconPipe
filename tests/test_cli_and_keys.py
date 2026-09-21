#!/usr/bin/env python3
"""CLI adapters, quiet console, and keyhacks-style Google/SendGrid/FCM checks."""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import base64 as b64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402

KATANA_HELP = """
  -list string[]     target url / list to crawl
  -jc, -js-crawl
  -jsl, -jsluice
  -kf, -known-files string
  -hl, -headless
  -nos, -no-sandbox
  -silent
  -d, -depth
  -c, -concurrency
  -rl, -rate-limit
  -timeout
  -o, -output
"""

TH_HELP = """
      --json
      --no-update
  filesystem [<flags>] [<path>...]
    Find credentials in a filesystem.
"""

PD_HTTPX_HELP = """
httpx is a fast and multi-purpose HTTP toolkit.
  -l, -list string  input file containing list of hosts
  -silent           silent mode
  -nc, -no-color    disable colors
  -o, -output string
  -t, -threads int
  -timeout int
projectdiscovery
"""

GOSPIDER_HELP = """
  -S, --sites string
  -c, --concurrent
  -d, --depth
  --js
  -t, --threads
  --sitemap
  --robots
  -q, --quiet
  -o, --output
"""

CHAOS_HELP = """
   -key string
   -d string
   -silent
   -o string
"""


class ToolCliAdapters(unittest.TestCase):
    def test_trufflehog_never_uses_path_flag(self):
        cmd = rp.trufflehog_filesystem_cmd("/tmp/dl", help_blob=TH_HELP)
        self.assertNotIn("--path", cmd)
        self.assertNotIn("--directory", cmd)
        self.assertIn("filesystem", cmd)
        self.assertEqual(cmd[-1], "/tmp/dl")
        self.assertIn("--json", cmd)
        self.assertIn("--no-update", cmd)

    def test_trufflehog_always_disables_updater(self):
        cmd = rp.trufflehog_filesystem_cmd(
            "/tmp/dl", help_blob="filesystem [<path>...]\n  Find credentials."
        )
        self.assertEqual(
            cmd[:4], ["trufflehog", "--no-update", "--json", "filesystem"]
        )
        self.assertTrue(
            rp._is_trufflehog_updater_error(
                'error occurred with trufflehog updater {"error": "cannot move binary"}'
            )
        )

    def test_katana_uses_pd_flags(self):
        cmd = rp.build_katana_cmd(
            "hosts.txt", "out.txt", headless=True, jsl=True, help_blob=KATANA_HELP
        )
        self.assertEqual(cmd[0], "katana")
        self.assertIn("-silent", cmd)
        self.assertIn("-list", cmd)
        self.assertIn("-jc", cmd)
        self.assertIn("-jsl", cmd)
        self.assertIn("-hl", cmd)
        self.assertNotIn("--path", cmd)

    def test_httpx_uses_pd_flags(self):
        cmd = rp.build_httpx_cmd(
            "/opt/pd/httpx",
            "hosts.txt",
            "live.txt",
            help_blob=PD_HTTPX_HELP,
        )
        self.assertEqual(cmd[0], "/opt/pd/httpx")
        self.assertIn("-silent", cmd)
        self.assertIn("-nc", cmd)
        self.assertIn("-l", cmd)
        self.assertIn("-o", cmd)
        self.assertNotIn("--path", cmd)

    def test_gospider_quiet(self):
        cmd = rp.build_gospider_cmd("hosts.txt", "out", help_blob=GOSPIDER_HELP)
        self.assertIn("-q", cmd)
        self.assertIn("-S", cmd)
        self.assertIn("--js", cmd)

    def test_help_has_flag_empty_blob_assumes_modern(self):
        self.assertTrue(rp.help_has_flag("", "-silent"))
        self.assertFalse(
            rp.help_has_flag(
                "Usage: httpx [OPTIONS] URL\nno such option: -s", "silent"
            )
        )

    def test_chaos_and_gau(self):
        chaos = rp.build_chaos_cmd(
            "example.com", "out.txt", "abc", help_blob=CHAOS_HELP
        )
        self.assertIn("-d", chaos)
        self.assertIn("-silent", chaos)
        self.assertIn("abc", chaos)
        gau = rp.build_gau_cmd("example.com", 7, help_blob="--threads")
        self.assertEqual(gau[-1], "example.com")
        self.assertIn("--threads", gau)
        www = rp.build_chaos_cmd(
            "https://www.optus.com.au/", "out.txt", "", help_blob=CHAOS_HELP
        )
        self.assertIn("optus.com.au", www)
        self.assertNotIn("www.optus.com.au", www)

    def test_normalize_scan_domain_strips_url_and_www(self):
        self.assertEqual(
            rp.normalize_scan_domain("https://www.optus.com.au/"),
            "optus.com.au",
        )
        self.assertEqual(rp.normalize_scan_domain("WWW.optus.com.au"), "optus.com.au")
        self.assertEqual(rp.normalize_scan_domain("optus.com.au."), "optus.com.au")
        self.assertEqual(rp.normalize_scan_domain("www.com"), "www.com")

    def test_parse_chaos_payload_expands_labels(self):
        hosts = rp.parse_chaos_subdomain_payload(
            {"domain": "optus.com.au", "subdomains": ["www", "mail", "optus.com.au"]},
            "www.optus.com.au",
        )
        self.assertIn("optus.com.au", hosts)
        self.assertIn("www.optus.com.au", hosts)
        self.assertIn("mail.optus.com.au", hosts)


class QuietConsole(unittest.TestCase):
    def test_keeps_status_drops_urls(self):
        self.assertTrue(rp.console_keep_line("[09:00:00] [*] Katana: 12 URLs added"))
        self.assertTrue(rp.console_keep_line("  [3/6] URL DISCOVERY"))
        self.assertTrue(rp.console_keep_line("[gui] Started: reconpipe.py"))
        self.assertTrue(
            rp.console_keep_line(
                "[09:00:00] [*] Timing: About 28% done; ETC: 20:51 (0:12:40 remaining)"
            )
        )
        self.assertFalse(rp.console_keep_line("https://cdn.example.com/app.js?x=1"))
        self.assertFalse(rp.console_keep_line("found endpoint /api/v1/users"))

    def test_verbose_keeps_all(self):
        with patch.dict(os.environ, {"RECONPIPE_VERBOSE": "1"}):
            self.assertTrue(rp.console_keep_line("https://cdn.example.com/app.js"))


class ScanEtaTests(unittest.TestCase):
    def test_fmt_hms(self):
        self.assertEqual(rp.fmt_hms(0), "0:00:00")
        self.assertEqual(rp.fmt_hms(400), "0:06:40")
        self.assertEqual(rp.fmt_remaining_short(40), "40s")
        self.assertEqual(rp.fmt_remaining_short(600), "10m")

    def test_skip_flags_shrink_budget(self):
        full = rp.ScanEta()
        full.configure(
            tools={"katana": True, "waymore": True, "gospider": True, "trufflehog": True}
        )
        full.set_work(subs=200, live=40, urls=500)
        slim = rp.ScanEta()
        slim.configure(
            skip_chaos=True,
            skip_httpx=True,
            skip_discovery=True,
            skip_intel=True,
            no_trufflehog=True,
            no_validate=True,
        )
        self.assertGreater(sum(full.budgets().values()), sum(slim.budgets().values()))

    def test_remaining_falls_as_stages_complete(self):
        eta = rp.ScanEta()
        eta.configure(tools={"katana": True, "waymore": True})
        eta.set_work(subs=80, live=20, urls=200)
        eta.begin_stage(1, "Subdomains")
        early = eta.snapshot()["remaining_s"]
        eta.begin_stage(6, "Saving Results")
        late = eta.snapshot()["remaining_s"]
        self.assertLess(late, early)
        snap = eta.snapshot()
        self.assertIn("ETC:", snap["timing"])
        self.assertIn("remaining", snap["timing"])

    def test_writes_scan_status_json(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            eta = rp.ScanEta(Path(td))
            eta.set_work(subs=10, live=4, urls=20)
            eta.begin_stage(3, "URL Discovery")
            path = Path(td) / "scan_status.json"
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["stage"], 3)
            self.assertGreaterEqual(data["remaining_s"], 0)
            self.assertIn("timing", data)


class GoogleKeyhacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rp.load_default_config()
    def test_maps_json_ok_vs_denied(self):
        self.assertEqual(
            rp.interpret_google_probe("maps_json", 200, '{"status":"OK"}'),
            "enabled",
        )
        self.assertEqual(
            rp.interpret_google_probe(
                "maps_json",
                200,
                '{"status":"REQUEST_DENIED","error_message":"API not enabled"}',
            ),
            "restricted",
        )
        self.assertEqual(
            rp.interpret_google_probe("geolocation", 200, "{}"),
            "enabled",
        )
        self.assertEqual(
            rp.interpret_google_probe(
                "gemini", 400, '{"error":{"message":"API_KEY_INVALID"}}'
            ),
            "invalid",
        )

    def test_summarize(self):
        valid, note = rp.summarize_google_spray(
            {"geocoding": "enabled", "youtube": "denied", "gemini": "restricted"}
        )
        self.assertTrue(valid)
        self.assertIn("enabled=geocoding", note)
        self.assertIn("gemini", note)

    def test_spray_skips_billed_image_apis(self):
        ids = [p["id"] for p in rp.GOOGLE_API_PROBES]
        blob = " ".join(str(p["url"]) for p in rp.GOOGLE_API_PROBES)
        self.assertIn("geocoding", ids)
        self.assertIn("timezone", ids)
        self.assertIn("elevation", ids)
        self.assertIn("youtube", ids)
        self.assertIn("gemini", ids)
        self.assertNotIn("staticmap", blob)
        self.assertNotIn("streetview", blob)
        self.assertNotIn("distancematrix", blob)
        self.assertIn("generativelanguage.googleapis.com", blob)
        self.assertIn("/v1beta/models", blob)

    def test_google_spray_flag_on_validator(self):
        self.assertTrue(rp.VALIDATORS["google_api"].google_api_spray)
        self.assertIn("/v3/scopes", rp.VALIDATORS["sendgrid"].url)
        self.assertIn("fcm.googleapis.com", rp.VALIDATORS["firebase_key"].url)
        self.assertIn("/v1/account", rp.VALIDATORS["stripe_live"].url)
        self.assertEqual(rp.VALIDATORS["sendgrid"].restricted_codes, [403])
        self.assertIn("{dc}", rp.VALIDATORS["mailchimp"].url)
        self.assertIn("github_app", rp.VALIDATORS)
        self.assertIn("google_oauth", rp.VALIDATORS)
        self.assertIn("api.hubapi.com/integrations/v1/me", rp.VALIDATORS["hubspot_api"].url)
        self.assertEqual(rp.VALIDATORS["hubspot_api"].headers.get("Authorization"), "Bearer {key}")
        self.assertEqual(rp.VALIDATORS["hubspot_api"].restricted_codes, [403])
        self.assertIn("api.groq.com/openai/v1/models", rp.VALIDATORS["groq_api"].url)
        self.assertEqual(rp.VALIDATORS["figma_token"].headers.get("X-Figma-Token"), "{key}")

    def test_mailchimp_dc_template(self):
        url = rp._format_tpl(
            rp.VALIDATORS["mailchimp"].url, "a" * 32 + "-us12"
        )
        self.assertIn("us12.api.mailchimp.com", url)

    def test_key_tester_types_include_new_checks(self):
        opts = set(rp.VALIDATORS.keys())
        self.assertIn("google_api", opts)
        self.assertIn("firebase_key", opts)
        self.assertIn("sendgrid", opts)
        self.assertIn("mailchimp", opts)
        self.assertIn("telegram_bot", opts)
        self.assertIn("cloudflare_api", opts)
        self.assertIn("huggingface_token", opts)
        self.assertIn("linear_api_key", opts)
        self.assertIn("hubspot_api", opts)
        self.assertIn("n8n_api", opts)
        self.assertIn("groq_api", opts)
        self.assertIn("figma_token", opts)
        self.assertIn("postman_api", opts)
        self.assertIn("vercel_token", opts)
        self.assertIn("doppler_token", opts)
        self.assertIn("postgres_uri", opts)

    def test_hubspot_private_app_token_shape(self):
        rx = re.compile(rp.PATTERNS["hubspot_api"])
        self.assertTrue(rx.search("pat-na1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        self.assertTrue(rx.search("pat-eu1-11111111-2222-3333-4444-555555555555"))
        self.assertIsNone(rx.search("pat-na1-short"))
        self.assertEqual(rp.gitleaks_type_for("hubspot-api-token", "pat-na1-x"), "hubspot_api")

    def test_n8n_legacy_and_jwt_keys(self):
        rx = re.compile(rp.PATTERNS["n8n_api"])
        self.assertTrue(rx.search("n8n_api_" + "A" * 20))
        self.assertIsNone(rx.search("n8n_api_short"))
        spec = rp.VALIDATORS["n8n_api"]
        self.assertTrue(spec.needs_n8n)
        self.assertEqual(spec.headers.get("X-N8N-API-KEY"), "{key}")
        self.assertIn("/api/v1/workflows", spec.url)
        self.assertIn(
            "--n8n-url",
            rp.argv_from_options(
                {"domain": "example.com", "n8n_url": "https://demo.app.n8n.cloud"}
            ),
        )

        header = b64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        payload = b64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "00000000-0000-4000-8000-000000000001",
                    "iss": "n8n",
                    "aud": "public-api",
                    "jti": "00000000-0000-4000-8000-000000000002",
                    "iat": 1781551662,
                }
            ).encode()
        ).decode().rstrip("=")
        token = f"{header}.{payload}.sig"
        meta = rp.inspect_jwt(token)
        self.assertTrue(rp.is_n8n_jwt(meta))
        self.assertEqual(rp.jwt_provider_kind(meta), "n8n_api")
        self.assertTrue(rp.is_n8n_api_token(token))
        self.assertEqual(rp.refine_secret_type("jwt", token), "n8n_api")
        self.assertEqual(rp.classify_secret_type(token), "n8n_api")
        self.assertEqual(rp.gitleaks_type_for("jwt", token), "n8n_api")
        self.assertEqual(
            rp.infer_n8n_base("https://acme.app.n8n.cloud/workflow/1"),
            "https://acme.app.n8n.cloud",
        )
        self.assertEqual(
            rp._n8n_instance_base("https://acme.app.n8n.cloud/api/v1"),
            "https://acme.app.n8n.cloud",
        )
        generic = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertFalse(rp.is_n8n_api_token(generic))
        self.assertEqual(rp.refine_secret_type("jwt", generic), "jwt")
        skipped = rp.validate_finding_configured_sync(
            {
                "type": "n8n_api",
                "key": "n8n_api_" + "A" * 20,
                "source_url": "gui://key-tester",
            },
            "example.com",
        )
        self.assertIn("n8n-url", skipped.get("note") or "")
        self.assertFalse(skipped.get("valid"))

    def test_exposure_types_not_every_secret(self):
        self.assertEqual(rp.EXPOSURE_TYPES, frozenset({"source_map_exposure"}))

    def test_trufflehog_maps_gemini_aiza_to_google_api(self):
        fake = "AIzaSy" + ("A" * 33)
        line = json.dumps(
            {
                "DetectorName": "GoogleGeminiAPIKey",
                "Raw": fake,
                "Verified": False,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "/tmp/app.js"}}
                },
            }
        )
        rows = rp.parse_trufflehog((line + "\n").encode())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["type"], "google_api")
        self.assertEqual(rows[0]["detector"], "GoogleGeminiAPIKey")
        self.assertEqual(rows[0]["key"], fake)
        self.assertFalse(rows[0]["verified"])

    def test_jwt_key_tester_still_works(self):
        finding = {
            "type": "jwt",
            "key": (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ),
        }
        out = rp.validate_finding_configured_sync(finding, "example.com")
        self.assertTrue(out.get("validated"))
        self.assertIn("jwt", out)


if __name__ == "__main__":
    unittest.main()
