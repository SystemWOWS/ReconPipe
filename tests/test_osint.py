#!/usr/bin/env python3
"""Offline tests for Shodan / Censys / ZoomEye / crt.sh host enrichment."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402


class OsintHelpers(unittest.TestCase):
    def test_belongs(self):
        self.assertTrue(rp._osint_belongs("www.example.com", "example.com"))
        self.assertTrue(rp._osint_belongs("*.api.example.com", "example.com"))
        self.assertFalse(rp._osint_belongs("evil.com", "example.com"))
        self.assertFalse(rp._osint_belongs("example.com.attacker.net", "example.com"))

    def test_merge(self):
        merged = rp.merge_host_lists(
            ["Example.com", "www.example.com"],
            ["*.api.example.com", "www.example.com"],
        )
        self.assertEqual(merged, ["api.example.com", "example.com", "www.example.com"])

    def test_shodan_parser(self):
        payload = {
            "subdomains": ["www", "api"],
            "domain": "example.com",
            "data": [{"subdomain": "mail", "value": "1.2.3.4"}],
        }
        with patch.object(rp, "_osint_http_json", return_value=payload):
            hosts = rp.query_shodan("example.com", "dummy-key")
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)

    def test_shodan_empty_without_key(self):
        self.assertEqual(rp.query_shodan("example.com", ""), [])

    def test_censys_parser(self):
        payload = {
            "result": {
                "hits": [
                    {"names": ["example.com", "www.example.com", "https://cdn.example.com"]},
                    {"dns": {"names": ["api.example.com"]}},
                ]
            }
        }
        with patch.object(rp, "_osint_http_json", return_value=payload):
            hosts = rp.query_censys("example.com", "id", "secret")
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)

    def test_zoomeye_parser(self):
        payload = {
            "list": [
                {"name": "vpn.example.com"},
                {"site": "https://dev.example.com"},
            ]
        }
        with patch.object(rp, "_osint_http_json", return_value=payload):
            hosts = rp.query_zoomeye("example.com", "dummy-key")
        self.assertIn("vpn.example.com", hosts)
        self.assertIn("dev.example.com", hosts)

    def test_crtsh_parser(self):
        payload = [
            {"name_value": "example.com\nwww.example.com"},
            {"common_name": "*.cdn.example.com"},
        ]
        with patch.object(rp, "_osint_http_json", return_value=payload):
            hosts = rp.query_crtsh("example.com")
        self.assertIn("www.example.com", hosts)
        self.assertIn("cdn.example.com", hosts)

    def test_collect_respects_skip(self):
        out = rp.collect_osint_hosts("example.com", skip_intel=True)
        self.assertEqual(out, {})

    def test_status_never_leaks_keys(self):
        st = rp.osint_source_status(
            shodan_key="secret-shodan",
            censys_id="cid",
            censys_secret="csec",
            zoomeye_key="zkey",
        )
        blob = " ".join(st.values())
        self.assertNotIn("secret-shodan", blob)
        self.assertEqual(st["shodan"], "key")
        self.assertEqual(st["censys"], "key")
        self.assertEqual(st["zoomeye"], "key")
        self.assertEqual(st["crtsh"], "on")

    def test_status_saved_keys_without_widget_values(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"RECONPIPE_HOME": td}, clear=False):
                rp.save_user_keys(
                    {
                        "shodan": "disk-shodan",
                        "censys_id": "cid",
                        "censys_secret": "csec",
                        "zoomeye": "disk-zoom",
                    }
                )
                for k in (
                    "SHODAN_API_KEY",
                    "CENSYS_API_ID",
                    "CENSYS_API_SECRET",
                    "ZOOMEYE_API_KEY",
                    "ZOOMEYE_KEY",
                ):
                    os.environ.pop(k, None)
                st = rp.osint_source_status()
                self.assertEqual(st["shodan"], "saved")
                self.assertEqual(st["censys"], "saved")
                self.assertEqual(st["zoomeye"], "saved")
                self.assertEqual(st["crtsh"], "on")
                blob = " ".join(st.values())
                self.assertNotIn("disk-shodan", blob)
                self.assertNotIn("csec", blob)

    def test_argv_includes_intel_flags(self):
        argv = rp.argv_from_options(
            {
                "domain": "example.com",
                "shodan_key": "s1",
                "censys_id": "id1",
                "censys_secret": "sec1",
                "zoomeye_key": "z1",
                "skip_crtsh": True,
            }
        )
        args = rp.build_parser().parse_args(argv)
        self.assertEqual(args.shodan_key, "s1")
        self.assertEqual(args.censys_id, "id1")
        self.assertEqual(args.zoomeye_key, "z1")
        self.assertTrue(args.skip_crtsh)

    def test_collect_merges_mocked_sources(self):
        with patch.object(rp, "query_shodan", return_value=["a.example.com"]):
            with patch.object(rp, "query_censys", return_value=["b.example.com"]):
                with patch.object(rp, "query_zoomeye", return_value=["c.example.com"]):
                    with patch.object(rp, "query_crtsh", return_value=["d.example.com"]):
                        out = rp.collect_osint_hosts(
                            "example.com",
                            shodan_key="k",
                            censys_id="i",
                            censys_secret="s",
                            zoomeye_key="z",
                        )
        self.assertEqual(set(out), {"shodan", "censys", "zoomeye", "crtsh"})


if __name__ == "__main__":
    os.environ.pop("SHODAN_API_KEY", None)
    unittest.main(verbosity=2)
