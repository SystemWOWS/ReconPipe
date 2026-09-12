#!/usr/bin/env python3
"""Saved targets, intel keys, and hit-bundle packing."""
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


class UserSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.patcher = patch.dict(os.environ, {"RECONPIPE_HOME": str(self.home)})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_keys_roundtrip(self):
        path = rp.save_user_keys({"shodan": "s1", "chaos": "c1", "zoomeye": ""})
        self.assertTrue(path.is_file())
        saved = rp.load_user_keys()
        self.assertEqual(saved["shodan"], "s1")
        self.assertEqual(saved["chaos"], "c1")
        self.assertNotIn("zoomeye", saved)
        st = rp.saved_keys_status()
        self.assertTrue(st["shodan"])
        self.assertFalse(st["zoomeye"])

    def test_apply_saved_keys_fills_empty_args(self):
        rp.save_user_keys({"shodan": "from-disk", "censys_id": "cid"})
        args = rp.build_parser().parse_args(["-d", "example.com"])
        rp.apply_saved_keys(args)
        self.assertEqual(args.shodan_key, "from-disk")
        self.assertEqual(args.censys_id, "cid")

    def test_cli_flag_wins_over_saved_keys(self):
        rp.save_user_keys({"shodan": "from-disk"})
        args = rp.build_parser().parse_args(
            ["-d", "example.com", "--shodan-key", "from-cli"]
        )
        rp.apply_saved_keys(args)
        self.assertEqual(args.shodan_key, "from-cli")

    def test_targets_upsert_and_delete(self):
        rp.upsert_saved_target({"name": "acme", "domain": "acme.example"})
        rp.upsert_saved_target({"name": "acme", "domain": "acme.example", "files": "u.txt"})
        rows = rp.list_saved_targets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["files"], "u.txt")
        rp.delete_saved_target("acme")
        self.assertEqual(rp.list_saved_targets(), [])

    def test_remember_scan_copies_url_list(self):
        urls = self.home / "files_to_scan.txt"
        urls.write_text("https://example.com/app.js\n", encoding="utf-8")
        entry = rp.remember_scan_target("example.com", files=urls, output=self.home)
        self.assertTrue(Path(entry["files"]).is_file())
        self.assertIn("lists", entry["files"])
        self.assertIn("example.com", Path(entry["files"]).read_text(encoding="utf-8"))
        hist = rp.load_scan_history()
        self.assertTrue(hist)
        self.assertEqual(hist[0]["domain"], "example.com")

    def test_rescan_defaults_reuse_saved_target(self):
        urls = self.home / "files_to_scan.txt"
        urls.write_text("https://example.com/app.js\n", encoding="utf-8")
        out = self.home / "recon_example_com"
        out.mkdir()
        rp.remember_scan_target("example.com", files=urls, output=out)
        args = rp.build_parser().parse_args(["-d", "example.com", "--rescan"])
        rp.apply_rescan_defaults(args)
        self.assertTrue(args.resume)
        self.assertTrue(Path(args.files).is_file())
        self.assertEqual(Path(args.output), out)
        argv = rp.argv_from_options({"domain": "example.com", "rescan": True, "resume": True})
        self.assertIn("--rescan", argv)
        self.assertIn("--resume", argv)


class HitBundleTests(unittest.TestCase):
    def test_packs_js_and_reports_when_keys_found(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            dl = out / "downloaded_files"
            dl.mkdir()
            (dl / "app.js").write_text("const k = 'x';", encoding="utf-8")
            (dl / "app.js.map").write_text("{}", encoding="utf-8")
            (out / "findings.json").write_text("[]", encoding="utf-8")
            (out / "summary.txt").write_text("summary", encoding="utf-8")
            url = "https://cdn.example.com/app.js"
            js2 = dl / rp.download_filename(url)
            js2.write_text("KEY", encoding="utf-8")
            dest = rp.pack_hit_bundle(
                out,
                [{"type": "google_api", "key": "AIza", "source_url": url}],
                exposures=[],
            )
            self.assertIsNotNone(dest)
            self.assertTrue((dest / "summary.txt").is_file())
            self.assertTrue((dest / "sources" / js2.name).is_file())
            self.assertTrue((dest / "sources" / "app.js.map").is_file())
            self.assertTrue((dest / "INDEX.txt").is_file())

    def test_skips_bundle_when_no_hits(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                rp.pack_hit_bundle(Path(td), [], exposures=[], informational=[])
            )


if __name__ == "__main__":
    unittest.main()
