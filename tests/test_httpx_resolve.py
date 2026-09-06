#!/usr/bin/env python3
"""ProjectDiscovery httpx vs Python httpx CLI detection."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402

PD_HELP = """
httpx is a fast and multi-purpose HTTP toolkit.
Usage:
  -l, -list string  input file containing list of hosts
  -silent           silent mode
  -nc, -no-color    disable colors
projectdiscovery
"""

PD_VERSION = "[INF] Current Version: v1.6.10"

PY_HELP = """
Usage: httpx [OPTIONS] URL

  HTTPX: A next generation HTTP client.

  Error: No such option: -s
"""


class HttpxClassify(unittest.TestCase):
    def test_pd_help(self):
        self.assertTrue(rp.is_projectdiscovery_httpx(PD_HELP))
        self.assertFalse(rp.is_python_httpx_cli(PD_HELP))

    def test_pd_version(self):
        self.assertTrue(rp.is_projectdiscovery_httpx(PD_VERSION))

    def test_python_cli(self):
        self.assertTrue(rp.is_python_httpx_cli(PY_HELP))
        self.assertFalse(rp.is_projectdiscovery_httpx(PY_HELP))

    def test_empty(self):
        self.assertFalse(rp.is_projectdiscovery_httpx(""))
        self.assertFalse(rp.is_python_httpx_cli(""))

    def test_resolve_skips_python_prefers_pd(self):
        mapping = {
            "/home/user/.local/bin/httpx": PY_HELP,
            "/home/user/go/bin/httpx": PD_HELP + PD_VERSION,
        }

        def fake_identify(path: str) -> str:
            return mapping.get(path, "")

        with patch.dict(os.environ, {"HTTPX_BIN": ""}, clear=False):
            os.environ.pop("HTTPX_BIN", None)
            with patch.object(rp, "_iter_named_binaries", return_value=list(mapping)):
                with patch.object(rp, "_httpx_identify", side_effect=fake_identify):
                    self.assertEqual(rp.resolve_httpx_bin(), "/home/user/go/bin/httpx")
                    self.assertEqual(
                        rp.python_httpx_on_path(), "/home/user/.local/bin/httpx"
                    )

    def test_httpx_bin_env_override(self):
        def fake_identify(path: str) -> str:
            if path == "/opt/pd/httpx":
                return PD_HELP
            return PY_HELP

        with patch.dict(os.environ, {"HTTPX_BIN": "/opt/pd/httpx"}):
            with patch.object(rp, "_httpx_identify", side_effect=fake_identify):
                self.assertEqual(rp.resolve_httpx_bin(), "/opt/pd/httpx")

    def test_httpx_bin_env_rejects_python(self):
        with patch.dict(os.environ, {"HTTPX_BIN": "/usr/bin/httpx"}):
            with patch.object(rp, "_httpx_identify", return_value=PY_HELP):
                with patch.object(rp, "_iter_named_binaries", return_value=[]):
                    self.assertIsNone(rp.resolve_httpx_bin())


if __name__ == "__main__":
    unittest.main()
