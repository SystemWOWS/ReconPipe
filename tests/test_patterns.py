#!/usr/bin/env python3
"""Pattern corpus tests: zero FNs/FPs + ReDoS timeouts on every regex."""
from __future__ import annotations

import re
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as r  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "patterns.yaml"
REGEX_TIMEOUT_SEC = 1.0
REDOS_TIMEOUT_SEC = 1.5


def _search(pattern: str, text: str):
    return re.search(pattern, text)


def search_with_timeout(pattern: str, text: str, timeout: float = REGEX_TIMEOUT_SEC):
    """Run re.search in a worker thread; raise TimeoutError on ReDoS-ish hangs."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_search, pattern, text)
        try:
            return fut.result(timeout=timeout)
        except FuturesTimeout as exc:
            raise TimeoutError(
                f"regex exceeded {timeout}s (possible ReDoS) pattern={pattern[:60]!r}"
            ) from exc


def load_fixtures() -> dict:
    data = yaml.safe_load(FIXTURES.read_text(encoding="utf-8"))
    return data["patterns"]


class PatternCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = load_fixtures()

    def test_fixture_coverage_matches_config(self):
        missing = sorted(set(r.PATTERNS) - set(self.fixtures))
        extra = sorted(set(self.fixtures) - set(r.PATTERNS))
        self.assertEqual(missing, [], msg=f"fixtures missing types: {missing}")
        self.assertEqual(extra, [], msg=f"fixtures have unknown types: {extra}")

    def test_known_good_no_false_negatives(self):
        for key_type, samples in self.fixtures.items():
            pattern = r.PATTERNS[key_type]
            for sample in samples.get("good") or []:
                with self.subTest(type=key_type, kind="good", sample=sample[:48]):
                    m = search_with_timeout(pattern, sample)
                    self.assertIsNotNone(
                        m, f"FN: {key_type} failed to match {sample!r}"
                    )
                    if key_type == "mapbox_token":
                        self.assertTrue(
                            r.is_mapbox_token(m.group(0)),
                            f"mapbox payload must JSON-validate: {sample!r}",
                        )

    def test_known_junk_no_false_positives(self):
        for key_type, samples in self.fixtures.items():
            pattern = r.PATTERNS[key_type]
            for sample in samples.get("junk") or []:
                with self.subTest(type=key_type, kind="junk", sample=sample[:48]):
                    m = search_with_timeout(pattern, sample)
                    self.assertIsNone(
                        m, f"FP: {key_type} matched junk {sample!r}"
                    )

    def test_every_regex_redos_hygiene(self):
        """Pathological inputs must not hang any compiled pattern."""
        attacks = [
            "a" * 50000,
            ("aws" + "secret" * 2000 + "=" + "A" * 100),
            ("api_key" + " " * 5000 + '="' + "x" * 5000),
            "pk." + "A" * 20000,
            "eyJ" + "A" * 10000 + "." + "B" * 10000 + "." + "C" * 10000,
            "-----BEGIN " + "X" * 5000 + " PRIVATE KEY-----",
            "https://hooks.slack.com/services/" + "T" * 5000,
        ]
        for key_type, pattern in r.PATTERNS.items():
            for i, attack in enumerate(attacks):
                with self.subTest(type=key_type, attack=i):
                    try:
                        search_with_timeout(pattern, attack, timeout=REDOS_TIMEOUT_SEC)
                    except TimeoutError:
                        self.fail(
                            f"ReDoS timeout on {key_type} attack#{i}"
                        )


class SarifHelperTests(unittest.TestCase):
    def test_write_sarif_shape(self):
        out = Path(__file__).parent / "fixtures" / "_tmp_test.sarif"
        findings = [
            {
                "type": "github_pat",
                "key": "ghp_" + "a" * 36,
                "source_url": "https://example.com/a.js",
                "valid": True,
                "note": "VALID: test",
                "hash": "abc",
            },
            {
                "type": "jwt",
                "key": "eyJhbGciOiJub25lIn0.e30.",
                "source_url": "https://example.com/b.js",
                "valid": False,
                "note": "Expired",
            },
        ]
        r.write_sarif(findings, out, domain="example.com")
        data = json_load(out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 2)
        levels = {res["ruleId"]: res["level"] for res in data["runs"][0]["results"]}
        self.assertEqual(levels["github_pat"], "error")
        self.assertEqual(levels["jwt"], "warning")
        out.unlink(missing_ok=True)


class TrufflehogCmdTests(unittest.TestCase):
    def test_filesystem_uses_positional_path(self):
        cmd = r.trufflehog_filesystem_cmd("/tmp/downloaded_files")
        self.assertEqual(cmd[0], "trufflehog")
        self.assertIn("filesystem", cmd)
        self.assertIn("/tmp/downloaded_files", cmd)
        self.assertNotIn("--path", cmd)
        self.assertEqual(cmd[-1], "/tmp/downloaded_files")
        self.assertIn("--no-update", cmd)
        self.assertIn("--json", cmd)


def json_load(path: Path):
    import json

    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
