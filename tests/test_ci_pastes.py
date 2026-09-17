#!/usr/bin/env python3
"""Public CI logs + paste-site search — injectable fetch, no live network."""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe_wave3 as w3  # noqa: E402

AWS_EX = "AKIAIOSFODNN7EXAMPLE"
GIST_ID = "a" * 32


def _zip_bytes(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in members.items():
            zf.writestr(name, text)
    return buf.getvalue()


class CiPasteTests(unittest.TestCase):
    def test_parse_forge_and_code_urls(self):
        gh = w3.parse_forge_repo("https://github.com/acme/app/blob/main/src/config.js")
        self.assertEqual(gh["forge"], "github")
        self.assertEqual(gh["owner"], "acme")
        self.assertEqual(gh["repo"], "app")
        ssh = w3.parse_forge_repo("git@github.com:acme/app.git")
        self.assertEqual((ssh["owner"], ssh["repo"]), ("acme", "app"))
        raw = w3.parse_forge_repo(
            "https://raw.githubusercontent.com/acme/app/main/.env"
        )
        self.assertEqual((raw["owner"], raw["repo"]), ("acme", "app"))
        gl = w3.parse_forge_repo("https://gitlab.com/acme/grp/app/-/jobs/9")
        self.assertEqual(gl["forge"], "gitlab")
        self.assertEqual(gl["project"], "acme/grp/app")
        rows = w3.repos_from_code_urls([
            "https://github.com/acme/app/blob/main/a.js",
            "https://github.com/acme/app/blob/main/b.js",
            "https://gitlab.com/acme/api/-/blob/main/.env",
        ])
        self.assertEqual(len(rows), 2)

    def test_keep_ci_member_and_zip_extract(self):
        self.assertTrue(w3.keep_ci_member("0_build.txt"))
        self.assertTrue(w3.keep_ci_member("1_Build"))
        self.assertTrue(w3.keep_ci_member(".env.production"))
        self.assertFalse(w3.keep_ci_member("photo.png"))
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "out"
            blob = _zip_bytes({
                "logs/0_build.txt": f"key={AWS_EX}\n",
                "../escape.bin": "nope",
                "photo.png": "x",
            })
            written = w3.extract_zip_scan_files(blob, dest)
            names = {p.name for p in written}
            self.assertIn("0_build.txt", names)
            self.assertNotIn("photo.png", names)
            for path in written:
                path.resolve().relative_to(dest.resolve())

    def test_collect_ci_targets_repo_org_and_code_search(self):
        seen = []

        def fake_json(url, headers=None, timeout=20):
            seen.append(url)
            if "/orgs/acme/repos" in url:
                return [
                    {"full_name": "acme/app", "private": False},
                    {"full_name": "acme/other", "private": False},
                    {"full_name": "acme/secret", "private": True},
                ]
            self.fail(f"unexpected fetch {url}")

        targets = w3.collect_ci_targets(
            repo_url="https://github.com/acme/app",
            github_org="acme",
            code_urls=["https://github.com/acme/app/blob/main/.env"],
            fetch_json=fake_json,
        )
        slugs = {(t["owner"], t["repo"]) for t in targets}
        self.assertIn(("acme", "app"), slugs)
        self.assertIn(("acme", "other"), slugs)
        self.assertNotIn(("acme", "secret"), slugs)
        self.assertTrue(any("/orgs/acme/repos" in u for u in seen))

        def boom(*_a, **_k):
            raise AssertionError("gitlab-only should not list GitHub orgs")

        gl_only = w3.collect_ci_targets(
            repo_url="https://gitlab.com/acme/api",
            fetch_json=boom,
        )
        self.assertEqual(gl_only[0]["forge"], "gitlab")

    def test_collect_github_ci_logs_and_artifacts(self):
        log_zip = _zip_bytes({"1_Build": f"export AWS_ACCESS_KEY_ID={AWS_EX}\n"})
        art_zip = _zip_bytes({".env": "OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbb\n"})

        def fake_json(url, headers=None, timeout=20):
            if "/actions/runs?" in url:
                return {"workflow_runs": [
                    {"id": 99, "name": "CI", "status": "completed", "conclusion": "success"},
                ]}
            if "/actions/runs/99/artifacts" in url:
                return {"artifacts": [
                    {"id": 7, "name": "dist", "expired": False, "size_in_bytes": 120},
                    {"id": 8, "name": "old", "expired": True, "size_in_bytes": 10},
                ]}
            self.fail(f"unexpected json {url}")

        def fake_bytes(url, headers=None, timeout=25, max_bytes=8_000_000):
            if url.endswith("/logs"):
                return 200, log_zip, {}
            if url.endswith("/artifacts/7/zip"):
                return 200, art_zip, {}
            if url.endswith("/zip"):
                return 403, b"", {}
            return 0, b"", {}

        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)
            files = w3.collect_ci_log_files(
                [{"forge": "github", "owner": "acme", "repo": "app"}],
                dest,
                fetch_json=fake_json,
                fetch_bytes=fake_bytes,
            )
            self.assertTrue(files)
            blob = "\n".join(p.read_text(encoding="utf-8") for p in files)
            self.assertIn(AWS_EX, blob)
            self.assertIn("sk-proj-", blob)

    def test_collect_gitlab_traces(self):
        def fake_json(url, headers=None, timeout=20):
            if "/jobs?" in url:
                return [{
                    "id": 3,
                    "name": "build",
                    "status": "success",
                    "artifacts_file": {"filename": "job.zip"},
                }]
            self.fail(f"unexpected json {url}")

        def fake_bytes(url, headers=None, timeout=25, max_bytes=8_000_000):
            if url.endswith("/trace"):
                return 200, b"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", {}
            if url.endswith("/artifacts"):
                return 200, _zip_bytes({"notes.txt": "token=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"}), {}
            return 0, b"", {}

        with tempfile.TemporaryDirectory() as td:
            files = w3.collect_ci_log_files(
                [{"forge": "gitlab", "owner": "acme", "repo": "app", "project": "acme/app"}],
                Path(td),
                fetch_json=fake_json,
                fetch_bytes=fake_bytes,
            )
            blob = "\n".join(p.read_text(encoding="utf-8") for p in files)
            self.assertIn("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", blob)
            self.assertIn("ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", blob)

    def test_paste_parsers_and_terms(self):
        terms = w3.paste_search_terms("example.com")
        self.assertIn("example.com", terms)
        self.assertTrue(any("AKIA" in t for t in terms))
        self.assertTrue(w3.paste_blob_matches(f"leak {AWS_EX}", "other.net"))
        self.assertTrue(w3.paste_blob_matches("config for example.com", "example.com"))
        self.assertFalse(w3.paste_blob_matches("hello world", "example.com"))
        rows = w3.parse_pastebin_scrape([
            {"key": "abc123", "title": "env", "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abc123"},
        ])
        self.assertEqual(rows[0]["id"], "abc123")
        dumps = w3.parse_psbdmp_search({"data": [{"id": "deadbeef", "text": "example.com"}]})
        self.assertEqual(dumps[0]["id"], "deadbeef")
        html = f'<a href="/octocat/{GIST_ID}">gist</a>'
        self.assertEqual(w3.parse_gist_search_html(html), [GIST_ID])
        self.assertEqual(w3.parse_ghostbin_search_html('<a href="/paste/abcd">x</a>'), ["abcd"])

    def test_collect_paste_files_mocked(self):
        calls = []

        def fake_json(url, headers=None, timeout=20):
            calls.append(url)
            if "scrape.pastebin.com/api_scraping.php" in url:
                return [{"key": "abc123", "title": "random"}]
            if "psbdmp.ws/api/v3/search/" in url:
                return {"data": [{"id": "deadbeef", "text": "example.com"}]}
            if url.endswith("/gists/public?per_page=50"):
                return [{
                    "id": "1111",
                    "description": "example.com secrets",
                    "files": {"a.env": {"raw_url": "https://gist.githubusercontent.com/x/raw"}},
                    "url": "https://api.github.com/gists/1111",
                }]
            if url.endswith("/gists/1111") or url.endswith(f"/gists/{GIST_ID}"):
                return {
                    "files": {
                        "secrets.env": {
                            "content": f"example.com\nAWS={AWS_EX}\n",
                            "raw_url": "https://gist.githubusercontent.com/raw",
                        }
                    }
                }
            return None

        def fake_text(url, headers=None, timeout=15):
            calls.append(url)
            if "pastebin.com/raw/abc123" in url or "api_scrape_item.php" in url:
                return 200, f"sk-ant-api03-{'c' * 24} example.com", {}
            if "pastebin.com/raw/deadbeef" in url or "psbdmp.ws/dump/" in url:
                return 200, f"{AWS_EX} example.com", {}
            if "gist.github.com/search" in url:
                return 200, f'<a href="/octocat/{GIST_ID}">x</a>', {}
            if "ghostbin" in url:
                return 404, "", {}
            return 200, "", {}

        def fake_bytes(*_a, **_k):
            return 0, b"", {}

        with tempfile.TemporaryDirectory() as td:
            files = w3.collect_paste_files(
                "example.com",
                Path(td),
                fetch_json=fake_json,
                fetch_text=fake_text,
                fetch_bytes=fake_bytes,
            )
            self.assertTrue(files)
            blob = "\n".join(p.read_text(encoding="utf-8") for p in files)
            self.assertIn("example.com", blob)
            self.assertTrue("AKIA" in blob or "sk-ant-" in blob)
            self.assertTrue(any("psbdmp.ws/api/v3/search/" in u for u in calls))


if __name__ == "__main__":
    unittest.main()
