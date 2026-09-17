#!/usr/bin/env python3
"""AI/MCP paths, key formats, verdict scoring, Docker Hub — no live network."""
from __future__ import annotations

import io
import json
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402
import reconpipe_addons as addons  # noqa: E402
import reconpipe_wave3 as w3  # noqa: E402


OPENAI_PROJ = "sk-proj-" + "a" * 20 + "-" + "b" * 20
OPENAI_LEGACY = "sk-" + "e" * 20 + "T3BlbkFJ" + "f" * 20
ANTHROPIC = "sk-ant-api03-" + "c" * 24
HF = "hf_" + "a" * 34


class AiMcpTests(unittest.TestCase):
    def test_sensitive_paths_include_2026_targets(self):
        paths = set(rp.SENSITIVE_PATHS)
        for item in (
            "/.cursor/mcp.json",
            "/.anthropic/config.json",
            "/.vscode/mcp.json",
            "/.mcp.json",
            "/claude_desktop_config.json",
            "/.config/gcloud/application_default_credentials.json",
            "/application_default_credentials.json",
            "/.codeium/windsurf/mcp_config.json",
            "/.continue/config.json",
        ):
            self.assertIn(item, paths)
        self.assertTrue(rp.DISCOVERY_KEEP_URL_RE.search("https://ex.com/.cursor/mcp.json"))
        self.assertTrue(
            rp.DISCOVERY_KEEP_URL_RE.search(
                "https://ex.com/.config/gcloud/application_default_credentials.json"
            )
        )
        mcp_hits = rp.mcp_like_urls(
            ["https://ex.com/app.js", "https://ex.com/.cursor/mcp.json", "https://ex.com/.cursor/mcp.json"]
        )
        self.assertEqual(mcp_hits, ["https://ex.com/.cursor/mcp.json"])

    def test_ai_key_regexes(self):
        ox = re.compile(rp.PATTERNS["openai_key"])
        ax = re.compile(rp.PATTERNS["anthropic_key"])
        hx = re.compile(rp.PATTERNS["huggingface_token"])
        self.assertTrue(ox.search(OPENAI_PROJ))
        self.assertTrue(ox.search("sk-svcacct-" + "d" * 24))
        self.assertTrue(ox.search(OPENAI_LEGACY))
        self.assertIsNone(ox.search("sk_live_" + "a" * 24))
        self.assertIsNone(ox.search(ANTHROPIC))
        self.assertTrue(ax.search(ANTHROPIC))
        self.assertTrue(ax.search("sk-ant-admin01-" + "e" * 24))
        self.assertIsNone(ax.search(OPENAI_PROJ))
        self.assertTrue(hx.search(HF))
        self.assertIsNone(hx.search("hf_short"))

    def test_openai_anthropic_hf_validators_configured(self):
        o = rp.VALIDATORS["openai_key"]
        self.assertIn("api.openai.com/v1/models", o.url)
        self.assertEqual(o.headers.get("Authorization"), "Bearer {key}")
        a = rp.VALIDATORS["anthropic_key"]
        self.assertIn("api.anthropic.com/v1/models", a.url)
        self.assertEqual(a.headers.get("x-api-key"), "{key}")
        self.assertEqual(a.headers.get("anthropic-version"), "2023-06-01")
        self.assertIn(404, a.invalid_codes)
        h = rp.VALIDATORS["huggingface_token"]
        self.assertIn("huggingface.co/api/whoami-v2", h.url)

    def test_mcp_extractor_and_classify(self):
        blob = json.dumps({
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "server", "--api-key", ANTHROPIC],
                    "env": {"OPENAI_API_KEY": OPENAI_PROJ, "HF_TOKEN": HF},
                },
                "remote": {
                    "url": "https://mcp.example.com/sse",
                    "headers": {"Authorization": "Bearer " + "ghp_" + "A" * 36},
                },
                "skip": {
                    "env": {"API_KEY": "${env:API_KEY}", "OTHER": "YOUR-KEY-HERE-PLEASE"},
                },
            }
        })
        self.assertTrue(addons.looks_like_mcp_config(".cursor/mcp.json", blob))
        rows = addons.extract_mcp_secrets(blob, ".cursor/mcp.json")
        keys = {r["key"] for r in rows}
        self.assertIn(OPENAI_PROJ, keys)
        self.assertIn(HF, keys)
        self.assertIn(ANTHROPIC, keys)
        self.assertTrue(any(k.startswith("ghp_") for k in keys))
        self.assertFalse(any("${" in k or "YOUR-KEY" in k for k in keys))
        findings = rp.findings_from_mcp_content(blob, "/tmp/.cursor/mcp.json")
        types = {f["type"] for f in findings}
        self.assertIn("openai_key", types)
        self.assertIn("anthropic_key", types)
        self.assertIn("huggingface_token", types)
        self.assertTrue(all(f.get("mcp_config") for f in findings))

    def test_ai_verdict_prioritizes_live_mcp(self):
        live_mcp = {
            "type": "openai_key",
            "key": OPENAI_PROJ,
            "valid": True,
            "confidence": 94,
            "severity": "high",
            "source_url": "/app/.cursor/mcp.json",
            "mcp_config": True,
        }
        dead_generic = {
            "type": "generic_secret",
            "key": "not-an-ai-key-value-zz",
            "valid": False,
            "validated": True,
            "confidence": 40,
            "severity": "low",
            "source_url": "https://ex.com/app.js",
        }
        ranked = rp.apply_ai_verdict([dead_generic, live_mcp])
        self.assertEqual(ranked[0]["ai_verdict"], "P1")
        self.assertEqual(ranked[0]["priority"], "P1")
        self.assertEqual(ranked[1]["ai_verdict"], "P3")
        self.assertGreater(ranked[0]["ai_score"], ranked[1]["ai_score"])
        self.assertIn("mcp_config", ranked[0]["ai_reasons"])
        self.assertIn("live", ranked[0]["ai_reasons"])

    def test_docker_hub_and_image_refs(self):
        qs = w3.docker_hub_queries("acme.com")
        self.assertIn("acme.com", qs)
        self.assertIn("acme", qs)
        rows = w3.parse_docker_hub_search({
            "results": [
                {"repo_name": "acme/api", "star_count": 3, "is_official": False},
                {"name": "acme/web"},
            ]
        })
        self.assertEqual([r["repo_name"] for r in rows], ["acme/api", "acme/web"])

        def fake_fetch(url, headers=None, timeout=20):
            self.assertIn("hub.docker.com", url)
            return {"results": [{"repo_name": "acme/api"}]}

        images = w3.collect_docker_hub_images("acme.com", fetch_json=fake_fetch)
        self.assertEqual(images, ["acme/api"])
        text = "FROM python:3.12\nFROM acme/api:1.2\n    image: ghcr.io/acme/worker:latest\n"
        refs = w3.extract_image_refs(text)
        self.assertTrue(any("acme/api" in r for r in refs))
        selected = w3.select_images_for_target(
            refs, "acme.com", hub_hits=["acme/api"]
        )
        self.assertTrue(any("acme/api" in r for r in selected))
        self.assertFalse(any(r.split(":")[0] == "python" for r in selected))

    def test_docker_save_layer_extract_and_trivy_parse(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            inner_buf = io.BytesIO()
            with tarfile.open(fileobj=inner_buf, mode="w") as inner:
                env = b"OPENAI_API_KEY=" + OPENAI_PROJ.encode() + b"\n"
                info = tarfile.TarInfo(name=".env")
                info.size = len(env)
                inner.addfile(info, io.BytesIO(env))
                mcp = json.dumps({"mcpServers": {"x": {"env": {"HF_TOKEN": HF}}}}).encode()
                minfo = tarfile.TarInfo(name=".cursor/mcp.json")
                minfo.size = len(mcp)
                inner.addfile(minfo, io.BytesIO(mcp))
                skip = b"hello"
                sinfo = tarfile.TarInfo(name="usr/bin/app")
                sinfo.size = len(skip)
                inner.addfile(sinfo, io.BytesIO(skip))
            layer_bytes = inner_buf.getvalue()
            save_path = td_path / "image.tar"
            with tarfile.open(save_path, mode="w") as outer:
                linfo = tarfile.TarInfo(name="abc123/layer.tar")
                linfo.size = len(layer_bytes)
                outer.addfile(linfo, io.BytesIO(layer_bytes))
            dest = td_path / "out"
            files = w3.extract_docker_save_credentials(save_path, dest)
            names = {p.name for p in files}
            self.assertIn(".env", names)
            self.assertIn("mcp.json", names)
            self.assertFalse(any(p.name == "app" for p in files))

            trivy = {
                "Results": [{
                    "Target": "acme/api:latest",
                    "Secrets": [{
                        "RuleID": "openai-api-key",
                        "Match": OPENAI_PROJ,
                    }],
                }]
            }
            hits = w3.findings_from_trivy_secrets(trivy, image="acme/api:latest")
            self.assertEqual(hits[0]["type"], "openai_key")
            self.assertEqual(hits[0]["scanner"], "trivy_image")

            def fake_save(ref, tar_path):
                Path(tar_path).write_bytes(save_path.read_bytes())
                return Path(tar_path)

            extracted, tf = w3.scan_public_image_layers(
                ["acme/api:latest"],
                td_path / "layers",
                pull_and_save=fake_save,
                trivy_scan=lambda _ref: hits,
            )
            self.assertTrue(extracted)
            self.assertEqual(len(tf), 1)

    def test_github_queries_include_mcp_and_cli_flags(self):
        qs = w3.github_search_queries("example.com")
        self.assertTrue(any("mcp.json" in q for q in qs))
        self.assertTrue(any("sk-ant-" in q for q in qs))
        parser = rp.build_parser()
        args = parser.parse_args([
            "-d", "example.com",
            "--skip-docker-hub",
            "--skip-image-layers",
            "--skip-ci-logs",
            "--skip-pastes",
        ])
        self.assertTrue(args.skip_docker_hub)
        self.assertTrue(args.skip_image_layers)
        self.assertTrue(args.skip_ci_logs)
        self.assertTrue(args.skip_pastes)
        argv = rp.argv_from_options({
            "domain": "example.com",
            "skip_docker_hub": True,
            "skip_image_layers": True,
            "skip_ci_logs": True,
            "skip_pastes": True,
        })
        self.assertIn("--skip-docker-hub", argv)
        self.assertIn("--skip-image-layers", argv)
        self.assertIn("--skip-ci-logs", argv)
        self.assertIn("--skip-pastes", argv)
        args2 = parser.parse_args(["--ci"])
        rp.apply_ci_defaults(args2)
        self.assertTrue(args2.skip_docker_hub)
        self.assertTrue(args2.skip_image_layers)
        self.assertTrue(args2.skip_ci_logs)
        self.assertTrue(args2.skip_pastes)


if __name__ == "__main__":
    unittest.main()
