#!/usr/bin/env python3
"""Docker packaging exists and compose/CLI wiring is consistent (no image build)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconpipe as rp  # noqa: E402


class DockerPackagingTests(unittest.TestCase):
    def test_dockerfile_and_compose_present(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        entry = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("reconpipe.py", dockerfile)
        self.assertIn("golang:1.26-bookworm", dockerfile)
        self.assertIn("projectdiscovery/httpx", dockerfile)
        self.assertIn("zricethezav/gitleaks/v8", dockerfile)
        self.assertIn("trufflehog", dockerfile)
        # Compose pulls the published image by default but can still build locally.
        self.assertIn("ghcr.io/systemwows/reconpipe", compose)
        self.assertIn("build: .", compose)
        self.assertIn("./scans:/work", compose)
        self.assertIn("./docker-home:/root/.reconpipe", compose)
        self.assertIn('command: ["gui"]', compose)
        self.assertIn("reconpipe.py", entry)
        self.assertIn('= "gui"', entry)

    def test_ghcr_publish_workflow_present(self):
        wf = (ROOT / ".github" / "workflows" / "docker-image.yml").read_text(encoding="utf-8")
        self.assertIn("docker/build-push-action", wf)
        self.assertIn("ghcr.io/${{ github.repository }}", wf)
        self.assertIn("packages: write", wf)

    def test_rescan_flag_on_parser(self):
        args = rp.build_parser().parse_args(["-d", "example.com", "--rescan"])
        self.assertTrue(args.rescan)
        rp.apply_rescan_defaults(args)
        self.assertTrue(args.resume)


if __name__ == "__main__":
    unittest.main()
