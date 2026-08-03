#!/usr/bin/env python3
"""Generate tests/fixtures/patterns.yaml with known-good / known-junk samples."""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reconpipe as r  # noqa: E402


def b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main() -> None:
    c: dict = {}
    c["google_api"] = {
        "good": ["AIza" + "A" * 35],
        "junk": ["AIzaShort", "AIza" + "!" * 35, "notgoogle"],
    }
    c["google_oauth"] = {
        "good": ["ya29." + "a" * 20],
        "junk": ["ya29.short", "ya28.aaaaaaaaaaaaaaaaaaaa"],
    }
    c["aws_access_key"] = {
        "good": ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"],
        "junk": ["AKIASHORT", "BKIAIOSFODNN7EXAMPLE", "akiaiosfodnn7example"],
    }
    c["aws_secret"] = {
        "good": [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        ],
        "junk": ["password=hello", "aws_key=short", "not related text"],
    }
    c["aws_session_token"] = {
        "good": ["aws_session_token=" + "A" * 100, "X-Amz-Security-Token: " + "B" * 120],
        "junk": ["aws_session_token=short", "session=hello"],
    }
    c["github_pat"] = {
        "good": ["ghp_" + "a" * 36],
        "junk": ["ghp_short", "gho_" + "a" * 36],
    }
    c["github_fine_pat"] = {
        "good": ["github_pat_" + "A" * 22 + "_" + "B" * 59],
        "junk": ["github_pat_short", "ghp_" + "a" * 36],
    }
    c["github_oauth"] = {"good": ["gho_" + "x" * 36], "junk": ["ghp_" + "x" * 36]}
    c["github_app"] = {
        "good": ["ghu_" + "x" * 36, "ghs_" + "y" * 36],
        "junk": ["ghx_" + "x" * 36],
    }
    c["gitlab_pat"] = {
        "good": ["glpat-" + "x" * 20],
        "junk": ["glpat-short", "ghp_xxx"],
    }
    c["stripe_live"] = {
        "good": ["sk_live_" + "a" * 24],
        "junk": ["sk_test_" + "a" * 24, "rk_live_" + "a" * 24],
    }
    c["stripe_test"] = {
        "good": ["sk_test_" + "a" * 24],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["stripe_restricted"] = {
        "good": ["rk_live_" + "a" * 24, "rk_test_" + "b" * 30],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["stripe_publishable"] = {
        "good": ["pk_live_" + "a" * 24],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["openai_key"] = {
        "good": ["sk-proj-" + "a" * 20 + "-" + "b" * 20],
        "junk": ["sk-proj-short", "sk_live_xxx"],
    }
    c["anthropic_key"] = {
        "good": ["sk-ant-api03-" + "c" * 20],
        "junk": ["sk-ant-api03-short"],
    }
    c["sendgrid"] = {
        "good": ["SG." + "a" * 22 + "." + "b" * 43],
        "junk": ["SG.short.short"],
    }
    c["mailgun"] = {"good": ["key-" + "a" * 32], "junk": ["key-short"]}
    c["twilio_sid"] = {
        "good": ["AC" + "a" * 32],
        "junk": ["AC" + "a" * 10, "SK" + "a" * 32],
    }
    c["twilio_token"] = {
        "good": ["SK" + "a" * 32],
        "junk": ["SK" + "z" * 32, "AC" + "a" * 32],
    }
    c["slack_token"] = {
        "good": ["xoxb-1234567890-abcdefghij"],
        "junk": ["xoxb-short", "xoxz-1234567890-abcdefghij"],
    }
    c["slack_webhook"] = {
        "good": [
            "https://hooks.slack.com/services/T01ABC/B01DEF/abcdefghijklmnopqrstuvwx"
        ],
        "junk": [
            "https://hooks.slack.com/services/nope",
            "https://example.com/hooks",
        ],
    }
    c["firebase_url"] = {
        "good": ["my-app-123.firebaseio.com"],
        "junk": ["firebaseio.com", "my.firebase.com"],
    }
    c["firebase_key"] = {
        "good": ["AAAA" + "a" * 7 + ":" + "b" * 140],
        "junk": ["AAAA:short"],
    }
    c["digitalocean_pat"] = {
        "good": ["dop_v1_" + "a" * 64],
        "junk": ["dop_v1_" + "a" * 32, "dop_v1_" + "g" * 64],
    }
    c["npm_token"] = {"good": ["npm_" + "A" * 36], "junk": ["npm_short"]}
    c["pypi_token"] = {
        "good": ["pypi-AgEIcHlwaS5vcmc" + "x" * 50],
        "junk": ["pypi-AgEIcHlwaS5vcmcshort"],
    }
    c["private_key_pem"] = {
        "good": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
        "junk": ["-----BEGIN CERTIFICATE-----", "BEGIN PRIVATE KEY"],
    }
    c["uuid_candidate"] = {
        "good": ["550e8400-e29b-41d4-a716-446655440000"],
        "junk": ["550e8400-e29b-61d4-a716-446655440000", "not-a-uuid"],
    }
    hdr = b64url({"alg": "HS256", "typ": "JWT"})
    payload = b64url({"sub": "1", "exp": 9999999999})
    c["jwt"] = {
        "good": [f"{hdr}.{payload}.sigsignature1"],
        "junk": ["eyJhbGciOiJIUzI1NiJ9", "not.a.jwt"],
    }
    c["shopify_token"] = {
        "good": ["shpat_" + "a" * 32],
        "junk": ["shpat_short", "shpss_" + "a" * 32],
    }
    c["shopify_secret"] = {
        "good": ["shpss_" + "a" * 32],
        "junk": ["shpat_" + "a" * 32],
    }
    c["mailchimp"] = {
        "good": ["a" * 32 + "-us1", "b" * 32 + "-us12"],
        "junk": ["a" * 32 + "-eu1", "short-us1"],
    }
    c["discord_token"] = {
        "good": ["M" + "a" * 24 + "." + "b" * 6 + "." + "c" * 27],
        "junk": ["X" + "a" * 24 + "." + "b" * 6 + "." + "c" * 27, "notdiscord"],
    }
    c["discord_webhook"] = {
        "good": [
            "https://discord.com/api/webhooks/123456789012345678/"
            "abcdefghijklmnopqrstuvwxyzABCDEFG"
        ],
        "junk": [
            "https://discord.com/api/webhooks/abc/token",
            "https://example.com/api/webhooks/1/t",
        ],
    }
    c["telegram_bot"] = {
        "good": ["1234567890:" + "A" * 35],
        "junk": ["12:short", "abcdefghij:" + "a" * 35],
    }
    mb = b64url({"u": "alice", "pad": "xxxxxxxxxx"})
    c["mapbox_token"] = {
        "good": [f"pk.{mb}"],
        "junk": ["pk.shorttoken", "pk_live_" + "a" * 24],
    }
    c["generic_secret"] = {
        "good": [
            'api_key = "AbCdEfGhIjKlMnOp1234"',
            'secret: "Qx9!mK2pL8vN4wR7"',
        ],
        "junk": [
            'api_key = "short"',
            "hello world",
            "no assignment here AbCdEfGhIjKlMnOp1234",
        ],
    }

    errors = []
    for t, samples in c.items():
        pat = r.PATTERNS.get(t)
        if not pat:
            errors.append(f"missing pattern {t}")
            continue
        rx = re.compile(pat)
        for g in samples["good"]:
            if not rx.search(g):
                errors.append(f"FN {t}: {g[:70]!r}")
            if t == "mapbox_token" and not r.is_mapbox_token(
                rx.search(g).group(0) if rx.search(g) else g
            ):
                errors.append(f"mapbox JSON fail {t}: {g[:50]!r}")
        for j in samples["junk"]:
            if rx.search(j):
                errors.append(f"FP {t}: {j[:70]!r}")

    if errors:
        print("ERRORS", len(errors))
        for e in errors:
            print(e)
        sys.exit(1)

    out = ROOT / "tests" / "fixtures" / "patterns.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.dump({"patterns": c}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"wrote {out} types={len(c)}")


if __name__ == "__main__":
    main()
