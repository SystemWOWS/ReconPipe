#!/usr/bin/env python3
"""Local/cloud LLM remediation reports for finished ReconPipe scans.

Sends redacted finding metadata only. The model is asked for verification
steps (re-check the public source, re-run Key Tester) and defensive fixes
(rotate, revoke, remove from the leak surface). It is not asked for
exploit PoCs or attack procedures.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROVIDERS = ("ollama", "openai", "anthropic", "openai_compat")

DEFAULT_MODELS = {
    "ollama": "llama3.1",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-latest",
    "openai_compat": "local-model",
}

DEFAULT_BASE_URLS = {
    "ollama": "http://127.0.0.1:11434",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "openai_compat": "http://127.0.0.1:1234/v1",
}

SYSTEM_PROMPT = """You are a defensive security assistant for ReconPipe, a secret-leak hunter.

Write a markdown report for the operator who already ran the scan. For each finding include:

1. What was found (type, severity, live/dead, redacted fingerprint, source URL).
2. How to verify it is still exposed — open/download the listed source, confirm the
   redacted value is still present, and re-run ReconPipe Key Tester for that type.
   After rotation, Key Tester should report invalid/revoked.
3. How to fix it — revoke/rotate at the vendor console, remove the secret from the
   public file/repo/bundle, switch to env vars or a secret manager, and add
   referer/IP restrictions when the vendor supports them.

Rules:
- Do not invent full secrets. Values in the input are already redacted.
- Do not write exploit PoCs, payloads, attack commands, or abuse recipes.
- Do not tell the reader how to use a stolen key against a third party.
- Prefer vendor revocation URLs from the input when present.
- If there are no findings, say the scan did not confirm a live leak and list
  prevention basics (no secrets in frontend JS, rotate on any exposure).
- Keep the tone operational and concise. Use markdown headings.
"""

FINDING_GUIDANCE: Dict[str, Dict[str, str]] = {
    "google_api": {
        "verify": "Key Tester type google_api (Maps JSON / YouTube / Gemini spray). Confirm the key string is still in the listed JS or HTML source.",
        "fix": "Restrict the key by HTTP referrer and API in Google Cloud Console, disable unused APIs, or rotate the key and rebuild the frontend without the old value.",
    },
    "firebase_key": {
        "verify": "Key Tester type firebase_key. Confirm the FCM/server key is still in the listed source.",
        "fix": "Rotate the Cloud Messaging key in Firebase/Google Cloud, remove it from client bundles, and keep server keys on the backend only.",
    },
    "stripe_live": {
        "verify": "Key Tester type stripe_live. Confirm sk_live is still in the listed source.",
        "fix": "Roll the secret key in the Stripe Dashboard immediately, move billing to the backend, and never ship sk_live in frontend JS.",
    },
    "openai_key": {
        "verify": "Key Tester type openai_key against api.openai.com/v1/models.",
        "fix": "Revoke the key at platform.openai.com, create a new key in a secret manager, and keep it off public repos and browser bundles.",
    },
    "anthropic_key": {
        "verify": "Key Tester type anthropic_key against Anthropic models list.",
        "fix": "Revoke in the Anthropic console, rotate, and store only in server-side secrets.",
    },
    "github_pat": {
        "verify": "Key Tester type github_pat. Confirm the ghp_ token is still in the listed file.",
        "fix": "Revoke the PAT in GitHub settings, purge it from git history if committed, and use fine-grained or Actions secrets instead.",
    },
    "aws_access_key": {
        "verify": "Key Tester type aws_access_key (STS GetCallerIdentity) with the paired secret if you have it.",
        "fix": "Disable/delete the IAM access key, rotate, investigate CloudTrail, and never embed AKIA keys in client code.",
    },
    "slack_token": {
        "verify": "Key Tester type slack_token (auth.test).",
        "fix": "Revoke the token in Slack, rotate the app credentials, and keep bot tokens in a secret store.",
    },
    "hubspot_api": {
        "verify": "Key Tester type hubspot_api (pat-na1/eu1/ap1 private app token).",
        "fix": "Rotate or delete the private app in HubSpot, remove the token from public JS/env files, and scope a new app tightly.",
    },
    "source_map_exposure": {
        "verify": "Open the listed .map URL and confirm original sources are downloadable.",
        "fix": "Stop publishing production source maps (or gate them), rebuild without maps, and treat any secrets found in reconstructed sources as leaked.",
    },
}


def default_llm_settings() -> Dict[str, Any]:
    return {
        "enabled": False,
        "auto": True,
        "provider": "ollama",
        "model": DEFAULT_MODELS["ollama"],
        "base_url": DEFAULT_BASE_URLS["ollama"],
        "timeout": 120,
        "max_findings": 40,
        "dark": True,
    }


def _user_io():
    import reconpipe as rp

    return rp


def load_app_settings() -> Dict[str, Any]:
    rp = _user_io()
    raw = rp._load_user_yaml("settings.yaml")
    out = default_llm_settings()
    if isinstance(raw.get("llm"), dict):
        llm = raw["llm"]
        for key in ("enabled", "auto", "provider", "model", "base_url"):
            if llm.get(key) is not None and str(llm.get(key)).strip() != "":
                out[key] = llm[key]
        for key in ("timeout", "max_findings"):
            if llm.get(key) is not None:
                try:
                    out[key] = int(llm[key])
                except (TypeError, ValueError):
                    pass
    ui = raw.get("ui") if isinstance(raw.get("ui"), dict) else {}
    if "dark" in ui:
        out["dark"] = bool(ui["dark"])
    elif "dark" in raw:
        out["dark"] = bool(raw["dark"])
    out["enabled"] = bool(out["enabled"])
    out["auto"] = bool(out["auto"])
    provider = str(out.get("provider") or "ollama").strip().lower()
    if provider not in PROVIDERS:
        provider = "ollama"
    out["provider"] = provider
    if not str(out.get("model") or "").strip():
        out["model"] = DEFAULT_MODELS[provider]
    if not str(out.get("base_url") or "").strip():
        out["base_url"] = DEFAULT_BASE_URLS[provider]
    out["timeout"] = max(10, min(int(out.get("timeout") or 120), 600))
    out["max_findings"] = max(1, min(int(out.get("max_findings") or 40), 200))
    out["dark"] = bool(out.get("dark", True))
    return out


def save_app_settings(values: Dict[str, Any], *, llm_key: Optional[str] = None) -> Path:
    rp = _user_io()
    current = rp._load_user_yaml("settings.yaml")
    merged = default_llm_settings()
    merged.update({k: v for k, v in (values or {}).items() if k in merged})
    provider = str(merged.get("provider") or "ollama").strip().lower()
    if provider not in PROVIDERS:
        provider = "ollama"
    merged["provider"] = provider
    current["llm"] = {
        "enabled": bool(merged["enabled"]),
        "auto": bool(merged["auto"]),
        "provider": provider,
        "model": str(merged.get("model") or DEFAULT_MODELS[provider]).strip(),
        "base_url": str(merged.get("base_url") or DEFAULT_BASE_URLS[provider]).strip(),
        "timeout": max(10, min(int(merged.get("timeout") or 120), 600)),
        "max_findings": max(1, min(int(merged.get("max_findings") or 40), 200)),
    }
    current["ui"] = {"dark": bool(merged.get("dark", True))}
    path = rp._save_user_yaml("settings.yaml", current, private=True)
    if llm_key is not None:
        rp.save_user_keys({"llm": llm_key})
    return path


def load_llm_key() -> str:
    rp = _user_io()
    saved = rp.load_user_keys()
    return (saved.get("llm") or os.environ.get("RECONPIPE_LLM_KEY") or "").strip()


def resolve_llm_key(provider: str, explicit: Optional[str] = None) -> str:
    key = (explicit or "").strip() or load_llm_key()
    if key:
        return key
    provider = (provider or "").strip().lower()
    if provider == "openai":
        return (os.environ.get("OPENAI_API_KEY") or "").strip()
    if provider == "anthropic":
        return (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    return ""


def apply_llm_settings(args: Any) -> Any:
    """CLI flag > env > ~/.reconpipe/settings.yaml. CI skips LLM unless --llm."""
    saved = load_app_settings()
    skip = bool(getattr(args, "skip_llm", False))
    force = bool(getattr(args, "llm", False))
    if bool(getattr(args, "ci", False)) and not force:
        skip = True
    enabled = (not skip) and (force or (bool(saved.get("enabled")) and bool(saved.get("auto"))))
    args.llm = bool(enabled)
    args.skip_llm = not enabled
    provider = (getattr(args, "llm_provider", None) or "").strip() or saved["provider"]
    if provider not in PROVIDERS:
        provider = saved["provider"]
    args.llm_provider = provider
    model = (getattr(args, "llm_model", None) or "").strip()
    args.llm_model = model or saved["model"] or DEFAULT_MODELS[provider]
    base = (getattr(args, "llm_base_url", None) or "").strip()
    args.llm_base_url = base or saved["base_url"] or DEFAULT_BASE_URLS[provider]
    args.llm_key = resolve_llm_key(provider, getattr(args, "llm_key", None))
    timeout = getattr(args, "llm_timeout", None)
    try:
        args.llm_timeout = int(timeout) if timeout not in (None, "") else saved["timeout"]
    except (TypeError, ValueError):
        args.llm_timeout = saved["timeout"]
    max_n = getattr(args, "llm_max_findings", None)
    try:
        args.llm_max_findings = int(max_n) if max_n not in (None, "") else saved["max_findings"]
    except (TypeError, ValueError):
        args.llm_max_findings = saved["max_findings"]
    return args


def redact_finding(finding: Dict[str, Any], redact_key) -> Dict[str, Any]:
    typ = str(finding.get("type") or "unknown")
    guide = FINDING_GUIDANCE.get(typ) or {}
    return {
        "type": typ,
        "severity": str(finding.get("severity") or ""),
        "valid": bool(finding.get("valid")),
        "validated": bool(finding.get("validated")),
        "note": str(finding.get("note") or "")[:240],
        "source_url": str(finding.get("source_url") or "")[:500],
        "scanner": str(finding.get("scanner") or ""),
        "fingerprint": redact_key(str(finding.get("key") or "")),
        "revocation": str(finding.get("revocation") or ""),
        "ai_verdict": str(finding.get("ai_verdict") or ""),
        "verify_hint": guide.get("verify") or (
            "Re-open the source URL and re-run Key Tester for this type."
        ),
        "fix_hint": guide.get("fix") or (
            "Revoke/rotate the credential at the vendor, remove it from the public source, "
            "and store the replacement in a secret manager."
        ),
    }


def findings_for_prompt(
    findings: Iterable[Dict[str, Any]],
    exposures: Optional[Iterable[Dict[str, Any]]] = None,
    *,
    redact_key,
    limit: int = 40,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in list(findings or []) + list(exposures or []):
        if not isinstance(item, dict):
            continue
        rows.append(redact_finding(item, redact_key))
        if len(rows) >= limit:
            break
    return rows


def build_fallback_markdown(
    domain: str,
    rows: List[Dict[str, Any]],
    *,
    reason: str = "",
) -> str:
    lines = [
        f"# Remediation report — {domain or 'scan'}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "This file explains how to **verify** each finding is still exposed and how to **fix** it.",
        "Verification means re-checking the listed public source and ReconPipe Key Tester — not exploiting the credential.",
        "",
    ]
    if reason:
        lines += [f"_Note: {reason}_", ""]
    if not rows:
        lines += [
            "## No confirmed findings",
            "",
            "The finished scan did not produce items to remediate. Keep secrets out of frontend JS, lock down source maps, and rotate anything that was ever committed.",
            "",
        ]
        return "\n".join(lines)
    lines += ["## Findings", ""]
    for i, row in enumerate(rows, 1):
        live = "LIVE" if row.get("valid") else "unconfirmed / dead"
        lines += [
            f"### {i}. `{row.get('type')}` ({row.get('severity') or 'unknown'}, {live})",
            "",
            f"- Fingerprint: `{row.get('fingerprint')}`",
            f"- Source: {row.get('source_url') or '(none)'}",
            f"- Scanner note: {row.get('note') or '—'}",
            "",
            "**Verify**",
            "",
            f"1. {row.get('verify_hint')}",
            "2. If the source is a URL, download it again and confirm the fingerprint is still present.",
            "3. After you rotate, Key Tester for this type should no longer report LIVE.",
            "",
            "**Fix**",
            "",
            f"- {row.get('fix_hint')}",
        ]
        if row.get("revocation"):
            lines.append(f"- Vendor console: {row['revocation']}")
        lines += ["", ""]
    lines += [
        "## Prevention",
        "",
        "- Keep API secrets on the server; never ship them in public JS, APKs, or source maps.",
        "- Use environment variables / a secret manager in CI.",
        "- Rotate anything that appeared in this report even if Key Tester was inconclusive.",
        "",
    ]
    return "\n".join(lines)


def build_user_prompt(domain: str, rows: List[Dict[str, Any]]) -> str:
    payload = {
        "domain": domain,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(rows),
        "findings": rows,
    }
    return (
        "Write the remediation markdown for this ReconPipe scan. "
        "Input is JSON with redacted fingerprints only.\n\n"
        + json.dumps(payload, indent=2)
    )


def _http_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: int,
) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw) if raw.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("LLM response was not a JSON object")
    return data


def _http_get_json(url: str, headers: Optional[Dict[str, str]], timeout: int) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw) if raw.strip() else {}
    if not isinstance(data, dict) and not isinstance(data, list):
        raise ValueError("unexpected JSON")
    return data if isinstance(data, dict) else {"items": data}


def _normalize_base(url: str) -> str:
    return (url or "").strip().rstrip("/")


def chat_completion(
    *,
    provider: str,
    model: str,
    base_url: str,
    api_key: str,
    system: str,
    user: str,
    timeout: int = 120,
) -> str:
    provider = (provider or "ollama").strip().lower()
    model = (model or DEFAULT_MODELS.get(provider) or "llama3.1").strip()
    base = _normalize_base(base_url) or DEFAULT_BASE_URLS.get(provider, "")
    timeout = max(10, min(int(timeout or 120), 600))
    headers = {"Content-Type": "application/json", "User-Agent": "ReconPipe/1.3"}

    if provider == "ollama":
        url = base if base.endswith("/api/chat") else f"{base}/api/chat"
        data = _http_json(
            url,
            {
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers,
            timeout,
        )
        msg = data.get("message") if isinstance(data.get("message"), dict) else {}
        text = str(msg.get("content") or data.get("response") or "").strip()
        if not text:
            raise ValueError("Ollama returned an empty message")
        return text

    if provider == "anthropic":
        if not api_key:
            raise ValueError("Anthropic needs an API key (Settings or ANTHROPIC_API_KEY)")
        url = base if "/v1/messages" in base else f"{base}/v1/messages"
        headers.update(
            {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
        )
        data = _http_json(
            url,
            {
                "model": model,
                "max_tokens": 4096,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            headers,
            timeout,
        )
        parts = data.get("content") or []
        texts = [
            str(p.get("text") or "")
            for p in parts
            if isinstance(p, dict) and p.get("type") in (None, "text")
        ]
        text = "\n".join(t for t in texts if t).strip()
        if not text:
            raise ValueError("Anthropic returned an empty message")
        return text

    # openai + openai_compat
    if provider == "openai" and not api_key:
        raise ValueError("OpenAI needs an API key (Settings or OPENAI_API_KEY)")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if base.endswith("/chat/completions"):
        url = base
    elif base.endswith("/v1"):
        url = f"{base}/chat/completions"
    else:
        url = f"{base}/v1/chat/completions"
    data = _http_json(
        url,
        {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        headers,
        timeout,
    )
    choices = data.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        raise ValueError("OpenAI-compatible endpoint returned no choices")
    msg = choices[0].get("message") if isinstance(choices[0].get("message"), dict) else {}
    text = str(msg.get("content") or "").strip()
    if not text:
        raise ValueError("OpenAI-compatible endpoint returned an empty message")
    return text


def ping_llm(
    *,
    provider: str,
    model: str,
    base_url: str,
    api_key: str,
    timeout: int = 20,
) -> Tuple[bool, str]:
    provider = (provider or "ollama").strip().lower()
    base = _normalize_base(base_url) or DEFAULT_BASE_URLS.get(provider, "")
    timeout = max(5, min(int(timeout or 20), 60))
    try:
        if provider == "ollama":
            data = _http_get_json(f"{base}/api/tags", {}, timeout)
            names = [
                str(m.get("name") or "")
                for m in (data.get("models") or [])
                if isinstance(m, dict)
            ]
            n = len([x for x in names if x])
            hint = f"Ollama reachable — {n} model(s)"
            if model and names and not any(model in x for x in names):
                hint += f" (pull `{model}` if chat fails)"
            return True, hint
        if provider == "anthropic":
            if not (api_key or "").strip():
                return False, "Set an Anthropic API key first"
            return True, "Anthropic API key is set (chat is used on report generate)"
        if provider == "openai" and not (api_key or "").strip():
            return False, "Set an OpenAI API key first"
        headers = {"User-Agent": "ReconPipe/1.3"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        models_url = f"{base}/models" if base.endswith("/v1") else f"{base}/v1/models"
        data = _http_get_json(models_url, headers, timeout)
        items = data.get("data") or data.get("items") or []
        return True, f"Endpoint reachable — {len(items)} model(s) listed"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        return False, f"Unreachable: {exc.reason or exc}"
    except Exception as exc:
        return False, str(exc)


def maybe_write_llm_report(
    output_dir: Path,
    domain: str,
    findings: List[Dict[str, Any]],
    exposures: Optional[List[Dict[str, Any]]] = None,
    informational: Optional[List[Dict[str, Any]]] = None,  # noqa: ARG001
    args: Any = None,
    *,
    force: bool = False,
) -> Optional[Path]:
    """Write remediation.md. Uses the LLM when enabled; otherwise a local template."""
    import reconpipe as rp

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if args is None:
        saved = load_app_settings()

        class _Args:
            llm = bool(saved.get("enabled"))
            skip_llm = not bool(saved.get("enabled"))
            ci = False
            llm_provider = saved["provider"]
            llm_model = saved["model"]
            llm_base_url = saved["base_url"]
            llm_key = load_llm_key()
            llm_timeout = saved["timeout"]
            llm_max_findings = saved["max_findings"]

        args = _Args()
        apply_llm_settings(args)

    enabled = bool(getattr(args, "llm", False))
    skip = bool(getattr(args, "skip_llm", False))
    use_llm = force or (enabled and not skip)
    if not use_llm:
        return None

    limit = int(getattr(args, "llm_max_findings", None) or 40)
    rows = findings_for_prompt(
        findings, exposures, redact_key=rp.redact_key, limit=limit
    )
    dest = output_dir / "remediation.md"
    meta: Dict[str, Any] = {
        "domain": domain,
        "provider": getattr(args, "llm_provider", ""),
        "model": getattr(args, "llm_model", ""),
        "llm_used": False,
        "finding_count": len(rows),
        "redacted": True,
    }

    text = ""
    error = ""
    if use_llm:
        try:
            text = chat_completion(
                provider=str(getattr(args, "llm_provider", "ollama")),
                model=str(getattr(args, "llm_model", "")),
                base_url=str(getattr(args, "llm_base_url", "")),
                api_key=str(getattr(args, "llm_key", "") or ""),
                system=SYSTEM_PROMPT,
                user=build_user_prompt(domain, rows),
                timeout=int(getattr(args, "llm_timeout", 120) or 120),
            )
            meta["llm_used"] = True
        except Exception as exc:
            error = str(exc)
            meta["error"] = error[:500]

    if not text.strip():
        reason = (
            f"LLM unavailable ({error}). Local template used instead."
            if error
            else (
                "LLM is off — local template. Enable it in Settings for a model-written report."
                if not use_llm
                else "LLM returned empty text — local template used."
            )
        )
        text = build_fallback_markdown(domain, rows, reason=reason)
    else:
        header = (
            f"<!-- ReconPipe LLM report  provider={meta['provider']} "
            f"model={meta['model']} redacted=true -->\n\n"
        )
        if not text.lstrip().startswith("#"):
            text = f"# Remediation report — {domain}\n\n{text}"
        text = header + text.strip() + "\n"

    dest.write_text(text, encoding="utf-8")
    (output_dir / "llm_report.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    return dest
