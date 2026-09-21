#!/usr/bin/env python3
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

RedactFn = Callable[[str], str]

VENDORS: Dict[str, Dict[str, str]] = {
    "google": {
        "name": "Google",
        "category": "Cloud & AI",
        "website": "https://cloud.google.com/",
        "about": "Maps, Gemini, Firebase, and Google Cloud APIs billed to a GCP project.",
    },
    "amazon": {
        "name": "Amazon Web Services",
        "category": "Cloud",
        "website": "https://aws.amazon.com/",
        "about": "IAM access keys and marketplace credentials for AWS accounts.",
    },
    "microsoft": {
        "name": "Microsoft / Azure",
        "category": "Cloud",
        "website": "https://azure.microsoft.com/",
        "about": "Azure storage, Cosmos, DevOps, and Microsoft 365 integrations.",
    },
    "github": {
        "name": "GitHub",
        "category": "Source control",
        "website": "https://github.com/",
        "about": "Source code, Actions, and org administration via personal access tokens.",
    },
    "gitlab": {
        "name": "GitLab",
        "category": "Source control",
        "website": "https://gitlab.com/",
        "about": "Git hosting, CI jobs, and registry access.",
    },
    "stripe": {
        "name": "Stripe",
        "category": "Payments",
        "website": "https://stripe.com/",
        "about": "Card payments, payouts, and customer billing.",
    },
    "openai": {
        "name": "OpenAI",
        "category": "AI",
        "website": "https://openai.com/",
        "about": "GPT APIs billed per token against the account quota.",
    },
    "anthropic": {
        "name": "Anthropic",
        "category": "AI",
        "website": "https://www.anthropic.com/",
        "about": "Claude API access billed to the workspace.",
    },
    "slack": {
        "name": "Slack",
        "category": "Comms",
        "website": "https://slack.com/",
        "about": "Workspace messaging, files, and incoming webhooks.",
    },
    "twilio": {
        "name": "Twilio",
        "category": "Comms",
        "website": "https://www.twilio.com/",
        "about": "SMS, voice, and Verify APIs billed per message.",
    },
    "sendgrid": {
        "name": "SendGrid (Twilio)",
        "category": "Email",
        "website": "https://sendgrid.com/",
        "about": "Transactional email sending on behalf of the domain.",
    },
    "hubspot": {
        "name": "HubSpot",
        "category": "CRM",
        "website": "https://www.hubspot.com/",
        "about": "CRM contacts, deals, and marketing automation.",
    },
    "shopify": {
        "name": "Shopify",
        "category": "Commerce",
        "website": "https://www.shopify.com/",
        "about": "Store admin, orders, and customer PII.",
    },
    "cloudflare": {
        "name": "Cloudflare",
        "category": "Infrastructure",
        "website": "https://www.cloudflare.com/",
        "about": "DNS, WAF, and account-wide zone changes.",
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "category": "Cloud",
        "website": "https://www.digitalocean.com/",
        "about": "Droplets, Spaces, and account billing.",
    },
    "heroku": {
        "name": "Heroku",
        "category": "PaaS",
        "website": "https://www.heroku.com/",
        "about": "App config vars, dynos, and add-ons.",
    },
    "hashicorp": {
        "name": "HashiCorp",
        "category": "Secrets",
        "website": "https://www.hashicorp.com/",
        "about": "Vault tokens that unlock stored secrets.",
    },
    "datadog": {
        "name": "Datadog",
        "category": "Observability",
        "website": "https://www.datadoghq.com/",
        "about": "Metrics, logs, and APM for the environment.",
    },
    "huggingface": {
        "name": "Hugging Face",
        "category": "AI",
        "website": "https://huggingface.co/",
        "about": "Model hub tokens and Inference API access.",
    },
    "notion": {
        "name": "Notion",
        "category": "Productivity",
        "website": "https://www.notion.so/",
        "about": "Workspace pages and databases.",
    },
    "linear": {
        "name": "Linear",
        "category": "Productivity",
        "website": "https://linear.app/",
        "about": "Issue tracker for the engineering org.",
    },
    "supabase": {
        "name": "Supabase",
        "category": "Data",
        "website": "https://supabase.com/",
        "about": "Postgres + auth; service keys bypass row-level security.",
    },
    "vercel": {
        "name": "Vercel",
        "category": "PaaS",
        "website": "https://vercel.com/",
        "about": "Deployments, env vars, and project settings.",
    },
    "netlify": {
        "name": "Netlify",
        "category": "PaaS",
        "website": "https://www.netlify.com/",
        "about": "Sites, env vars, and deploy keys.",
    },
    "algolia": {
        "name": "Algolia",
        "category": "Search",
        "website": "https://www.algolia.com/",
        "about": "Search indices; admin keys can rewrite the catalog.",
    },
    "okta": {
        "name": "Okta",
        "category": "Identity",
        "website": "https://www.okta.com/",
        "about": "Workforce SSO and user directory.",
    },
    "discord": {
        "name": "Discord",
        "category": "Comms",
        "website": "https://discord.com/",
        "about": "Bot tokens and incoming webhooks for servers.",
    },
    "telegram": {
        "name": "Telegram",
        "category": "Comms",
        "website": "https://telegram.org/",
        "about": "Bot API that can message users who started the bot.",
    },
    "paypal": {
        "name": "PayPal",
        "category": "Payments",
        "website": "https://www.paypal.com/",
        "about": "Checkout and payouts; secrets move money.",
    },
    "square": {
        "name": "Square",
        "category": "Payments",
        "website": "https://squareup.com/",
        "about": "POS and payments APIs.",
    },
    "intercom": {
        "name": "Intercom",
        "category": "Support",
        "website": "https://www.intercom.com/",
        "about": "Customer conversations and contact data.",
    },
    "sentry": {
        "name": "Sentry",
        "category": "Observability",
        "website": "https://sentry.io/",
        "about": "Error tracking; auth tokens can read project events.",
    },
    "pagerduty": {
        "name": "PagerDuty",
        "category": "Ops",
        "website": "https://www.pagerduty.com/",
        "about": "On-call routing and incident APIs.",
    },
    "groq": {
        "name": "Groq",
        "category": "AI",
        "website": "https://groq.com/",
        "about": "Fast LLM inference billed to the GroqCloud account.",
    },
    "xai": {
        "name": "xAI",
        "category": "AI",
        "website": "https://x.ai/",
        "about": "Grok API access billed to the xAI account.",
    },
    "perplexity": {
        "name": "Perplexity",
        "category": "AI",
        "website": "https://www.perplexity.ai/",
        "about": "Search/answer API billed per request.",
    },
    "fireworks": {
        "name": "Fireworks AI",
        "category": "AI",
        "website": "https://fireworks.ai/",
        "about": "Hosted model inference.",
    },
    "figma": {
        "name": "Figma",
        "category": "Design",
        "website": "https://www.figma.com/",
        "about": "Design files, comments, and team libraries.",
    },
    "databricks": {
        "name": "Databricks",
        "category": "Data",
        "website": "https://www.databricks.com/",
        "about": "Workspace tokens for notebooks, jobs, and data.",
    },
    "postman": {
        "name": "Postman",
        "category": "API tooling",
        "website": "https://www.postman.com/",
        "about": "Collections, environments, and workspace secrets.",
    },
    "sonarqube": {
        "name": "SonarQube / SonarCloud",
        "category": "Code quality",
        "website": "https://www.sonarsource.com/",
        "about": "Analysis tokens for projects and quality gates.",
    },
    "cloudinary": {
        "name": "Cloudinary",
        "category": "Media",
        "website": "https://cloudinary.com/",
        "about": "Image/video CDN; URL credentials can upload or overwrite assets.",
    },
    "razorpay": {
        "name": "Razorpay",
        "category": "Payments",
        "website": "https://razorpay.com/",
        "about": "India-focused payments; live keys move money.",
    },
    "flutterwave": {
        "name": "Flutterwave",
        "category": "Payments",
        "website": "https://flutterwave.com/",
        "about": "African payments API; secret keys authorize charges.",
    },
    "other": {
        "name": "Other / unclassified",
        "category": "General",
        "website": "",
        "about": "Credentials that do not map to a named vendor in the catalog.",
    },
}

# key type -> (vendor_id, product label)
TYPE_VENDOR: Dict[str, Tuple[str, str]] = {
    "google_api": ("google", "Maps / Gemini / Cloud API key"),
    "google_oauth": ("google", "OAuth access token"),
    "firebase_key": ("google", "Firebase Cloud Messaging key"),
    "firebase_url": ("google", "Firebase realtime database URL"),
    "gcp_service_acct": ("google", "GCP service-account JSON"),
    "aws_access_key": ("amazon", "IAM access key ID"),
    "aws_secret": ("amazon", "IAM secret access key"),
    "aws_session_token": ("amazon", "STS session token"),
    "aws_mws_auth": ("amazon", "Marketplace Web Service auth"),
    "azure_sas": ("microsoft", "Azure SAS token"),
    "azure_client_secret": ("microsoft", "Entra ID client secret"),
    "azure_storage_key": ("microsoft", "Storage account key"),
    "azure_cosmos_key": ("microsoft", "Cosmos DB key"),
    "azure_devops_pat": ("microsoft", "Azure DevOps PAT"),
    "teams_webhook": ("microsoft", "Teams incoming webhook"),
    "github_pat": ("github", "Classic personal access token"),
    "github_fine_pat": ("github", "Fine-grained PAT"),
    "github_oauth": ("github", "OAuth token"),
    "github_app": ("github", "GitHub App token"),
    "gitlab_pat": ("gitlab", "Personal access token"),
    "stripe_live": ("stripe", "Live secret key"),
    "stripe_test": ("stripe", "Test secret key"),
    "stripe_restricted": ("stripe", "Restricted key"),
    "stripe_publishable": ("stripe", "Publishable key (public)"),
    "openai_key": ("openai", "API key"),
    "anthropic_key": ("anthropic", "API key"),
    "huggingface_token": ("huggingface", "User access token"),
    "groq_api": ("groq", "GroqCloud API key"),
    "xai_api": ("xai", "Grok API key"),
    "perplexity_api": ("perplexity", "API key"),
    "fireworks_api": ("fireworks", "Inference API key"),
    "slack_token": ("slack", "Bot / user token"),
    "slack_webhook": ("slack", "Incoming webhook"),
    "slack_app_token": ("slack", "App-level token (xapp-)"),
    "twilio_sid": ("twilio", "Account SID"),
    "twilio_token": ("twilio", "Auth token / API key"),
    "sendgrid": ("sendgrid", "API key"),
    "mailgun": ("sendgrid", "Mailgun API key"),
    "hubspot_api": ("hubspot", "Private app token"),
    "shopify_token": ("shopify", "Admin API token"),
    "shopify_secret": ("shopify", "App secret"),
    "cloudflare_api": ("cloudflare", "API token"),
    "digitalocean_pat": ("digitalocean", "Personal access token"),
    "heroku_api": ("heroku", "API key"),
    "hashicorp_vault": ("hashicorp", "Vault token"),
    "datadog_api_key": ("datadog", "API key"),
    "notion_token": ("notion", "Integration token"),
    "linear_api_key": ("linear", "API key"),
    "supabase_service": ("supabase", "Service-role JWT"),
    "supabase_anon": ("supabase", "Anon JWT"),
    "vercel_token": ("vercel", "Account token"),
    "netlify_pat": ("netlify", "Personal access token"),
    "algolia_api": ("algolia", "Search API key"),
    "algolia_admin": ("algolia", "Admin API key"),
    "okta_api": ("okta", "SSWS API token"),
    "discord_token": ("discord", "Bot / user token"),
    "discord_webhook": ("discord", "Incoming webhook"),
    "telegram_bot": ("telegram", "Bot token"),
    "paypal_secret": ("paypal", "Client secret"),
    "paypal_client_id": ("paypal", "Client ID"),
    "square_access": ("square", "Access token"),
    "square_application": ("square", "Application ID"),
    "intercom_token": ("intercom", "Access token"),
    "sentry_auth": ("sentry", "Auth token"),
    "sentry_dsn": ("sentry", "DSN"),
    "pagerduty_api": ("pagerduty", "API token"),
    "figma_token": ("figma", "Personal access token"),
    "databricks_token": ("databricks", "Workspace PAT"),
    "postman_api": ("postman", "API key"),
    "sonar_token": ("sonarqube", "User token"),
    "cloudinary_url": ("cloudinary", "cloudinary:// URL"),
    "razorpay_key": ("razorpay", "API key"),
    "flutterwave_secret": ("flutterwave", "Secret key"),
    "source_map_exposure": ("other", "JavaScript source map"),
}


PREFIX_VENDOR = (
    ("google", "google"),
    ("firebase", "google"),
    ("gcp", "google"),
    ("aws", "amazon"),
    ("azure", "microsoft"),
    ("github", "github"),
    ("gitlab", "gitlab"),
    ("stripe", "stripe"),
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("slack", "slack"),
    ("twilio", "twilio"),
    ("sendgrid", "sendgrid"),
    ("hubspot", "hubspot"),
    ("shopify", "shopify"),
    ("cloudflare", "cloudflare"),
    ("heroku", "heroku"),
    ("vault", "hashicorp"),
    ("datadog", "datadog"),
    ("huggingface", "huggingface"),
    ("notion", "notion"),
    ("linear", "linear"),
    ("supabase", "supabase"),
    ("vercel", "vercel"),
    ("netlify", "netlify"),
    ("algolia", "algolia"),
    ("okta", "okta"),
    ("discord", "discord"),
    ("telegram", "telegram"),
    ("paypal", "paypal"),
    ("square", "square"),
    ("intercom", "intercom"),
    ("sentry", "sentry"),
    ("pagerduty", "pagerduty"),
    ("groq", "groq"),
    ("xai", "xai"),
    ("perplexity", "perplexity"),
    ("fireworks", "fireworks"),
    ("figma", "figma"),
    ("databricks", "databricks"),
    ("postman", "postman"),
    ("sonar", "sonarqube"),
    ("cloudinary", "cloudinary"),
    ("razorpay", "razorpay"),
    ("flutterwave", "flutterwave"),
)


def vendor_for_type(key_type: str) -> Tuple[str, str]:
    t = str(key_type or "").strip()
    if t in TYPE_VENDOR:
        return TYPE_VENDOR[t]
    low = t.lower()
    for prefix, vid in PREFIX_VENDOR:
        if low.startswith(prefix) or prefix in low:
            label = t.replace("_", " ")
            return vid, label
    return "other", t.replace("_", " ") or "unknown"


def vendor_record(vendor_id: str) -> Dict[str, str]:
    row = VENDORS.get(vendor_id) or VENDORS["other"]
    return dict(row)


def _iter_findings(
    findings: Optional[Iterable[Dict[str, Any]]] = None,
    exposures: Optional[Iterable[Dict[str, Any]]] = None,
    informational: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Tuple[str, Dict[str, Any]]]:
    rows: List[Tuple[str, Dict[str, Any]]] = []
    for f in findings or []:
        if isinstance(f, dict):
            rows.append(("actionable", f))
    for f in informational or []:
        if isinstance(f, dict):
            rows.append(("informational", f))
    for f in exposures or []:
        if isinstance(f, dict):
            rows.append(("exposure", f))
    return rows


def group_findings_by_vendor(
    findings: Optional[Iterable[Dict[str, Any]]] = None,
    exposures: Optional[Iterable[Dict[str, Any]]] = None,
    informational: Optional[Iterable[Dict[str, Any]]] = None,
    *,
    redact: Optional[RedactFn] = None,
) -> List[Dict[str, Any]]:
    if redact is None:
        def redact(value: str) -> str:
            text = value or ""
            if len(text) <= 8:
                return "*" * len(text)
            return f"{text[:4]}…{text[-4:]}"

    buckets: Dict[str, Dict[str, Any]] = {}
    for tier, item in _iter_findings(findings, exposures, informational):
        typ = str(item.get("type") or "unknown")
        vid, product = vendor_for_type(typ)
        rec = vendor_record(vid)
        bucket = buckets.get(vid)
        if bucket is None:
            bucket = {
                "id": vid,
                "name": rec["name"],
                "category": rec["category"],
                "website": rec["website"],
                "about": rec["about"],
                "keys": [],
                "live": 0,
                "total": 0,
            }
            buckets[vid] = bucket
        live = bool(item.get("valid"))
        bucket["total"] += 1
        if live:
            bucket["live"] += 1
        bucket["keys"].append(
            {
                "type": typ,
                "product": product,
                "tier": tier,
                "valid": live,
                "severity": str(item.get("severity") or ""),
                "fingerprint": redact(str(item.get("key") or "")),
                "source_url": str(item.get("source_url") or ""),
                "note": str(item.get("note") or "")[:200],
                "revocation": str(item.get("revocation") or ""),
            }
        )

    out = list(buckets.values())
    out.sort(key=lambda b: (-int(b["live"]), -int(b["total"]), str(b["name"])))
    return out


def vendors_json_payload(
    domain: str,
    groups: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "domain": domain,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vendor_count": len(groups),
        "live_vendors": sum(1 for g in groups if g.get("live")),
        "vendors": groups,
    }


def vendor_dashboard_html(domain: str, groups: List[Dict[str, Any]]) -> str:
    cards = []
    if not groups:
        cards.append(
            "<p class='empty'>No vendors yet — run a scan or load findings.</p>"
        )
    for g in groups:
        live = int(g.get("live") or 0)
        total = int(g.get("total") or 0)
        badge = "LIVE" if live else "seen"
        rows = []
        for k in g.get("keys") or []:
            status = "LIVE" if k.get("valid") else "—"
            src = html.escape(str(k.get("source_url") or "")[:80])
            rows.append(
                "<tr>"
                f"<td><code>{html.escape(str(k.get('type')))}</code></td>"
                f"<td>{html.escape(str(k.get('product') or ''))}</td>"
                f"<td>{html.escape(str(k.get('severity') or ''))}</td>"
                f"<td>{status}</td>"
                f"<td><code>{html.escape(str(k.get('fingerprint') or ''))}</code></td>"
                f"<td class='src'>{src}</td>"
                "</tr>"
            )
        web = html.escape(str(g.get("website") or ""))
        link = f"<a href='{web}' target='_blank' rel='noopener'>{web}</a>" if web else ""
        cards.append(
            "<article class='card'>"
            f"<header><h3>{html.escape(str(g.get('name')))}</h3>"
            f"<span class='badge {'live' if live else 'seen'}'>{badge} {live}/{total}</span></header>"
            f"<p class='cat'>{html.escape(str(g.get('category') or ''))}</p>"
            f"<p>{html.escape(str(g.get('about') or ''))}</p>"
            f"<p class='web'>{link}</p>"
            "<table><thead><tr><th>Type</th><th>Product</th><th>Sev</th>"
            "<th>Live</th><th>Fingerprint</th><th>Source</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</article>"
        )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Vendors — {html.escape(domain)}</title>"
        "<style>"
        "body{font-family:Segoe UI,system-ui,sans-serif;background:#0d1117;color:#e6edf3;"
        "margin:0;padding:24px} h1{font-size:22px;margin:0 0 8px}"
        ".sub{color:#8b949e;margin:0 0 20px} .grid{display:grid;gap:16px}"
        ".card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}"
        ".card header{display:flex;justify-content:space-between;align-items:center;gap:12px}"
        ".card h3{margin:0;font-size:18px} .cat{color:#8b949e;font-size:12px;margin:4px 0}"
        ".badge{font-size:11px;padding:2px 8px;border-radius:999px;background:#30363d}"
        ".badge.live{background:#3d1f00;color:#f0883e} table{width:100%;border-collapse:collapse;"
        "font-size:12px;margin-top:10px} th,td{text-align:left;padding:6px 8px;"
        "border-bottom:1px solid #21262d} code{font-family:ui-monospace,Consolas,monospace}"
        ".src{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        "a{color:#58a6ff} .empty{color:#8b949e}"
        "</style></head><body>"
        f"<h1>Vendors &amp; API keys — {html.escape(domain)}</h1>"
        "<p class='sub'>Fingerprints only. Full secrets stay in findings.json (keep that file private).</p>"
        f"<div class='grid'>{''.join(cards)}</div>"
        "</body></html>"
    )


def _worst_severity(groups: List[Dict[str, Any]]) -> str:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    best = 9
    label = "info"
    for g in groups:
        for k in g.get("keys") or []:
            s = str(k.get("severity") or "").lower()
            r = rank.get(s, 8)
            if r < best:
                best = r
                label = s or "info"
    return label


def export_pentest_markdown(
    domain: str,
    groups: List[Dict[str, Any]],
    *,
    generated: Optional[str] = None,
) -> str:
    ts = generated or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_n = sum(int(g.get("live") or 0) for g in groups)
    total = sum(int(g.get("total") or 0) for g in groups)
    sev = _worst_severity(groups)
    lines = [
        f"# Exposed credentials on {domain}",
        "",
        f"**Asset:** `{domain}`  ",
        f"**Severity:** {sev or 'undetermined'}  ",
        f"**Weakness:** CWE-798 / CWE-540 (hard-coded / leaked credentials)  ",
        f"**Generated:** {ts}",
        "",
        "## Summary",
        "",
        f"ReconPipe found **{total}** credential candidate(s) across **{len(groups)}** vendor(s). "
        f"**{live_n}** validated as live against the provider. "
        "This report is for authorized testing of this asset only.",
        "",
        "## Impact",
        "",
        "A live third-party key in a public JS bundle, repo, or config lets anyone who fetches "
        "that file use the vendor account (billing, data, or admin) until the key is revoked. "
        "Impact depends on the vendor scopes listed below — not on attacking the host itself.",
        "",
        "## Steps to reproduce (verify the leak)",
        "",
        "1. Open each **Source** URL below (or download the file from the scan workspace).",
        "2. Confirm the listed **fingerprint** is still present in the file.",
        "3. In ReconPipe **Key Tester**, paste the credential and select the listed type.",
        "4. A **LIVE** result means the provider still accepts the key. After rotation, the same "
        "check should return invalid/revoked.",
        "",
        "Do not use the credential against the vendor beyond the Key Tester / documented validator.",
        "",
        "## Evidence",
        "",
    ]
    if not groups:
        lines += ["_No findings._", ""]
    for g in groups:
        lines += [f"### {g.get('name')} ({g.get('category')})", ""]
        if g.get("about"):
            lines.append(g["about"])
            lines.append("")
        if g.get("website"):
            lines.append(f"- Vendor: {g['website']}")
        lines.append(f"- Live keys: {g.get('live')} / {g.get('total')}")
        lines.append("")
        for k in g.get("keys") or []:
            live = "LIVE" if k.get("valid") else "unconfirmed"
            lines += [
                f"- `{k.get('type')}` — {k.get('product')} ({k.get('severity') or 'n/a'}, {live})",
                f"  - Fingerprint: `{k.get('fingerprint')}`",
                f"  - Source: {k.get('source_url') or '(none)'}",
            ]
            if k.get("revocation"):
                lines.append(f"  - Revoke: {k['revocation']}")
            if k.get("note"):
                lines.append(f"  - Note: {k['note']}")
        lines.append("")
    lines += [
        "## Remediation",
        "",
        "1. Revoke or rotate every **LIVE** key at the vendor console linked above.",
        "2. Remove the secret from the public file, git history, APK, or source map.",
        "3. Store replacements in a secret manager / CI variables — not frontend JS.",
        "4. Restrict remaining keys (HTTP referrer, IP, least-privilege scopes) where the vendor allows it.",
        "5. Re-run Key Tester and this scan; LIVE should drop to zero.",
        "",
        "## References",
        "",
        "- CWE-798: Use of Hard-coded Credentials",
        "- CWE-540: Inclusion of Sensitive Information in Source Code",
        "",
    ]
    return "\n".join(lines)


def export_executive_markdown(
    domain: str,
    groups: List[Dict[str, Any]],
    *,
    generated: Optional[str] = None,
) -> str:
    ts = generated or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_n = sum(int(g.get("live") or 0) for g in groups)
    live_companies = [g for g in groups if g.get("live")]
    lines = [
        f"# Security briefing — {domain}",
        "",
        f"_For leadership · {ts} · secrets are redacted_",
        "",
        "## Bottom line",
        "",
    ]
    if live_n:
        names = ", ".join(str(g.get("name")) for g in live_companies[:8])
        extra = "…" if len(live_companies) > 8 else ""
        lines.append(
            f"**{live_n} live API credential(s)** were confirmed on public assets for **{domain}**, "
            f"tied to: {names}{extra}. These are working keys, not just strings in a file. "
            "Treat this as an incident until they are rotated."
        )
    elif groups:
        lines.append(
            f"Candidates were found on **{domain}**, but none validated as live in this run. "
            "Still review and rotate anything that looks production-grade."
        )
    else:
        lines.append(
            f"This scan of **{domain}** did not surface credential candidates. "
            "Keep secrets out of frontend code and public repos."
        )
    lines += [
        "",
        "## What this means",
        "",
        "- **Who is affected:** customers and the business, if a live key can read CRM/payment/"
        "cloud data or run up vendor bills.",
        "- **What we did:** authorized secret scanning of public/in-scope files. We did **not** "
        "log into customer accounts or use keys beyond a provider “is this key accepted?” check.",
        "- **What we need:** revoke live keys this week, then a short follow-up scan.",
        "",
        "## Vendors involved",
        "",
        "| Company | Category | Live keys | Total seen | Why it matters |",
        "|---|---|---:|---:|---|",
    ]
    if not groups:
        lines.append("| — | — | 0 | 0 | No vendors in this scan |")
    for g in groups:
        about = str(g.get("about") or "").replace("|", "/")
        lines.append(
            f"| {g.get('name')} | {g.get('category')} | {g.get('live')} | {g.get('total')} | {about} |"
        )
    lines += [
        "",
        "## Ask for this week",
        "",
        "1. **Security / eng:** revoke every live key; remove it from the public file.",
        "2. **Finance:** watch Stripe/cloud/AI invoices for unexpected usage.",
        "3. **Leadership:** no customer notification is implied by this scan alone — "
        "legal/privacy should decide if personal data was in reach of a live key.",
        "",
        "## Appendix — fingerprints (not full secrets)",
        "",
    ]
    for g in groups:
        for k in g.get("keys") or []:
            if not k.get("valid"):
                continue
            lines.append(
                f"- {g.get('name')} `{k.get('type')}` `{k.get('fingerprint')}`"
            )
    if live_n == 0:
        lines.append("_No live fingerprints._")
    lines.append("")
    return "\n".join(lines)


def export_executive_html(domain: str, groups: List[Dict[str, Any]]) -> str:
    md_like = export_executive_markdown(domain, groups)
    live_n = sum(int(g.get("live") or 0) for g in groups)
    rows = []
    for g in groups:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(g.get('name')))}</td>"
            f"<td>{html.escape(str(g.get('category') or ''))}</td>"
            f"<td>{int(g.get('live') or 0)}</td>"
            f"<td>{int(g.get('total') or 0)}</td>"
            f"<td>{html.escape(str(g.get('about') or ''))}</td>"
            "</tr>"
        )
    headline = (
        f"{live_n} live credential(s) confirmed"
        if live_n
        else "No live credentials confirmed in this run"
    )
    color = "#f0883e" if live_n else "#3fb950"
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Briefing — {html.escape(domain)}</title>"
        "<style>"
        "body{font-family:Segoe UI,system-ui,sans-serif;background:#0d1117;color:#e6edf3;"
        "margin:0;padding:40px 48px;max-width:1100px}"
        "h1{font-size:32px;margin:0 0 8px} .kicker{color:#8b949e;letter-spacing:.04em;"
        "text-transform:uppercase;font-size:12px}"
        f".hero{{font-size:28px;color:{color};margin:16px 0 28px;font-weight:650}}"
        "table{width:100%;border-collapse:collapse;font-size:15px}"
        "th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #30363d;vertical-align:top}"
        "th{color:#8b949e;font-weight:600} .note{color:#8b949e;margin-top:28px;font-size:14px}"
        "</style></head><body>"
        "<p class='kicker'>Leadership briefing</p>"
        f"<h1>{html.escape(domain)}</h1>"
        f"<p class='hero'>{html.escape(headline)}</p>"
        "<table><thead><tr><th>Company</th><th>Category</th><th>Live</th>"
        "<th>Seen</th><th>Why it matters</th></tr></thead>"
        f"<tbody>{''.join(rows) or '<tr><td colspan=5>No vendors</td></tr>'}</tbody></table>"
        "<p class='note'>Fingerprints only — full secrets are not shown in this briefing. "
        "Ask security for the pentest write-up if you need technical detail.</p>"
        f"<!-- source length {len(md_like)} -->"
        "</body></html>"
    )


REPORT_TEMPLATES = {
    "pentest": {
        "id": "pentest",
        "label": "Pentest / bug bounty (HackerOne, Bugcrowd, Intigriti)",
        "filename": "report_pentest.md",
        "kind": "markdown",
    },
    "executive": {
        "id": "executive",
        "label": "Executive briefing (CEO / CTO / board)",
        "filename": "report_executive.md",
        "kind": "markdown",
    },
}


def render_report_template(
    template_id: str,
    domain: str,
    groups: List[Dict[str, Any]],
) -> str:
    tid = (template_id or "pentest").strip().lower()
    if tid in {"executive", "exec", "board", "ceo"}:
        return export_executive_markdown(domain, groups)
    return export_pentest_markdown(domain, groups)


def write_vendor_and_reports(
    output_dir: Path,
    domain: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    exposures: Optional[List[Dict[str, Any]]] = None,
    informational: Optional[List[Dict[str, Any]]] = None,
    *,
    redact: Optional[RedactFn] = None,
) -> Dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    groups = group_findings_by_vendor(
        findings, exposures, informational, redact=redact
    )
    written: Dict[str, Path] = {}
    payload = vendors_json_payload(domain, groups)
    p_json = output_dir / "vendors.json"
    p_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    written["vendors.json"] = p_json
    p_html = output_dir / "vendors.html"
    p_html.write_text(vendor_dashboard_html(domain, groups), encoding="utf-8")
    written["vendors.html"] = p_html
    p_pt = output_dir / "report_pentest.md"
    p_pt.write_text(export_pentest_markdown(domain, groups), encoding="utf-8")
    written["report_pentest.md"] = p_pt
    p_ex = output_dir / "report_executive.md"
    p_ex.write_text(export_executive_markdown(domain, groups), encoding="utf-8")
    written["report_executive.md"] = p_ex
    p_exh = output_dir / "report_executive.html"
    p_exh.write_text(export_executive_html(domain, groups), encoding="utf-8")
    written["report_executive.html"] = p_exh
    return written
