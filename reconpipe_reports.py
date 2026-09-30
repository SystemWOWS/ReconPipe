#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import math
from collections import Counter
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
    "n8n": {
        "name": "n8n",
        "category": "Automation",
        "website": "https://n8n.io/",
        "about": "Workflow automation. A live public API key can list workflows and stored credentials on the instance (paid/self-hosted Public API).",
    },
    "ethereum": {
        "name": "Ethereum / EVM",
        "category": "Web3",
        "website": "https://ethereum.org/",
        "about": "EVM private keys and seed phrases found in the app or site.",
    },
    "solana": {
        "name": "Solana",
        "category": "Web3",
        "website": "https://solana.com/",
        "about": "Solana secret keys found in the app or site.",
    },
    "bitcoin": {
        "name": "Bitcoin",
        "category": "Web3",
        "website": "https://bitcoin.org/",
        "about": "Bitcoin wallet import and extended keys.",
    },
    "infura": {
        "name": "Infura",
        "category": "Web3",
        "website": "https://www.infura.io/",
        "about": "Ethereum RPC and IPFS project credentials.",
    },
    "alchemy": {
        "name": "Alchemy",
        "category": "Web3",
        "website": "https://www.alchemy.com/",
        "about": "Web3 RPC API keys billed to an Alchemy app.",
    },
    "quicknode": {
        "name": "QuickNode",
        "category": "Web3",
        "website": "https://www.quicknode.com/",
        "about": "Web3 endpoint tokens.",
    },
    "helius": {
        "name": "Helius",
        "category": "Web3",
        "website": "https://www.helius.dev/",
        "about": "Solana RPC API keys.",
    },
    "binance": {
        "name": "Binance",
        "category": "Crypto",
        "website": "https://www.binance.com/",
        "about": "Exchange API key and secret.",
    },
    "etherscan": {
        "name": "Etherscan",
        "category": "Web3",
        "website": "https://etherscan.io/",
        "about": "Block explorer API keys (Etherscan and sister explorers).",
    },
    "coingecko": {
        "name": "CoinGecko",
        "category": "Crypto",
        "website": "https://www.coingecko.com/",
        "about": "Market-data API keys.",
    },
    "coinmarketcap": {
        "name": "CoinMarketCap",
        "category": "Crypto",
        "website": "https://coinmarketcap.com/",
        "about": "Market-data API keys.",
    },
    "thegraph": {
        "name": "The Graph",
        "category": "DeFi",
        "website": "https://thegraph.com/",
        "about": "Subgraph gateway API keys.",
    },
    "moralis": {
        "name": "Moralis",
        "category": "Web3",
        "website": "https://moralis.io/",
        "about": "Web3 data API keys.",
    },
    "opensea": {
        "name": "OpenSea",
        "category": "Web3",
        "website": "https://opensea.io/",
        "about": "NFT marketplace API keys.",
    },
    "pinata": {
        "name": "Pinata",
        "category": "Web3",
        "website": "https://pinata.cloud/",
        "about": "IPFS pinning API keys.",
    },
    "thirdweb": {
        "name": "thirdweb",
        "category": "Web3",
        "website": "https://thirdweb.com/",
        "about": "thirdweb secret keys.",
    },
    "privy": {
        "name": "Privy",
        "category": "Web3",
        "website": "https://www.privy.io/",
        "about": "Embedded-wallet app secrets.",
    },
    "tenderly": {
        "name": "Tenderly",
        "category": "Web3",
        "website": "https://tenderly.co/",
        "about": "Tenderly access tokens.",
    },
    "walletconnect": {
        "name": "WalletConnect",
        "category": "Web3",
        "website": "https://walletconnect.com/",
        "about": "WalletConnect project ids shipped in the client.",
    },
    "web3": {
        "name": "Web3 / DeFi",
        "category": "Web3",
        "website": "",
        "about": "RPC providers, wallet SDKs, and known DeFi contracts in the app.",
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
    "n8n_api": ("n8n", "Public API key"),
    "evm_private_key": ("ethereum", "EVM private key"),
    "solana_private_key": ("solana", "Solana secret key"),
    "btc_wif": ("bitcoin", "Bitcoin WIF"),
    "bip39_mnemonic": ("ethereum", "Seed phrase"),
    "chain_xprv": ("bitcoin", "Extended private key"),
    "chain_xpub": ("bitcoin", "Extended public key"),
    "infura_api": ("infura", "Infura project id"),
    "infura_ipfs": ("infura", "Infura IPFS credential"),
    "alchemy_api": ("alchemy", "Alchemy API key"),
    "quicknode_token": ("quicknode", "QuickNode endpoint token"),
    "helius_api": ("helius", "Helius API key"),
    "ankr_rpc": ("web3", "Ankr RPC key"),
    "chainstack_rpc": ("web3", "Chainstack endpoint"),
    "getblock_rpc": ("web3", "GetBlock token"),
    "blast_rpc": ("web3", "Blast API token"),
    "drpc_key": ("web3", "dRPC key"),
    "thegraph_api": ("thegraph", "Gateway API key"),
    "coingecko_api": ("coingecko", "CoinGecko API key"),
    "coinmarketcap_api": ("coinmarketcap", "CoinMarketCap API key"),
    "etherscan_api": ("etherscan", "Explorer API key"),
    "moralis_api": ("moralis", "Moralis API key"),
    "opensea_api": ("opensea", "OpenSea API key"),
    "pinata_api": ("pinata", "Pinata API key"),
    "thirdweb_secret": ("thirdweb", "Secret key"),
    "privy_secret": ("privy", "App secret"),
    "tenderly_api": ("tenderly", "Access token"),
    "binance_api": ("binance", "API key"),
    "binance_secret": ("binance", "API secret"),
    "trongrid_api": ("web3", "TronGrid API key"),
    "oneinch_api": ("web3", "1inch API key"),
    "zerox_api": ("web3", "0x API key"),
    "dune_api": ("web3", "Dune API key"),
    "covalent_api": ("web3", "Covalent API key"),
    "walletconnect_project": ("walletconnect", "Project id"),
    "web3_rpc": ("web3", "RPC provider"),
    "web3_sdk": ("web3", "Web3 / DeFi marker"),
    "defi_contract": ("web3", "Known contract"),
    "ens_name": ("web3", "ENS name"),
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
    ("n8n", "n8n"),
    ("infura", "infura"),
    ("alchemy", "alchemy"),
    ("quicknode", "quicknode"),
    ("helius", "helius"),
    ("binance", "binance"),
    ("etherscan", "etherscan"),
    ("coingecko", "coingecko"),
    ("coinmarketcap", "coinmarketcap"),
    ("thegraph", "thegraph"),
    ("moralis", "moralis"),
    ("opensea", "opensea"),
    ("pinata", "pinata"),
    ("thirdweb", "thirdweb"),
    ("privy", "privy"),
    ("tenderly", "tenderly"),
    ("walletconnect", "walletconnect"),
    ("solana", "solana"),
    ("ethereum", "ethereum"),
    ("web3", "web3"),
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


def finding_source_location(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("source_url")
        or finding.get("file")
        or finding.get("source")
        or finding.get("path")
        or ""
    ).strip()


def finding_line_number(finding: Dict[str, Any]) -> str:
    for key in ("line", "StartLine", "start_line", "startLine", "Line"):
        value = finding.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def finding_source_short(source: str, limit: int = 72) -> str:
    text = (source or "").replace("https://", "").replace("http://", "")
    if len(text) <= limit:
        return text
    keep = max(12, (limit - 1) // 2)
    return f"{text[:keep]}…{text[-keep:]}"


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = float(len(text))
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 2)


def _default_redact(value: str) -> str:
    text = value or ""
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}…{text[-4:]}"


def enrich_finding_row(
    finding: Dict[str, Any],
    *,
    tier: str = "actionable",
    redact: Optional[RedactFn] = None,
    reveal: bool = False,
) -> Dict[str, Any]:
    """Company, where-found, and redacted fingerprint for the live findings table."""
    redact_fn = redact or _default_redact
    typ = str(finding.get("type") or finding.get("detector") or "unknown")
    vid, product = vendor_for_type(typ)
    rec = vendor_record(vid)
    key = str(finding.get("key") or "")
    fingerprint = key if reveal else redact_fn(key)
    source = finding_source_location(finding)
    line = finding_line_number(finding)
    about = str(rec.get("about") or "").split(". ")[0].rstrip(".")
    description = product
    if about:
        description = f"{product} — {about}."
    scanner = str(finding.get("scanner") or finding.get("detector") or "")
    entropy = finding.get("entropy")
    if entropy is None and key:
        entropy = _shannon_entropy(key)
    try:
        entropy_n = round(float(entropy), 2) if entropy is not None else None
    except (TypeError, ValueError):
        entropy_n = None
    valid = finding.get("valid")
    if valid is True:
        verdict = "LIVE"
    elif finding.get("validated") and valid is False:
        verdict = "invalid"
    else:
        verdict = str(tier or "seen")
    return {
        "rule": typ,
        "company": rec.get("name") or vid,
        "vendor_id": vid,
        "category": rec.get("category") or "",
        "product": product,
        "description": description,
        "source_url": source,
        "source_short": finding_source_short(source),
        "line": line,
        "scanner": scanner,
        "entropy": entropy_n,
        "confidence": finding.get("confidence"),
        "severity": str(finding.get("severity") or ""),
        "valid": bool(valid),
        "validated": bool(finding.get("validated")),
        "verdict": verdict,
        "fingerprint": fingerprint,
        "git_commit": str(finding.get("git_commit") or "")[:12],
        "git_author": str(finding.get("git_author") or ""),
        "git_date": str(finding.get("git_date") or ""),
        "tier": tier,
        "hash": str(finding.get("hash") or ""),
        "from_wayback": bool(finding.get("from_wayback")),
        "mcp_config": bool(finding.get("mcp_config")),
    }


def findings_report_stats(
    findings: Optional[Iterable[Dict[str, Any]]] = None,
    exposures: Optional[Iterable[Dict[str, Any]]] = None,
    informational: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for group in (findings, informational, exposures):
        for item in group or []:
            if isinstance(item, dict):
                rows.append(item)
    sources: set = set()
    rules: set = set()
    companies: set = set()
    live_n = 0
    by_company: Counter = Counter()
    for item in rows:
        src = finding_source_location(item)
        if src:
            sources.add(src)
        typ = str(item.get("type") or "unknown")
        rules.add(typ)
        name = vendor_record(vendor_for_type(typ)[0])["name"]
        companies.add(name)
        by_company[name] += 1
        if item.get("valid"):
            live_n += 1
    return {
        "total": len(rows),
        "sources": len(sources),
        "rules": len(rules),
        "companies": len(companies),
        "live": live_n,
        "by_company": by_company.most_common(10),
    }


def findings_dashboard_html(
    domain: str,
    rows: List[Dict[str, Any]],
    *,
    stats: Optional[Dict[str, Any]] = None,
    generated: Optional[str] = None,
    scan_mode: str = "ReconPipe",
    live: bool = False,
    fragment: bool = False,
    cap: int = 200,
    total: Optional[int] = None,
) -> str:
    """Gitleaks-style scan report: stats, company graph, filterable-looking table."""
    ts = generated or datetime.now().strftime("%b %d, %Y %H:%M:%S")
    shown = list(rows or [])[: max(1, int(cap))]
    if not shown and rows:
        shown = []
    n_total = int(total if total is not None else len(rows or []))
    st = dict(stats or {})
    if not st:
        st = {
            "total": n_total,
            "sources": len({str(r.get("source_url") or "") for r in (rows or []) if r.get("source_url")}),
            "rules": len({str(r.get("rule") or "") for r in (rows or []) if r.get("rule")}),
            "companies": len({str(r.get("company") or "") for r in (rows or []) if r.get("company")}),
            "live": sum(1 for r in (rows or []) if r.get("valid")),
            "by_company": [],
        }
    bars = st.get("by_company") or []
    max_bar = max((int(c) for _n, c in bars), default=1) or 1
    bar_html = []
    for name, count in bars:
        pct = max(4, int(round(100.0 * int(count) / max_bar)))
        bar_html.append(
            "<div class='rp-gl-bar-row'>"
            f"<span class='rp-gl-bar-name'>{html.escape(str(name))}</span>"
            "<span class='rp-gl-bar-track'><span class='rp-gl-bar-fill' "
            f"style='width:{pct}%'></span></span>"
            f"<span class='rp-gl-bar-n'>{int(count)}</span>"
            "</div>"
        )
    if not bar_html:
        bar_html.append("<p class='rp-gl-empty'>No companies yet — hits appear here during the scan.</p>")

    body_rows = []
    for row in shown:
        line = str(row.get("line") or "")
        file_cell = html.escape(str(row.get("source_short") or row.get("source_url") or "—"))
        if line:
            file_cell += f"<div class='rp-gl-sub'>Line: {html.escape(line)}</div>"
        if row.get("from_wayback"):
            file_cell += "<div class='rp-gl-sub'>Wayback snapshot</div>"
        if row.get("mcp_config"):
            file_cell += "<div class='rp-gl-sub'>MCP config</div>"
        meta_bits = []
        if row.get("entropy") is not None:
            meta_bits.append(f"Entropy: {html.escape(str(row.get('entropy')))}")
        if row.get("confidence") not in (None, ""):
            meta_bits.append(f"Confidence: {html.escape(str(row.get('confidence')))}")
        if row.get("scanner"):
            meta_bits.append(f"Scanner: {html.escape(str(row.get('scanner')))}")
        if row.get("git_author"):
            meta_bits.append(f"Author: {html.escape(str(row.get('git_author')))}")
        if row.get("git_date"):
            meta_bits.append(f"Date: {html.escape(str(row.get('git_date')))}")
        if row.get("git_commit"):
            meta_bits.append(f"Commit: {html.escape(str(row.get('git_commit')))}")
        sev = str(row.get("severity") or "")
        if sev:
            meta_bits.append(f"Severity: {html.escape(sev)}")
        meta_bits.append(f"Status: {html.escape(str(row.get('verdict') or ''))}")
        meta = "<br>".join(meta_bits) if meta_bits else "—"
        company = html.escape(str(row.get("company") or "Other"))
        cat = html.escape(str(row.get("category") or ""))
        pill_cls = "rp-secret-pill live" if row.get("valid") else "rp-secret-pill"
        body_rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(row.get('rule') or ''))}</code></td>"
            f"<td class='rp-gl-file'>{file_cell}</td>"
            f"<td><strong>{company}</strong>"
            f"{f'<div class=\"rp-gl-sub\">{cat}</div>' if cat else ''}</td>"
            f"<td>{html.escape(str(row.get('description') or ''))}</td>"
            f"<td><span class='{pill_cls}'>{html.escape(str(row.get('fingerprint') or ''))}</span></td>"
            f"<td class='rp-gl-meta'>{meta}</td>"
            "</tr>"
        )
    if not body_rows:
        body_rows.append(
            "<tr><td colspan='6' class='rp-gl-empty'>No findings match the current filters.</td></tr>"
        )

    cap_note = ""
    if n_total > len(shown):
        cap_note = (
            f"<p class='rp-gl-sub'>Showing first {len(shown)} of {n_total} findings.</p>"
        )
    live_badge = "<span class='rp-gl-live'>LIVE</span>" if live else ""
    inner = (
        "<section class='rp-gl'>"
        "<div class='rp-gl-title-row'>"
        "<div>"
        "<h2>Security Scan Report</h2>"
        f"<div class='rp-gl-sub'>Generated on {html.escape(ts)}"
        f"{' · ' + html.escape(domain) if domain else ''}</div>"
        "</div>"
        f"{live_badge}"
        "</div>"
        "<div class='rp-gl-stats'>"
        f"<div><div class='v'>{int(st.get('total') or 0)}</div><div class='k'>Total Findings</div></div>"
        f"<div><div class='v'>{int(st.get('sources') or 0)}</div><div class='k'>Sources Affected</div></div>"
        f"<div><div class='v'>{int(st.get('rules') or 0)}</div><div class='k'>Unique Rules</div></div>"
        f"<div><div class='v'>{int(st.get('companies') or 0)}</div><div class='k'>Companies</div></div>"
        f"<div><div class='v'>{html.escape(scan_mode or 'ReconPipe')}</div>"
        "<div class='k'>Scan Mode</div></div>"
        "</div>"
        "<h3 class='rp-gl-h3'>Keys by company</h3>"
        f"<div class='rp-gl-bars'>{''.join(bar_html)}</div>"
        f"{cap_note}"
        "<div class='rp-gl-table-wrap'><table class='rp-gl-table'>"
        "<thead><tr>"
        "<th>Rule</th><th>Where found</th><th>Company</th>"
        "<th>Description</th><th>Secret</th><th>Metadata</th>"
        "</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></div>"
        "<div class='rp-gl-foot'>Generated by ReconPipe"
        f"<span>Total Findings: {int(st.get('total') or 0)}</span></div>"
        "</section>"
    )
    styles = (
        "<style>"
        ".rp-gl{font-family:Segoe UI,system-ui,sans-serif;color:inherit}"
        ".rp-gl-title-row{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}"
        ".rp-gl h2{margin:0;font-size:22px;font-weight:700}"
        ".rp-gl-h3{margin:16px 0 8px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.7}"
        ".rp-gl-sub{font-size:12px;opacity:.65;margin-top:2px}"
        ".rp-gl-live{background:#22c55e;color:#052e16;font-size:10px;font-weight:800;"
        "letter-spacing:.14em;padding:4px 10px;border-radius:999px}"
        ".rp-gl-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));"
        "gap:8px;padding:16px 18px;margin:12px 0;border:1px solid rgba(127,127,127,.25);"
        "border-radius:10px}"
        ".rp-gl-stats .v{font-size:26px;font-weight:700;line-height:1.15}"
        ".rp-gl-stats .k{font-size:11px;opacity:.65;margin-top:4px}"
        ".rp-gl-bar-row{display:flex;align-items:center;gap:10px;margin:5px 0}"
        ".rp-gl-bar-name{width:160px;font-size:12px;white-space:nowrap;overflow:hidden;"
        "text-overflow:ellipsis}"
        ".rp-gl-bar-track{flex:1;height:8px;border-radius:99px;background:rgba(127,127,127,.25);overflow:hidden}"
        ".rp-gl-bar-fill{display:block;height:100%;background:#f0883e}"
        ".rp-gl-bar-n{width:28px;text-align:right;font-size:12px;font-variant-numeric:tabular-nums}"
        ".rp-gl-table-wrap{overflow:auto;margin-top:8px}"
        ".rp-gl-table{width:100%;border-collapse:collapse;font-size:13px}"
        ".rp-gl-table th{text-align:left;font-size:11px;opacity:.65;padding:8px 10px;"
        "border-bottom:1px solid rgba(127,127,127,.25)}"
        ".rp-gl-table td{padding:12px 10px;border-bottom:1px solid rgba(127,127,127,.18);"
        "vertical-align:top}"
        ".rp-gl-file{max-width:240px;word-break:break-all}"
        ".rp-gl-meta{font-size:12px;opacity:.8;white-space:nowrap}"
        ".rp-secret-pill{font-family:ui-monospace,Consolas,monospace;font-size:12px;"
        "background:#fecaca;color:#9f1239;padding:4px 10px;border-radius:4px;display:inline-block}"
        ".rp-secret-pill.live{background:#bbf7d0;color:#14532d}"
        ".rp-gl-empty{opacity:.6;padding:18px;text-align:center}"
        ".rp-gl-foot{display:flex;justify-content:space-between;font-size:11px;opacity:.55;margin-top:10px}"
        "@media (prefers-color-scheme: dark){"
        ".rp-secret-pill{background:#7f1d1d;color:#fecaca}"
        ".rp-secret-pill.live{background:#14532d;color:#bbf7d0}"
        "}"
        "</style>"
    )
    if fragment:
        return styles + inner
    banner = (
        "<header class='gl-banner'>ReconPipe Security Findings</header>"
    )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Security Scan Report — {html.escape(domain)}</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"{styles}"
        "<style>body{margin:0;background:#f3f4f6;color:#111827}"
        ".gl-banner{background:#1d4ed8;color:#fff;padding:14px 24px;font-weight:700;font-size:20px}"
        ".rp-gl{max-width:1200px;margin:20px auto;background:#fff;padding:24px;"
        "border-radius:12px;box-shadow:0 1px 2px rgba(0,0,0,.06)}"
        "@media (prefers-color-scheme: dark){body{background:#0f172a;color:#e5e7eb}"
        ".rp-gl{background:#111827}.gl-banner{background:#1e3a8a}}</style>"
        "</head><body>"
        f"{banner}{inner}"
        "</body></html>"
    )


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


_GRAPH_VENDOR_CAP = 20
_GRAPH_KEY_CAP = 2
_GRAPH_KEY_VENDOR_CAP = 8


def _graph_clip(text: str, limit: int = 18) -> str:
    cleaned = " ".join(str(text or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def vendor_graph_signature(domain: str, groups: List[Dict[str, Any]]) -> Tuple:
    """Cheap identity for the map so the GUI can skip identical redraws."""
    parts = []
    for g in groups or []:
        if not isinstance(g, dict):
            continue
        keys = tuple(
            (str(k.get("type") or ""), bool(k.get("valid")))
            for k in (g.get("keys") or [])[:_GRAPH_KEY_CAP]
            if isinstance(k, dict)
        )
        parts.append(
            (
                str(g.get("id") or ""),
                int(g.get("live") or 0),
                int(g.get("total") or 0),
                keys,
            )
        )
    parts.sort()
    return (str(domain or ""), tuple(parts))


def vendor_graph_model(domain: str, groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Left-to-right topology. No physics and no per-frame work."""
    ranked = sorted(
        [g for g in (groups or []) if isinstance(g, dict)],
        key=lambda g: (
            -int(g.get("live") or 0),
            -int(g.get("total") or 0),
            str(g.get("name") or ""),
        ),
    )
    omitted = max(0, len(ranked) - _GRAPH_VENDOR_CAP)
    ranked = ranked[:_GRAPH_VENDOR_CAP]
    expand_keys = 0 < len(ranked) <= _GRAPH_KEY_VENDOR_CAP

    node_w, node_h = 156, 48
    gap_x, gap_y = 84, 18
    pad = 36
    root_d = 64

    blocks: List[Tuple[Dict[str, Any], List[Dict[str, Any]], int]] = []
    for g in ranked:
        keys: List[Dict[str, Any]] = []
        if expand_keys:
            keys = [k for k in (g.get("keys") or []) if isinstance(k, dict)][:_GRAPH_KEY_CAP]
        blocks.append((g, keys, max(1, len(keys))))

    slots = sum(span for _, _, span in blocks) or 1
    content_h = slots * node_h + max(0, slots - 1) * gap_y
    height = max(168, pad * 2 + content_h)
    root_cx = pad + root_d / 2
    root_cy = height / 2
    vendor_x = pad + root_d + gap_x
    show_keys = expand_keys and any(keys for _, keys, _ in blocks)
    key_x = vendor_x + node_w + gap_x
    width = (key_x if show_keys else vendor_x) + node_w + pad

    label = _graph_clip(domain or "target", 16)
    nodes: List[Dict[str, Any]] = [
        {
            "id": "root",
            "kind": "root",
            "title": label,
            "subtitle": (
                f"{len(ranked)} compan{'y' if len(ranked) == 1 else 'ies'}"
                if ranked
                else "no companies yet"
            ),
            "cx": root_cx,
            "cy": root_cy,
            "d": root_d,
            "live": 0,
        }
    ]
    edges: List[Dict[str, float]] = []
    y = max(pad, (height - content_h) / 2.0)
    for g, keys, span in blocks:
        block_h = span * node_h + max(0, span - 1) * gap_y
        vid = str(g.get("id") or "")
        live = int(g.get("live") or 0)
        total = int(g.get("total") or 0)
        vy = y + (block_h - node_h) / 2.0
        nodes.append(
            {
                "id": vid,
                "kind": "vendor",
                "title": _graph_clip(str(g.get("name") or vid)),
                "subtitle": f"LIVE {live}/{total}" if live else f"{total} seen",
                "x": vendor_x,
                "y": vy,
                "w": node_w,
                "h": node_h,
                "live": live,
            }
        )
        edges.append(
            {
                "x1": root_cx + root_d / 2.0,
                "y1": root_cy,
                "x2": float(vendor_x),
                "y2": vy + node_h / 2.0,
            }
        )
        for i, key in enumerate(keys):
            ky = y + i * (node_h + gap_y)
            nodes.append(
                {
                    "id": vid,
                    "kind": "key",
                    "title": _graph_clip(str(key.get("product") or key.get("type") or "key")),
                    "subtitle": "LIVE" if key.get("valid") else _graph_clip(str(key.get("type") or ""), 16),
                    "x": key_x,
                    "y": ky,
                    "w": node_w,
                    "h": node_h,
                    "live": 1 if key.get("valid") else 0,
                }
            )
            edges.append(
                {
                    "x1": float(vendor_x + node_w),
                    "y1": vy + node_h / 2.0,
                    "x2": float(key_x),
                    "y2": ky + node_h / 2.0,
                }
            )
        y += block_h + gap_y

    return {
        "width": int(width),
        "height": int(height),
        "nodes": nodes,
        "edges": edges,
        "omitted": omitted,
        "vendors": len(ranked),
    }


def vendor_graph_svg(
    domain: str,
    groups: List[Dict[str, Any]],
    model: Optional[Dict[str, Any]] = None,
) -> str:
    """Static SVG topology. Trusted markup; labels are escaped."""
    model = model if model is not None else vendor_graph_model(domain, groups)
    w = int(model["width"])
    h = int(model["height"])
    parts: List[str] = [
        f'<svg class="rp-topo" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Findings graph">'
    ]
    for edge in model["edges"]:
        parts.append(
            '<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            'stroke="#3a3a3a" stroke-width="1.25"/>'.format(**edge)
        )
    for node in model["nodes"]:
        vid = html.escape(str(node.get("id") or ""), quote=True)
        title = html.escape(str(node.get("title") or ""), quote=True)
        sub = html.escape(str(node.get("subtitle") or ""), quote=True)
        live = int(node.get("live") or 0) > 0
        if node.get("kind") == "root":
            cx = float(node["cx"])
            cy = float(node["cy"])
            r = float(node["d"]) / 2.0
            parts.append(
                f'<g data-vid="{vid}">'
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="#070707" stroke="#9ca3af" stroke-width="1.5"/>'
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r - 8:.1f}" fill="none" stroke="#374151" stroke-width="1"/>'
                f'<text x="{cx:.1f}" y="{cy + r + 16:.1f}" text-anchor="middle" fill="#e5e7eb" '
                f'font-size="11" font-family="Segoe UI,system-ui,sans-serif">{title}</text>'
                f'<text x="{cx:.1f}" y="{cy + r + 30:.1f}" text-anchor="middle" fill="#6b7280" '
                f'font-size="10" font-family="Segoe UI,system-ui,sans-serif">{sub}</text>'
                "</g>"
            )
            continue
        stroke = "#ef4444" if live else "#166534"
        fill = "#140606" if live else "#07140c"
        ink = "#f87171" if live else "#4ade80"
        x = float(node["x"])
        y = float(node["y"])
        nw = float(node["w"])
        nh = float(node["h"])
        parts.append(
            f'<g data-vid="{vid}">'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{nw:.1f}" height="{nh:.1f}" rx="3" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.25"/>'
            f'<text x="{x + 10:.1f}" y="{y + 20:.1f}" fill="{ink}" font-size="12" '
            f'font-family="Segoe UI,system-ui,sans-serif">{title}</text>'
            f'<text x="{x + 10:.1f}" y="{y + 36:.1f}" fill="#9ca3af" font-size="10" '
            f'font-family="Segoe UI,system-ui,sans-serif">{sub}</text>'
            "</g>"
        )
    parts.append("</svg>")
    return "".join(parts)


def vendor_scene_nodes(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Layout company nodes for NiceGUI ui.scene (circle, height = hit count)."""
    items = [g for g in (groups or []) if isinstance(g, dict)]
    n = max(len(items), 1)
    radius = max(3.0, 0.55 * n)
    nodes: List[Dict[str, Any]] = []
    for i, g in enumerate(items):
        angle = (2.0 * math.pi * i) / n if items else 0.0
        live = int(g.get("live") or 0)
        total = max(int(g.get("total") or 1), 1)
        height = 0.45 + min(2.8, 0.22 * total)
        vid = str(g.get("id") or f"v{i}")
        nodes.append(
            {
                "id": vid,
                "name": str(g.get("name") or vid),
                "category": str(g.get("category") or ""),
                "x": round(radius * math.cos(angle), 3),
                "y": round(radius * math.sin(angle), 3),
                "h": round(height, 3),
                "live": live,
                "total": total,
                "color": "#3fb950" if live else "#f0883e",
            }
        )
    return nodes


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
    enriched: List[Dict[str, Any]] = []
    for tier, item in _iter_findings(findings, exposures, informational):
        enriched.append(enrich_finding_row(item, tier=tier, redact=redact))
    stats = findings_report_stats(findings, exposures, informational)
    p_fr = output_dir / "findings_report.html"
    p_fr.write_text(
        findings_dashboard_html(
            domain,
            enriched,
            stats=stats,
            scan_mode="ReconPipe",
            fragment=False,
        ),
        encoding="utf-8",
    )
    written["findings_report.html"] = p_fr
    return written
