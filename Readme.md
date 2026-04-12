# ReconPipe 🔑

**Automated API Key Leak Hunter**

Single-command pipeline:
```
Chaos → httpx → [Katana + waymore + gospider] → TruffleHog → Async Key Validator
```

---

## Quick Start

```bash
pip3 install aiohttp waymore
python3 reconpipe.py -d target.com
```

---

## Installation

### Python dependencies
```bash
pip3 install aiohttp waymore
```

### Go tools (ProjectDiscovery + community stack)
```bash
# Subdomain discovery
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Live host filtering
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# PRIMARY: Active crawl + JS endpoint parsing (replaces gau for active discovery)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Active web spider: JS links, S3 buckets, subdomains
go install github.com/jaeles-project/gospider@latest

# Passive archive fallback (Wayback + CommonCrawl + AlienVault OTX + VirusTotal)
go install github.com/lc/gau/v2/cmd/gau@latest

# Last resort passive fallback
go install github.com/tomnomnom/waybackurls@latest
```

### TruffleHog
```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Chaos API Key
```bash
export CHAOS_KEY="your_key_here"   # get from https://cloud.projectdiscovery.io
```

---

## Usage

```bash
# Full pipeline
python3 reconpipe.py -d target.com

# Enable headless Chrome (for SPA/React/Angular targets)
python3 reconpipe.py -d target.com --headless

# Use existing subdomain list (skip Chaos)
python3 reconpipe.py -d target.com --subdomains subs.txt

# Use existing URL list (skip all discovery steps)
python3 reconpipe.py -d target.com --files urls.txt

# Built-in regex scanner only (no TruffleHog required)
python3 reconpipe.py -d target.com --no-trufflehog

# Skip validation (scan only)
python3 reconpipe.py -d target.com --no-validate

# Custom output + higher concurrency
python3 reconpipe.py -d target.com -o /tmp/results --concurrency 20
```

---

## URL Discovery — 3-Layer Architecture

Step 3 now runs three tools in parallel layers and deduplicates the combined result:

| Layer | Tool | Type | What it finds |
|-------|------|------|---------------|
| 1 | **Katana** | Active crawler | Live JS endpoints, XHR requests, forms, robots.txt, sitemap — uses `-jc` (JS crawl) + `-jsl` (jsluice deep analysis) |
| 2 | **waymore** | Passive archive | Archived URLs from Wayback Machine — also downloads archived responses to find hidden endpoints not in URL lists |
| 2† | **gau** | Passive fallback | Wayback + CommonCrawl + AlienVault OTX + VirusTotal (fallback if waymore not installed) |
| 3 | **gospider** | Active spider | JS link extraction, S3 bucket discovery, subdomain extraction, robots.txt + sitemap |

† gau/waybackurls are automatically used as fallbacks if waymore isn't installed.

### Why this is better than gau alone

- **gau/waybackurls** are purely passive — they only return what's been archived. If a JS file was never indexed, it won't appear.
- **Katana** actively crawls live endpoints, parses JS files in real-time with jsluice, extracts XHR requests, and handles modern SPAs with headless Chrome (`--headless` flag).
- **waymore** is strictly superior to gau for passive discovery — it handles Wayback Machine rate limiting properly and can download archived page responses to find endpoints buried in HTML/JS that were never directly indexed.
- **gospider** catches JS-linked endpoints that Katana misses due to depth limits, and extracts S3 bucket URLs from response bodies.

---

## Full Pipeline

| Step | Tool | Purpose | Fallback |
|------|------|---------|---------|
| 1 | **chaos** | Passive subdomain dataset | Single target domain |
| 2 | **httpx** | Filter live/responsive hosts | Use all subdomains |
| 3a | **katana** | Active crawl + JS parsing | — |
| 3b | **waymore** | Passive archive + response download | → gau → waybackurls |
| 3c | **gospider** | Active JS spider + S3 | — |
| 4 | **trufflehog** | Scan files for secrets | Built-in regex scanner |
| 5 | **aiohttp** (async) | Validate keys against provider APIs | Sync urllib fallback |
| 6 | — | Save JSON + summary | — |

Every tool is optional — ReconPipe detects what's installed and gracefully falls back.

---

## Output Files

```
recon_target_com/
├── subdomains.txt        ← Chaos subdomain list
├── live_hosts.txt        ← httpx-filtered live hosts
├── katana_input.txt      ← Input list for katana
├── katana_urls.txt       ← Katana crawl output
├── waymore_out/          ← Per-host waymore results
├── gospider_input.txt    ← Input list for gospider
├── gospider_out/         ← Per-host gospider results
├── files_to_scan.txt     ← Deduplicated combined URL list
├── findings.json         ← All findings with validation results
├── valid_keys.json       ← Confirmed valid keys only
└── summary.txt           ← Human-readable report
```

---

## Supported Key Types

**Regex scanner (18 types):** Google API, Google OAuth, AWS, GitHub PAT/OAuth, Stripe live/test, SendGrid, Mailgun, Twilio, Slack token/webhook, Firebase, Heroku, JWT, Shopify, Mailchimp, Discord token/webhook, Telegram Bot, Mapbox, generic `api_key=...`

**Async validator (12 types with active verification):** Google, GitHub, Stripe, Slack, SendGrid, Mailgun, Twilio, Discord, Telegram Bot, Mapbox, Shopify, Twilio

---

## Notes

- **Referer spoofing:** Validator sets `Referer: https://target.com/` on all requests — bypasses domain-restricted keys that return 403 from your IP.
- **Deduplication:** SHA256-hashed keys, only unique instances validated.
- **Rate limiting:** 300ms sleep per semaphore slot, configurable with `--concurrency`.
- **`--headless` flag:** Enables Katana's headless Chrome mode (`-hl -nos`) for targets using React/Angular/Vue SPAs that don't expose endpoints in static HTML.

---
![alt text](https://github.com/SystemWOWS/ReconPipe/blob/main/false_positives.png)
## Install as global command

```bash
chmod +x reconpipe.py
sudo ln -sf $(pwd)/reconpipe.py /usr/local/bin/reconpipe
reconpipe -d target.com
```

---

## Legal

Only run against targets with **explicit written authorization** (bug bounty programs, pentest engagements).
