# ReconPipe 🔑

**Automated API Key Leak Hunter**

Single-command pipeline:
```
Chaos → httpx → [Katana + waymore + gospider] → TruffleHog → Async Key Validator
```

Patterns, validators, and confidence scores load from `config.yaml` (overridable with `--config`).

---

## Quick Start

```bash
pip3 install -r requirements.txt
python3 reconpipe.py -d target.com

# Professional GUI (localhost NiceGUI — all CLI options + in-app key re-test)
python3 reconpipegui.py
```

Or on Linux (Debian, Ubuntu, Kali, Fedora, Arch, openSUSE, and derivatives), install system packages + Go tools + Python deps with:

```bash
sudo bash install.sh
```

The installer detects the user behind `sudo`, so Go tools land in `~/go/bin` and pip packages in `~/.local/bin` for *your* account (not root's). Each tool is also symlinked into `/usr/local/bin`, so it works in any shell — including new terminals and `sudo` — without reloading your profile.

---

## Installation

### Python dependencies

```bash
pip3 install -r requirements.txt   # aiohttp, PyYAML, nicegui (required)
pip3 install waymore               # recommended passive archives
# optional: pip3 install boto3     # cleaner AWS STS checks
```

### Professional GUI

```bash
python3 reconpipegui.py
# Then open http://127.0.0.1:8088 in a browser (it does not auto-launch Firefox).
# Override bind address/port if needed:
#   RECONPIPE_GUI_HOST=127.0.0.1 RECONPIPE_GUI_PORT=8088 python3 reconpipegui.py
# Auto-open a tab: RECONPIPE_GUI_SHOW=1 python3 reconpipegui.py
```

Opens a localhost-only NiceGUI app with:

- Every CLI option (domain, files, skips, concurrency, Chaos key, Shopify host, config overlays, ignore hashes, SARIF, fail-on-valid, headless, …)
- Tool preflight status
- Live pipeline console + stage tracker (runs `reconpipe.py` as a cancellable subprocess)
- Findings browser (actionable / informational / exposures) with redacted secrets and Reveal
- **Test with configured validator** — re-runs ReconPipe’s existing `config.yaml` validators only
- Artifact preview for `findings.json`, `valid_keys.json`, `summary.txt`, SARIF, etc.

Do not expose the GUI beyond localhost on untrusted networks — result files can contain live secrets.

### Go tools (ProjectDiscovery + community stack)

```bash
# Subdomain discovery
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Live host filtering
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# NiceGUI/pip also ship a Python CLI named `httpx`. ReconPipe ignores it.
# If preflight still shows httpx MISSING after `go install`:
#   export HTTPX_BIN="$HOME/go/bin/httpx"
#   # or put $HOME/go/bin before ~/.local/bin
# Kali: apt install httpx-toolkit   # binary name: httpx-toolkit

# PRIMARY: Active crawl + JS endpoint parsing
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Optional: deeper JS analysis for Katana (-jsl)
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Active web spider: JS links, S3 buckets, subdomains
go install github.com/jaeles-project/gospider@latest

# Passive archive fallback (Wayback + CommonCrawl + AlienVault OTX + VirusTotal)
go install github.com/lc/gau/v2/cmd/gau@latest

# Last-resort passive fallback
go install github.com/tomnomnom/waybackurls@latest
```

### TruffleHog

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Chaos API Key

```bash
export CHAOS_KEY="your_key_here"   # get from https://cloud.projectdiscovery.io
# or pass --chaos-key on the CLI
```

### Passive intel (optional)

After Chaos, ReconPipe can merge extra hostnames from Shodan, Censys, ZoomEye, and crt.sh. Missing keys are skipped; a source error never aborts the scan.

```bash
export SHODAN_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export ZOOMEYE_API_KEY="..."

python3 reconpipe.py -d target.com
python3 reconpipe.py -d target.com --skip-intel      # Chaos only
python3 reconpipe.py -d target.com --skip-crtsh      # skip the no-key CT lookup
```

The GUI **Passive intel** panel maps to the same flags. crt.sh needs no key; the others do.

---

## Usage

```bash
# Full pipeline
python3 reconpipe.py -d target.com

# Enable headless Chrome (for SPA/React/Angular targets)
python3 reconpipe.py -d target.com --headless

# Use existing subdomain list (skip Chaos)
python3 reconpipe.py -d target.com --subdomains subs.txt

# Use existing URL list (skip URL discovery; Chaos/httpx still run unless skipped)
python3 reconpipe.py -d target.com --files urls.txt

# Skip individual stages
python3 reconpipe.py -d target.com --skip-chaos
python3 reconpipe.py -d target.com --skip-httpx
python3 reconpipe.py -d target.com --skip-gau          # skip waymore/gau/waybackurls only
python3 reconpipe.py -d target.com --skip-discovery    # skip katana/waymore/gau/gospider

# Built-in regex scanner only (no TruffleHog required)
python3 reconpipe.py -d target.com --no-trufflehog

# Skip validation (scan only)
python3 reconpipe.py -d target.com --no-validate

# Custom output + higher concurrency
python3 reconpipe.py -d target.com -o /tmp/results --concurrency 20

# Shopify store host for shpat_ validation
python3 reconpipe.py -d target.com --shopify-domain store.myshopify.com

# Merge engagement overlay onto config.yaml
python3 reconpipe.py -d target.com --config engagement.example.yaml

# Write SARIF (default: <output>/results.sarif) and keep exit 0 even if live keys found
python3 reconpipe.py -d target.com --sarif out.sarif --no-fail-on-valid

# Permanently suppress a finding hash (from findings.json) in the baseline
python3 reconpipe.py -d target.com --ignore-hash <sha256>
```

By default, exit code **1** when any live-validated key is found (CI merge gate). Use `--no-fail-on-valid` to disable.

---

## URL Discovery — 3-Layer Architecture

Step 3 runs three layers (where tools are installed) and deduplicates the combined result:

| Layer | Tool | Type | What it finds |
|-------|------|------|---------------|
| 1 | **Katana** | Active crawler | Live endpoints, JS crawl (`-jc`), optional jsluice (`-jsl`), robots/sitemap (`-kf all`) |
| 2 | **waymore** | Passive archive | Archived URLs from Wayback Machine (mode `U`) |
| 2† | **gau** | Passive fallback | Wayback + CommonCrawl + AlienVault OTX + VirusTotal |
| 2‡ | **waybackurls** | Last-resort fallback | Wayback Machine only |
| 3 | **gospider** | Active spider | JS link extraction, S3-ish URLs, robots + sitemap |

† gau is used if waymore is not installed.  
‡ waybackurls is used if neither waymore nor gau is installed.  
`--skip-gau` skips the entire passive layer; Katana and gospider still run.  
`--skip-discovery` skips all three layers and scans live hosts only.

### Why this is better than gau alone

- **gau/waybackurls** are purely passive — they only return what's been archived.
- **Katana** actively crawls live hosts, parses JS, and supports headless Chrome (`--headless` → `-hl -nos`) for SPAs.
- **waymore** handles Wayback rate limiting better than gau for many targets.
- **gospider** catches JS-linked endpoints that Katana may miss due to depth limits.

---

## Full Pipeline

| Step | Tool | Purpose | Fallback |
|------|------|---------|----------|
| 1 | **chaos** | Passive subdomain dataset | Single target domain / `--subdomains` |
| 2 | **httpx** | Filter live/responsive hosts | Treat all subdomains as live |
| 3a | **katana** | Active crawl + JS parsing | — |
| 3b | **waymore** | Passive archive URLs | → gau → waybackurls |
| 3c | **gospider** | Active JS spider | — |
| 4 | **trufflehog** | Scan downloaded files for secrets | Built-in regex scanner (`config.yaml` patterns) |
| 5 | **aiohttp** (async) | Validate keys against provider APIs | Sync urllib fallback |
| 6 | — | Save JSON, SARIF, summary, baseline | — |

Every external tool is optional — ReconPipe detects what's installed and falls back gracefully.

---

## Configuration

Default rules live in `config.yaml` next to `reconpipe.py`:

- `patterns` — regex detectors
- `confidence` / `min_confidence` — scoring threshold (default min: 30)
- `validators` — live check specs (URL, auth, AWS STS, Twilio pair, JWT inspect, etc.)
- `informational_types` — public-by-design hits (e.g. Stripe publishable, Firebase URL)
- `exposure_types` — non-secret leak surface (e.g. source map exposure)

Overlay files merge on top (repeatable `--config`). Set a pattern or validator to `null` to remove it. See `engagement.example.yaml`.

---

## Output Files

```
recon_target_com/
├── subdomains.txt              ← Chaos subdomain list
├── live_hosts.txt              ← httpx-filtered live hosts
├── katana_input.txt            ← Input list for katana
├── katana_urls.txt             ← Katana crawl output
├── waymore_out/                ← Per-host waymore results
├── gospider_input.txt          ← Input list for gospider
├── gospider_out/               ← Per-host gospider results
├── files_to_scan.txt           ← Deduplicated combined URL list
├── downloaded_files/           ← Local copies for TruffleHog filesystem scan
├── findings.json               ← Actionable findings (+ validation results)
├── valid_keys.json             ← Confirmed valid keys only (if any)
├── informational.json          ← Public-by-design hits
├── source_map_exposures.json   ← Public .map / source-map exposures
├── results.sarif               ← SARIF 2.1.0 (findings + exposures)
├── summary.txt                 ← Human-readable report
└── .reconpipe_ignore.json      ← Baseline (type+source suppression / --ignore-hash)
```

---

## Supported Key Types

**Regex scanner** (`config.yaml` patterns — 38 types), including: Google API/OAuth, AWS access/secret/session, GitHub PAT/fine-grained/OAuth/app, GitLab PAT, Stripe live/test/restricted/publishable, OpenAI, Anthropic, SendGrid, Mailgun, Twilio SID/token, Slack token/webhook, Firebase URL/key, DigitalOcean PAT, npm, PyPI, PEM private keys, UUID→Heroku context, JWT, Shopify token/secret, Mailchimp, Discord token/webhook, Telegram Bot, Mapbox, generic secrets.

Also detects **source map exposures** (`.map` / source-map JSON) as a separate exposure tier.

**Live validators** (provider API / STS / inspect — where configured): Google, GitHub (PAT/fine/OAuth), GitLab, Stripe (live/test/restricted), OpenAI, Anthropic, DigitalOcean, npm, PyPI, Slack token/webhook, SendGrid, Mailgun, AWS STS (`aws_access_key` + paired secret/session), Twilio SID+token pair, Shopify (`--shopify-domain`), Discord token/webhook, Telegram Bot, Mapbox, Heroku, JWT inspect.

Informational (not treated as secrets): Stripe publishable keys, Firebase RTDB URLs.

---

## Notes

- **Referer spoofing:** Validator sets `Referer: https://target.com/` on requests — helps exercise domain-restricted keys that return 403 from your IP.
- **Deduplication:** SHA256-hashed keys; only unique instances are validated. Baseline remembers type+source so re-scans suppress known hits (or permanently via `--ignore-hash`).
- **Rate limiting:** Async `DomainRateLimiter` (global `--concurrency`, capped per host) plus short jittered delays (~300ms) between validation slots.
- **`--headless`:** Enables Katana headless Chrome (`-hl -nos`) for React/Angular/Vue SPAs.
- **CI:** Writes SARIF by default; exit 1 on live-validated keys unless `--no-fail-on-valid`.

---

## Install as global command

```bash
chmod +x reconpipe.py
sudo ln -sf $(pwd)/reconpipe.py /usr/local/bin/reconpipe
reconpipe -d target.com
```

---
