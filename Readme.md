# ReconPipe

ReconPipe finds leaked API keys and secrets on a target you are authorized to test.

It enumerates hosts, crawls and archives URLs, downloads likely leak surfaces (JavaScript, `.env`, source maps, configs), scans them with several engines, then **live-validates** matches against provider APIs so you can tell a dead string from a working credential.

```
subdomains → live hosts → URL discovery → extra surfaces → download → secret scan → validate → reports
```

Patterns, confidence scores, and validators load from `[config.yaml](config.yaml)`. Overlay extra rules with `--config`. Missing tools are skipped; the pipeline keeps going.

Use this only on assets you own or have written permission to test. Validated keys are live credentials — treat output as sensitive.

---



## Contents

- [Quick start](#quick-start)
- [Docker](#docker)
- [How a scan works](#how-a-scan-works)
- [Installation](#installation)
- [API keys](#api-keys)
- [Usage](#usage)
- [Desktop GUI](#desktop-gui)
- [LLM remediation](#llm-remediation)
- [Configuration](#configuration)
- [Secret detection](#secret-detection)
- [Extra leak surfaces](#extra-leak-surfaces)
- [Output](#output)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Tests](#tests)
- [License](#license)

---



## Quick start

**Docker (GUI like an app):** from the `ReconPipe` folder:

```bash
docker compose up -d --build    # first time
# later:
docker compose up -d
```

Open http://127.0.0.1:8088 and run the scan from the GUI. Stop with `docker compose down`.

Optional CLI in the same image:

```bash
docker compose run --rm reconpipe -d example.com
docker compose run --rm reconpipe --rescan -d example.com
```

Results land in `scans/`. Saved keys, targets, and history land in `docker-home/` (same role as `~/.reconpipe` on the host).

**Linux (Debian, Ubuntu, Kali, Fedora, Arch, openSUSE):**

```bash
sudo bash install.sh
python3 reconpipe.py -d example.com
```

The installer puts Go tools in `~/go/bin`, Python packages in `~/.local/bin`, and links binaries into `/usr/local/bin`. Reload the shell after the first install:

```bash
source ~/.bashrc   # or ~/.zshrc
```

**Python only** (any OS with Python 3.9+):

```bash
pip3 install -r requirements.txt
python3 reconpipe.py -d example.com
```

Without the Go tools you still get the built-in regex scanner and validators. Discovery and TruffleHog are richer once those binaries are on `PATH`.

**GUI:**

```bash
python3 reconpipegui.py
# Linux launcher after install.sh:
reconpipe-gui
```

---



## Docker

Full tool PATH without running `install.sh`. Docker Desktop on Windows works; run the commands from a folder that has `docker-compose.yml`.

**Start the GUI (this is the usual way):**

```bash
docker compose up -d --build    # first time, or after you change the Dockerfile
docker compose up -d            # later starts
```

Then open http://127.0.0.1:8088 — same idea as launching an app. Leave it running; `docker compose down` stops it.

**CLI** (same image, one-shot container):

```bash
docker compose run --rm reconpipe -d example.com
docker compose run --rm reconpipe --rescan -d example.com
```

Or pull a published image instead of building:

```bash
docker compose pull
docker compose up -d
```

Pin a version:

```bash
RECONPIPE_IMAGE=ghcr.io/systemwows/reconpipe:v1.3 docker compose pull
```

| Path on host     | Path in container        | What it is                                      |
| ---------------- | ------------------------ | ----------------------------------------------- |
| `scans/`         | `/work`                  | Output folders (`recon_example_com/`, …)        |
| `docker-home/`   | `/root/.reconpipe`       | `keys.yaml`, `settings.yaml`, `targets.yaml`, `history.yaml` |

Pass API keys as env vars (`CHAOS_KEY`, `GITHUB_TOKEN`, …) or save them from the GUI into `docker-home/keys.yaml`.

ProjectDiscovery `httpx` is kept at `/opt/pd-bin/httpx` (`HTTPX_BIN`) so pip/NiceGUI cannot replace it with the Python `httpx` CLI.

The GHCR package must be **public** for anonymous `docker compose pull`. If it is private, run `docker login ghcr.io` first with a token that can read packages. Publishing the image redistributes the third-party recon binaries under their own licenses.

`--rescan` reuses the saved URL list and output directory for that domain, then `--resume` (skip files already downloaded). In the GUI: **Saved targets → Rescan**, or **History → Rescan**.

`--docker-fallback` is a different feature: it runs *missing* host binaries via `docker run --rm`. You do not need it inside this image.

Katana `--headless` needs Chrome, which this image does not ship. Leave headless off in Docker. whatweb, gowitness, and wappalyzer are also not in the image (Ruby / Chrome / Node).

---



## How a scan works

Every stage is optional. If a binary is missing, ReconPipe logs it and continues.


| Stage          | What runs                                                                                                                        | Purpose                          |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| Subdomains     | Chaos, subfinder, amass, assetfinder, findomain, crt.sh, optional Shodan / Censys / ZoomEye / certstream                         | Build a host list                |
| Resolve / live | dnsx, httpx                                                                                                                      | Keep hosts that actually respond |
| URL discovery  | Katana, gospider, hakrawler, paramspider, LinkFinder                                                                             | Active crawl and JS endpoints    |
| Archives       | waymore → gau → waybackurls                                                                                                      | Historical URLs                  |
| Extra surfaces | Sensitive paths; GitHub/GitLab code search + CI logs; Pastebin/Gists; Docker Hub/layers; buckets; OpenAPI; `--repo` / `--apk` / `--package`; JS maps + history; optional Nuclei / naabu / screenshots | Leak files crawlers miss. Detail: [Extra leak surfaces](#extra-leak-surfaces) |
| Download       | Parallel fetch of JS, maps, JSON, HTML, env-like URLs                                                                            | Local copies for scanners        |
| Secret scan    | TruffleHog, Gitleaks, jsleak, `config.yaml` regex, [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) extras | Extract candidates               |
| Validate       | Async HTTP checks (aiohttp) against provider APIs                                                                                | Confirm the key still works      |
| Report         | JSON, SARIF, HTML/Markdown, vendor dashboard, pentest + executive templates, HackerOne/Jira drafts; rule-based P1/P2/P3 in `ai_verdict.json`; optional LLM `remediation.md` | Review, CI, verify-and-fix, leadership brief |


`--files urls.txt` skips URL discovery. `--subdomains hosts.txt` skips Chaos. `--no-trufflehog` uses only the built-in regex engine. `--no-validate` stops after detection.

---



## Installation



### Linux installer

```bash
sudo bash install.sh
```

Installs system packages (Python, Go, Chromium, libpcap, nmap, Node, Ruby), Python deps (including the GUI and waymore), ProjectDiscovery tools (Chaos, subfinder, dnsx, httpx, Katana, nuclei, naabu), crawl/archive tools (gospider, gau, waybackurls, hakrawler, jsluice), secret scanners (TruffleHog, Gitleaks, jsleak), extra enumerators (amass, assetfinder, findomain), LinkFinder, ParamSpider, WhatWeb, Wappalyzer, gowitness, spray, `reconpipe` / `reconpipe-gui` launchers.

`sudo` is used for system packages. Go and pip installs still land in **your** home directory, not root’s. Extra tools that fail to install are skipped at scan time; they do not abort the installer.

### Manual (Linux / macOS)

```bash
pip3 install -r requirements.txt
pip3 install waymore          # recommended archive layer
# optional: pip3 install boto3  # cleaner AWS STS checks
```

Go toolchain (1.21+):

```bash
# Subdomains and live hosts
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Crawl
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest   # optional, for Katana -jsl

# Archives
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Secret scanners
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/byt3hx/jsleak@latest

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin
```

Put `$HOME/go/bin` **ahead** of `~/.local/bin` on `PATH`. The Python `httpx` package also ships a CLI named `httpx`; ReconPipe ignores that one, but a wrong binary on `PATH` is a common first-run issue. See [Troubleshooting](#troubleshooting).

Optional but useful when present: amass, assetfinder, findomain, hakrawler, paramspider, LinkFinder, naabu, whatweb, wappalyzer, gowitness, nuclei, spray.

`--docker-fallback` can run a missing tool via `docker run --rm` when an image is known.

### Windows

1. Install [Python 3.9+](https://www.python.org/downloads/) and (optionally) [Go](https://go.dev/dl/).
2. From the `ReconPipe` folder:

```powershell
py -m pip install -r requirements.txt
py reconpipe.py -d example.com
py reconpipegui.py
```

`install.sh` is Linux-only. Install Go tools with the same `go install` commands, then ensure `%USERPROFILE%\go\bin` is on `PATH`. For native httpx on Kali-style setups the binary may be named `httpx-toolkit`.

### GUI native window (Linux)

The GUI prefers a desktop window (pywebview + WebKit), not Firefox, so a long crawl cannot freeze your browser.

```bash
pip3 install pywebview
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1
```

`install.sh` already does this. Use `--browser` if you want a localhost tab instead.

---



## API keys

None of these are required. Missing keys skip that source; a source error never aborts the scan.


| Key                    | Environment                          | Used for                                                                           |
| ---------------------- | ------------------------------------ | ---------------------------------------------------------------------------------- |
| ProjectDiscovery Chaos | `CHAOS_KEY` or `PDCP_API_KEY`        | Subdomain dataset ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)) |
| Shodan                 | `SHODAN_API_KEY`                     | Extra hostnames                                                                    |
| Censys                 | `CENSYS_API_ID`, `CENSYS_API_SECRET` | Extra hostnames                                                                    |
| ZoomEye                | `ZOOMEYE_API_KEY`                    | Extra hostnames                                                                    |
| crt.sh                 | —                                    | Certificate Transparency (no key)                                                  |
| LLM (optional)         | `RECONPIPE_LLM_KEY` (or `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`) | Cloud LLM for `remediation.md`; local Ollama needs no key        |


CLI flags (`--chaos-key`, `--shodan-key`, `--llm-key`, …) override the environment. The GUI **Save keys** panel and **Settings** tab write `~/.reconpipe/keys.yaml` and `settings.yaml` (mode `0600`). Resolution order is **CLI → environment → saved file**.

Override the config directory with `RECONPIPE_HOME`.

```bash
export CHAOS_KEY="your_key"
python3 reconpipe.py -d example.com
python3 reconpipe.py -d example.com --skip-intel      # Chaos / subfinder only
python3 reconpipe.py -d example.com --skip-crtsh
```

---



## Usage

Replace `example.com` with a domain you are allowed to scan.

### Typical scans

```bash
# Full pipeline
python3 reconpipe.py -d example.com

# SPA / React / Angular (Katana headless Chrome)
python3 reconpipe.py -d example.com --headless

# You already have hosts
python3 reconpipe.py -d example.com --subdomains subs.txt

# You already have URLs (skips crawl/archives)
python3 reconpipe.py -d example.com --files urls.txt

# Rescan a domain you already ran (saved URL list + output dir + resume)
python3 reconpipe.py -d example.com --rescan
docker compose run --rm reconpipe --rescan -d example.com

# Several domains (each gets its own output directory)
python3 reconpipe.py --domain-list domains.txt

# Regex scanner only (no TruffleHog)
python3 reconpipe.py -d example.com --no-trufflehog

# Detect but do not hit provider APIs
python3 reconpipe.py -d example.com --no-validate

# Custom output + validation concurrency
python3 reconpipe.py -d example.com -o /tmp/results --concurrency 20
```



### Skip stages

```bash
python3 reconpipe.py -d example.com --skip-chaos
python3 reconpipe.py -d example.com --skip-httpx
python3 reconpipe.py -d example.com --skip-gau          # archives only; Katana/gospider still run
python3 reconpipe.py -d example.com --skip-discovery    # no crawl or archives; live hosts only
```



### Git repository

Full clone (history included) plus TruffleHog git and Gitleaks:

```bash
python3 reconpipe.py -d example.com --repo https://github.com/org/app.git
python3 reconpipe.py -d example.com --repo https://github.com/org/app.git --repo-shallow
python3 reconpipe.py -d example.com --repo ./local-clone --iac-scan
```



### CI

By default ReconPipe writes SARIF and **exits 1** if any key validates as live.

```bash
python3 reconpipe.py -d example.com --sarif out.sarif
python3 reconpipe.py -d example.com --no-fail-on-valid   # always exit 0
python3 reconpipe.py -d example.com --ignore-hash <sha256>  # suppress a known finding
```



### Resume

```bash
# Reuse files_to_scan.txt; skip re-download of files already on disk
python3 reconpipe.py -d example.com --resume

# Jump to a later pipeline checkpoint
python3 reconpipe.py -d example.com --resume-from discovery
python3 reconpipe.py -d example.com --resume-from validate
```

`--resume-from` choices: `chaos`, `httpx`, `discovery`, `trufflehog`, `validate`.

`--rescan` is the usual “run this domain again” flag: it loads `~/.reconpipe/targets.yaml` (or `docker-home/targets.yaml` in Docker), points `-o` / `--files` at the last run, and turns on `--resume`.

### Extra regex packs and jsleak

A small high-confidence pack ships in `wordlists/secrets_patterns.yml`. To pull a filtered slice of [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (~350 high-confidence rules, duplicates of built-in prefixes dropped):

```bash
python3 reconpipe.py -d example.com --refresh-secrets-db
python3 reconpipe.py -d example.com --secrets-db ./my-patterns.yml
python3 reconpipe.py -d example.com --skip-secrets-db
python3 reconpipe.py -d example.com --skip-jsleak
```

`--refresh-secrets-db` writes `~/.reconpipe/secrets_patterns.yml`. It does **not** load all ~1600 upstream rules on every scan.

If `jsleak` is on `PATH`, discovered JS URLs are scanned for links and secrets. The LinkFinder-style extractor is built in even without the binary.

### Polite scanning, proxy, authenticated crawl

```bash
python3 reconpipe.py -d example.com --polite
python3 reconpipe.py -d example.com --requests-per-second 2
python3 reconpipe.py -d example.com --proxy http://127.0.0.1:8080
python3 reconpipe.py -d example.com -H "Authorization: Bearer TOKEN"
python3 reconpipe.py -d example.com --credentials cookies.yaml
python3 reconpipe.py -d example.com --burp-import burp.xml
```

`--spray` is **opt-in**. It brute-forces extra leak/backup paths on live hosts. Leave it off unless that is in scope.

### Alerts

```bash
python3 reconpipe.py -d example.com --notify-webhook https://hooks.slack.com/services/...
python3 reconpipe.py -d example.com --telegram-bot TOKEN --telegram-chat ID
python3 reconpipe.py -d example.com --smtp-host smtp.example.com --smtp-to you@example.com
```

PagerDuty and Opsgenie flags are also available. `--no-notify` skips the desktop notification when a scan finishes.

### LLM report after a scan

```bash
# Local Ollama (default provider). Pull a model first: ollama pull llama3.1
python3 reconpipe.py -d example.com --llm --llm-provider ollama --llm-model llama3.1

# LM Studio / vLLM / llama.cpp (OpenAI-compatible)
python3 reconpipe.py -d example.com --llm --llm-provider openai_compat \
  --llm-base-url http://127.0.0.1:1234/v1 --llm-model local-model

# Cloud
python3 reconpipe.py -d example.com --llm --llm-provider openai --llm-model gpt-4o-mini
python3 reconpipe.py -d example.com --skip-llm   # override Settings if LLM is on
```

`--ci` skips the LLM unless you also pass `--llm`. See [LLM remediation](#llm-remediation).

---



## Desktop GUI

Docker (recommended): `docker compose up -d` then http://127.0.0.1:8088.

```bash
python3 reconpipegui.py              # native window when a display + pywebview exist
python3 reconpipegui.py --browser    # http://127.0.0.1:8088
```

```bash
RECONPIPE_GUI_HOST=127.0.0.1 RECONPIPE_GUI_PORT=8088 python3 reconpipegui.py --browser
RECONPIPE_GUI_NATIVE=0 python3 reconpipegui.py   # force browser even on a desktop
```

The window covers the same options as the CLI: domain, skips, concurrency, intel keys, Shopify host, config overlays, SARIF, headless, resume, and the extra scanners.

Tabs:

- **Scan** — target, intel keys, stage skips, start / cancel
- **Apps** — APK / IPA / package IDs
- **Console** — live log and stage tracker (`reconpipe.py` as a cancellable subprocess)
- **Findings** — actionable / informational / exposures, redacted secrets, Reveal, re-test. **Report template** picker + **Generate report**: pentest / bug-bounty write-up (HackerOne, Bugcrowd, Intigriti style) or an executive briefing for a CEO/CTO meeting
- **Vendors** — companies whose keys showed up, with a short about/website blurb, product type, live vs seen, and redacted fingerprints
- **Key Tester** — paste one or more credentials, pick a type (auto-detected when the prefix is unique), live-check without a full scan. Includes HubSpot private-app tokens (`pat-na1-…` / `pat-eu1-…` / `pat-ap1-…`)
- **Artifacts** — preview/download reports (including `vendors.html`, `report_pentest.md`, `report_executive.md` / `.html`, `remediation.md`) plus a zip when the scan finishes
- **History** — past scans (`~/.reconpipe/history.yaml`) with Open / Rescan
- **Settings** — dark mode, LLM provider (Ollama / OpenAI-compatible / OpenAI / Anthropic), model, base URL, API key, auto-run after scan, Test LLM, Generate report from a finished workspace

Also included:

- Tool preflight (what is on `PATH`)
- Live CPU / RAM meters (header + footer) for the GUI and the scan process tree
- Domain queue, saved targets, and **Rescan** (reuses URL list + output folder)

Do not bind `--browser` beyond localhost on an untrusted network. Result files can contain live secrets.

---



## LLM remediation

Optional. After findings are saved, ReconPipe can write `remediation.md`: how to **verify** each hit is still exposed (re-check the listed source and Key Tester) and how to **fix** it (rotate/revoke, remove it from the leak surface, use a secret manager).

This is separate from `ai_verdict.json`, which is still a **rule-based** P1/P2/P3 rank for AI-vendor / MCP hits and does not call a model.

Only **redacted fingerprints** are sent to the model, not full secrets. If the LLM is unreachable, a local template with the same Verify / Fix sections is written instead.

**GUI:** Settings → enable LLM reports → Save. Leave **Run automatically when a scan finishes** on, or load a finished output folder and click **Generate report from finished scan**.

**Local (no cloud key):**

1. Install [Ollama](https://ollama.com/) and `ollama pull llama3.1`.
2. Provider `ollama`, base URL `http://127.0.0.1:11434` (default).
3. LM Studio / llama.cpp: provider `openai_compat`, base URL usually `http://127.0.0.1:1234/v1`.

**Cloud:** provider `openai` or `anthropic`, paste a key (or `RECONPIPE_LLM_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`).

Saved in `~/.reconpipe/settings.yaml` (and the key in `keys.yaml`). Docker: `docker-home/settings.yaml`.

---



## Configuration

Default rules live in `config.yaml` next to `reconpipe.py`:


| Key                             | Role                                                                       |
| ------------------------------- | -------------------------------------------------------------------------- |
| `patterns`                      | Regex detectors (~169 types)                                               |
| `confidence` / `min_confidence` | Score threshold (default minimum: 30)                                      |
| `validators`                    | Live checks (URL, auth, AWS STS, Twilio pair, JWT inspect, URI inspect, …) |
| `informational_types`           | Public-by-design hits (Stripe publishable, Firebase URL, …)                |
| `exposure_types`                | Non-secret leak surface (source maps)                                      |
| `severity` / compliance tags    | Report metadata                                                            |


Overlays merge on top (repeatable `--config`). Set a pattern or validator to `null` to remove it:

```bash
python3 reconpipe.py -d example.com --config engagement.example.yaml
```

See `[engagement.example.yaml](engagement.example.yaml)` for the overlay shape.

Shopify Admin tokens need a store host:

```bash
python3 reconpipe.py -d example.com --shopify-domain store.myshopify.com
```

Vault (`hvs`/`hvb`) and Grafana (`glsa_`) checks take `--vault-addr` and `--grafana-url`.

---



## Secret detection

ReconPipe stacks several engines. Hits are de-duplicated (SHA-256 of the secret) and scored before validation.


| Engine                                                    | When it runs                                                                                                                |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `config.yaml` regex                                       | Always                                                                                                                      |
| Bundled secrets pack                                      | Unless `--skip-secrets-db`                                                                                                  |
| User / refreshed secrets-patterns-db YAML                 | If `~/.reconpipe/secrets_patterns.yml` exists, or `--secrets-db`                                                            |
| Public-API query keys (`?api_key=`, `?appid=`)            | Fingerprints from [public-apis](https://github.com/public-apis/public-apis); `--skip-public-apis` / `--refresh-public-apis` |
| TruffleHog filesystem (and `trufflehog git` for `--repo`) | If installed; `--no-trufflehog` disables                                                                                    |
| Gitleaks                                                  | If installed; `--skip-gitleaks` disables                                                                                    |
| jsleak                                                    | If installed; `--skip-jsleak` disables                                                                                      |
| Built-in JS parser                                        | Endpoints + assignments in downloaded JS                                                                                    |


Covered families include cloud (AWS, GCP, Azure, OCI), git forges, payments (including Razorpay `rzp_live_` / Flutterwave `FLWSECK-`), email/SMS, Slack/Discord/Telegram (including Slack app tokens `xapp-`), CRM (HubSpot private-app `pat-na1-` / `pat-eu1-` / `pat-ap1-` tokens; live-check `GET https://api.hubapi.com/integrations/v1/me`), AI vendors (OpenAI `sk-` / `sk-proj-` / `sk-svcacct-`, Anthropic `sk-ant-api03-` / `sk-ant-admin01-`, Hugging Face `hf_`, Groq `gsk_`, xAI `xai-`, Perplexity `pplx-`, Fireworks `fw_`), design/data tooling (Figma `figd_`, Databricks `dapi`, Postman `PMAK-`, Sonar `squ_`, Cloudinary `cloudinary://`), PaaS (Vercel, Railway, Render, Fly, Heroku), data stores (Mongo, Postgres, Redis URIs), CI, observability, and generic `api_key=` assignments. Informational hits (publishable keys, client SDK IDs) are stored separately and are not treated as secrets.

Validators send `Referer: https://<target>/` so domain-restricted keys are more likely to exercise than fail as 403 from your IP. AWS access keys pair with nearby secrets for STS. OpenAI keys are checked with `GET https://api.openai.com/v1/models`, Anthropic with `GET https://api.anthropic.com/v1/models` (`x-api-key` + `anthropic-version: 2023-06-01`), Hugging Face with `GET https://huggingface.co/api/whoami-v2`. PayPal, WooCommerce, Mixpanel, and Algolia halves are paired the same way when they share a source. Database URIs are inspected locally — ReconPipe does not connect to leaked database hosts.

Low-confidence or noisy matches can land in `quarantine.json` instead of the main findings list.

---

## Extra leak surfaces

These run during discovery unless you skip them.

**Public code search** — GitHub (and GitLab with a token) for the target domain, then the same regex/validators on the raw files. Queries also look for MCP client configs (`mcp.json`, `claude_desktop_config.json`) and AI key prefixes (`sk-proj-`, `sk-ant-`, `hf_`). Set `GITHUB_TOKEN` (or `--github-token`) to raise the search rate limit. `--github-org acme` scopes to an org. `--skip-code-search` disables it.

**CI logs / build artifacts** — For `--repo`, `--github-org`, and any GitHub/GitLab project found in code search, ReconPipe pulls recent **public** GitHub Actions run logs (ZIP) and lists/downloads build artifacts, plus GitLab job traces and job artifacts. Those files land in `ci_logs/` and go through the same regex / TruffleHog / Gitleaks pass as git history — secrets often appear in a build log even when they were never committed. Artifact ZIP download may 403 without a token; listing and run logs are the unauthenticated path. `--skip-ci-logs` disables it.

**Paste sites** — Separate from git repos: recent Pastebin dumps (scraping API when the Pro/IP allowlist works, plus [psbdmp.ws](https://psbdmp.ws) keyword search), GitHub Gists (public timeline + gist.github.com search — REST code search does not cover gists), and a Ghostbin probe (often offline). Queries use the target domain plus known prefixes (`AKIA`, `sk-`, `ghp_`, …). Matching bodies are written to `paste_sources/`. `--skip-pastes` disables it.

**Docker Hub / image layers** — Paired with GitHub as a second primary source. ReconPipe searches Docker Hub for the target name, plus any `FROM` / `image:` refs found in Dockerfiles, Compose, and K8s/Terraform during `--iac-scan` / `--repo`. Public images are pulled (docker or Trivy) and **every layer** is scanned for baked-in `.env`, MCP configs, and gcloud ADC files — the same idea as git-repo scanning, different artifact. `--skip-docker-hub` / `--skip-image-layers` disable the two halves.

**AI-vendor / MCP configs** — The sensitive-path probe hits leak surfaces such as `.cursor/mcp.json`, `.anthropic/config.json`, `.vscode/mcp.json`, `.mcp.json`, `claude_desktop_config.json`, Windsurf/Continue/Codex paths, and web-root equivalents of `~/.config/gcloud/application_default_credentials.json`. JSON `mcpServers` / `env` / `headers` / `--api-key=` args are parsed specifically. GitGuardian's *State of Secrets Sprawl 2026* found **24,008** unique secrets in public MCP configs, **2,117** still live (~9%).

After validation, those hits (and every other finding) get a **rule-based priority**, not a model call. The field is still named `ai_verdict` in `ai_verdict.json` / HTML (`P1` / `P2` / `P3`) because it ranks **AI-vendor keys** (OpenAI / Anthropic / Hugging Face) and MCP-config leaks:

| Priority | Meaning |
| -------- | ------- |
| **P1** | Live AI-vendor or MCP credential, or a combined score ≥ 80 |
| **P2** | Unverified or dead AI/MCP hit, or score ≥ 60 |
| **P3** | Everything else |

The score starts from regex confidence and adds/subtracts fixed points for: AI-provider type, MCP config source, live vs dead validation, severity, and container-image origin. That ranking does **not** call an LLM. Optional model-written verify/fix text is `remediation.md` — see [LLM remediation](#llm-remediation).

**Mobile apps** — GUI **Apps** tab, or CLI `--apk app.apk` / `--ipa app.ipa` (repeatable; `.xapk` / `.apkm` too). `--package com.example.app` (repeatable) downloads the APK first with [apkeep](https://github.com/EFForg/apkeep) (preferred; default source APKPure, no Play credentials) or `gplaycli`, then runs the same extract/scan. Pin a version with `com.example.app@1.2.3` (apkeep). Unzips the archive, keeps JS/JSON/XML/plist, strings-dumps binaries (Firebase, Maps keys, `.env`), and scans those files. In Docker, upload the package on the Apps tab (host `/home/.../Downloads` paths are not visible in the container), or install `apkeep` in the image / use `--docker-fallback`.

**JS source maps** — After download, every `.js` file is checked for `//# sourceMappingURL=` and for `same-url.js.map`. A public map is parsed (`sourcesContent`, or HTTP fetch of listed `sources`) and the original files are written to `reconstructed_sources/`. TruffleHog, Gitleaks, and `config.yaml` regex scan that tree like downloaded JS, then the same live validators run. `--skip-sourcemaps` disables it. Public maps still also appear in `source_map_exposures.json`.

**Historical live JS** — For every discovered `.js` URL (capped at 40 URLs), ReconPipe queries Wayback CDX (`collapse=digest`, oldest-first) and downloads **unique** bodies. Default is **15 unique versions per URL** (`--js-history-max N`, range 1–200), oldest first — older copies are the ones most likely to still hold a key that was later removed. Hash-identical timestamps are skipped. Unique versions land in `reconstructed_sources/_wayback/` so TruffleHog, Gitleaks, regex, and validators treat them like current / map-reconstructed code. Consecutive unique versions are diffed; lines that disappeared are flagged in `js_history_removed.json` and as `js_history_diff` findings. `--skip-js-history` turns the stage off. `--skip-wayback-bodies` only skips snapshots for URLs that fail to download.

**Cloud buckets** — Guess S3/GCS/Azure names from the domain, probe listing, and queue readable objects that look like configs. `--skip-buckets` disables it. Only names derived from the target are tried.

**OpenAPI / Swagger / Postman** — Parse discovered specs for extra endpoints and example/auth values. `--skip-openapi` disables it.

**Finding store** — `~/.reconpipe/findings.db` records first-seen / last-seen / last-valid (hashes only, not the secret). Validation results are cached for 6 hours so re-scans skip provider APIs. `--skip-store` / `--no-validation-cache` turn these off.

**`--watch SECONDS`** — CLI loop: run the full scan, sleep, repeat. Combine with the store to spot newly valid keys.

**`--ci`** — Shift-left: skip live recon (including GitHub/GitLab code search, CI logs, paste sites, Docker Hub, and bucket probes), clone/scan `--repo` (default: current directory), write SARIF, still exit 1 on live keys. The LLM report is skipped unless you also pass `--llm`.

```bash
python3 reconpipe.py --ci --repo .
# or from git hooks:
bash scripts/pre-commit
```

A sample GitHub Action lives in `.github/workflows/reconpipe.yml`.

**`--certstream-seconds N`** — Listen to the public certstream CT feed for N seconds and merge matching hostnames (needs aiohttp).

**Repo git metadata** — After `--repo`, findings from the working tree get `git log -S` author/commit/date when git can see the string.

Downloads send `If-None-Match` / `If-Modified-Since` using `download_etag.json` so `--resume` skips unchanged files.

---



## Output

Default directory: `recon_<domain>/` (override with `-o`).

Start here:


| File                                     | Contents                                     |
| ---------------------------------------- | -------------------------------------------- |
| `summary.txt`                            | Human-readable wrap-up                       |
| `report.html` / `report.md`              | Reviewable reports                           |
| `findings.json`                          | Actionable findings and validation results   |
| `valid_keys.json`                        | Confirmed live keys only                     |
| `informational.json`                     | Public-by-design hits                        |
| `source_map_exposures.json`              | Public `.map` files                          |
| `reconstructed_sources/`                 | Original files from maps + unique archived JS |
| `js_history.json` / `js_history_removed.json` | Wayback JS index and removed-line diffs   |
| `ai_verdict.json`                        | Rule-based P1/P2/P3 priority (not an LLM) |
| `remediation.md` / `llm_report.json`     | Verify-and-fix writeup (LLM or local template) |
| `docker_hub_images.json` / `image_refs.json` | Public images queued for layer scan   |
| `results.sarif`                          | SARIF 2.1.0 for CI                           |
| `export_hackerone.md` / `export_jira.md` | Draft write-ups                              |
| `vendors.json` / `vendors.html`          | Companies + key types, fingerprints only     |
| `report_pentest.md`                      | Bug-bounty style (CWE, impact, verify steps) |
| `report_executive.md` / `.html`          | Meeting-room brief for CEO / CTO / board     |
| `.reconpipe_ignore.json`                 | Baseline (type + source, or `--ignore-hash`) |


Useful intermediates: `subdomains.txt`, `live_hosts.txt`, `files_to_scan.txt`, `downloaded_files/`, `reconstructed_sources/`, `image_layers/`, `js_history.json`, `js_history_removed.json`, `js_endpoints.json`, `js_secrets.json`, `gitleaks.json`, `jsleak.txt`, `sensitive_paths.txt`, `wayback_sources.json`, `code_search_urls.txt`, `docker_hub_images.json`, `image_refs.json`, `ai_verdict.json`, `remediation.md`, `llm_report.json`, `vendors.json`, `report_pentest.md`, `report_executive.md`, `buckets.json`, `openapi_urls.txt`, `download_etag.json`, `pipeline_metrics.json`, `checkpoint.json`.

Keep the output directory private. `valid_keys.json` is the highest-risk file.

---



## CLI reference

Run `python3 reconpipe.py -h` for the full list. Grouped below.

**Target**


| Flag                                                | Meaning                                  |
| --------------------------------------------------- | ---------------------------------------- |
| `-d`, `--domain`                                    | Target domain                            |
| `--domain-list FILE`                                | One domain per line                      |
| `--subdomains FILE`                                 | Existing hosts (skips Chaos)             |
| `--files FILE`                                      | Existing URLs (skips discovery)          |
| `-o`, `--output DIR`                                | Output directory                         |
| `--include-pattern FILE` / `--exclude-pattern FILE` | Host globs                               |
| `--repo URL`                                        | Clone and scan a git repo                |
| `--repo-shallow`                                    | `--depth 1` clone (no history scan)      |
| `--apk FILE` / `--ipa FILE`                         | Unzip and scan a local mobile app        |
| `--package ID`                                      | Fetch an Android app (apkeep / gplaycli) then scan |
| `--iac-scan`                                        | Also walk Docker / K8s / Terraform files |


**Skip / extra stages**


| Flag                                                                                       | Meaning                                      |
| ------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `--skip-chaos` `--skip-subfinder` `--skip-amass` `--skip-assetfinder` `--skip-findomain`   | Subdomain sources                            |
| `--skip-intel` `--skip-crtsh`                                                              | Passive hostname intel                       |
| `--skip-dnsx` `--skip-httpx`                                                               | Resolve / live filter                        |
| `--skip-gau`                                                                               | Passive archives only                        |
| `--skip-discovery`                                                                         | All URL discovery                            |
| `--skip-hakrawler` `--skip-paramspider` `--skip-naabu` `--skip-whatweb` `--skip-gowitness` | Optional recon                               |
| `--nuclei` `--nuclei-templates PATH` `--nuclei-import FILE`                                | Nuclei                                       |
| `--skip-wayback-bodies`                                                                    | Do not fetch Wayback snapshots for dead URLs |
| `--skip-js-history`                                                                        | Do not fetch older copies of still-live JS   |
| `--js-history-max N`                                                                       | Unique Wayback JS versions per URL (default 15, oldest first) |
| `--skip-sourcemaps`                                                                        | Do not reconstruct original files from maps  |
| `--skip-sensitive-paths`                                                                   | Skip `.env` / `.git` / swagger / MCP probes |
| `--spray`                                                                                  | Opt-in extra leak-path brute                 |
| `--no-trufflehog` `--skip-gitleaks` `--skip-jsleak`                                        | Secret engines                               |
| `--no-validate`                                                                            | Detection only                               |
| `--headless`                                                                               | Katana Chrome for SPAs                       |
| `--amass-active`                                                                           | Amass without `-passive`                     |
| `--llm` / `--skip-llm`                                                                     | Write / skip `remediation.md` after the scan |
| `--llm-provider` `--llm-model` `--llm-base-url` `--llm-key`                                | Ollama, openai_compat, openai, anthropic     |
| `--llm-timeout SEC` `--llm-max-findings N`                                                 | LLM HTTP timeout (default 120) and cap       |


**Secrets packs**


| Flag                                           | Meaning                               |
| ---------------------------------------------- | ------------------------------------- |
| `--secrets-db FILE`                            | Extra YAML (repeatable)               |
| `--refresh-secrets-db`                         | Download filtered secrets-patterns-db |
| `--skip-secrets-db`                            | Ignore bundled/user extra regexes     |
| `--secrets-db-medium`                          | Also keep medium-confidence rules     |
| `--skip-public-apis` / `--refresh-public-apis` | Query-string vendor key catalog       |
| `--skip-code-search`                           | Skip GitHub/GitLab public code search |
| `--skip-ci-logs`                               | Skip public Actions / GitLab job logs |
| `--skip-pastes`                                | Skip Pastebin / Gist / Ghostbin       |
| `--skip-docker-hub`                            | Skip Docker Hub public image search   |
| `--skip-image-layers`                          | Skip pull/scan of public image layers |
| `--github-token` / `--gitlab-token`            | Tokens for code search                |
| `--github-org ORG`                             | Scope GitHub search to an org         |
| `--apk FILE` / `--ipa FILE`                    | Unzip and scan a mobile app           |
| `--package ID`                                 | Download via apkeep/gplaycli, then scan |
| `--skip-buckets`                               | Skip S3/GCS/Azure name guesses        |
| `--skip-openapi`                               | Skip OpenAPI/Swagger/Postman parse    |
| `--ci`                                         | Local-repo scan, skip live recon      |
| `--watch SECONDS`                              | Repeat the scan on an interval        |
| `--certstream-seconds N`                       | Live CT hostnames via certstream      |
| `--skip-store` / `--no-validation-cache`       | SQLite history / 6h validation cache  |


**Runtime**


| Flag                                   | Meaning                                   |
| -------------------------------------- | ----------------------------------------- |
| `--concurrency N`                      | Validation concurrency (default 10)       |
| `--download-workers N`                 | Download parallelism (default 16)         |
| `--gau-threads N`                      | gau threads (default 5)                   |
| `--polite`                             | ~500 ms delay between requests            |
| `--requests-per-second N`              | Global rate limit                         |
| `--proxy URL` `--proxy-auth USER:PASS` | HTTP proxy                                |
| `-H NAME:VALUE`                        | Extra request header (repeatable)         |
| `--credentials FILE`                   | Cookies + headers YAML/JSON               |
| `--burp-import FILE`                   | Burp XML URLs                             |
| `--docker-fallback`                    | Run missing tools in Docker when possible |
| `--resume` / `--resume-from STAGE`     | Continue a previous run                   |
| `--rescan`                             | Reuse saved target lists + output, resume |
| `--config FILE`                        | Overlay YAML (repeatable)                 |
| `--sarif FILE`                         | SARIF path                                |
| `--no-fail-on-valid`                   | Do not exit 1 on live keys                |
| `--ignore-hash SHA256`                 | Permanent baseline suppress (repeatable)  |


---



## Troubleshooting

`httpx` **shows as missing after** `go install`

The Python `httpx` library installs a different CLI with the same name. ReconPipe only accepts ProjectDiscovery httpx.

```bash
export HTTPX_BIN="$HOME/go/bin/httpx"
# or put $HOME/go/bin before ~/.local/bin
# Kali package: apt install httpx-toolkit   # binary name: httpx-toolkit
```

**Chaos returns nothing**

Set `CHAOS_KEY` or `PDCP_API_KEY`, or pass `--chaos-key`. You can always feed `--subdomains`.

**amass: “unable to build the pool of untrusted resolvers”**

Amass could not reach its default public DNS resolvers (common on Windows, VPNs, and filtered networks). ReconPipe continues without Amass results. Point Amass at a resolver you can reach (`amass enum -r 8.8.8.8 …`), skip it with `--skip-amass`, or run from a less filtered network.

**LLM report missing / “LLM unavailable”**

Ollama must be running and the model pulled (`ollama pull llama3.1`). For cloud providers, set a key in Settings or `RECONPIPE_LLM_KEY`. `--ci` skips the LLM unless you also pass `--llm`. A failed model call still writes a local Verify/Fix template in `remediation.md`.

**Scan is slow**

Archives (waymore/gau) and headless Katana dominate runtime. Use `--skip-gau` or `--skip-discovery` with `--files`, lower `--concurrency`, or `--polite` / `--requests-per-second` on fragile targets.

**Too many false positives**

Raise `min_confidence` in an overlay, disable `generic_secret`, or `--skip-secrets-db`. Do not enable `--secrets-db-medium` unless you want noisier vendor-context regexes.

**GUI opens in a browser instead of a window**

Install pywebview and WebKit (see [Installation](#installation)), or pass `--native`. `--browser` forces a localhost tab.

**Need a global** `reconpipe` **command**

```bash
chmod +x reconpipe.py
sudo ln -sf "$(pwd)/reconpipe.py" /usr/local/bin/reconpipe
reconpipe -d example.com
```

---



## Tests

```bash
python3 -m unittest tests.test_wave2 tests.test_wave3 tests.test_new_features tests.test_cli_and_keys \
  tests.test_patterns tests.test_user_settings tests.test_llm tests.test_reports tests.test_httpx_resolve tests.test_osint tests.test_docker -q

# GUI wiring (Windows: set PYTHONIOENCODING=utf-8)
python3 tests/test_gui_integration.py
```

---



## License

MIT. See [LICENSE](LICENSE).

Third-party scanners keep their own licenses. TruffleHog-derived pattern sets are AGPL; ReconPipe does not vendor that full database. The bundled extras in `wordlists/secrets_patterns.yml` follow [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (CC BY-SA 4.0).