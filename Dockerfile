# ReconPipe — CLI + GUI with recon binaries on PATH.
#
#   docker compose up -d --build
#   open http://127.0.0.1:8088

FROM golang:1.26-bookworm AS tools

ENV CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org,direct \
    GOTOOLCHAIN=auto \
    GOBIN=/out/bin
RUN mkdir -p /out/bin

# One RUN per binary so a later failure does not rebuild tools that already compiled.
# Current ProjectDiscovery httpx needs Go >= 1.26 (golang:1.22 fails at @latest).
RUN go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/jaeles-project/gospider@latest
RUN go install github.com/tomnomnom/waybackurls@latest
# go.mod still declares zricethezav/... even though the GitHub repo is gitleaks/gitleaks.
RUN go install github.com/zricethezav/gitleaks/v8@latest \
 || go install github.com/gitleaks/gitleaks/v8@latest

# Optional extras — image still builds if one of these repos moves.
# Keep the original order so cached layers (jsleak → nuclei) stay valid.
RUN go install github.com/byt3hx/jsleak@latest || go install github.com/channyein1337/jsleak@latest || true
RUN go install github.com/tomnomnom/assetfinder@latest || true
RUN go install github.com/hakluke/hakrawler@latest || true
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 || go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
 || true
RUN go install github.com/tomnomnom/anew@latest || true
RUN go install github.com/BishopFox/jsluice/cmd/jsluice@latest || true
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@latest || true
RUN go install github.com/owasp-amass/amass/v4/...@v4.2.0 \
 || go install github.com/owasp-amass/amass/v4/...@master \
 || true

# naabu needs libpcap (CGO). Keep it optional so a missing header does not fail the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/* \
 && CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 || true
# Drop Go module/build caches so the builder stage does not fill the CI disk.
RUN go clean -cache -modcache -testcache || true

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RECONPIPE_HOME=/root/.reconpipe \
    RECONPIPE_WORKDIR=/work \
    RECONPIPE_GUI_NATIVE=0 \
    RECONPIPE_GUI_SHOW=0 \
    RECONPIPE_GUI_HOST=0.0.0.0 \
    RECONPIPE_GUI_PORT=8088 \
    HTTPX_BIN=/opt/pd-bin/httpx \
    PATH=/opt/pd-bin:/usr/local/bin:/usr/bin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git unzip wget libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# One copy only. PATH puts /opt/pd-bin first so pip's Python httpx CLI cannot
# shadow ProjectDiscovery httpx (duplicating into /usr/local/bin filled GH runners).
COPY --from=tools /out/bin/ /opt/pd-bin/

# TruffleHog ships a static release; faster and more reliable than go install here.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin \
    && trufflehog --version >/dev/null

# findomain / spray ship prebuilt Linux binaries.
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64|amd64) fd=findomain-linux.zip; sp=spray_linux_amd64 ;; \
      aarch64|arm64) fd=findomain-aarch64.zip; sp=spray_linux_arm64 ;; \
      *) fd=""; sp="" ;; \
    esac; \
    if [ -n "$fd" ]; then \
      tmp="$(mktemp -d)"; \
      curl -fsSL "https://github.com/findomain/findomain/releases/latest/download/${fd}" -o "$tmp/fd.zip" \
        && unzip -qo "$tmp/fd.zip" -d "$tmp" \
        && dest="$(find "$tmp" -maxdepth 2 -type f -name 'findomain*' ! -name '*.zip' | head -1)" \
        && test -n "$dest" \
        && mv "$dest" /usr/local/bin/findomain \
        && chmod +x /usr/local/bin/findomain \
        || true; \
      curl -fsSL "https://github.com/chainreactors/spray/releases/latest/download/${sp}" -o /usr/local/bin/spray \
        && chmod +x /usr/local/bin/spray \
        || rm -f /usr/local/bin/spray; \
      rm -rf "$tmp"; \
    fi

WORKDIR /opt/reconpipe
COPY requirements.txt /opt/reconpipe/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt waymore
RUN pip install --no-cache-dir "git+https://github.com/devanshbatham/ParamSpider.git" || true

# LinkFinder is a script, not a PyPI console entry.
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder \
 && (pip install --no-cache-dir -r /opt/LinkFinder/requirements.txt || pip install --no-cache-dir jsbeautifier) \
 && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/LinkFinder/linkfinder.py "$@"' > /usr/local/bin/linkfinder \
 && chmod +x /usr/local/bin/linkfinder \
 || true

# pip/NiceGUI may drop a Python CLI at /usr/local/bin/httpx — point those names
# at the PD binary without copying the whole tool dir again.
RUN if [ -x /opt/pd-bin/httpx ]; then \
      rm -f /usr/local/bin/httpx /usr/local/bin/httpx-toolkit; \
      ln -s /opt/pd-bin/httpx /usr/local/bin/httpx; \
      ln -s /opt/pd-bin/httpx /usr/local/bin/httpx-toolkit; \
    fi

COPY reconpipe.py reconpipe_addons.py reconpipe_wave3.py reconpipe_llm.py reconpipe_reports.py reconpipegui.py /opt/reconpipe/
COPY config.yaml /opt/reconpipe/config.yaml
COPY wordlists /opt/reconpipe/wordlists
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /work /root/.reconpipe \
 && python3 -m py_compile reconpipe.py reconpipe_addons.py reconpipe_wave3.py reconpipe_llm.py reconpipe_reports.py reconpipegui.py

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["gui"]
