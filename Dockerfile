# ReconPipe — CLI + GUI with core recon binaries on PATH.
# Build once, then scans skip the host install.sh wait.
#
#   docker compose build
#   docker compose run --rm reconpipe -d example.com
#   docker compose --profile gui up gui

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
RUN go install github.com/byt3hx/jsleak@latest || go install github.com/channyein1337/jsleak@latest || true
RUN go install github.com/tomnomnom/assetfinder@latest || true
RUN go install github.com/hakluke/hakrawler@latest || true
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 || go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
 || true

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
    PATH=/usr/local/bin:/usr/bin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git unzip wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/bin/ /usr/local/bin/

# TruffleHog ships a static release; faster and more reliable than go install here.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin \
    && trufflehog --version >/dev/null

WORKDIR /opt/reconpipe
COPY requirements.txt /opt/reconpipe/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt waymore

COPY reconpipe.py reconpipe_addons.py reconpipe_wave3.py reconpipegui.py /opt/reconpipe/
COPY config.yaml /opt/reconpipe/config.yaml
COPY wordlists /opt/reconpipe/wordlists
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /work /root/.reconpipe \
 && python3 -m py_compile reconpipe.py reconpipe_addons.py reconpipe_wave3.py reconpipegui.py

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
