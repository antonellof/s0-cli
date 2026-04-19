# syntax=docker/dockerfile:1.7
#
# s0-cli runtime image.
#
# Goals:
# - Reproducible: pin every external scanner version.
# - Self-contained: ships every scanner the harness can use, so a clean image
#   passes `s0 doctor` with all scanners green.
# - Small enough for CI: ~700MB; the bulk is semgrep + trivy DBs (lazy-loaded
#   on first use, not at build time, to keep the layer cacheable).
# - No secrets baked in. Provider keys are passed via env at runtime.
#
# Usage:
#   docker build -t s0-cli .
#   docker run --rm -v "$PWD:/work" -w /work \
#     -e OPENAI_API_KEY="$OPENAI_API_KEY" s0-cli scan .
#
# Or pull the published image (when available):
#   docker run --rm -v "$PWD:/work" -w /work ghcr.io/<owner>/s0-cli:latest scan .

FROM python:3.12-slim-bookworm AS base

ARG GITLEAKS_VERSION=8.18.4
ARG TRIVY_VERSION=0.51.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    S0_RUNS_DIR=/work/runs

# OS-level deps the harness shells out to: git for diff/blame, ripgrep for
# the agent's `grep` tool, plus curl + ca-certs for fetching scanner binaries.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        git \
        ripgrep \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# gitleaks is shipped as a single statically-linked binary on GitHub releases.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch="x64" ;; \
      arm64) gl_arch="arm64" ;; \
      *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tgz; \
    gitleaks version

# trivy ships a tarball per arch as well.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tr_arch="64bit" ;; \
      arm64) tr_arch="ARM64" ;; \
      *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tr_arch}.tar.gz"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tgz; \
    trivy --version

# Python scanners + s0-cli itself. We split this into its own layer so changes
# to the source tree don't invalidate the (slow) scanner-binary downloads above.
WORKDIR /opt/s0-cli
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install "semgrep==1.78.0" "bandit==1.7.9" \
    && pip install . \
    && s0 version

# Run as a non-root user; the host bind-mount must be readable by uid 1000
# (or override at runtime with `docker run --user`).
RUN useradd --create-home --uid 1000 s0
USER s0
WORKDIR /work

# tini gives clean signal handling so Ctrl+C inside `s0 optimize` triggers the
# loop's graceful-shutdown path instead of being eaten by PID 1.
ENTRYPOINT ["/usr/bin/tini", "--", "s0"]
CMD ["--help"]
