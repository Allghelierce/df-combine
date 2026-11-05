# syntax=docker/dockerfile:1
# Isolated analysis image: identification, safe extraction, built-in scanners and FwAnalyzer.
# The sandbox broker starts it per job with:
#   --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#   --memory/--cpus/--pids-limit, firmware mounted read-only, unprivileged user.
#
# Behind a TLS-intercepting proxy, pass its CA certificate as a build secret (optional):
#   docker build --secret id=extra_ca,src=proxy-ca.crt -f docker/sandbox.Dockerfile -t dfa-sandbox:latest .

# ---- FwAnalyzer (Go) -------------------------------------------------------
FROM golang:1.22-bookworm AS fwanalyzer
# Pinned upstream revision (the project is no longer actively developed).
ARG FWANALYZER_VERSION=v0.0.0-20231008152640-a0db45054642
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem && export SSL_CERT_FILE=/tmp/ca.pem; \
    fi \
 && CGO_ENABLED=0 GOBIN=/out go install github.com/cruise-automation/fwanalyzer/cmd/fwanalyzer@${FWANALYZER_VERSION}

# ---- runtime ---------------------------------------------------------------
FROM ubuntu:24.04
RUN --mount=type=secret,id=extra_ca \
    apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pyelftools python3-pip ca-certificates squashfs-tools e2fsprogs e2tools mtools cpio erofs-utils \
      binutils \
 && if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem && export PIP_CERT=/tmp/ca.pem; \
    fi \
 && pip install --no-cache-dir --break-system-packages "ubi_reader==0.8.16" "jefferson==0.4.8" "lz4==4.4.5" \
      "zstandard>=0.22" "lzallright>=0.2" \
 && rm -f /tmp/ca.pem \
 && apt-get purge -y python3-pip && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin analyzer \
 && ln -s /usr/bin/python3 /usr/local/bin/python
COPY --from=fwanalyzer /out/fwanalyzer /usr/local/bin/fwanalyzer

WORKDIR /opt/dfa
COPY backend/dfa/__init__.py dfa/__init__.py
COPY backend/dfa/core dfa/core
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/dfa DFA_IN_SANDBOX=1
USER analyzer
CMD ["python", "-m", "dfa.core.analyze", "--help"]
