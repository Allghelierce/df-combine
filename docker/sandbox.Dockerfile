# Isolated analysis image: identification, safe extraction, built-in scanners and FwAnalyzer.
# It is started per scan by the worker with:
#   --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#   --memory/--cpus/--pids-limit, firmware mounted read-only, unprivileged user.

# ---- FwAnalyzer (Go) -------------------------------------------------------
FROM golang:1.22-bookworm AS fwanalyzer
# Pinned upstream revision (the project is no longer actively developed).
ARG FWANALYZER_VERSION=v0.0.0-20231008152640-a0db45054642
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/cruise-automation/fwanalyzer/cmd/fwanalyzer@${FWANALYZER_VERSION}

# ---- runtime ---------------------------------------------------------------
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pyelftools squashfs-tools e2fsprogs e2tools mtools cpio \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin analyzer \
 && ln -s /usr/bin/python3 /usr/local/bin/python
COPY --from=fwanalyzer /out/fwanalyzer /usr/local/bin/fwanalyzer

WORKDIR /opt/dfa
COPY backend/dfa/__init__.py dfa/__init__.py
COPY backend/dfa/core dfa/core
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/dfa
USER analyzer
CMD ["python", "-m", "dfa.core.analyze", "--help"]
