# syntax=docker/dockerfile:1
# Images for the API, the worker and the sandbox broker.
#
#   target "app"    (default) - API + worker. No Docker client and no Docker socket: analysis
#                               jobs are requested from the broker over a Unix socket.
#   target "broker"           - the only component with Docker access. It accepts a fixed set of
#                               job profiles (analyze, fwanalyzer, cwe_checker, ghidra) with
#                               validated parameters and starts hardened, network-less containers.
# See docs/SECURITY.md.
#
# Behind a TLS-intercepting proxy, pass its CA certificate as a build secret (optional):
#   docker build --secret id=extra_ca,src=proxy-ca.crt -f docker/app.Dockerfile .

FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi \
 && npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS base
RUN groupadd --gid 10002 dfa \
 && useradd --uid 10002 --gid 10002 --create-home --shell /usr/sbin/nologin dfa
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then \
      cat "$(python -c 'import certifi; print(certifi.where())' 2>/dev/null || echo /etc/ssl/certs/ca-certificates.crt)" \
          /run/secrets/extra_ca > /tmp/ca.pem 2>/dev/null || cp /run/secrets/extra_ca /tmp/ca.pem; \
      export PIP_CERT=/tmp/ca.pem; \
    fi \
 && pip install --no-cache-dir -r requirements.txt \
 && rm -f /tmp/ca.pem
COPY backend/ ./
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DFA_DATA_DIR=/data

# ---- sandbox broker ----------------------------------------------------------
FROM base AS broker
# Static Docker CLI only (no daemon); it talks to the host daemon through the mounted socket.
COPY --from=docker:27.3.1-cli /usr/local/bin/docker /usr/local/bin/docker
# Runs as root inside its container: it needs the Docker socket and must hand scan directories to
# the sandbox UIDs and back. It has no network (network_mode: none) and serves only the Unix socket.
CMD ["python", "-m", "dfa.broker", "--socket", "/run/dfa/broker.sock", "--group", "10002", "--mode", "660"]

# ---- API + worker ------------------------------------------------------------
FROM base AS app
COPY --from=ui /ui/dist /app/frontend/dist
ENV DFA_FRONTEND_DIST=/app/frontend/dist
USER dfa
EXPOSE 8000
CMD ["uvicorn", "dfa.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]
