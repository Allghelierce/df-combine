# Images for the API, the worker and the sandbox broker.
#
#   target "app"    (default) - API + worker. No Docker client and no Docker socket: analysis
#                               jobs are requested from the broker over a Unix socket.
#   target "broker"           - the only component with Docker access. It accepts a fixed set of
#                               job profiles (analyze, fwanalyzer, cwe_checker, ghidra) with
#                               validated parameters and starts hardened, network-less containers.
# See docs/SECURITY.md.

FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS base
RUN groupadd --gid 10002 dfa \
 && useradd --uid 10002 --gid 10002 --create-home --shell /usr/sbin/nologin dfa
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
ENV PYTHONUNBUFFERED=1 DFA_DATA_DIR=/data

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
