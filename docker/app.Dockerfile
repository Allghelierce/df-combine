# API + worker image (also serves the built React dashboard).
# The worker launches per-scan sandbox containers (dfa-sandbox image) through the
# Docker socket - see docs/SECURITY.md for the implications.

FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker.io \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10002 --create-home --shell /usr/sbin/nologin dfa
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=ui /ui/dist /app/frontend/dist
ENV PYTHONUNBUFFERED=1 DFA_DATA_DIR=/data DFA_FRONTEND_DIST=/app/frontend/dist
EXPOSE 8000
CMD ["uvicorn", "dfa.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]
