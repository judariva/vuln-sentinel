# Imagen única del producto: la API y los jobs (PLAN §2). Cada componente cambia solo el módulo
# que ejecuta: `python -m <módulo>` (infra/terraform/modules/vuln-sentinel/, `args` de cada app y job).
#
# Dependencias exactas y con hash: el workflow `images.yml` genera `requirements.lock.txt` con
# `uv export --locked` (desde uv.lock) antes del build, y pip lo instala con --require-hashes.
# El fichero no se versiona: sale siempre del lock.
#
# Base fijada por digest (índice multiarquitectura de la etiqueta, leído del registro de Docker Hub
# con una petición anónima el 2026-11-26). La etiqueta queda para leerla; manda el digest.
# Dependabot (`.github/dependabot.yml`) propone cada semana el digest nuevo en un PR.

# Portal (web/): se construye aquí y la API lo sirve en el mismo origen (VS_WEB_DIST). Mismo digest
# de Node que infra/compose/Dockerfile. npm ci instala exacto desde package-lock.json (con integridad).
# Sin VITE_API_BASE_URL: el portal llama a la API en su mismo origen. La marca, por build-arg.
FROM node:24-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530 AS web
ARG VITE_BRAND_NAME=vuln-sentinel
ENV VITE_BRAND_NAME=${VITE_BRAND_NAME}
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM python:3.15-slim-bookworm@sha256:498829c717b1e59fc42f0e7865eafe4e04ca0f70a3769d4ae70ba218df54507c

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src

# /app es de solo lectura para el usuario 10001: lo que escribe el job de publicación va a /tmp
# (efímero; en la F1b, a R2). compose.yaml lo cambia por su volumen.
ENV VS_FEED_DIR=/tmp/vs/feed

WORKDIR /app

COPY requirements.lock.txt ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.lock.txt

COPY LICENSE NOTICE ./
COPY src ./src
COPY config ./config
COPY schema ./schema
# Consultas de métricas que ejecuta `vs.jobs.daily` (T13).
COPY docs/metrics ./docs/metrics
# Portal estático: solo el build, sin node_modules ni fuentes.
COPY --from=web /web/dist ./web/dist
ENV VS_WEB_DIST=/app/web/dist

# Sin root (UID fijo, sin shell de login). El contenedor no necesita escribir en /app.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vs
USER 10001

ENTRYPOINT ["python", "-m"]
