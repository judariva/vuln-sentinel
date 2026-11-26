# Imagen para probar en local con `docker compose up` (compose.yaml). NO es la de producción.
#
# Diferencias con el Dockerfile de la raíz (el que construye images.yml):
# - genera `requirements.lock.txt` dentro del build, desde uv.lock, con el mismo comando que
#   images.yml; así un clon nuevo no necesita ningún paso previo;
# - construye el portal (web/dist) para que la API lo sirva en el mismo origen.
# Las dependencias de Python se instalan igual: exactas y con hash (--require-hashes).
#
# Bases fijadas por digest, leídos con `docker pull` el 2026-11-26.

FROM node:24-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.9.30@sha256:538e0b39736e7feae937a65983e49d2ab75e1559d35041f9878b7b7e51de91e4 AS uv

FROM python:3.13-slim-bookworm@sha256:f0fa218d5b06f9b9235024fa061cde2cb141f726de52134471053d2d9b5324a3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv export --locked --no-dev --no-emit-project --format requirements-txt -o requirements.lock.txt \
    && pip install --require-hashes --only-binary=:all: -r requirements.lock.txt

COPY LICENSE NOTICE ./
COPY src ./src
COPY config ./config
COPY schema ./schema
COPY docs/metrics ./docs/metrics
COPY --from=web /web/dist ./web/dist

# Sin root. /data guarda la clave de desarrollo y el feed escrito (volumen de compose).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vs \
    && mkdir /data && chown 10001 /data
USER 10001

ENTRYPOINT ["python", "-m"]
