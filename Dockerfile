# Imagen única del producto: la API y los jobs (PLAN §2). Cada componente cambia solo el módulo
# que ejecuta: `python -m <módulo>` (infra/main.bicep, parámetro `entrypoints`).
#
# Dependencias exactas y con hash: el workflow `images.yml` genera `requirements.lock.txt` con
# `uv export --locked` (desde uv.lock) antes del build, y pip lo instala con --require-hashes.
# El fichero no se versiona: sale siempre del lock.
#
# Base fijada por etiqueta. El digest se fija en cuanto se pueda leer desde una sesión con red
# (pregunta abierta del informe de T9); el workflow publica la imagen por digest.
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY requirements.lock.txt ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.lock.txt

COPY LICENSE NOTICE ./
COPY src ./src
COPY config ./config
COPY schema ./schema

# Sin root (UID fijo, sin shell de login). El contenedor no necesita escribir en /app.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vs
USER 10001

ENTRYPOINT ["python", "-m"]
