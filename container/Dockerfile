# syntax=docker/dockerfile:1.7
FROM python:3.11-slim@sha256:6d7b4dd7d1ef8f68f2d88ca6e3e8f25f631b7d831bdb9fee9601e606b9c7c9ee

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_CACHE_DIR=/var/cache/pip

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nsjail nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
COPY src /app/src
COPY container/entrypoint.sh /entrypoint.sh
COPY container/nsjail.cfg /etc/nsjail.cfg

RUN pip install --no-cache-dir .

VOLUME ["/var/cache/pip"]
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
