# Optional tool-worker image. Separate from the API image to reduce attack surface.
# Python integrations + Chromium are installed; native CLI engines remain reported
# as unavailable until their pinned binaries are added to this image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY backend/requirements.txt /tmp/requirements.txt
COPY backend/requirements-tools.txt /tmp/requirements-tools.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt -r /tmp/requirements-tools.txt \
    && python -m playwright install --with-deps chromium \
    && groupadd --system webguard \
    && useradd --system --gid webguard --home-dir /nonexistent --shell /usr/sbin/nologin webguard \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/* /tmp/requirements.txt /tmp/requirements-tools.txt

COPY backend/app /app/app
COPY security /tmp/security
RUN python -m pip install /tmp/security \
    && rm -rf /tmp/security \
    && chown -R webguard:webguard /app

USER webguard:webguard
CMD ["python", "-m", "app.tooling.worker"]
