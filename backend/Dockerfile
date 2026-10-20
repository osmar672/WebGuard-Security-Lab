FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt \
    && groupadd --system webguard \
    && useradd --system --gid webguard --home-dir /nonexistent --shell /usr/sbin/nologin webguard

COPY backend/app /app/app
COPY backend/alembic /app/alembic
COPY backend/alembic.ini /app/alembic.ini
COPY security /tmp/security
RUN python -m pip install /tmp/security && rm -rf /tmp/security

USER webguard:webguard
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import json,os,urllib.request; host=os.environ['WEBGUARD_ALLOWED_HOSTS'].split(',')[0].strip(); req=urllib.request.Request('http://127.0.0.1:8000/api/health',headers={'Host':host}); d=json.load(urllib.request.urlopen(req,timeout=3)); assert d.get('database') == 'ok'"
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "172.30.80.12"]
