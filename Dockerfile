FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so the layer is cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY app ./app
COPY gunicorn.conf.py .

# Run as an unprivileged user. Seed writable-volume paths with the right owner
# so Docker copies their permissions into newly created named volumes.
RUN useradd --system --uid 10001 --no-create-home appuser \
    && mkdir -p /data /geoip \
    && chown appuser:appuser /data
USER appuser

EXPOSE 8080

# Container-internal port is fixed at 8080; remap on the host in compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
