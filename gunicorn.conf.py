"""Gunicorn configuration. Values come from the environment where useful.

NOTE on concurrency: the in-memory dedup cache lives inside one worker. Keep
WEB_CONCURRENCY=1 (the default) so it stays authoritative. Threads handle
concurrent requests fine for this low-volume workload. If you truly need
multiple workers, move dedup to a shared store first.
"""
import os

bind = f"{os.getenv('LISTEN_HOST', '0.0.0.0')}:{os.getenv('LISTEN_PORT', '8080')}"
workers = int(os.getenv("WEB_CONCURRENCY", "1"))
threads = int(os.getenv("WEB_THREADS", "4"))
worker_class = "gthread"
timeout = int(os.getenv("WEB_TIMEOUT", "30"))
graceful_timeout = 30
keepalive = 5

# Log to stdout/stderr so `docker logs` captures everything.
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
