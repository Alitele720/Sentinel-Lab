"""Deployment-oriented configuration helpers for the LAN honeypot mode."""

import os
from pathlib import Path

from .runtime import runtime


def parse_csv(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _strip_quotes(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_dotenv_file(dotenv_path=None, *, override=False):
    """Load a simple .env file into os.environ."""
    env_path = Path(dotenv_path) if dotenv_path else runtime.base_dir / ".env"
    if not env_path.exists():
        return False

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = _strip_quotes(value.strip())
        if override or key not in os.environ:
            os.environ[key] = value
    return True


def load_deploy_config():
    """Load deployment defaults from environment variables."""
    load_dotenv_file()
    return {
        "SECRET_KEY": os.environ.get("IDS_SECRET_KEY", "change-me-before-production"),
        "HOST": os.environ.get("IDS_HOST", "0.0.0.0"),
        "PORT": int(os.environ.get("IDS_PORT", "5000")),
        "PRODUCTION_MODE": parse_bool(os.environ.get("IDS_PRODUCTION_MODE"), True),
        "START_WATCHER": parse_bool(os.environ.get("IDS_START_WATCHER"), True),
        "SYNC_INGEST_REAL_REQUESTS": parse_bool(os.environ.get("IDS_SYNC_INGEST_REAL_REQUESTS"), True),
        "ADMIN_ALLOWED_IPS": parse_csv(os.environ.get("IDS_ADMIN_ALLOWED_IPS", "127.0.0.1,::1")),
        "TRUST_PROXY": parse_bool(os.environ.get("IDS_TRUST_PROXY"), False),
        "TRUSTED_PROXY_IPS": parse_csv(os.environ.get("IDS_TRUSTED_PROXY_IPS", "")),
        "ADMIN_AUTH_ENABLED": parse_bool(os.environ.get("IDS_ADMIN_AUTH_ENABLED"), True),
        "ADMIN_USERNAME": os.environ.get("IDS_ADMIN_USERNAME", "admin"),
        "ADMIN_PASSWORD": os.environ.get("IDS_ADMIN_PASSWORD", "changeme"),
        "EXPOSE_LABS": parse_bool(os.environ.get("IDS_EXPOSE_LABS"), False),
    }
