"""Production-oriented entrypoint for the LAN honeypot IDS."""

import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
VENDOR_DIR = BASE_DIR / ".vendor"
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))

from ids_app import create_app


app = create_app()


if __name__ == "__main__":
    host = app.config.get("HOST", "0.0.0.0")
    port = int(app.config.get("PORT", 5000))
    try:
        from waitress import serve
    except ImportError:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        serve(app, host=host, port=port)
