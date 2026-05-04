"""Production-oriented entrypoint for the LAN honeypot IDS."""

import socket
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
VENDOR_DIR = BASE_DIR / ".vendor"
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))

from ids_app import create_app


app = create_app()


def get_lan_addresses():
    addresses = set()
    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip_value = item[4][0]
            if not ip_value.startswith("127."):
                addresses.add(ip_value)
    except socket.gaierror:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            ip_value = probe.getsockname()[0]
            if not ip_value.startswith("127."):
                addresses.add(ip_value)
    except OSError:
        pass
    return sorted(addresses)


def print_access_urls(host, port):
    urls = [f"http://127.0.0.1:{port}"]
    if host not in {"127.0.0.1", "localhost"}:
        urls.extend(f"http://{ip_value}:{port}" for ip_value in get_lan_addresses())
    if host not in {"0.0.0.0", "127.0.0.1", "localhost"}:
        urls.append(f"http://{host}:{port}")

    print("服务已启动，可访问地址：")
    for url in dict.fromkeys(urls):
        print(f"  {url}")


if __name__ == "__main__":
    host = app.config.get("HOST", "0.0.0.0")
    port = int(app.config.get("PORT", 5000))
    print_access_urls(host, port)
    try:
        from waitress import serve
    except ImportError:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        serve(app, host=host, port=port)
