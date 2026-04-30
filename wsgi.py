"""WSGI entrypoint for LAN honeypot deployment."""

from ids_app import create_app


app = create_app()
