"""Admin access control and honeypot-facing request helpers."""

from datetime import timedelta
from functools import wraps

from flask import current_app, g, jsonify, redirect, render_template, request, session, url_for


ADMIN_ENDPOINTS = {
    "admin_home",
    "dashboard",
    "api_stats",
    "alerts",
    "export_alerts",
    "logs",
    "rules",
    "config",
    "blacklist",
    "admin_login",
    "admin_logout",
}


def is_trusted_proxy(remote_addr):
    trusted = current_app.config.get("TRUSTED_PROXY_IPS", [])
    return bool(remote_addr) and remote_addr in trusted


def resolve_source_ip(req):
    """Resolve the client IP, only trusting proxy headers from allowed proxies."""
    remote_addr = req.remote_addr or "0.0.0.0"
    if not current_app.config.get("TRUST_PROXY"):
        return remote_addr
    if not is_trusted_proxy(remote_addr):
        return remote_addr

    forwarded = req.headers.get("X-Forwarded-For", "")
    if not forwarded.strip():
        return remote_addr
    return forwarded.split(",")[0].strip() or remote_addr


def admin_allowed_for_ip(ip_value):
    allowed_ips = current_app.config.get("ADMIN_ALLOWED_IPS", [])
    return bool(ip_value) and ip_value in allowed_ips


def is_admin_authenticated():
    if not current_app.config.get("ADMIN_AUTH_ENABLED", True):
        return True
    return bool(session.get("admin_authenticated"))


def mark_admin_authenticated():
    session.permanent = True
    session["admin_authenticated"] = True


def clear_admin_auth():
    session.permanent = False
    session.pop("admin_authenticated", None)


def apply_session_defaults(app):
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(hours=8))


def admin_access_granted(ip_value):
    if not admin_allowed_for_ip(ip_value):
        return False
    return is_admin_authenticated()


def admin_forbidden_response():
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify({"ok": False, "message": "需要管理员访问权限。"}), 403
    return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        current_ip = getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")
        if not admin_allowed_for_ip(current_ip):
            return admin_forbidden_response()
        if not is_admin_authenticated() and request.endpoint != "admin_login":
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def labs_publicly_exposed():
    return bool(current_app.config.get("EXPOSE_LABS", False))


def labs_access_allowed():
    if labs_publicly_exposed():
        return True
    current_ip = getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")
    return admin_access_granted(current_ip)
