"""Flask application factory for the LAN-accessible honeypot IDS."""

from flask import Flask, g, jsonify, render_template, request, session

from .deploy import load_deploy_config
from .detection import consume_pending_logs, start_watcher_once, write_access_log
from .lab import build_request_record, get_request_port
from .routes_admin import register_admin_routes
from .routes_public import register_public_routes
from .runtime import runtime
from .security import ADMIN_ENDPOINTS, admin_allowed_for_ip, apply_session_defaults, is_admin_authenticated, resolve_source_ip
from .storage import (
    attack_type_label,
    close_db,
    connect_db,
    ensure_data_dir,
    format_display_time,
    get_config_map,
    get_db,
    get_enforcement_state,
    init_db,
    repair_legacy_text_encoding,
    seed_defaults,
    severity_badge,
)


def create_app(config_overrides=None, *, runtime_overrides=None):
    """Create the honeypot IDS Flask application."""
    if runtime_overrides:
        runtime.configure(**runtime_overrides)

    ensure_data_dir()
    init_db()
    seed_defaults()
    repair_db = connect_db()
    try:
        repair_legacy_text_encoding(repair_db)
        repair_db.commit()
    finally:
        repair_db.close()

    app = Flask(
        __name__,
        template_folder=str(runtime.base_dir / "templates"),
        static_folder=str(runtime.base_dir / "static"),
    )
    app.config.update(load_deploy_config())
    if config_overrides:
        app.config.update(config_overrides)
    apply_session_defaults(app)

    app.teardown_appcontext(close_db)
    app.jinja_env.globals["attack_type_label"] = attack_type_label
    app.jinja_env.globals["severity_badge"] = severity_badge
    app.jinja_env.globals["format_display_time"] = format_display_time
    app.jinja_env.globals["is_admin_authenticated"] = is_admin_authenticated
    app.jinja_env.globals["admin_allowed_for_ip"] = admin_allowed_for_ip

    register_public_routes(app)
    register_admin_routes(app)

    if app.config.get("START_WATCHER", True):
        start_watcher_once()

    @app.before_request
    def apply_request_guards():
        db = get_db()
        if session.pop("skip_request_logging_once", False):
            g.skip_request_logging = True

        g.request_port = get_request_port(request)
        g.effective_ip = resolve_source_ip(request)
        config_map = get_config_map(db)

        if request.endpoint in ADMIN_ENDPOINTS:
            return None

        enforcement_state = get_enforcement_state(db, g.effective_ip, g.request_port, config_map=config_map)
        if enforcement_state["whitelisted"]:
            return None

        port_block = enforcement_state["port_block"]
        if port_block:
            g.request_blocked = True
            g.request_port_blocked = True
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"ok": False, "message": f"当前对端口 {g.request_port} 的访问已被阻断。"}), 403
            return (
                render_template(
                    "port_blocked.html",
                    source_ip=g.effective_ip,
                    blocked_port=g.request_port,
                    blocked_until=format_display_time(port_block["expires_at"]),
                    reason=port_block["reason"],
                ),
                403,
            )

        blacklist_entry = enforcement_state["blacklist"]
        if blacklist_entry:
            g.request_blocked = True
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"ok": False, "message": "当前来源地址已被加入黑名单。"}), 403
            return render_template("blocked.html", source_ip=g.effective_ip), 403
        return None

    @app.after_request
    def capture_request(response):
        if request.path.startswith("/static/") or getattr(g, "skip_request_logging", False):
            return response
        write_access_log(build_request_record(response.status_code))
        if app.config.get("SYNC_INGEST_REAL_REQUESTS", True):
            consume_pending_logs()
        return response

    return app
