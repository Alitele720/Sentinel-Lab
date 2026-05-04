"""Admin and configuration routes for the honeypot."""

import csv
import sqlite3
from datetime import timedelta
from io import StringIO

from flask import Response, flash, g, jsonify, redirect, render_template, request, session, url_for

from .lab import (
    build_bruteforce_payload,
    build_lab_feedback,
    build_login_attempt_records,
    build_sql_payload,
    build_xss_payload,
    get_bruteforce_state,
    push_records_to_pipeline,
    reset_bruteforce_experiment,
    resolve_bruteforce_action,
    resolve_demo_ip,
    wants_json_response,
)
from .runtime import runtime
from .security import admin_required, clear_admin_auth, labs_access_allowed, mark_admin_authenticated
from .storage import (
    attack_type_label,
    block_ip,
    block_port_for_ip,
    cleanup_security_entries,
    format_display_time,
    get_china_day_start_utc,
    get_config_map,
    get_db,
    get_enforcement_state,
    get_int_config,
    is_ip_whitelisted,
    is_valid_ip,
    is_valid_port,
    parse_iso,
    severity_badge,
    to_china_time,
    to_iso,
    unblock_ip,
    unblock_port_for_ip,
    utc_now,
    validate_config_form,
    validate_rule_form,
)


def register_admin_routes(app):
    app.jinja_env.globals["attack_type_label"] = attack_type_label
    app.jinja_env.globals["severity_badge"] = severity_badge
    app.jinja_env.globals["format_display_time"] = format_display_time

    def build_dashboard_context():
        db = get_db()
        cleanup_security_entries(db)
        today_start = to_iso(get_china_day_start_utc())
        stats = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM request_logs WHERE timestamp >= ?) AS today_requests,
                (SELECT COUNT(*) FROM attack_events WHERE created_at >= ?) AS today_alerts,
                (SELECT COUNT(*) FROM blacklist WHERE active = 1) AS active_blacklist,
                (SELECT COUNT(*) FROM attack_events WHERE severity = 'high' AND created_at >= ?) AS high_alerts
            """,
            (today_start, today_start, today_start),
        ).fetchone()
        recent_alerts = db.execute("SELECT * FROM attack_events ORDER BY created_at DESC LIMIT 10").fetchall()
        return {
            "stats": stats,
            "recent_alerts": recent_alerts,
            "current_ip": getattr(g, "effective_ip", request.remote_addr or "0.0.0.0"),
        }

    def render_admin_index(**context):
        db = get_db()
        cleanup_security_entries(db)
        config_map = get_config_map(db)
        summary = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM request_logs) AS request_total,
                (SELECT COUNT(*) FROM attack_events) AS alert_total,
                (SELECT COUNT(*) FROM blacklist WHERE active = 1) AS blacklist_total
            """
        ).fetchone()
        focus_ip = context.pop("focus_ip", None)
        if not focus_ip:
            focus_ip = request.args.get("focus_ip", "").strip()
        if not focus_ip:
            focus_ip = getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")
        selected_demo_ip = resolve_demo_ip(db, focus_ip)
        bruteforce_feedback = context.pop("bruteforce_feedback", None)
        if bruteforce_feedback is None:
            bruteforce_feedback = session.pop("bruteforce_feedback", None)
        return render_template(
            "index.html",
            summary=summary,
            current_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0"),
            selected_demo_ip=selected_demo_ip,
            bruteforce_state=get_bruteforce_state(db, selected_demo_ip),
            bruteforce_feedback=bruteforce_feedback,
            scan_demo_urls=[
                {"label": "/admin", "url": url_for("admin_probe", demo_ip=selected_demo_ip)},
                {"label": "/phpmyadmin", "url": url_for("phpmyadmin_probe", demo_ip=selected_demo_ip)},
                {"label": "/.env", "url": url_for("env_probe", demo_ip=selected_demo_ip)},
            ],
            **context,
        )

    def json_or_redirect(payload, *, status_code=200, fallback_endpoint="admin_home", **fallback_kwargs):
        if wants_json_response():
            return jsonify(payload), status_code
        message = payload.get("message", "")
        if message:
            category = "success" if payload.get("ok") else "warning"
            session["bruteforce_feedback"] = {
                "title": payload.get("title") or "实验结果",
                "message": message,
                "tone": category,
            }
            flash(message, category)
        return redirect(url_for(fallback_endpoint, **fallback_kwargs))

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        current_ip = getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")
        if request.method == "POST":
            if current_ip not in app.config.get("ADMIN_ALLOWED_IPS", []):
                return render_template("admin_login.html", error="当前 IP 不在管理员访问白名单中。"), 403
            if not app.config.get("ADMIN_AUTH_ENABLED", True):
                mark_admin_authenticated()
                return redirect(url_for("admin_home"))
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == app.config.get("ADMIN_USERNAME") and password == app.config.get("ADMIN_PASSWORD"):
                mark_admin_authenticated()
                return redirect(url_for(request.args.get("next") or "admin_home"))
            return render_template("admin_login.html", error="管理员账号或密码错误。"), 403
        return render_template("admin_login.html", error="")

    @app.route("/admin/logout")
    def admin_logout():
        clear_admin_auth()
        return redirect(url_for("admin_login"))

    @app.route("/ops")
    @admin_required
    def admin_home():
        return render_template("dashboard.html", **build_dashboard_context())

    @app.route("/lab/sql", methods=["GET", "POST"])
    def lab_sql():
        if not labs_access_allowed():
            return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403
        query = ""
        results = []
        focus_ip = g.effective_ip
        if request.method == "POST":
            focus_ip = request.form.get("demo_ip", "").strip()
            query = request.form.get("q", "")
            if not is_valid_ip(focus_ip):
                g.skip_request_logging = True
                payload = build_sql_payload(focus_ip, query, [], ok=False, message="demo_ip 无效。", title="SQL 测试失败")
                if wants_json_response():
                    return jsonify(payload), 400
                return (render_admin_index(focus_ip=focus_ip, sql_query=query, sql_feedback=build_lab_feedback(payload["title"], payload["message"], "warning")), 400)
            if not query.strip():
                g.skip_request_logging = True
                payload = build_sql_payload(focus_ip, query, [], ok=False, message="请输入 SQL 测试载荷。", title="SQL 测试失败")
                if wants_json_response():
                    return jsonify(payload), 400
                return (render_admin_index(focus_ip=focus_ip, sql_query=query, sql_feedback=build_lab_feedback(payload["title"], payload["message"], "warning")), 400)
            sample_data = ["alice", "bob", "charlie", "david"]
            results = [item for item in sample_data if query.lower() in item.lower()] or ["没有匹配到示例数据。"]
            payload = build_sql_payload(focus_ip, query, results, ok=True, message="SQL 测试已提交。", title="SQL 测试已提交")
            if wants_json_response():
                return jsonify(payload)
            return render_admin_index(focus_ip=focus_ip, sql_query=query, sql_results=results, sql_feedback=build_lab_feedback(payload["title"], payload["message"], "success"))
        return render_admin_index(focus_ip=focus_ip, sql_query=query, sql_results=results)

    @app.route("/lab/xss", methods=["GET", "POST"])
    def lab_xss():
        if not labs_access_allowed():
            return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403
        message_text = ""
        focus_ip = g.effective_ip
        if request.method == "POST":
            focus_ip = request.form.get("demo_ip", "").strip()
            message_text = request.form.get("message", "")
            if not is_valid_ip(focus_ip):
                g.skip_request_logging = True
                payload = build_xss_payload(focus_ip, message_text, ok=False, message="demo_ip 无效。", title="XSS 测试失败")
                if wants_json_response():
                    return jsonify(payload), 400
                return (render_admin_index(focus_ip=focus_ip, xss_message=message_text, xss_feedback=build_lab_feedback(payload["title"], payload["message"], "warning")), 400)
            if not message_text.strip():
                g.skip_request_logging = True
                payload = build_xss_payload(focus_ip, message_text, ok=False, message="请输入 XSS 测试载荷。", title="XSS 测试失败")
                if wants_json_response():
                    return jsonify(payload), 400
                return (render_admin_index(focus_ip=focus_ip, xss_message=message_text, xss_feedback=build_lab_feedback(payload["title"], payload["message"], "warning")), 400)
            payload = build_xss_payload(focus_ip, message_text, ok=True, message="XSS 测试已提交。", title="XSS 测试已提交")
            if wants_json_response():
                return jsonify(payload)
            return render_admin_index(focus_ip=focus_ip, xss_message=message_text, xss_feedback=build_lab_feedback(payload["title"], payload["message"], "success"))
        return render_admin_index(focus_ip=focus_ip, xss_message=message_text)

    @app.route("/api/bruteforce-state")
    @admin_required
    def api_bruteforce_state():
        demo_ip = request.args.get("demo_ip", "").strip()
        state = get_bruteforce_state(get_db(), demo_ip)
        ok = bool(demo_ip) and is_valid_ip(demo_ip)
        status_code = 200 if ok else 400
        message = "" if ok else "请输入有效的 demo_ip。"
        return jsonify(build_bruteforce_payload(state, ok=ok, message=message, action="state", title="状态刷新")), status_code

    @app.route("/lab/login", methods=["GET", "POST"])
    def lab_login():
        if not labs_access_allowed():
            return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403
        if request.method == "GET":
            return redirect(url_for("admin_home"))
        g.skip_request_logging = True
        source_ip = request.form.get("demo_ip", "").strip() or g.effective_ip
        username = request.form.get("username", "admin").strip() or "admin"
        password = request.form.get("password", "")
        if not is_valid_ip(source_ip):
            state = get_bruteforce_state(get_db(), source_ip)
            payload = build_bruteforce_payload(state, ok=False, message="demo_ip 无效。", action="manual_login", title="手动登录失败")
            return json_or_redirect(payload, status_code=400)
        login_result = "success" if username == "admin" and password == "password123" else "failure"
        push_records_to_pipeline(build_login_attempt_records(source_ip, 1, login_result, username=username))
        state = get_bruteforce_state(get_db(), source_ip)
        message = "已记录 1 次成功登录。" if login_result == "success" else f"已记录 1 次失败登录，当前窗口失败次数：{state['failure_count']}。"
        payload = build_bruteforce_payload(state, ok=True, message=message, action="manual_login", title="手动登录完成")
        return json_or_redirect(payload, focus_ip=source_ip)

    @app.route("/lab/bruteforce", methods=["POST"])
    def lab_bruteforce():
        if not labs_access_allowed():
            return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403
        g.skip_request_logging = True
        source_ip = request.form.get("demo_ip", "").strip()
        if not is_valid_ip(source_ip):
            state = get_bruteforce_state(get_db(), source_ip)
            payload = build_bruteforce_payload(state, ok=False, message="demo_ip 无效。", action="batch", title="批量模拟失败")
            return json_or_redirect(payload, status_code=400)
        action, attempts, login_result, base_message, error_message = resolve_bruteforce_action(request.form)
        if error_message:
            state = get_bruteforce_state(get_db(), source_ip)
            payload = build_bruteforce_payload(state, ok=False, message=error_message, action=action or "batch", title="批量模拟失败")
            return json_or_redirect(payload, status_code=400, focus_ip=source_ip)
        push_records_to_pipeline(build_login_attempt_records(source_ip, attempts, login_result))
        state = get_bruteforce_state(get_db(), source_ip)
        payload = build_bruteforce_payload(state, ok=True, message=base_message, action=action, title="暴力破解实验已提交")
        return json_or_redirect(payload, focus_ip=source_ip)

    @app.route("/lab/bruteforce/reset", methods=["POST"])
    def reset_bruteforce():
        if not labs_access_allowed():
            return render_template("blocked.html", source_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0")), 403
        g.skip_request_logging = True
        source_ip = request.form.get("target_ip", "").strip()
        if not is_valid_ip(source_ip):
            state = get_bruteforce_state(get_db(), source_ip)
            payload = build_bruteforce_payload(state, ok=False, message="目标 IP 无效。", action="reset", title="重置失败")
            return json_or_redirect(payload, status_code=400)
        reset_bruteforce_experiment(get_db(), source_ip)
        state = get_bruteforce_state(get_db(), source_ip)
        payload = build_bruteforce_payload(state, ok=True, message=f"{source_ip} 已重置完成。", action="reset", title="实验重置完成")
        return json_or_redirect(payload, focus_ip=source_ip)

    @app.route("/dashboard")
    @admin_required
    def dashboard():
        return render_template("dashboard.html", **build_dashboard_context())

    @app.route("/api/stats")
    @admin_required
    def api_stats():
        db = get_db()
        def bucket_time(value, *, minute=0, second=0, microsecond=0):
            return to_china_time(value).replace(minute=minute, second=second, microsecond=microsecond)
        def severity_rank(value):
            return {"low": 1, "medium": 2, "high": 3}.get(value, 0)
        now_utc = utc_now()
        since = to_iso(now_utc - timedelta(hours=24))
        request_rows = db.execute("SELECT timestamp FROM request_logs WHERE timestamp >= ? ORDER BY timestamp", (since,)).fetchall()
        connection_rows = db.execute("SELECT timestamp FROM connection_events WHERE timestamp >= ? ORDER BY timestamp", (since,)).fetchall()
        attack_rows = db.execute("SELECT attack_type, COUNT(*) AS total FROM attack_events GROUP BY attack_type ORDER BY total DESC").fetchall()
        ip_rows = db.execute("SELECT source_ip, COUNT(*) AS total FROM attack_events GROUP BY source_ip ORDER BY total DESC LIMIT 10").fetchall()
        local_now = bucket_time(now_utc, minute=0, second=0, microsecond=0)
        hour_buckets = [local_now - timedelta(hours=offset) for offset in range(23, -1, -1)]
        request_counts = {bucket: 0 for bucket in hour_buckets}
        connection_counts = {bucket: 0 for bucket in hour_buckets}
        for row in request_rows:
            try:
                bucket = bucket_time(parse_iso(row["timestamp"]), minute=0, second=0, microsecond=0)
            except (TypeError, ValueError):
                continue
            if bucket in request_counts:
                request_counts[bucket] += 1
        for row in connection_rows:
            try:
                bucket = bucket_time(parse_iso(row["timestamp"]), minute=0, second=0, microsecond=0)
            except (TypeError, ValueError):
                continue
            if bucket in connection_counts:
                connection_counts[bucket] += 1
        local_realtime_now = to_china_time(now_utc)
        local_realtime_now = local_realtime_now - timedelta(seconds=local_realtime_now.second % 5, microseconds=local_realtime_now.microsecond)
        realtime_buckets = [local_realtime_now - timedelta(seconds=offset * 5) for offset in range(59, -1, -1)]
        realtime_request_counts = {bucket: 0 for bucket in realtime_buckets}
        realtime_connection_counts = {bucket: 0 for bucket in realtime_buckets}
        realtime_cutoff = realtime_buckets[0]
        realtime_cutoff_iso = to_iso(realtime_cutoff)
        for row in request_rows:
            try:
                event_time = to_china_time(parse_iso(row["timestamp"]))
            except (TypeError, ValueError):
                continue
            if event_time < realtime_cutoff:
                continue
            bucket = event_time - timedelta(seconds=event_time.second % 5, microseconds=event_time.microsecond)
            if bucket in realtime_request_counts:
                realtime_request_counts[bucket] += 1
        for row in connection_rows:
            try:
                event_time = to_china_time(parse_iso(row["timestamp"]))
            except (TypeError, ValueError):
                continue
            if event_time < realtime_cutoff:
                continue
            bucket = event_time - timedelta(seconds=event_time.second % 5, microseconds=event_time.microsecond)
            if bucket in realtime_connection_counts:
                realtime_connection_counts[bucket] += 1
        recent_connection_summary = db.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(DISTINCT source_ip) AS unique_sources,
                COUNT(DISTINCT target_port) AS unique_target_ports
            FROM connection_events
            WHERE timestamp >= ?
            """,
            (realtime_cutoff_iso,),
        ).fetchone()
        top_connection_sources = db.execute(
            """
            SELECT source_ip, COUNT(*) AS total
            FROM connection_events
            WHERE timestamp >= ?
            GROUP BY source_ip
            ORDER BY total DESC, source_ip ASC
            LIMIT 5
            """,
            (realtime_cutoff_iso,),
        ).fetchall()
        top_target_ports = db.execute(
            """
            SELECT target_port, COUNT(*) AS total
            FROM connection_events
            WHERE timestamp >= ?
            GROUP BY target_port
            ORDER BY total DESC, target_port ASC
            LIMIT 5
            """,
            (realtime_cutoff_iso,),
        ).fetchall()
        recent_port_scan_rows = db.execute(
            """
            SELECT severity
            FROM attack_events
            WHERE attack_type = 'port_scan'
              AND created_at >= ?
            """,
            (realtime_cutoff_iso,),
        ).fetchall()
        highest_severity = None
        if recent_port_scan_rows:
            highest_severity = max((row["severity"] for row in recent_port_scan_rows), key=severity_rank)
        capture_thread = runtime.portscan_capture_thread
        capture_enabled = bool(app.config.get("PORTSCAN_CAPTURE_ENABLED", False))
        capture_running = bool(capture_thread and capture_thread.is_alive())
        if capture_enabled and capture_running:
            capture_state = "running"
            capture_label = "开启"
        elif capture_enabled:
            capture_state = "stopped"
            capture_label = "异常未知"
        else:
            capture_state = "disabled"
            capture_label = "关闭"
        return jsonify({
            "captureStatus": {
                "enabled": capture_enabled,
                "running": capture_running,
                "state": capture_state,
                "label": capture_label,
                "interface": app.config.get("PORTSCAN_CAPTURE_INTERFACE", "") or "默认网卡",
                "filter": app.config.get("PORTSCAN_CAPTURE_FILTER", "tcp"),
            },
            "requestsByHour": [{"hour": bucket.strftime("%H:00"), "total": request_counts[bucket]} for bucket in hour_buckets],
            "trafficByHour": [{"hour": bucket.strftime("%H:00"), "request_total": request_counts[bucket], "connection_total": connection_counts[bucket]} for bucket in hour_buckets],
            "trafficRealtime": [{"time": bucket.strftime("%H:%M:%S"), "request_total": realtime_request_counts[bucket], "connection_total": realtime_connection_counts[bucket]} for bucket in realtime_buckets],
            "recentConnectionSummary": {
                "total": recent_connection_summary["total"] or 0,
                "unique_sources": recent_connection_summary["unique_sources"] or 0,
                "unique_target_ports": recent_connection_summary["unique_target_ports"] or 0,
            },
            "topConnectionSources": [{"ip": row["source_ip"], "total": row["total"]} for row in top_connection_sources],
            "topTargetPorts": [{"port": row["target_port"], "total": row["total"]} for row in top_target_ports],
            "recentPortScanAlerts": {
                "total": len(recent_port_scan_rows),
                "highest_severity": highest_severity,
            },
            "attacksByType": [{"type": attack_type_label(row["attack_type"]), "total": row["total"]} for row in attack_rows],
            "topAttackIps": [{"ip": row["source_ip"], "total": row["total"]} for row in ip_rows],
        })

    @app.route("/alerts")
    @admin_required
    def alerts():
        rows = get_db().execute("SELECT * FROM attack_events ORDER BY created_at DESC LIMIT 200").fetchall()
        return render_template("alerts.html", rows=rows)

    @app.route("/export/alerts.csv")
    @admin_required
    def export_alerts():
        rows = get_db().execute("SELECT created_at, source_ip, attack_type, severity, score, threshold_value, request_path, summary FROM attack_events ORDER BY created_at DESC").fetchall()
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["created_at", "source_ip", "attack_type", "severity", "score", "threshold", "request_path", "summary"])
        for row in rows:
            writer.writerow([format_display_time(row["created_at"]), row["source_ip"], attack_type_label(row["attack_type"]), row["severity"], row["score"], row["threshold_value"], row["request_path"], row["summary"]])
        return Response(buffer.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})

    @app.route("/rules", methods=["GET", "POST"])
    @admin_required
    def rules():
        db = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "toggle":
                db.execute("UPDATE rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (request.form.get("rule_id"),))
                db.commit()
                flash("规则状态已更新。", "success")
            elif action == "delete":
                db.execute("DELETE FROM rules WHERE id = ?", (request.form.get("rule_id"),))
                db.commit()
                flash("规则已删除。", "success")
            elif action in {"add", "update"}:
                payload, errors = validate_rule_form(request.form)
                if errors:
                    for error in errors:
                        flash(error, "warning")
                else:
                    try:
                        if action == "add":
                            db.execute("INSERT INTO rules(name, attack_type, match_type, pattern, score, enabled, description) VALUES (?, ?, ?, ?, ?, 1, ?)", (payload["name"], payload["attack_type"], payload["match_type"], payload["pattern"], payload["score"], payload["description"]))
                            flash("规则已新增。", "success")
                        else:
                            db.execute("UPDATE rules SET name = ?, attack_type = ?, match_type = ?, pattern = ?, score = ?, description = ? WHERE id = ?", (payload["name"], payload["attack_type"], payload["match_type"], payload["pattern"], payload["score"], payload["description"], request.form.get("rule_id")))
                            flash("规则已更新。", "success")
                        db.commit()
                    except sqlite3.IntegrityError:
                        db.rollback()
                        flash("规则名称已存在。", "warning")
            return redirect(url_for("rules"))
        rows = db.execute("SELECT * FROM rules ORDER BY attack_type, id").fetchall()
        return render_template("rules.html", rows=rows)

    @app.route("/config", methods=["GET", "POST"])
    @admin_required
    def config():
        db = get_db()
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "clear_records":
                from .lab import clear_experiment_records
                g.skip_request_logging = True
                clear_experiment_records(db)
                session.pop("bruteforce_feedback", None)
                session["skip_request_logging_once"] = True
                flash("实验记录已清空。", "success")
                redirect_to = request.form.get("redirect_to", "").strip()
                return redirect(url_for("dashboard" if redirect_to == "dashboard" else "config"))
            updates, errors = validate_config_form(request.form)
            if errors:
                for error in errors:
                    flash(error, "warning")
            else:
                for key, value in updates.items():
                    db.execute("UPDATE system_config SET value = ? WHERE key = ?", (value, key))
                db.commit()
                flash("系统配置已更新。", "success")
            return redirect(url_for("config"))
        rows = db.execute("SELECT * FROM system_config ORDER BY key").fetchall()
        return render_template("config.html", rows=rows)

    @app.route("/blacklist", methods=["GET", "POST"])
    @admin_required
    def blacklist():
        db = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            config_map = get_config_map(db)
            if action == "add":
                ip_value = request.form.get("source_ip", "").strip()
                reason = request.form.get("reason", "").strip() or "管理员手动封禁"
                if not is_valid_ip(ip_value):
                    flash("请输入有效的 IP 地址。", "danger")
                elif is_ip_whitelisted(db, ip_value, config_map=config_map):
                    flash("白名单 IP 不能被封禁。", "warning")
                else:
                    block_ip(db, ip_value, reason, created_by="admin", config_map=config_map)
                    flash("IP 已加入黑名单。", "success")
            elif action == "add_port_block":
                ip_value = request.form.get("source_ip", "").strip()
                raw_port = request.form.get("port", "").strip()
                reason = request.form.get("reason", "").strip() or "管理员手动端口阻断"
                if not is_valid_ip(ip_value):
                    flash("请输入有效的 IP 地址。", "danger")
                elif not is_valid_port(raw_port):
                    flash("请输入有效的 TCP 端口。", "danger")
                elif is_ip_whitelisted(db, ip_value, config_map=config_map):
                    flash("白名单 IP 不能被加入端口阻断。", "warning")
                else:
                    block_port_for_ip(db, ip_value, int(raw_port), reason, created_by="admin", config_map=config_map)
                    flash(f"已为 {ip_value} 阻断端口 {raw_port}。", "success")
            elif action == "unblock":
                unblock_ip(db, request.form.get("source_ip", "").strip())
                flash("IP 已解除封禁。", "success")
            elif action == "unblock_port":
                ip_value = request.form.get("source_ip", "").strip()
                raw_port = request.form.get("port", "").strip()
                if is_valid_port(raw_port):
                    unblock_port_for_ip(db, ip_value, int(raw_port))
                    flash(f"已为 {ip_value} 解除端口 {raw_port} 阻断。", "success")
                else:
                    flash("端口号无效。", "danger")
            return redirect(url_for("blacklist"))
        cleanup_security_entries(db)
        ip_rows = db.execute("SELECT * FROM blacklist ORDER BY active DESC, created_at DESC").fetchall()
        port_rows = db.execute("SELECT * FROM port_blocks ORDER BY active DESC, created_at DESC").fetchall()
        return render_template("blacklist.html", ip_rows=ip_rows, port_rows=port_rows, target_port=get_int_config(db, "port_block_target_port"))
