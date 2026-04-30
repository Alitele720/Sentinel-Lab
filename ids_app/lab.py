"""课程演示、伪造请求和实验状态展示相关辅助逻辑。"""

import uuid
from datetime import timedelta

from flask import g, request

from .constants import DEFAULT_DEMO_IP
from .detection import consume_pending_logs, ingest_connection_event, write_access_log
from .runtime import runtime
from .storage import (
    connect_db,
    format_display_time,
    get_config_map,
    get_enforcement_state,
    get_int_config,
    is_ip_whitelisted,
    is_valid_ip,
    is_valid_port,
    to_iso,
    utc_now,
)


def get_effective_ip(req):
    """优先选择 demo_ip，同时保留回退到真实客户端 IP 的能力。"""
    candidates = [
        req.headers.get("X-Demo-IP"),
        req.args.get("demo_ip"),
        req.form.get("demo_ip"),
    ]
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        candidates.append(forwarded.split(",")[0].strip())
    candidates.append(req.remote_addr or "0.0.0.0")

    for item in candidates:
        if item and is_valid_ip(item.strip()):
            return item.strip()
    return "0.0.0.0"


def get_request_port(req):
    """统一推断当前请求目标端口，供端口阻断判断使用。"""
    server_port = req.environ.get("SERVER_PORT")
    if server_port and str(server_port).isdigit():
        return int(server_port)

    host = req.host or ""
    if host.startswith("["):
        closing = host.rfind("]")
        if closing != -1 and closing + 2 <= len(host) and host[closing + 1] == ":":
            candidate = host[closing + 2 :]
            if candidate.isdigit():
                return int(candidate)
    elif ":" in host:
        candidate = host.rsplit(":", 1)[1]
        if candidate.isdigit():
            return int(candidate)

    if req.scheme == "https":
        return 443
    if req.scheme == "http":
        return 80
    return 5000


def resolve_protected_target_ip(req, fallback_ip="127.0.0.1"):
    """推断当前受保护主机的 IP，失败时回退到可控兜底值。"""
    candidates = []
    server_name = req.environ.get("SERVER_NAME")
    if server_name:
        candidates.append(server_name.strip())

    host = (req.host or "").strip()
    if host.startswith("["):
        closing = host.find("]")
        if closing != -1:
            candidates.append(host[1:closing])
    elif ":" in host:
        candidates.append(host.rsplit(":", 1)[0].strip())
    elif host:
        candidates.append(host)

    for candidate in candidates:
        if candidate == "localhost":
            return "127.0.0.1"
        if is_valid_ip(candidate):
            return candidate
    return fallback_ip


def build_request_record(response_status):
    """把当前 Flask 请求序列化成统一的结构化日志格式。"""
    json_data = request.get_json(silent=True)
    if not isinstance(json_data, dict):
        json_data = {}

    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": to_iso(utc_now()),
        "source_ip": getattr(g, "effective_ip", get_effective_ip(request)),
        "remote_addr": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "full_path": request.full_path if request.query_string else request.path,
        "status_code": response_status,
        "query_params": request.args.to_dict(flat=False),
        "form_data": request.form.to_dict(flat=False),
        "json_data": json_data,
        "user_agent": request.headers.get("User-Agent"),
        "referer": request.headers.get("Referer"),
        "login_result": getattr(g, "login_result", None),
        "blocked": bool(getattr(g, "request_blocked", False)),
    }


def build_lab_record(
    source_ip,
    path,
    *,
    method="POST",
    query_params=None,
    form_data=None,
    json_data=None,
    status_code=200,
    login_result=None,
    blocked=False,
):
    """为实验场景构造伪造日志，绕开真实请求链路也能复用检测流程。"""
    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": to_iso(utc_now()),
        "source_ip": source_ip,
        "remote_addr": source_ip,
        "method": method,
        "path": path,
        "full_path": path,
        "status_code": status_code,
        "query_params": query_params or {},
        "form_data": form_data or {},
        "json_data": json_data or {},
        "user_agent": "IDS-Lab-Simulator/1.0",
        "referer": "/",
        "login_result": login_result,
        "blocked": blocked,
    }


def process_logs_now():
    consume_pending_logs()


def push_records_to_pipeline(records):
    """让实验生成的伪造记录走和真实流量完全相同的检测通道。"""
    for record in records:
        write_access_log(record)
    process_logs_now()


def build_connection_event(source_ip, target_ip, target_port, *, protocol="tcp", result="attempted", source_kind="lab_portscan"):
    """为端口扫描实验构造结构化连接事件。"""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": to_iso(utc_now()),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_port": int(target_port),
        "protocol": protocol,
        "result": result,
        "source_kind": source_kind,
    }


def push_connection_events_to_pipeline(records):
    """直接写入连接事件表，并触发端口扫描检测。"""
    conn = connect_db()
    try:
        for record in records:
            ingest_connection_event(conn, record)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def build_login_attempt_records(source_ip, attempts, login_result, username="admin"):
    """为暴力破解演示批量生成登录尝试记录。"""
    records = []
    for index in range(attempts):
        password = "password123" if login_result == "success" else f"wrong-{index + 1}"
        records.append(
            build_lab_record(
                source_ip,
                "/lab/login",
                form_data={
                    "demo_ip": [source_ip],
                    "username": [username],
                    "password": [password],
                },
                login_result=login_result,
            )
        )
    return records


def build_bruteforce_payload(state, *, ok=True, message="", action="", title="", errors=None):
    payload = {
        "ok": ok,
        "message": message,
        "action": action,
        "title": title,
        "state": state,
    }
    if errors:
        payload["errors"] = errors
    return payload


def wants_json_response():
    """同时兼容前端 fetch 调用和普通表单提交。"""
    accept = request.headers.get("Accept", "")
    requested_with = request.headers.get("X-Requested-With", "")
    return "application/json" in accept or requested_with == "XMLHttpRequest"


def get_bruteforce_state(db, source_ip):
    """组装适合前端展示的暴力破解实验状态摘要。"""
    config_map = get_config_map(db)
    window_minutes = get_int_config(db, "bruteforce_window_minutes", config_map=config_map)
    low = get_int_config(db, "bruteforce_low_threshold", config_map=config_map)
    high = get_int_config(db, "bruteforce_high_threshold", config_map=config_map)
    block_threshold = get_int_config(db, "bruteforce_block_threshold", config_map=config_map)

    state = {
        "source_ip": source_ip,
        "window_minutes": window_minutes,
        "failure_count": 0,
        "low_threshold": low,
        "high_threshold": high,
        "block_threshold": block_threshold,
        "stage_key": "idle",
        "stage_label": "未触发",
        "stage_hint": "当前还未触发告警。",
        "next_hint": f"再失败 {low} 次触发低危告警。",
        "blocked": False,
        "blocked_until": "",
        "blocked_until_display": "",
        "latest_summary": "",
        "latest_severity": "",
        "latest_created_at": "",
        "latest_created_at_display": "",
        "whitelisted": False,
    }

    if not source_ip or not is_valid_ip(source_ip):
        state["stage_label"] = "无效 IP"
        state["stage_hint"] = "请填写合法的 demo_ip。"
        state["next_hint"] = "例如 10.10.10.88。"
        return state

    state["whitelisted"] = is_ip_whitelisted(db, source_ip, config_map=config_map)
    if state["whitelisted"]:
        state["stage_key"] = "whitelist"
        state["stage_label"] = "白名单 IP"
        state["stage_hint"] = "当前 IP 在白名单中，不参与实验。"
        state["next_hint"] = "请改用其他 demo_ip，例如 10.10.10.88。"
        return state

    since = to_iso(utc_now() - timedelta(minutes=window_minutes))
    state["failure_count"] = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE source_ip = ?
          AND success = 0
          AND created_at >= ?
        """,
        (source_ip, since),
    ).fetchone()["total"]

    # 复用请求拦截时使用的同一套状态来源，避免页面和真实行为不一致。
    security_state = get_enforcement_state(
        db,
        source_ip,
        get_int_config(db, "port_block_target_port", config_map=config_map),
        config_map=config_map,
    )
    blacklist_entry = security_state["blacklist"]

    latest_event = db.execute(
        """
        SELECT *
        FROM attack_events
        WHERE source_ip = ?
          AND attack_type = 'bruteforce'
        ORDER BY id DESC
        LIMIT 1
        """,
        (source_ip,),
    ).fetchone()
    if latest_event:
        state["latest_summary"] = latest_event["summary"]
        state["latest_severity"] = latest_event["severity"]
        state["latest_created_at"] = latest_event["created_at"]
        state["latest_created_at_display"] = format_display_time(latest_event["created_at"])

    if blacklist_entry:
        state["blocked"] = True
        state["blocked_until"] = blacklist_entry["expires_at"] or ""
        state["blocked_until_display"] = format_display_time(blacklist_entry["expires_at"])
        state["stage_key"] = "blocked"
        state["stage_label"] = "已封禁"
        state["stage_hint"] = "该 IP 已进入黑名单。"
        state["next_hint"] = "可到黑名单页面解除，或重置当前实验。"
        return state

    failures = state["failure_count"]
    if failures >= high:
        state["stage_key"] = "high"
        state["stage_label"] = "高危"
        state["stage_hint"] = "已触发高危告警。"
        remaining = max(block_threshold - failures, 0)
        state["next_hint"] = (
            "已达到自动封禁阈值。"
            if remaining == 0
            else f"再失败 {remaining} 次将自动封禁。"
        )
    elif failures >= low:
        state["stage_key"] = "low"
        state["stage_label"] = "低危"
        state["stage_hint"] = "已触发低危告警。"
        remaining = max(high - failures, 0)
        state["next_hint"] = (
            "已达到高危阈值。"
            if remaining == 0
            else f"再失败 {remaining} 次将升级为高危告警。"
        )
    elif failures > 0:
        state["stage_key"] = "warming"
        state["stage_label"] = "计数中"
        state["stage_hint"] = "系统正在累计失败次数。"
        state["next_hint"] = f"再失败 {max(low - failures, 0)} 次触发低危告警。"

    return state


def reset_bruteforce_experiment(db, source_ip):
    """清理某个 demo IP 的暴力破解计数和联动封禁状态。"""
    db.execute("DELETE FROM login_attempts WHERE source_ip = ?", (source_ip,))
    db.execute(
        """
        DELETE FROM attack_events
        WHERE source_ip = ?
          AND attack_type = 'bruteforce'
        """,
        (source_ip,),
    )
    db.execute("UPDATE blacklist SET active = 0 WHERE source_ip = ?", (source_ip,))
    db.execute(
        """
        UPDATE port_blocks
        SET active = 0
        WHERE source_ip = ?
          AND trigger_attack_type = 'bruteforce'
        """,
        (source_ip,),
    )
    db.commit()


def clear_experiment_records(db):
    """清空实验产生的数据，但保留规则和系统配置。"""
    db.execute("DELETE FROM attack_events")
    db.execute("DELETE FROM login_attempts")
    db.execute("DELETE FROM connection_events")
    db.execute("DELETE FROM blacklist")
    db.execute("DELETE FROM port_blocks")
    db.execute("DELETE FROM request_logs")
    db.commit()

    with runtime.log_ingest_lock:
        runtime.log_file.write_text("", encoding="utf-8")
        runtime.bad_log_file.write_text("", encoding="utf-8")
        runtime.reset_ingest_state()


def resolve_bruteforce_action(form):
    """把前端点击的批量动作翻译成检测链路可消费的输入。"""
    action = form.get("action", "").strip()
    if action == "fail_once":
        return action, 1, "failure", "已模拟失败 1 次。", None
    if action == "fail_5":
        return action, 5, "failure", "已模拟失败 5 次。", None
    if action == "fail_10":
        return action, 10, "failure", "已模拟失败 10 次。", None
    if action == "success_once":
        return action, 1, "success", "已模拟成功登录 1 次。", None
    if action == "custom_count":
        raw_count = form.get("count", "").strip()
        try:
            count = int(raw_count)
        except ValueError:
            return action, None, None, "", "自定义次数必须是数字。"
        if count < 1 or count > 50:
            return action, None, None, "", "自定义次数必须在 1 到 50 之间。"
        return action, count, "failure", f"已模拟失败 {count} 次。", None
    return action, None, None, "", "未识别的暴力破解实验动作。"


def build_lab_feedback(title="", message="", tone="success"):
    return {
        "title": title or "实验结果",
        "message": message,
        "tone": tone,
    }


def build_sql_payload(source_ip, query, results, *, ok=True, message="", title="SQL 测试结果"):
    return {
        "ok": ok,
        "title": title,
        "message": message,
        "demo_ip": source_ip,
        "query": query,
        "results": results,
    }


def build_xss_payload(source_ip, message_text, *, ok=True, message="", title="XSS 测试结果"):
    return {
        "ok": ok,
        "title": title,
        "message": message,
        "demo_ip": source_ip,
        "message_text": message_text,
        "safe_echo": message_text,
        "dangerous_preview_html": message_text,
    }


def build_portscan_payload(
    source_ip,
    target_ip,
    start_port,
    end_port,
    *,
    protocol="tcp",
    attempted_ports=0,
    unique_ports=0,
    blocked=False,
    blocked_until="",
    summary="",
    ok=True,
    message="",
    title="端口扫描结果",
):
    return {
        "ok": ok,
        "title": title,
        "message": message,
        "demo_ip": source_ip,
        "target_ip": target_ip,
        "protocol": protocol,
        "start_port": start_port,
        "end_port": end_port,
        "attempted_ports": attempted_ports,
        "unique_ports": unique_ports,
        "blocked": blocked,
        "blocked_until": blocked_until,
        "blocked_until_display": format_display_time(blocked_until),
        "summary": summary,
    }


def get_portscan_state(db, source_ip, target_ip):
    """返回首页端口扫描实验需要的状态摘要。"""
    config_map = get_config_map(db)
    state = {
        "source_ip": source_ip,
        "target_ip": target_ip,
        "window_minutes": get_int_config(db, "portscan_window_minutes", config_map=config_map),
        "low_threshold": get_int_config(db, "portscan_low_threshold", config_map=config_map),
        "high_threshold": get_int_config(db, "portscan_high_threshold", config_map=config_map),
        "unique_port_count": 0,
        "blocked": False,
        "blocked_until": "",
        "blocked_until_display": "",
        "latest_summary": "",
        "latest_created_at": "",
        "latest_created_at_display": "",
    }
    if not source_ip or not target_ip or not is_valid_ip(source_ip) or not is_valid_ip(target_ip):
        return state

    since = to_iso(utc_now() - timedelta(minutes=state["window_minutes"]))
    row = db.execute(
        """
        SELECT COUNT(DISTINCT target_port) AS total
        FROM connection_events
        WHERE source_ip = ?
          AND target_ip = ?
          AND protocol = 'tcp'
          AND timestamp >= ?
        """,
        (source_ip, target_ip, since),
    ).fetchone()
    state["unique_port_count"] = row["total"] if row else 0

    security_state = get_enforcement_state(
        db,
        source_ip,
        get_int_config(db, "port_block_target_port", config_map=config_map),
        config_map=config_map,
    )
    blacklist_entry = security_state["blacklist"]
    if blacklist_entry:
        state["blocked"] = True
        state["blocked_until"] = blacklist_entry["expires_at"] or ""
        state["blocked_until_display"] = format_display_time(blacklist_entry["expires_at"])

    latest_event = db.execute(
        """
        SELECT *
        FROM attack_events
        WHERE source_ip = ?
          AND attack_type = 'port_scan'
          AND request_path = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (source_ip, f"tcp://{target_ip}"),
    ).fetchone()
    if latest_event:
        state["latest_summary"] = latest_event["summary"]
        state["latest_created_at"] = latest_event["created_at"]
        state["latest_created_at_display"] = format_display_time(latest_event["created_at"])
    return state


def build_portscan_records(source_ip, target_ip, start_port, end_port, *, protocol="tcp"):
    """按端口范围批量生成连接事件。"""
    return [build_connection_event(source_ip, target_ip, port, protocol=protocol) for port in range(start_port, end_port + 1)]


def validate_portscan_inputs(source_ip, start_port, end_port):
    """校验端口扫描实验输入，并返回规范化后的端口范围。"""
    if not is_valid_ip(source_ip):
        return None, None, "请输入合法的 demo_ip，例如 10.10.10.99。"
    if not is_valid_port(start_port):
        return None, None, "起始端口必须在 1 到 65535 之间。"
    if not is_valid_port(end_port):
        return None, None, "结束端口必须在 1 到 65535 之间。"

    start = int(start_port)
    end = int(end_port)
    if start > end:
        return None, None, "起始端口不能大于结束端口。"
    if end - start > 127:
        return None, None, "一次最多模拟 128 个端口。"
    return start, end, None


def resolve_demo_ip(db, preferred_ip=""):
    """优先返回合法且不在白名单中的 demo IP，否则回退到默认值。"""
    candidate = (preferred_ip or "").strip()
    if candidate and is_valid_ip(candidate) and not is_ip_whitelisted(db, candidate):
        return candidate
    return DEFAULT_DEMO_IP
