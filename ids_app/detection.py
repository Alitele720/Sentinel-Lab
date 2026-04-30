"""日志归一化、入库与攻击检测主链路。"""

import html
import json
import re
import sqlite3
import threading
import time
from datetime import timedelta
from urllib.parse import unquote_plus

from .constants import SENSITIVE_PATH_PATTERNS, STATIC_EXTENSIONS
from .runtime import runtime
from .storage import (
    attack_type_label,
    block_ip,
    block_port_for_ip,
    connect_db,
    get_config_map,
    get_int_config,
    is_ip_whitelisted,
    to_iso,
    parse_iso,
    utc_now,
)


def normalize_payload(record):
    """把请求内容压平成一个归一化字符串，便于轻量匹配。"""
    parts = [
        record.get("path", ""),
        json.dumps(record.get("query_params", {}), ensure_ascii=False),
        json.dumps(record.get("form_data", {}), ensure_ascii=False),
        json.dumps(record.get("json_data", {}), ensure_ascii=False),
    ]
    combined = " ".join(parts)
    # 连续解码两次，兼容实验里常见的双重编码输入。
    for _ in range(2):
        combined = unquote_plus(combined)
        combined = html.unescape(combined)
    combined = combined.lower()
    combined = re.sub(r"\s+", " ", combined).strip()
    return combined


def write_access_log(record):
    """向本地访问日志追加一条结构化请求记录。"""
    with runtime.log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_bad_log_line(raw_line, error_message):
    """把坏日志单独隔离出来，避免它们被静默丢失。"""
    entry = {
        "logged_at": to_iso(utc_now()),
        "error": error_message,
        "raw_line": raw_line,
    }
    with runtime.bad_log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


class LogWatcher(threading.Thread):
    """后台线程，定期消费新追加的日志内容。"""

    def __init__(self):
        super().__init__(daemon=True)

    def run(self):
        while True:
            try:
                consume_pending_logs()
            except Exception as exc:  # pragma: no cover - background safety net
                print(f"[watcher] {exc}")
            time.sleep(1)


def recent_event_exists(db, source_ip, attack_type, *, request_path=None, config_map=None):
    """用冷却时间限制重复告警，避免告警表被刷屏。"""
    config_map = config_map or get_config_map(db)
    since = to_iso(utc_now() - timedelta(seconds=get_int_config(db, "alert_cooldown_seconds", config_map=config_map)))
    params = [source_ip, attack_type, since]
    query = """
        SELECT 1
        FROM attack_events
        WHERE source_ip = ?
          AND attack_type = ?
          AND created_at >= ?
    """
    if request_path is not None:
        query += "\n          AND request_path = ?"
        params.append(request_path)
    query += "\n        LIMIT 1"
    row = db.execute(query, params).fetchone()
    return row is not None


def get_latest_event(db, source_ip, attack_type, *, request_path=None):
    """读取某类攻击的最近一条告警，用于升级判断。"""
    params = [source_ip, attack_type]
    query = """
        SELECT *
        FROM attack_events
        WHERE source_ip = ?
          AND attack_type = ?
    """
    if request_path is not None:
        query += "\n          AND request_path = ?"
        params.append(request_path)
    query += "\n        ORDER BY id DESC\n        LIMIT 1"
    return db.execute(query, params).fetchone()


def build_port_scan_request_path(protocol, target_ip):
    return f"{protocol}://{target_ip}"


def load_enabled_rules(db):
    """按攻击类型组织已启用规则，方便内容检测阶段直接使用。"""
    rows = db.execute(
        """
        SELECT *
        FROM rules
        WHERE enabled = 1
        ORDER BY attack_type, id
        """
    ).fetchall()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["attack_type"], []).append(row)
    return grouped


def match_rule(rule, normalized_payload):
    """防御性执行单条规则；坏正则按未命中处理。"""
    if rule["match_type"] == "keyword":
        return rule["pattern"].lower() in normalized_payload
    if rule["match_type"] == "regex":
        try:
            return re.search(rule["pattern"], normalized_payload, re.IGNORECASE) is not None
        except re.error:
            return False
    return False


def create_event(
    db,
    request_log_id,
    source_ip,
    attack_type,
    severity,
    score,
    threshold_value,
    matched_rules,
    request_path,
    summary,
    *,
    auto_block=False,
    config_map=None,
):
    """落库一条告警，并按需要联动自动封禁副作用。"""
    config_map = config_map or get_config_map(db)
    blocked = 0
    if auto_block:
        blocked = 1 if block_ip(db, source_ip, summary, commit=False, config_map=config_map) else 0
        if blocked and get_int_config(db, "port_block_enabled", config_map=config_map):
            block_port_for_ip(
                db,
                source_ip,
                get_int_config(db, "port_block_target_port", config_map=config_map),
                summary,
                created_by="system",
                trigger_attack_type=attack_type,
                commit=False,
                config_map=config_map,
            )
    db.execute(
        """
        INSERT INTO attack_events(
            request_log_id, created_at, source_ip, attack_type, severity, score,
            threshold_value, matched_rules, request_path, summary, blocked, auto_blocked
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_log_id,
            to_iso(utc_now()),
            source_ip,
            attack_type,
            severity,
            score,
            threshold_value,
            json.dumps(matched_rules, ensure_ascii=False),
            request_path,
            summary,
            blocked,
            1 if auto_block else 0,
        ),
    )


def detect_content_attacks(db, request_log_id, record, normalized_payload, *, config_map=None):
    """基于归一化后的请求内容，对 SQLi 和 XSS 规则做评分。"""
    rules = load_enabled_rules(db)
    config_map = config_map or get_config_map(db)
    attack_definitions = [
        ("sql_injection", get_int_config(db, "sql_score_threshold", config_map=config_map)),
        ("xss", get_int_config(db, "xss_score_threshold", config_map=config_map)),
    ]
    for attack_type, threshold in attack_definitions:
        score = 0
        matched = []
        for rule in rules.get(attack_type, []):
            if match_rule(rule, normalized_payload):
                score += int(rule["score"])
                matched.append(rule["name"])
        if score >= threshold and not recent_event_exists(db, record["source_ip"], attack_type, config_map=config_map):
            severity = "high" if score >= threshold + 2 else "medium"
            summary = f"{attack_type_label(attack_type)}命中 {len(matched)} 条规则，评分 {score}"
            create_event(
                db,
                request_log_id,
                record["source_ip"],
                attack_type,
                severity,
                score,
                threshold,
                matched,
                record["path"],
                summary,
                config_map=config_map,
            )


def detect_bruteforce(db, request_log_id, record, *, config_map=None):
    """在滑动时间窗口内累计登录失败次数，并按阈值升级。"""
    login_result = record.get("login_result")
    if login_result not in {"success", "failure"}:
        return

    config_map = config_map or get_config_map(db)
    db.execute(
        """
        INSERT INTO login_attempts(source_ip, created_at, success, request_path)
        VALUES (?, ?, ?, ?)
        """,
        (
            record["source_ip"],
            record["timestamp"],
            1 if login_result == "success" else 0,
            record["path"],
        ),
    )
    if login_result != "failure":
        return

    since = to_iso(
        parse_iso(record["timestamp"])
        - timedelta(minutes=get_int_config(db, "bruteforce_window_minutes", config_map=config_map))
    )
    count = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE source_ip = ?
          AND success = 0
          AND created_at >= ?
        """,
        (record["source_ip"], since),
    ).fetchone()["total"]

    low = get_int_config(db, "bruteforce_low_threshold", config_map=config_map)
    high = get_int_config(db, "bruteforce_high_threshold", config_map=config_map)
    block_threshold = get_int_config(db, "bruteforce_block_threshold", config_map=config_map)
    if count < low:
        return

    severity = "low"
    threshold = low
    auto_block = False
    if count >= block_threshold:
        severity = "high"
        threshold = block_threshold
        auto_block = True
    elif count >= high:
        severity = "high"
        threshold = high

    last_event = get_latest_event(db, record["source_ip"], "bruteforce")
    if last_event:
        last_threshold = int(last_event["threshold_value"])
        last_auto_blocked = int(last_event["auto_blocked"])
        # 即使处于冷却时间内，状态升级时也允许产生新的更强告警。
        if auto_block and not last_auto_blocked:
            pass
        elif threshold > last_threshold:
            pass
        elif recent_event_exists(db, record["source_ip"], "bruteforce", config_map=config_map):
            return

    summary = f"登录失败次数达到 {count} 次，疑似暴力破解"
    create_event(
        db,
        request_log_id,
        record["source_ip"],
        "bruteforce",
        severity,
        count,
        threshold,
        [f"failed_attempts:{count}"],
        record["path"],
        summary,
        auto_block=auto_block,
        config_map=config_map,
    )


def detect_scan(db, request_log_id, record, *, config_map=None):
    """根据短时间窗口内的访问模式，近似识别 Web 路径探测行为。"""
    config_map = config_map or get_config_map(db)
    since = to_iso(
        parse_iso(record["timestamp"])
        - timedelta(minutes=get_int_config(db, "scan_window_minutes", config_map=config_map))
    )
    source_ip = record["source_ip"]
    rows = db.execute(
        """
        SELECT path, status_code
        FROM request_logs
        WHERE source_ip = ?
          AND timestamp >= ?
        """,
        (source_ip, since),
    ).fetchall()
    if not rows:
        return

    unique_paths = {row["path"] for row in rows}
    status_404 = sum(1 for row in rows if int(row["status_code"]) == 404)
    sensitive_hits = sum(
        1 for row in rows if any(row["path"].startswith(pattern) for pattern in SENSITIVE_PATH_PATTERNS)
    )

    unique_threshold = get_int_config(db, "scan_unique_paths_threshold", config_map=config_map)
    error_threshold = get_int_config(db, "scan_404_threshold", config_map=config_map)
    sensitive_threshold = get_int_config(db, "scan_sensitive_threshold", config_map=config_map)

    triggers = []
    if len(unique_paths) >= unique_threshold:
        triggers.append(f"unique_paths:{len(unique_paths)}")
    if status_404 >= error_threshold:
        triggers.append(f"status_404:{status_404}")
    if sensitive_hits >= sensitive_threshold:
        triggers.append(f"sensitive_hits:{sensitive_hits}")
    if not triggers:
        return

    score = len(triggers) * 2 + (1 if status_404 >= error_threshold else 0)
    severity = "high" if len(triggers) >= 2 else "medium"
    auto_block = len(triggers) >= 2
    last_event = get_latest_event(db, source_ip, "scan_probe")
    if last_event:
        last_score = int(last_event["score"])
        last_auto_blocked = int(last_event["auto_blocked"])
        # 和暴力破解一样，状态升级时要让告警流中保留可见变化。
        if auto_block and not last_auto_blocked:
            pass
        elif score > last_score:
            pass
        elif recent_event_exists(db, source_ip, "scan_probe", config_map=config_map):
            return

    summary = f"短时间内访问 {len(unique_paths)} 个路径，404 次数 {status_404}，敏感路径探测 {sensitive_hits} 次"
    create_event(
        db,
        request_log_id,
        source_ip,
        "scan_probe",
        severity,
        score,
        unique_threshold,
        triggers,
        record["path"],
        summary,
        auto_block=auto_block,
        config_map=config_map,
    )


def validate_connection_event(record):
    """校验端口扫描实验使用的连接事件结构。"""
    if not isinstance(record, dict):
        raise ValueError("连接事件必须是对象。")
    required = ("event_id", "timestamp", "source_ip", "target_ip", "target_port", "protocol", "result", "source_kind")
    missing = [key for key in required if key not in record]
    if missing:
        raise ValueError(f"连接事件缺少字段：{', '.join(missing)}")
    return record


def detect_port_scan(db, _connection_event_id, record, *, config_map=None):
    """根据短时间内命中的唯一目标端口数识别端口扫描。"""
    config_map = config_map or get_config_map(db)
    since = to_iso(
        parse_iso(record["timestamp"])
        - timedelta(minutes=get_int_config(db, "portscan_window_minutes", config_map=config_map))
    )
    rows = db.execute(
        """
        SELECT target_port
        FROM connection_events
        WHERE source_ip = ?
          AND target_ip = ?
          AND protocol = ?
          AND timestamp >= ?
        """,
        (record["source_ip"], record["target_ip"], record["protocol"], since),
    ).fetchall()
    if not rows:
        return

    unique_ports = sorted({int(row["target_port"]) for row in rows})
    unique_port_count = len(unique_ports)
    low = get_int_config(db, "portscan_low_threshold", config_map=config_map)
    high = get_int_config(db, "portscan_high_threshold", config_map=config_map)
    if unique_port_count < low:
        return

    request_path = build_port_scan_request_path(record["protocol"], record["target_ip"])
    severity = "medium"
    threshold = low
    auto_block = False
    if unique_port_count >= high:
        severity = "high"
        threshold = high
        auto_block = True

    last_event = get_latest_event(db, record["source_ip"], "port_scan", request_path=request_path)
    if last_event:
        last_threshold = int(last_event["threshold_value"])
        last_auto_blocked = int(last_event["auto_blocked"])
        if auto_block and not last_auto_blocked:
            pass
        elif threshold > last_threshold:
            pass
        elif recent_event_exists(
            db,
            record["source_ip"],
            "port_scan",
            request_path=request_path,
            config_map=config_map,
        ):
            return

    summary = (
        f"短时间内对 {record['target_ip']} 发起 {unique_port_count} 个唯一 TCP 端口探测，"
        f"最近端口范围 {unique_ports[0]}-{unique_ports[-1]}"
    )
    matched = [
        f"target_ip:{record['target_ip']}",
        f"unique_ports:{unique_port_count}",
        f"port_span:{unique_ports[0]}-{unique_ports[-1]}",
        f"source_kind:{record['source_kind']}",
    ]
    create_event(
        db,
        None,
        record["source_ip"],
        "port_scan",
        severity,
        unique_port_count,
        threshold,
        matched,
        request_path,
        summary,
        auto_block=auto_block,
        config_map=config_map,
    )


def validate_log_record(record):
    """尽早拒绝结构不完整的日志，保证后续入库字段稳定。"""
    if not isinstance(record, dict):
        raise ValueError("日志记录必须是对象。")
    required = ("request_id", "timestamp", "source_ip", "method", "path", "status_code")
    missing = [key for key in required if key not in record]
    if missing:
        raise ValueError(f"日志记录缺少字段：{', '.join(missing)}")
    return record


def ingest_record(db, record):
    """先写入一条请求日志，再依次运行所有检测器。"""
    record = validate_log_record(record)
    normalized = normalize_payload(record)
    try:
        cursor = db.execute(
            """
            INSERT INTO request_logs(
                request_id, timestamp, source_ip, remote_addr, method, path, full_path,
                status_code, user_agent, referer, query_data, form_data, json_data,
                raw_record, normalized_payload, login_result, blocked
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["request_id"],
                record["timestamp"],
                record["source_ip"],
                record.get("remote_addr"),
                record["method"],
                record["path"],
                record.get("full_path"),
                int(record["status_code"]),
                record.get("user_agent"),
                record.get("referer"),
                json.dumps(record.get("query_params", {}), ensure_ascii=False),
                json.dumps(record.get("form_data", {}), ensure_ascii=False),
                json.dumps(record.get("json_data", {}), ensure_ascii=False),
                json.dumps(record, ensure_ascii=False),
                normalized,
                record.get("login_result"),
                1 if record.get("blocked") else 0,
            ),
        )
    except ValueError as exc:
        raise ValueError(f"日志记录字段不合法：{exc}") from exc
    except sqlite3.IntegrityError:
        return

    request_log_id = cursor.lastrowid
    config_map = get_config_map(db)
    if is_ip_whitelisted(db, record["source_ip"], config_map=config_map):
        return

    # 静态资源请求噪音较大，对这类演示的教学价值很低，直接跳过。
    if record["path"].endswith(STATIC_EXTENSIONS):
        return

    detectors = (
        lambda: detect_content_attacks(db, request_log_id, record, normalized, config_map=config_map),
        lambda: detect_bruteforce(db, request_log_id, record, config_map=config_map),
        lambda: detect_scan(db, request_log_id, record, config_map=config_map),
    )
    for detector in detectors:
        try:
            detector()
        except Exception as exc:
            # 单个检测器异常，不应拖垮整条检测链。
            print(f"[detect] {exc}")


def ingest_connection_event(db, record):
    """写入一条连接事件，并按需触发端口扫描检测。"""
    record = validate_connection_event(record)
    try:
        cursor = db.execute(
            """
            INSERT INTO connection_events(
                event_id, timestamp, source_ip, target_ip, target_port,
                protocol, result, source_kind, raw_record
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["event_id"],
                record["timestamp"],
                record["source_ip"],
                record["target_ip"],
                int(record["target_port"]),
                record["protocol"],
                record["result"],
                record["source_kind"],
                json.dumps(record, ensure_ascii=False),
            ),
        )
    except ValueError as exc:
        raise ValueError(f"连接事件字段不合法：{exc}") from exc
    except sqlite3.IntegrityError:
        return

    config_map = get_config_map(db)
    if is_ip_whitelisted(db, record["source_ip"], config_map=config_map):
        return

    try:
        detect_port_scan(db, cursor.lastrowid, record, config_map=config_map)
    except Exception as exc:
        print(f"[detect] {exc}")


def consume_pending_logs():
    """消费新增日志，但不会跳过那些意外失败、仍应重试的记录。"""
    with runtime.log_ingest_lock:
        if not runtime.log_file.exists():
            return

        with runtime.log_file.open("r", encoding="utf-8") as handle:
            handle.seek(runtime.log_offset)
            while True:
                line_start = handle.tell()
                line = handle.readline()
                if not line:
                    break
                next_offset = handle.tell()
                stripped = line.strip()
                if not stripped:
                    runtime.log_offset = next_offset
                    continue

                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    # JSON 坏掉后这一行已无法恢复，隔离后继续处理后续日志。
                    write_bad_log_line(stripped, f"JSONDecodeError: {exc}")
                    runtime.log_offset = next_offset
                    continue

                conn = connect_db()
                try:
                    ingest_record(conn, record)
                    conn.commit()
                except ValueError as exc:
                    conn.rollback()
                    # 字段结构有问题同样不可恢复，可以安全隔离并跳过。
                    write_bad_log_line(stripped, str(exc))
                    runtime.log_offset = next_offset
                except Exception:
                    conn.rollback()
                    # 回退到当前行起点，便于临时性失败后下次重试。
                    handle.seek(line_start)
                    raise
                else:
                    # 只有当整条记录真正处理完成后，才推进读取偏移量。
                    runtime.log_offset = next_offset
                finally:
                    conn.close()


def start_watcher_once():
    """保证后台 watcher 在线程级别只启动一次。"""
    with runtime.watcher_lock:
        if runtime.watcher_thread is None:
            runtime.watcher_thread = LogWatcher()
            runtime.watcher_thread.start()
