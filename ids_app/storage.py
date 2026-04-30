"""数据库访问、表单校验和安全状态辅助逻辑。"""

import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import g

from .constants import (
    ALLOWED_MATCH_TYPES,
    ALLOWED_RULE_ATTACK_TYPES,
    ATTACK_TYPE_LABELS,
    CHINA_TIMEZONE,
    CONFIG_SPECS,
    DEFAULT_CONFIG,
    DEFAULT_RULES,
    DISPLAY_DATETIME_FORMAT,
)
from .runtime import runtime


MOJIBAKE_FRAGMENTS = (
    "鏃ュ",
    "鍙ｅ",
    "璇锋",
    "绯荤",
    "鐧诲",
    "榛戝",
    "鍛婅",
    "妫€",
    "灏佺",
    "缁熻",
    "閰嶇",
    "閲嶇",
    "闃绘",
)


def utc_now():
    return datetime.now(timezone.utc)


def to_iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value):
    return datetime.fromisoformat(value)


def to_china_time(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(CHINA_TIMEZONE)


def format_display_time(value):
    if not value:
        return ""
    try:
        return to_china_time(parse_iso(value)).strftime(DISPLAY_DATETIME_FORMAT)
    except (TypeError, ValueError):
        return value


def get_china_day_start_utc():
    local_now = to_china_time(utc_now())
    local_day_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    return local_day_start.astimezone(timezone.utc)


def ensure_data_dir():
    """在 Flask 启动前，先准备好演示所需的数据目录和日志文件。"""
    runtime.data_dir.mkdir(exist_ok=True)
    runtime.log_file.touch(exist_ok=True)
    runtime.bad_log_file.touch(exist_ok=True)


def connect_db():
    """创建 SQLite 连接，并启用字典式行访问。"""
    conn = sqlite3.connect(runtime.db_file)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    """在一次请求内复用同一个数据库连接。"""
    if "db" not in g:
        g.db = connect_db()
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """原地初始化数据库结构，让演示项目可自举启动。"""
    conn = connect_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                remote_addr TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                full_path TEXT,
                status_code INTEGER NOT NULL,
                user_agent TEXT,
                referer TEXT,
                query_data TEXT,
                form_data TEXT,
                json_data TEXT,
                raw_record TEXT NOT NULL,
                normalized_payload TEXT NOT NULL,
                login_result TEXT,
                blocked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_log_id INTEGER,
                created_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                threshold_value INTEGER NOT NULL,
                matched_rules TEXT,
                request_path TEXT,
                summary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                blocked INTEGER NOT NULL DEFAULT 0,
                auto_blocked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (request_log_id) REFERENCES request_logs(id)
            );

            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                attack_type TEXT NOT NULL,
                match_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                score INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT 'system'
            );

            CREATE TABLE IF NOT EXISTS port_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT 'system',
                trigger_attack_type TEXT,
                UNIQUE(source_ip, port)
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                created_at TEXT NOT NULL,
                success INTEGER NOT NULL,
                request_path TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                result TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                raw_record TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def seed_defaults():
    """补齐默认配置和初始规则，同时修复内置描述文本。"""
    conn = connect_db()
    try:
        for key, (value, description) in DEFAULT_CONFIG.items():
            conn.execute(
                """
                INSERT INTO system_config(key, value, description)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET description = excluded.description
                """,
                (key, value, description),
            )
        for rule in DEFAULT_RULES:
            conn.execute(
                """
                INSERT INTO rules(name, attack_type, match_type, pattern, score, enabled, description)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(name) DO UPDATE SET description = excluded.description
                """,
                (
                    rule["name"],
                    rule["attack_type"],
                    rule["match_type"],
                    rule["pattern"],
                    rule["score"],
                    rule["description"],
                ),
            )
        conn.commit()
    finally:
        conn.close()


def repair_mojibake_text(value):
    """尝试修复“UTF-8 被按 GBK 误解码”留下的典型中文乱码。"""
    if not value or not isinstance(value, str):
        return value

    try:
        repaired = value.encode("gb18030").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value

    if repaired == value:
        return value

    try:
        # 只有当“修复后再按同样错误方式编码回来”能得到原字符串时，才认定它真的是历史乱码。
        roundtrip_value = repaired.encode("utf-8").decode("gb18030")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value

    if roundtrip_value != value or "\ufffd" in repaired:
        return value

    marker_hits = sum(value.count(fragment) for fragment in MOJIBAKE_FRAGMENTS)
    repaired_marker_hits = sum(repaired.count(fragment) for fragment in MOJIBAKE_FRAGMENTS)
    if marker_hits and repaired_marker_hits >= marker_hits:
        return value
    return repaired


def repair_legacy_text_encoding(db):
    """修复数据库里历史遗留的用户可见乱码文本，避免页面继续展示旧乱码。"""
    repair_targets = (
        ("attack_events", "id", ("summary",)),
        ("blacklist", "id", ("reason",)),
        ("port_blocks", "id", ("reason",)),
        ("rules", "id", ("description",)),
        ("system_config", "key", ("description",)),
    )
    repaired_rows = 0

    for table, key_column, text_columns in repair_targets:
        select_columns = ", ".join((key_column, *text_columns))
        rows = db.execute(f"SELECT {select_columns} FROM {table}").fetchall()
        for row in rows:
            assignments = []
            values = []
            for column in text_columns:
                repaired = repair_mojibake_text(row[column])
                if repaired != row[column]:
                    assignments.append(f"{column} = ?")
                    values.append(repaired)

            if not assignments:
                continue

            values.append(row[key_column])
            db.execute(
                f"UPDATE {table} SET {', '.join(assignments)} WHERE {key_column} = ?",
                values,
            )
            repaired_rows += 1

    return repaired_rows


def get_config_map(db):
    """一次性读出全部配置，减少重复逐项查询。"""
    rows = db.execute("SELECT key, value FROM system_config").fetchall()
    return {row["key"]: row["value"] for row in rows}


def get_int_config(db, key, *, config_map=None):
    """安全读取整数配置，异常时回退到默认值。"""
    config_map = config_map or get_config_map(db)
    raw_value = config_map.get(key, DEFAULT_CONFIG[key][0])
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return int(DEFAULT_CONFIG[key][0])


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def parse_whitelist(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def is_ip_whitelisted(db, ip_value, *, config_map=None):
    """统一白名单判断来源，避免请求链路和管理页面口径不一致。"""
    config_map = config_map or get_config_map(db)
    return ip_value in parse_whitelist(config_map.get("ip_whitelist", ""))


def cleanup_blacklist(db, *, now=None, commit=True):
    now = now or to_iso(utc_now())
    db.execute(
        """
        UPDATE blacklist
        SET active = 0
        WHERE active = 1
          AND expires_at IS NOT NULL
          AND expires_at <= ?
        """,
        (now,),
    )
    if commit:
        db.commit()


def cleanup_port_blocks(db, *, now=None, commit=True):
    now = now or to_iso(utc_now())
    db.execute(
        """
        UPDATE port_blocks
        SET active = 0
        WHERE active = 1
          AND expires_at IS NOT NULL
          AND expires_at <= ?
        """,
        (now,),
    )
    if commit:
        db.commit()


def cleanup_security_entries(db):
    """在做状态判断前，先清理已过期的封禁和端口阻断记录。"""
    now = to_iso(utc_now())
    cleanup_blacklist(db, now=now, commit=False)
    cleanup_port_blocks(db, now=now, commit=False)
    db.commit()


def get_active_blacklist_entry(db, ip_value, *, cleanup=True):
    if cleanup:
        cleanup_security_entries(db)
    return db.execute(
        """
        SELECT *
        FROM blacklist
        WHERE source_ip = ? AND active = 1
        LIMIT 1
        """,
        (ip_value,),
    ).fetchone()


def get_active_port_block_entry(db, ip_value, port, *, cleanup=True):
    if cleanup:
        cleanup_security_entries(db)
    return db.execute(
        """
        SELECT *
        FROM port_blocks
        WHERE source_ip = ? AND port = ? AND active = 1
        LIMIT 1
        """,
        (ip_value, port),
    ).fetchone()


def is_blacklisted(db, ip_value, *, cleanup=True):
    return get_active_blacklist_entry(db, ip_value, cleanup=cleanup) is not None


def is_port_blocked(db, ip_value, port, *, cleanup=True):
    return get_active_port_block_entry(db, ip_value, port, cleanup=cleanup) is not None


def get_enforcement_state(db, ip_value, port, *, config_map=None):
    """返回统一的拦截状态，供页面、接口和请求拦截共用。"""
    config_map = config_map or get_config_map(db)
    whitelisted = is_ip_whitelisted(db, ip_value, config_map=config_map)
    if whitelisted:
        return {"whitelisted": True, "blacklist": None, "port_block": None}
    cleanup_security_entries(db)
    return {
        "whitelisted": False,
        "blacklist": get_active_blacklist_entry(db, ip_value, cleanup=False),
        "port_block": get_active_port_block_entry(db, ip_value, port, cleanup=False),
    }


def block_ip(db, ip_value, reason, created_by="system", *, commit=True, config_map=None):
    """写入或刷新黑名单记录，让重复命中时自动延长封禁窗口。"""
    if not ip_value:
        return False
    config_map = config_map or get_config_map(db)
    if is_ip_whitelisted(db, ip_value, config_map=config_map):
        return False
    expires_at = to_iso(
        utc_now() + timedelta(minutes=get_int_config(db, "blacklist_duration_minutes", config_map=config_map))
    )
    current = db.execute("SELECT id FROM blacklist WHERE source_ip = ?", (ip_value,)).fetchone()
    if current:
        db.execute(
            """
            UPDATE blacklist
            SET reason = ?, created_at = ?, expires_at = ?, active = 1, created_by = ?
            WHERE source_ip = ?
            """,
            (reason, to_iso(utc_now()), expires_at, created_by, ip_value),
        )
    else:
        db.execute(
            """
            INSERT INTO blacklist(source_ip, reason, created_at, expires_at, active, created_by)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (ip_value, reason, to_iso(utc_now()), expires_at, created_by),
        )
    if commit:
        db.commit()
    return True


def unblock_ip(db, ip_value, *, commit=True):
    db.execute("UPDATE blacklist SET active = 0 WHERE source_ip = ?", (ip_value,))
    if commit:
        db.commit()


def block_port_for_ip(
    db,
    ip_value,
    port,
    reason,
    created_by="system",
    trigger_attack_type=None,
    *,
    commit=True,
    config_map=None,
):
    """写入或刷新某个 IP 的端口阻断，并记录触发它的攻击类型。"""
    if not ip_value:
        return False
    config_map = config_map or get_config_map(db)
    if is_ip_whitelisted(db, ip_value, config_map=config_map):
        return False
    expires_at = to_iso(
        utc_now() + timedelta(minutes=get_int_config(db, "port_block_duration_minutes", config_map=config_map))
    )
    current = db.execute(
        "SELECT id FROM port_blocks WHERE source_ip = ? AND port = ?",
        (ip_value, port),
    ).fetchone()
    if current:
        db.execute(
            """
            UPDATE port_blocks
            SET reason = ?, created_at = ?, expires_at = ?, active = 1, created_by = ?, trigger_attack_type = ?
            WHERE source_ip = ? AND port = ?
            """,
            (reason, to_iso(utc_now()), expires_at, created_by, trigger_attack_type, ip_value, port),
        )
    else:
        db.execute(
            """
            INSERT INTO port_blocks(source_ip, port, reason, created_at, expires_at, active, created_by, trigger_attack_type)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (ip_value, port, reason, to_iso(utc_now()), expires_at, created_by, trigger_attack_type),
        )
    if commit:
        db.commit()
    return True


def unblock_port_for_ip(db, ip_value, port, *, commit=True):
    db.execute(
        "UPDATE port_blocks SET active = 0 WHERE source_ip = ? AND port = ?",
        (ip_value, port),
    )
    if commit:
        db.commit()


def unblock_port_blocks_for_attack(db, ip_value, attack_type, *, commit=True):
    db.execute(
        """
        UPDATE port_blocks
        SET active = 0
        WHERE source_ip = ?
          AND trigger_attack_type = ?
        """,
        (ip_value, attack_type),
    )
    if commit:
        db.commit()


def validate_config_value(key, raw_value):
    """按 CONFIG_SPECS 校验并规范化单个配置项。"""
    spec = CONFIG_SPECS[key]
    value = (raw_value or "").strip()
    if spec["type"] == "int":
        try:
            parsed = int(value)
        except ValueError:
            return None, f"{key} 必须是整数。"
        if parsed < spec["min"]:
            return None, f"{key} 不能小于 {spec['min']}。"
        return str(parsed), None

    if spec["type"] == "bool":
        if value not in {"0", "1"}:
            return None, f"{key} 只能保存为 0 或 1。"
        return value, None

    if spec["type"] == "port":
        if not is_valid_port(value):
            return None, f"{key} 必须是 1 到 65535 之间的端口号。"
        return str(int(value)), None

    if spec["type"] == "ip":
        if not is_valid_ip(value):
            return None, f"{key} 必须是合法 IP。"
        return value, None

    if spec["type"] == "ip_list":
        items = parse_whitelist(value)
        invalid_items = [item for item in items if not is_valid_ip(item)]
        if invalid_items:
            return None, f"{key} 包含非法 IP：{', '.join(invalid_items)}"
        return ",".join(items), None

    return value, None


def validate_config_form(form):
    """校验整份配置表单，并保证阈值之间的前后关系合理。"""
    updates = {}
    errors = []
    for key in DEFAULT_CONFIG:
        if key not in form:
            continue
        normalized, error = validate_config_value(key, form.get(key, ""))
        if error:
            errors.append(error)
            continue
        updates[key] = normalized

    # 这些阈值后续会被联动比较，所以这里提前拦截不合理顺序。
    low = updates.get("bruteforce_low_threshold", DEFAULT_CONFIG["bruteforce_low_threshold"][0])
    high = updates.get("bruteforce_high_threshold", DEFAULT_CONFIG["bruteforce_high_threshold"][0])
    block = updates.get("bruteforce_block_threshold", DEFAULT_CONFIG["bruteforce_block_threshold"][0])
    if int(low) > int(high):
        errors.append("bruteforce_low_threshold 不能大于 bruteforce_high_threshold。")
    if int(high) > int(block):
        errors.append("bruteforce_high_threshold 不能大于 bruteforce_block_threshold。")

    portscan_low = updates.get("portscan_low_threshold", DEFAULT_CONFIG["portscan_low_threshold"][0])
    portscan_high = updates.get("portscan_high_threshold", DEFAULT_CONFIG["portscan_high_threshold"][0])
    if int(portscan_low) > int(portscan_high):
        errors.append("portscan_low_threshold 不能大于 portscan_high_threshold。")

    return updates, errors


def validate_rule_form(form):
    """在规则进入实时检测链路前，先完成必要校验。"""
    payload = {
        "name": form.get("name", "").strip(),
        "attack_type": form.get("attack_type", "").strip(),
        "match_type": form.get("match_type", "").strip(),
        "pattern": form.get("pattern", "").strip(),
        "description": form.get("description", "").strip(),
    }
    errors = []
    if not payload["name"]:
        errors.append("规则名称不能为空。")
    if payload["attack_type"] not in ALLOWED_RULE_ATTACK_TYPES:
        errors.append("攻击类型不合法。")
    if payload["match_type"] not in ALLOWED_MATCH_TYPES:
        errors.append("匹配方式不合法。")
    if not payload["pattern"]:
        errors.append("匹配内容不能为空。")
    try:
        payload["score"] = int(form.get("score", "1"))
    except ValueError:
        errors.append("评分必须是整数。")
    else:
        if payload["score"] < 1:
            errors.append("评分必须大于等于 1。")
    if payload["match_type"] == "regex" and payload["pattern"]:
        try:
            re.compile(payload["pattern"])
        except re.error as exc:
            errors.append(f"正则规则无效：{exc}")
    return payload, errors


def attack_type_label(value):
    return ATTACK_TYPE_LABELS.get(value, value)


def severity_badge(value):
    return {"low": "secondary", "medium": "warning", "high": "danger"}.get(value, "secondary")
