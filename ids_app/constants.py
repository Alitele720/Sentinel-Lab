"""Shared default values and constants for the IDS demo application."""

from datetime import timedelta, timezone


DEFAULT_CONFIG = {
    "sql_score_threshold": ("4", "SQL 注入风险评分阈值"),
    "xss_score_threshold": ("3", "XSS 风险评分阈值"),
    "bruteforce_window_minutes": ("5", "暴力破解检测时间窗口（分钟）"),
    "bruteforce_low_threshold": ("5", "暴力破解低危阈值"),
    "bruteforce_high_threshold": ("10", "暴力破解高危阈值"),
    "bruteforce_block_threshold": ("15", "暴力破解自动封禁阈值"),
    "scan_window_minutes": ("1", "异常探测检测时间窗口（分钟）"),
    "scan_unique_paths_threshold": ("30", "异常探测唯一路径阈值"),
    "scan_404_threshold": ("15", "异常探测 404 阈值"),
    "scan_sensitive_threshold": ("5", "敏感路径探测阈值"),
    "portscan_window_minutes": ("1", "端口扫描检测时间窗口（分钟）"),
    "portscan_low_threshold": ("10", "端口扫描低危告警阈值"),
    "portscan_high_threshold": ("20", "端口扫描高危告警/封禁阈值"),
    "blacklist_duration_minutes": ("60", "自动封禁时长（分钟）"),
    "port_block_enabled": ("1", "端口阻断模块开关（1 为启用，0 为关闭）"),
    "port_block_target_port": ("5000", "应用层端口阻断目标端口"),
    "port_block_duration_minutes": ("60", "端口阻断时长（分钟）"),
    "alert_cooldown_seconds": ("60", "同类告警冷却时间（秒）"),
    "ip_whitelist": ("127.0.0.1,::1", "IP 白名单，多个地址用逗号分隔"),
}

CONFIG_SPECS = {
    "sql_score_threshold": {"type": "int", "min": 1},
    "xss_score_threshold": {"type": "int", "min": 1},
    "bruteforce_window_minutes": {"type": "int", "min": 1},
    "bruteforce_low_threshold": {"type": "int", "min": 1},
    "bruteforce_high_threshold": {"type": "int", "min": 1},
    "bruteforce_block_threshold": {"type": "int", "min": 1},
    "scan_window_minutes": {"type": "int", "min": 1},
    "scan_unique_paths_threshold": {"type": "int", "min": 1},
    "scan_404_threshold": {"type": "int", "min": 1},
    "scan_sensitive_threshold": {"type": "int", "min": 1},
    "portscan_window_minutes": {"type": "int", "min": 1},
    "portscan_low_threshold": {"type": "int", "min": 1},
    "portscan_high_threshold": {"type": "int", "min": 1},
    "blacklist_duration_minutes": {"type": "int", "min": 1},
    "port_block_enabled": {"type": "bool"},
    "port_block_target_port": {"type": "port"},
    "port_block_duration_minutes": {"type": "int", "min": 1},
    "alert_cooldown_seconds": {"type": "int", "min": 0},
    "ip_whitelist": {"type": "ip_list"},
}

DEMO_IP_SUGGESTIONS = [
    "10.10.10.66",
    "10.10.10.67",
    "10.10.10.88",
    "10.10.10.99",
]
DEFAULT_DEMO_IP = DEMO_IP_SUGGESTIONS[0]

DEFAULT_RULES = [
    {
        "name": "SQL_Always_True_Keyword",
        "attack_type": "sql_injection",
        "match_type": "keyword",
        "pattern": "' or 1=1",
        "score": 3,
        "description": "检测恒真条件注入",
    },
    {
        "name": "SQL_Union_Select",
        "attack_type": "sql_injection",
        "match_type": "keyword",
        "pattern": "union select",
        "score": 3,
        "description": "检测 UNION SELECT 注入特征",
    },
    {
        "name": "SQL_Or_True",
        "attack_type": "sql_injection",
        "match_type": "regex",
        "pattern": r"('|%27)\s*or\s+1=1",
        "score": 3,
        "description": "检测 or 1=1 逻辑绕过",
    },
    {
        "name": "SQL_Sleep_Function",
        "attack_type": "sql_injection",
        "match_type": "keyword",
        "pattern": "sleep(",
        "score": 3,
        "description": "检测时间盲注函数",
    },
    {
        "name": "SQL_Benchmark_Function",
        "attack_type": "sql_injection",
        "match_type": "keyword",
        "pattern": "benchmark(",
        "score": 3,
        "description": "检测 benchmark 函数",
    },
    {
        "name": "SQL_Information_Schema",
        "attack_type": "sql_injection",
        "match_type": "keyword",
        "pattern": "information_schema",
        "score": 2,
        "description": "检测元数据表探测",
    },
    {
        "name": "SQL_Comment_Tail",
        "attack_type": "sql_injection",
        "match_type": "regex",
        "pattern": r"(--|\#)\s*$",
        "score": 1,
        "description": "检测注释截断符",
    },
    {
        "name": "XSS_Script_Tag",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "<script",
        "score": 3,
        "description": "检测 script 标签",
    },
    {
        "name": "XSS_Javascript_Protocol",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "javascript:",
        "score": 2,
        "description": "检测 javascript 协议",
    },
    {
        "name": "XSS_OnError_Handler",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "onerror=",
        "score": 2,
        "description": "检测 onerror 事件处理器",
    },
    {
        "name": "XSS_OnLoad_Handler",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "onload=",
        "score": 2,
        "description": "检测 onload 事件处理器",
    },
    {
        "name": "XSS_Alert_Call",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "alert(",
        "score": 1,
        "description": "检测 alert 调用",
    },
    {
        "name": "XSS_Document_Cookie",
        "attack_type": "xss",
        "match_type": "keyword",
        "pattern": "document.cookie",
        "score": 2,
        "description": "检测 cookie 窃取代码",
    },
]

ATTACK_TYPE_LABELS = {
    "sql_injection": "SQL 注入",
    "xss": "XSS",
    "bruteforce": "暴力破解",
    "scan_probe": "异常探测",
    "port_scan": "端口扫描",
}
ALLOWED_ATTACK_TYPES = tuple(ATTACK_TYPE_LABELS.keys())
ALLOWED_RULE_ATTACK_TYPES = ("sql_injection", "xss")
ALLOWED_MATCH_TYPES = ("keyword", "regex")

SENSITIVE_PATH_PATTERNS = [
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/.env",
    "/wp-admin",
    "/manager/html",
    "/actuator",
    "/shell",
    "/console",
    "/config",
]

STATIC_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg")
CHINA_TIMEZONE = timezone(timedelta(hours=8))
DISPLAY_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
