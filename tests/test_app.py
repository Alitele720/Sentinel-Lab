"""Regression and deployment tests for the LAN honeypot IDS."""

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from ids_app import create_app
from ids_app.deploy import load_dotenv_file
from ids_app.detection import consume_pending_logs, normalize_payload, write_access_log
from ids_app.lab import build_connection_event, build_lab_record, push_connection_events_to_pipeline
from ids_app.portscan_capture import packet_to_connection_event
from ids_app.runtime import BASE_DIR, runtime
from ids_app.storage import (
    connect_db,
    repair_legacy_text_encoding,
    to_iso,
    utc_now,
    validate_config_form,
    validate_rule_form,
)


JSON_HEADERS = {
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest",
}

def to_mojibake(value):
    return value.encode("utf-8").decode("gb18030")


def maybe_to_mojibake(value):
    try:
        return to_mojibake(value)
    except UnicodeDecodeError:
        return ""


KNOWN_MOJIBAKE_SOURCE_TERMS = (
    "数据库",
    "请求",
    "系统",
    "登录",
    "黑名单",
    "告警",
    "检测",
    "封禁",
    "配置",
    "端口阻断",
    "暴力破解",
    "异常探测",
    "端口扫描",
    "管理员",
)
KNOWN_MOJIBAKE_FRAGMENTS = tuple(
    fragment for term in KNOWN_MOJIBAKE_SOURCE_TERMS if (fragment := maybe_to_mojibake(term))
)


class AppTestCase(unittest.TestCase):
    """Cover the most important correctness and deployment guardrails."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        runtime.configure(base_dir=BASE_DIR, data_dir=self.temp_dir.name)
        runtime.watcher_thread = None
        self.base_config = {
            "TESTING": True,
            "START_WATCHER": False,
            "SECRET_KEY": "test-secret",
            "ADMIN_AUTH_ENABLED": False,
            "ADMIN_ALLOWED_IPS": ["127.0.0.1", "::1"],
            "EXPOSE_LABS": True,
            "SYNC_INGEST_REAL_REQUESTS": True,
            "PORTSCAN_CAPTURE_ENABLED": False,
            "TRUST_PROXY": False,
            "TRUSTED_PROXY_IPS": [],
        }
        self.app = create_app(self.base_config)
        self.client = self.app.test_client()

    def tearDown(self):
        runtime.watcher_thread = None
        self.temp_dir.cleanup()
        runtime.configure(base_dir=BASE_DIR)

    def get_db(self):
        return connect_db()

    def create_client(self, **config_overrides):
        app = create_app({**self.base_config, **config_overrides})
        return app.test_client()

    def build_connection_events(self, source_ip, target_ip, start_port, end_port):
        return [build_connection_event(source_ip, target_ip, port, source_kind="npcap") for port in range(start_port, end_port + 1)]

    def test_validate_config_form_rejects_invalid_values(self):
        updates, errors = validate_config_form(
            {
                "port_block_target_port": "70000",
                "ip_whitelist": "127.0.0.1,not-an-ip",
                "bruteforce_low_threshold": "10",
                "bruteforce_high_threshold": "5",
            }
        )
        self.assertGreaterEqual(len(errors), 3)
        self.assertNotIn("port_block_target_port", updates)
        self.assertNotIn("ip_whitelist", updates)

    def test_validate_rule_form_rejects_bad_regex(self):
        payload, errors = validate_rule_form(
            {
                "name": "broken-rule",
                "attack_type": "xss",
                "match_type": "regex",
                "pattern": "(",
                "score": "2",
                "description": "broken",
            }
        )
        self.assertEqual(payload["name"], "broken-rule")
        self.assertTrue(errors)

    def test_load_dotenv_file_reads_env_without_overwriting_existing_os_environ(self):
        temp_env = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False, encoding="utf-8")
        try:
            temp_env.write(
                "\n".join(
                    [
                        "IDS_HOST=0.0.0.0",
                        "IDS_PORT=6001",
                        'IDS_ADMIN_USERNAME="dotenv-admin"',
                    ]
                )
            )
            temp_env.close()

            previous_port = os.environ.get("IDS_PORT")
            previous_host = os.environ.get("IDS_HOST")
            previous_admin = os.environ.get("IDS_ADMIN_USERNAME")
            os.environ["IDS_PORT"] = "7001"
            os.environ.pop("IDS_HOST", None)
            os.environ.pop("IDS_ADMIN_USERNAME", None)

            loaded = load_dotenv_file(temp_env.name)

            self.assertTrue(loaded)
            self.assertEqual(os.environ.get("IDS_HOST"), "0.0.0.0")
            self.assertEqual(os.environ.get("IDS_PORT"), "7001")
            self.assertEqual(os.environ.get("IDS_ADMIN_USERNAME"), "dotenv-admin")
        finally:
            os.unlink(temp_env.name)
            if previous_port is None:
                os.environ.pop("IDS_PORT", None)
            else:
                os.environ["IDS_PORT"] = previous_port
            if previous_host is None:
                os.environ.pop("IDS_HOST", None)
            else:
                os.environ["IDS_HOST"] = previous_host
            if previous_admin is None:
                os.environ.pop("IDS_ADMIN_USERNAME", None)
            else:
                os.environ["IDS_ADMIN_USERNAME"] = previous_admin

    def test_create_app_loads_project_dotenv_from_runtime_base_dir(self):
        project_dir = tempfile.TemporaryDirectory()
        previous_port = os.environ.get("IDS_PORT")
        previous_secret = os.environ.get("IDS_SECRET_KEY")
        try:
            runtime.configure(base_dir=project_dir.name, data_dir=Path(project_dir.name) / "data")
            Path(project_dir.name, ".env").write_text(
                "\n".join(
                    [
                        "IDS_PORT=6123",
                        "IDS_SECRET_KEY=from-dotenv",
                    ]
                ),
                encoding="utf-8",
            )
            os.environ.pop("IDS_PORT", None)
            os.environ.pop("IDS_SECRET_KEY", None)

            app = create_app({"TESTING": True, "START_WATCHER": False})

            self.assertEqual(app.config["PORT"], 6123)
            self.assertEqual(app.config["SECRET_KEY"], "from-dotenv")
        finally:
            if previous_port is None:
                os.environ.pop("IDS_PORT", None)
            else:
                os.environ["IDS_PORT"] = previous_port
            if previous_secret is None:
                os.environ.pop("IDS_SECRET_KEY", None)
            else:
                os.environ["IDS_SECRET_KEY"] = previous_secret
            project_dir.cleanup()
            runtime.configure(base_dir=BASE_DIR)

    def test_normalize_payload_decodes_encoded_content(self):
        normalized = normalize_payload(
            {
                "path": "/search",
                "query_params": {"q": ["%3Cscript%3Ealert%281%29%3C%2Fscript%3E"]},
                "form_data": {},
                "json_data": {},
            }
        )
        self.assertIn("<script>alert(1)</script>", normalized)

    def test_consume_pending_logs_skips_bad_json_and_processes_following_records(self):
        bad_line = "{bad json"
        runtime.log_file.write_text(f"{bad_line}\n", encoding="utf-8")
        write_access_log(build_lab_record("10.10.10.66", "/search", query_params={"q": ["' or 1=1 --"]}))

        consume_pending_logs()

        db = self.get_db()
        try:
            request_count = db.execute("SELECT COUNT(*) AS total FROM request_logs").fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(request_count, 1)
        self.assertIn("JSONDecodeError", runtime.bad_log_file.read_text(encoding="utf-8"))

    def test_invalid_config_and_regex_do_not_break_ingest(self):
        db = self.get_db()
        try:
            db.execute("UPDATE system_config SET value = 'oops' WHERE key = 'sql_score_threshold'")
            db.execute("UPDATE rules SET pattern = '(' WHERE name = 'SQL_Or_True'")
            db.commit()
        finally:
            db.close()

        write_access_log(build_lab_record("10.10.10.77", "/search", query_params={"q": ["' or 1=1 --"]}))
        consume_pending_logs()

        db = self.get_db()
        try:
            request_count = db.execute("SELECT COUNT(*) AS total FROM request_logs").fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(request_count, 1)

    def test_repair_legacy_text_encoding_fixes_old_garbled_rows(self):
        clean_summary = "SQL 注入命中 2 条规则，评分 6"
        clean_reason = "请求日志入库完成"
        broken_summary = to_mojibake(clean_summary)
        broken_reason = to_mojibake(clean_reason)

        db = self.get_db()
        try:
            db.execute(
                """
                INSERT INTO attack_events(
                    created_at, source_ip, attack_type, severity, score,
                    threshold_value, matched_rules, request_path, summary
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-04-28T00:00:00+00:00",
                    "10.10.10.66",
                    "sql_injection",
                    "medium",
                    6,
                    4,
                    "[]",
                    "/search",
                    broken_summary,
                ),
            )
            db.execute(
                """
                INSERT INTO blacklist(source_ip, reason, created_at, expires_at, active, created_by)
                VALUES (?, ?, ?, ?, 1, 'system')
                """,
                (
                    "10.10.10.88",
                    broken_reason,
                    "2026-04-28T00:00:00+00:00",
                    "2026-04-28T01:00:00+00:00",
                ),
            )
            repaired_rows = repair_legacy_text_encoding(db)
            db.commit()

            repaired_summary = db.execute(
                "SELECT summary FROM attack_events WHERE source_ip = '10.10.10.66'"
            ).fetchone()["summary"]
            repaired_reason = db.execute(
                "SELECT reason FROM blacklist WHERE source_ip = '10.10.10.88'"
            ).fetchone()["reason"]
        finally:
            db.close()

        self.assertEqual(repaired_rows, 2)
        self.assertEqual(repaired_summary, clean_summary)
        self.assertEqual(repaired_reason, clean_reason)

    def test_source_files_do_not_keep_known_mojibake_literals(self):
        search_roots = ("ids_app", "templates", "static")
        offenders = []
        for root in search_roots:
            for path in Path(BASE_DIR, root).rglob("*"):
                if path.suffix not in {".py", ".html", ".js", ".css"}:
                    continue
                text = path.read_text(encoding="utf-8")
                for fragment in KNOWN_MOJIBAKE_FRAGMENTS:
                    if fragment in text:
                        offenders.append(f"{path.relative_to(BASE_DIR)}: {fragment}")
        self.assertEqual(offenders, [])

    def test_public_routes_smoke(self):
        for path in ["/", "/portal", "/search", "/contact", "/health"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_public_search_request_is_logged(self):
        response = self.client.get("/search?q=alice", environ_overrides={"REMOTE_ADDR": "10.10.10.30"})
        self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute(
                "SELECT source_ip, path FROM request_logs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            db.close()
        self.assertEqual(row["source_ip"], "10.10.10.30")
        self.assertEqual(row["path"], "/search")

    def test_public_sql_injection_request_creates_alert(self):
        response = self.client.get(
            "/search?q=' or 1=1 --",
            environ_overrides={"REMOTE_ADDR": "10.10.10.31"},
        )
        self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT attack_type
                FROM attack_events
                WHERE source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.31",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["attack_type"], "sql_injection")

    def test_public_xss_request_creates_alert(self):
        response = self.client.post(
            "/contact",
            data={"name": "user", "email": "a@b.c", "message": "<script>alert(1)</script>"},
            environ_overrides={"REMOTE_ADDR": "10.10.10.32"},
        )
        self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT attack_type
                FROM attack_events
                WHERE source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.32",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["attack_type"], "xss")

    def test_public_bruteforce_requests_create_alert(self):
        for _ in range(5):
            response = self.client.post(
                "/portal",
                data={"username": "admin", "password": "wrong"},
                environ_overrides={"REMOTE_ADDR": "10.10.10.33"},
            )
            self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT attack_type
                FROM attack_events
                WHERE source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.33",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["attack_type"], "bruteforce")

    def test_public_scan_probe_request_creates_alert(self):
        for path in ["/admin", "/phpmyadmin", "/.env", "/wp-admin", "/manager/html"]:
            self.client.get(path, environ_overrides={"REMOTE_ADDR": "10.10.10.34"})
        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT attack_type
                FROM attack_events
                WHERE source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.34",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["attack_type"], "scan_probe")

    def test_non_admin_ip_cannot_access_management_routes(self):
        locked_client = self.create_client(ADMIN_AUTH_ENABLED=False, EXPOSE_LABS=False)
        for path in ["/dashboard", "/alerts", "/logs", "/rules", "/config", "/blacklist"]:
            response = locked_client.get(path, environ_overrides={"REMOTE_ADDR": "10.10.10.200"})
            self.assertEqual(response.status_code, 403, path)

    def test_admin_auth_login_required_when_enabled(self):
        guarded_client = self.create_client(
            ADMIN_AUTH_ENABLED=True,
            EXPOSE_LABS=False,
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="secret",
        )
        response = guarded_client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login", response.headers["Location"])

        login_response = guarded_client.post(
            "/admin/login",
            data={"username": "admin", "password": "secret"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        response = guarded_client.get("/dashboard", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)

    def test_admin_session_persists_across_multiple_management_pages(self):
        guarded_client = self.create_client(
            ADMIN_AUTH_ENABLED=True,
            EXPOSE_LABS=False,
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="secret",
        )

        login_response = guarded_client.post(
            "/admin/login",
            data={"username": "admin", "password": "secret"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        for path in ["/ops", "/dashboard", "/alerts", "/logs", "/rules", "/config", "/blacklist", "/ops"]:
            response = guarded_client.get(path, environ_overrides={"REMOTE_ADDR": "127.0.0.1"}, follow_redirects=False)
            self.assertEqual(response.status_code, 200, path)

    def test_public_nav_shows_admin_home_after_login(self):
        guarded_client = self.create_client(
            ADMIN_AUTH_ENABLED=True,
            EXPOSE_LABS=False,
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="secret",
        )

        before_login = guarded_client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        self.assertIn("管理登录", before_login.get_data(as_text=True))

        login_response = guarded_client.post(
            "/admin/login",
            data={"username": "admin", "password": "secret"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)

        after_login = guarded_client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        body = after_login.get_data(as_text=True)
        self.assertIn("进入后台", body)
        self.assertIn("退出后台", body)

    def test_untrusted_proxy_header_is_ignored(self):
        proxy_client = self.create_client(TRUST_PROXY=False)
        response = proxy_client.get(
            "/search?q=test",
            headers={"X-Forwarded-For": "10.1.1.50"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute("SELECT source_ip FROM request_logs ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            db.close()
        self.assertEqual(row["source_ip"], "127.0.0.1")

    def test_trusted_proxy_header_is_used_when_enabled(self):
        proxy_client = self.create_client(TRUST_PROXY=True, TRUSTED_PROXY_IPS=["127.0.0.1"])
        response = proxy_client.get(
            "/search?q=test",
            headers={"X-Forwarded-For": "10.1.1.51"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(response.status_code, 200)
        db = self.get_db()
        try:
            row = db.execute("SELECT source_ip FROM request_logs ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            db.close()
        self.assertEqual(row["source_ip"], "10.1.1.51")

    def test_production_lab_routes_are_not_public(self):
        locked_client = self.create_client(ADMIN_AUTH_ENABLED=False, EXPOSE_LABS=False)
        response = locked_client.post(
            "/lab/bruteforce",
            data={"demo_ip": "10.10.10.66", "action": "fail_once"},
            headers=JSON_HEADERS,
            environ_overrides={"REMOTE_ADDR": "10.10.10.201"},
        )
        self.assertEqual(response.status_code, 403)

    def test_blacklisted_source_is_blocked_on_following_request(self):
        for _ in range(15):
            self.client.post(
                "/portal",
                data={"username": "admin", "password": "wrong"},
                environ_overrides={"REMOTE_ADDR": "10.10.10.35"},
            )
        response = self.client.get("/search?q=followup", environ_overrides={"REMOTE_ADDR": "10.10.10.35"})
        self.assertEqual(response.status_code, 403)

    def test_repeated_log_consumption_does_not_duplicate_request_rows(self):
        write_access_log(build_lab_record("10.10.10.40", "/search", query_params={"q": ["alice"]}))
        consume_pending_logs()
        consume_pending_logs()
        db = self.get_db()
        try:
            total = db.execute("SELECT COUNT(*) AS total FROM request_logs WHERE source_ip = ?", ("10.10.10.40",)).fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(total, 1)

    def test_bruteforce_reset_route_clears_linked_port_block(self):
        payload = {"demo_ip": "10.10.10.88", "action": "custom_count", "count": "15"}
        response = self.client.post("/lab/bruteforce", data=payload, headers=JSON_HEADERS)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["state"]["blocked"])

        response = self.client.post("/lab/bruteforce/reset", data={"target_ip": "10.10.10.88"}, headers=JSON_HEADERS)
        self.assertEqual(response.status_code, 200)
        reset_data = response.get_json()
        self.assertFalse(reset_data["state"]["blocked"])

        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT active
                FROM port_blocks
                WHERE source_ip = ?
                  AND trigger_attack_type = 'bruteforce'
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.88",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["active"], 0)

    def test_invalid_config_post_is_rejected_without_overwriting_value(self):
        db = self.get_db()
        try:
            before = db.execute("SELECT value FROM system_config WHERE key = 'port_block_target_port'").fetchone()["value"]
        finally:
            db.close()

        response = self.client.post("/config", data={"action": "save", "port_block_target_port": "70000"}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        db = self.get_db()
        try:
            after = db.execute("SELECT value FROM system_config WHERE key = 'port_block_target_port'").fetchone()["value"]
        finally:
            db.close()
        self.assertEqual(before, after)

    def test_invalid_rule_post_is_rejected(self):
        response = self.client.post(
            "/rules",
            data={
                "action": "add",
                "name": "bad-regex",
                "attack_type": "xss",
                "match_type": "regex",
                "pattern": "(",
                "score": "2",
                "description": "bad",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        db = self.get_db()
        try:
            row = db.execute("SELECT COUNT(*) AS total FROM rules WHERE name = 'bad-regex'").fetchone()
        finally:
            db.close()
        self.assertEqual(row["total"], 0)

    def test_pages_and_stats_api_smoke(self):
        for path in ["/ops", "/dashboard", "/alerts", "/logs", "/rules", "/config", "/blacklist"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(
            sorted(data.keys()),
            [
                "attacksByType",
                "captureStatus",
                "recentConnectionSummary",
                "recentPortScanAlerts",
                "requestsByHour",
                "topAttackIps",
                "topConnectionSources",
                "topTargetPorts",
                "trafficByHour",
                "trafficRealtime",
            ],
        )
        self.assertEqual(len(data["trafficByHour"]), 24)
        self.assertEqual(len(data["trafficRealtime"]), 60)

    def test_admin_logs_page_shows_runtime_log_tail(self):
        write_access_log(build_lab_record("10.10.10.99", "/search", query_params={"q": ["log-viewer"]}))

        response = self.client.get("/logs?lines=20")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("运行日志", body)
        self.assertIn("10.10.10.99", body)
        self.assertIn("log-viewer", body)

    def test_admin_logs_page_shows_bad_log_tail(self):
        runtime.bad_log_file.write_text("bad-line-for-viewer\n", encoding="utf-8")

        response = self.client.get("/logs?file=bad&lines=20")

        self.assertEqual(response.status_code, 200)
        self.assertIn("bad-line-for-viewer", response.get_data(as_text=True))

    def test_stats_api_returns_zero_filled_traffic_buckets_when_empty(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertEqual(len(data["trafficByHour"]), 24)
        self.assertTrue(all(item["request_total"] == 0 for item in data["trafficByHour"]))
        self.assertTrue(all(item["connection_total"] == 0 for item in data["trafficByHour"]))
        self.assertEqual(len(data["trafficRealtime"]), 60)
        self.assertTrue(all(item["request_total"] == 0 for item in data["trafficRealtime"]))
        self.assertTrue(all(item["connection_total"] == 0 for item in data["trafficRealtime"]))
        self.assertEqual(data["captureStatus"]["state"], "disabled")
        self.assertFalse(data["captureStatus"]["enabled"])
        self.assertEqual(data["captureStatus"]["interface"], "默认网卡")
        self.assertEqual(data["recentConnectionSummary"], {"total": 0, "unique_sources": 0, "unique_target_ports": 0})
        self.assertEqual(data["topConnectionSources"], [])
        self.assertEqual(data["topTargetPorts"], [])
        self.assertEqual(data["recentPortScanAlerts"], {"total": 0, "highest_severity": None})

    def test_stats_api_aggregates_request_and_connection_traffic_by_hour(self):
        timestamp = to_iso(utc_now())

        db = self.get_db()
        try:
            db.execute(
                """
                INSERT INTO request_logs(
                    request_id, timestamp, source_ip, remote_addr, method, path, full_path,
                    status_code, user_agent, referer, query_data, form_data, json_data,
                    raw_record, normalized_payload, login_result, blocked
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    timestamp,
                    "10.10.10.81",
                    "10.10.10.81",
                    "GET",
                    "/traffic-demo",
                    "/traffic-demo",
                    200,
                    "unit-test",
                    "/",
                    "{}",
                    "{}",
                    "{}",
                    "{}",
                    "/traffic-demo",
                    None,
                    0,
                ),
            )
            db.commit()
        finally:
            db.close()

        push_connection_events_to_pipeline([build_connection_event("10.10.10.81", "127.0.0.1", 443)])

        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertEqual(len(data["trafficByHour"]), 24)
        self.assertEqual(sum(item["request_total"] for item in data["trafficByHour"]), 1)
        self.assertEqual(sum(item["connection_total"] for item in data["trafficByHour"]), 1)
        self.assertTrue(any(item["request_total"] == 1 and item["connection_total"] == 1 for item in data["trafficByHour"]))
        self.assertEqual(sum(item["total"] for item in data["requestsByHour"]), 1)
        self.assertEqual(len(data["trafficRealtime"]), 60)
        self.assertEqual(sum(item["request_total"] for item in data["trafficRealtime"]), 1)
        self.assertEqual(sum(item["connection_total"] for item in data["trafficRealtime"]), 1)
        self.assertTrue(any(item["request_total"] == 1 and item["connection_total"] == 1 for item in data["trafficRealtime"]))
        self.assertEqual(data["recentConnectionSummary"], {"total": 1, "unique_sources": 1, "unique_target_ports": 1})
        self.assertEqual(data["topConnectionSources"], [{"ip": "10.10.10.81", "total": 1}])
        self.assertEqual(data["topTargetPorts"], [{"port": 443, "total": 1}])

    def test_stats_api_summarizes_recent_connection_sources_ports_and_portscan_alerts(self):
        records = [
            build_connection_event("10.10.10.90", "127.0.0.1", 22),
            build_connection_event("10.10.10.90", "127.0.0.1", 80),
            build_connection_event("10.10.10.91", "127.0.0.1", 80),
        ]
        push_connection_events_to_pipeline(records)
        db = self.get_db()
        try:
            db.execute(
                """
                INSERT INTO attack_events(
                    created_at, source_ip, attack_type, severity, score,
                    threshold_value, matched_rules, request_path, summary
                )
                VALUES (?, ?, 'port_scan', 'high', 20, 20, ?, ?, ?)
                """,
                (
                    to_iso(utc_now()),
                    "10.10.10.90",
                    "[]",
                    "tcp://127.0.0.1",
                    "unit test port scan",
                ),
            )
            db.commit()
        finally:
            db.close()

        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertEqual(data["recentConnectionSummary"], {"total": 3, "unique_sources": 2, "unique_target_ports": 2})
        self.assertEqual(data["topConnectionSources"][0], {"ip": "10.10.10.90", "total": 2})
        self.assertIn({"ip": "10.10.10.91", "total": 1}, data["topConnectionSources"])
        self.assertEqual(data["topTargetPorts"][0], {"port": 80, "total": 2})
        self.assertIn({"port": 22, "total": 1}, data["topTargetPorts"])
        self.assertEqual(data["recentPortScanAlerts"], {"total": 1, "highest_severity": "high"})

    def test_connection_events_are_persisted(self):
        push_connection_events_to_pipeline([build_connection_event("10.10.10.66", "192.168.1.10", 22)])

        db = self.get_db()
        try:
            total = db.execute("SELECT COUNT(*) AS total FROM connection_events").fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(total, 1)

    def test_connection_event_api_and_portscan_lab_are_removed(self):
        response = self.client.post(
            "/api/connection-events",
            json={"source_ip": "10.10.10.90", "target_ip": "192.168.1.10", "target_port": 22},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 404)

        response = self.client.post(
            "/lab/portscan",
            data={"demo_ip": "10.10.10.90", "start_port": "20", "end_port": "24"},
            headers=JSON_HEADERS,
        )
        self.assertEqual(response.status_code, 404)

    def test_admin_home_no_longer_shows_portscan_simulator(self):
        response = self.client.get("/ops")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertNotIn("portscan-form", body)
        self.assertNotIn("提交端口扫描", body)

    def test_portscan_capture_parses_inbound_tcp_syn(self):
        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            self.skipTest("scapy is not installed")

        packet = IP(src="10.10.10.90", dst="192.168.1.10") / TCP(dport=22, flags="S")
        event = packet_to_connection_event(packet, local_ips={"192.168.1.10"})

        self.assertIsNotNone(event)
        self.assertEqual(event["source_ip"], "10.10.10.90")
        self.assertEqual(event["target_ip"], "192.168.1.10")
        self.assertEqual(event["target_port"], 22)
        self.assertEqual(event["protocol"], "tcp")
        self.assertEqual(event["source_kind"], "npcap")

    def test_portscan_capture_ignores_non_probe_packets(self):
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            self.skipTest("scapy is not installed")

        local_ips = {"192.168.1.10"}
        ack_packet = IP(src="10.10.10.90", dst="192.168.1.10") / TCP(dport=22, flags="SA")
        outbound_packet = IP(src="192.168.1.10", dst="10.10.10.90") / TCP(dport=22, flags="S")
        other_target_packet = IP(src="10.10.10.90", dst="192.168.1.11") / TCP(dport=22, flags="S")
        udp_packet = IP(src="10.10.10.90", dst="192.168.1.10") / UDP(dport=53)

        self.assertIsNone(packet_to_connection_event(ack_packet, local_ips=local_ips))
        self.assertIsNone(packet_to_connection_event(outbound_packet, local_ips=local_ips))
        self.assertIsNone(packet_to_connection_event(other_target_packet, local_ips=local_ips))
        self.assertIsNone(packet_to_connection_event(udp_packet, local_ips=local_ips))

    def test_portscan_below_threshold_creates_no_alert(self):
        push_connection_events_to_pipeline(self.build_connection_events("10.10.10.70", "192.168.1.10", 20, 24))

        db = self.get_db()
        try:
            total = db.execute(
                "SELECT COUNT(*) AS total FROM attack_events WHERE attack_type = 'port_scan' AND source_ip = ?",
                ("10.10.10.70",),
            ).fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(total, 0)

    def test_portscan_alert_counts_unique_ports_per_target(self):
        push_connection_events_to_pipeline(self.build_connection_events("10.10.10.71", "192.168.1.10", 30, 39))

        db = self.get_db()
        try:
            row = db.execute(
                """
                SELECT severity, score, threshold_value, request_path
                FROM attack_events
                WHERE attack_type = 'port_scan' AND source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.71",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "medium")
        self.assertEqual(row["score"], 10)
        self.assertEqual(row["threshold_value"], 10)
        self.assertEqual(row["request_path"], "tcp://192.168.1.10")

    def test_portscan_deduplicates_repeated_ports(self):
        records = [build_connection_event("10.10.10.72", "192.168.1.10", 80) for _ in range(12)]
        push_connection_events_to_pipeline(records)

        db = self.get_db()
        try:
            events = db.execute("SELECT COUNT(*) AS total FROM connection_events WHERE source_ip = ?", ("10.10.10.72",)).fetchone()["total"]
            alerts = db.execute(
                "SELECT COUNT(*) AS total FROM attack_events WHERE attack_type = 'port_scan' AND source_ip = ?",
                ("10.10.10.72",),
            ).fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(events, 12)
        self.assertEqual(alerts, 0)

    def test_portscan_does_not_mix_targets(self):
        first_target = [build_connection_event("10.10.10.73", "192.168.1.10", port) for port in range(100, 106)]
        second_target = [build_connection_event("10.10.10.73", "192.168.1.11", port) for port in range(200, 206)]
        push_connection_events_to_pipeline(first_target + second_target)

        db = self.get_db()
        try:
            total = db.execute(
                "SELECT COUNT(*) AS total FROM attack_events WHERE attack_type = 'port_scan' AND source_ip = ?",
                ("10.10.10.73",),
            ).fetchone()["total"]
        finally:
            db.close()
        self.assertEqual(total, 0)

    def test_portscan_high_threshold_auto_blocks_source(self):
        push_connection_events_to_pipeline(self.build_connection_events("10.10.10.74", "192.168.1.10", 40, 59))

        db = self.get_db()
        try:
            alert = db.execute(
                """
                SELECT severity, auto_blocked
                FROM attack_events
                WHERE attack_type = 'port_scan' AND source_ip = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                ("10.10.10.74",),
            ).fetchone()
            blacklist = db.execute("SELECT active FROM blacklist WHERE source_ip = ?", ("10.10.10.74",)).fetchone()
            port_block = db.execute(
                "SELECT active FROM port_blocks WHERE source_ip = ? AND trigger_attack_type = 'port_scan'",
                ("10.10.10.74",),
            ).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["auto_blocked"], 1)
        self.assertIsNotNone(blacklist)
        self.assertEqual(blacklist["active"], 1)
        self.assertIsNotNone(port_block)
        self.assertEqual(port_block["active"], 1)

    def test_portscan_route_contributes_to_connection_traffic_curve(self):
        push_connection_events_to_pipeline(self.build_connection_events("10.10.10.75", "192.168.1.10", 50, 54))

        stats_response = self.client.get("/api/stats")
        self.assertEqual(stats_response.status_code, 200)
        data = stats_response.get_json()

        self.assertEqual(sum(item["connection_total"] for item in data["trafficByHour"]), 5)
        self.assertTrue(any(item["connection_total"] == 5 for item in data["trafficByHour"]))
        self.assertEqual(sum(item["connection_total"] for item in data["trafficRealtime"]), 5)
        self.assertTrue(any(item["connection_total"] == 5 for item in data["trafficRealtime"]))


if __name__ == "__main__":
    unittest.main()
