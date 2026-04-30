"""Public honeypot-facing routes."""

from flask import g, jsonify, render_template, request


def register_public_routes(app):
    @app.route("/")
    def index():
        return render_template(
            "honeypot_index.html",
            current_ip=getattr(g, "effective_ip", request.remote_addr or "0.0.0.0"),
        )

    @app.route("/portal", methods=["GET", "POST"])
    def portal():
        username = ""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            g.login_result = "success" if username == "employee" and password == "Spring2026!" else "failure"
            return render_template(
                "portal.html",
                username=username,
                message="欢迎回来。" if g.login_result == "success" else "用户名或密码错误。",
                tone="success" if g.login_result == "success" else "warning",
            )
        return render_template("portal.html", username=username)

    @app.route("/search", methods=["GET"])
    def search():
        query = request.args.get("q", "")
        results = []
        if query.strip():
            results = [
                {"title": "季度访问控制策略", "snippet": f"已接收查询关键词：{query}"},
                {"title": "合作方接入指引", "snippet": "内部文档预览暂不可用。"},
            ]
        return render_template("search.html", query=query, results=results)

    @app.route("/contact", methods=["GET", "POST"])
    def contact():
        submitted = request.method == "POST"
        return render_template("contact.html", submitted=submitted)

    @app.route("/health")
    def health():
        return jsonify({"ok": True, "service": "lan-honeypot", "message": "服务运行正常"})

    @app.route("/admin")
    def admin_probe():
        return ("管理员控制台暂不可用。", 404)

    @app.route("/phpmyadmin")
    def phpmyadmin_probe():
        return ("禁止访问。", 404)

    @app.route("/.env")
    def env_probe():
        return ("文件不存在。", 404)

    @app.route("/<path:subpath>", methods=["GET", "POST"])
    def catch_all(subpath):
        return (f"路径 /{subpath} 不存在。", 404)
