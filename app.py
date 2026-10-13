"""
app.py
------
Flask Web Dashboard for PyWall (Python Firewall).

Features:
1. Dashboard View: Live statistics, configured rules, and inspected packet logs.
2. Rule Management: Add new 5-tuple firewall rules dynamically.
3. Traffic Simulator Integration: Button click se direct fake packets generate karke test kar sakte hain.
4. Clean, cybersecurity-themed Web UI.
"""

from flask import Flask, render_template, request, redirect, url_for
from database import (
    init_db,
    get_all_rules,
    add_rule,
    delete_rule,
    get_recent_logs,
    get_traffic_stats,
    clear_logs as db_clear_logs
)
from traffic_simulator import run_single_burst

app = Flask(__name__)


@app.route("/")
def index():
    """Main dashboard page."""
    rules = get_all_rules()
    logs = get_recent_logs(limit=50)
    stats = get_traffic_stats()
    msg = request.args.get("msg")
    return render_template("index.html", rules=rules, logs=logs, stats=stats, message=msg)


@app.route("/add_rule", methods=["POST"])
def route_add_rule():
    """Naya rule create karta hai."""
    rule_name = request.form.get("rule_name")
    protocol = request.form.get("protocol")
    src_ip = request.form.get("src_ip", "*")
    dst_ip = request.form.get("dst_ip", "*")
    dst_port = request.form.get("dst_port", "*")
    action = request.form.get("action", "ALLOW")

    add_rule(rule_name, protocol, src_ip, dst_ip, dst_port, action)
    return redirect(url_for("index", msg=f"Rule '{rule_name}' successfully added!"))


@app.route("/delete_rule/<int:rule_id>", methods=["POST"])
def route_delete_rule(rule_id):
    """Rule delete karta hai."""
    delete_rule(rule_id)
    return redirect(url_for("index", msg=f"Rule #{rule_id} deleted."))


@app.route("/simulate", methods=["POST"])
def route_simulate():
    """Web UI se traffic simulator run karta hai."""
    count = int(request.form.get("count", 6))
    run_single_burst(count=count)
    return redirect(url_for("index", msg=f"Successfully simulated {count} packets through the firewall engine!"))


@app.route("/clear_logs", methods=["POST"])
def route_clear_logs():
    """Audit logs reset karta hai."""
    db_clear_logs()
    return redirect(url_for("index", msg="Audit logs cleared."))


if __name__ == "__main__":
    init_db()
    print("\n" + "="*50)
    print("🛡️  PyWall Web Dashboard is running!")
    print("🌐  Open your browser at: http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
