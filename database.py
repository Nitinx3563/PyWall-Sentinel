"""
database.py
-----------
SQLite Database setup for Firewall Rules and Traffic Logs.

Yeh file 2 tables handle karegi:
1. rules: User ke defined firewall rules (e.g. ALLOW HTTP, ALLOW DNS)
2. traffic_logs: Har inspected packet ka record (timestamp, 5-tuple, status ALLOW/BLOCK, reason)
"""

import sqlite3
import os

# Vercel serverless environment strictly allows file writes only in /tmp
if os.environ.get("VERCEL"):
    DB_FILE = "/tmp/firewall.db"
else:
    DB_FILE = os.path.join(os.path.dirname(__file__), "firewall.db")


def get_db_connection():
    """Database connection return karta hai with row access by column name."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Tables create karta hai agar pehle se exist nahi karti hain, aur default rules insert karta hai."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Rules Table: Firewall ke filter rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT '*',
        src_ip TEXT NOT NULL DEFAULT '*',
        dst_ip TEXT NOT NULL DEFAULT '*',
        dst_port TEXT NOT NULL DEFAULT '*',
        action TEXT NOT NULL DEFAULT 'ALLOW',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Traffic Logs Table: Har packet ka audit trail
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        protocol TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        src_port INTEGER NOT NULL,
        dst_ip TEXT NOT NULL,
        dst_port INTEGER NOT NULL,
        action TEXT NOT NULL,
        matched_rule TEXT NOT NULL
    );
    """)

    # Check agar rules table empty hai, toh initial basic rules add karte hain
    cursor.execute("SELECT COUNT(*) as count FROM rules")
    count = cursor.fetchone()["count"]

    if count == 0:
        default_rules = [
            ("Allow Web HTTP", "TCP", "*", "*", "80", "ALLOW"),
            ("Allow Web HTTPS", "TCP", "*", "*", "443", "ALLOW"),
            ("Allow DNS Queries", "UDP", "*", "*", "53", "ALLOW"),
            ("Allow SSH to Internal Server", "TCP", "192.168.1.*", "192.168.1.100", "22", "ALLOW"),
        ]
        cursor.executemany("""
        INSERT INTO rules (rule_name, protocol, src_ip, dst_ip, dst_port, action)
        VALUES (?, ?, ?, ?, ?, ?)
        """, default_rules)

    conn.commit()
    conn.close()


def get_all_rules():
    """Saare firewall rules fetch karta hai."""
    conn = get_db_connection()
    rules = conn.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
    conn.close()
    return rules


def add_rule(rule_name, protocol, src_ip, dst_ip, dst_port, action="ALLOW"):
    """Naya rule insert karta hai."""
    conn = get_db_connection()
    conn.execute("""
    INSERT INTO rules (rule_name, protocol, src_ip, dst_ip, dst_port, action)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        rule_name.strip(),
        protocol.strip().upper(),
        src_ip.strip(),
        dst_ip.strip(),
        dst_port.strip(),
        action.strip().upper()
    ))
    conn.commit()
    conn.close()


def delete_rule(rule_id):
    """Rule ID ke basis par rule delete karta hai."""
    conn = get_db_connection()
    conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def log_packet(packet, action, matched_rule):
    """Inspected packet ko database traffic_logs me store karta hai."""
    conn = get_db_connection()
    conn.execute("""
    INSERT INTO traffic_logs (protocol, src_ip, src_port, dst_ip, dst_port, action, matched_rule)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        packet["protocol"],
        packet["src_ip"],
        packet["src_port"],
        packet["dst_ip"],
        packet["dst_port"],
        action,
        matched_rule
    ))
    conn.commit()
    conn.close()


def get_recent_logs(limit=50):
    """Latest traffic logs fetch karta hai."""
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return logs


def get_traffic_stats():
    """Dashboard metrics ke liye total, allowed, blocked counts calculate karta hai."""
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM traffic_logs").fetchone()["c"]
    allowed = conn.execute("SELECT COUNT(*) as c FROM traffic_logs WHERE action = 'ALLOW'").fetchone()["c"]
    blocked = conn.execute("SELECT COUNT(*) as c FROM traffic_logs WHERE action = 'BLOCK'").fetchone()["c"]
    conn.close()
    return {"total": total, "allowed": allowed, "blocked": blocked}


def clear_logs():
    """Testing ke liye logs reset/clear karta hai."""
    conn = get_db_connection()
    conn.execute("DELETE FROM traffic_logs")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
    print(f"Total Rules: {len(get_all_rules())}")
