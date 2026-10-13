"""
firewall_core.py
----------------
Firewall Core Logic and Rule Engine.

Networking Concepts:
1. Packet 5-Tuple:
   - Source IP: Sender ka address (kis machine se packet chala)
   - Destination IP: Target ka address (kahan pahunchna hai)
   - Source Port: Sender ka temporary (ephemeral) port (e.g., 51234)
   - Destination Port: Target service ka port (e.g., 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS)
   - Protocol: L4 Transport protocol (TCP, UDP, ICMP)

2. Strict "Default-Deny" Policy (Zero Trust):
   - Agar packet kisi ALLOW rule se match nahi hota, toh firewall use turant BLOCK / DROP karega.
   - "Anything not explicitly permitted is forbidden."
"""

import fnmatch
from database import get_all_rules, log_packet


def match_field(packet_val, rule_val):
    """
    Check karta hai ki packet ka value rule ke value se match hota hai ya nahi.
    - '*' ka matlab WILD-CARD (koi bhi value accept hogi).
    - fnmatch use karke '192.168.1.*' jaise patterns bhi match ho sakte hain.
    """
    rule_str = str(rule_val).strip()
    pack_str = str(packet_val).strip()

    # Rule me '*' hai to sab allowed
    if rule_str == "*":
        return True

    # Exact match ya wildcard pattern match (case-insensitive)
    return fnmatch.fnmatch(pack_str.lower(), rule_str.lower())


def match_port(packet_port, rule_port):
    """
    Port matching logic:
    - '*' -> Any port
    - '80' -> Exact port
    - '80,443' -> Multiple comma-separated ports
    - '8000-8080' -> Port range
    """
    rule_port_str = str(rule_port).strip()
    if rule_port_str == "*":
        return True

    pack_port_int = int(packet_port)

    # Comma separated ports (e.g., "80,443,8080")
    if "," in rule_port_str:
        ports = [int(p.strip()) for p in rule_port_str.split(",") if p.strip().isdigit()]
        return pack_port_int in ports

    # Port range (e.g., "8000-8080")
    if "-" in rule_port_str:
        parts = rule_port_str.split("-")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start_p, end_p = int(parts[0]), int(parts[1])
            return start_p <= pack_port_int <= end_p

    # Exact port
    if rule_port_str.isdigit():
        return pack_port_int == int(rule_port_str)

    return False


def evaluate_packet(packet, rules):
    """
    Core Rule Engine:
    Har packet ko active rules ke sath sequentially check karta hai (First-match principle).
    Agar koi rule match nahi hota, toh STRICT DEFAULT-DENY lagta hai.
    """
    for rule in rules:
        # 1. Protocol check
        if not match_field(packet["protocol"], rule["protocol"]):
            continue

        # 2. Source IP check
        if not match_field(packet["src_ip"], rule["src_ip"]):
            continue

        # 3. Destination IP check
        if not match_field(packet["dst_ip"], rule["dst_ip"]):
            continue

        # 4. Destination Port check
        if not match_port(packet["dst_port"], rule["dst_port"]):
            continue

        # Agar yahan tak aa gaya, matlab ye rule MATCH ho gaya!
        action = rule["action"].upper()
        rule_name = rule["rule_name"]
        reason = f"Rule #{rule['id']} '{rule_name}' matched"
        return action, reason

    # Agar loop khatam ho gaya aur koi ALLOW rule match nahi hua:
    # => STRICT DEFAULT-DENY POLICY!
    return "BLOCK", "Default-Deny Policy (No matching ALLOW rule)"


def inspect_packet(packet):
    """
    Public function: Packet ko evaluate karta hai aur audit log DB me save karta hai.
    
    Expected packet dictionary format:
    {
        'src_ip': '192.168.1.50',
        'src_port': 54321,
        'dst_ip': '142.250.190.46',
        'dst_port': 80,
        'protocol': 'TCP'
    }
    """
    # 1. Current active rules fetch karo
    rules = get_all_rules()

    # 2. Packet evaluate karo
    action, reason = evaluate_packet(packet, rules)

    # 3. Database me log record karo
    log_packet(packet, action, reason)

    return {
        "packet": packet,
        "action": action,
        "reason": reason
    }


if __name__ == "__main__":
    # Test sample packets
    from database import init_db
    init_db()

    print("--- Testing Firewall Core Engine ---")

    # Packet 1: HTTP Traffic (Should be ALLOWed based on default rules)
    p1 = {
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "src_port": 50123,
        "dst_ip": "93.184.216.34",
        "dst_port": 80
    }
    res1 = inspect_packet(p1)
    print(f"P1 (HTTP Port 80): {res1['action']} -> {res1['reason']}")

    # Packet 2: Telnet Traffic (Port 23 - Should be BLOCKED by Default-Deny)
    p2 = {
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "src_port": 50124,
        "dst_ip": "10.0.0.5",
        "dst_port": 23
    }
    res2 = inspect_packet(p2)
    print(f"P2 (Telnet Port 23): {res2['action']} -> {res2['reason']}")

    # Packet 3: DNS Traffic (UDP Port 53 - Should be ALLOWed)
    p3 = {
        "protocol": "UDP",
        "src_ip": "192.168.1.45",
        "src_port": 55100,
        "dst_ip": "8.8.8.8",
        "dst_port": 53
    }
    res3 = inspect_packet(p3)
    print(f"P3 (DNS Port 53): {res3['action']} -> {res3['reason']}")
