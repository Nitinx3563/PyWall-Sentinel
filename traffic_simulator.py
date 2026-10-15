b"""
traffic_simulator.py
--------------------
Safe Network Traffic Simulator for Testing Python Firewall.

Networking Concept:
Real firewalls (jaise Linux iptables ya pfSense) network interface cards (NICs) se packets sniff karte hain.
Lekin testing ke liye hume root privileges ya real packets ki zarurat nahi hai!
Yeh script realistic simulated packets (HTTP, HTTPS, SSH, DNS, Telnet, Port Scans)
create karke firewall_core me bhejti hai.
"""

import time
import random
from firewall_core import inspect_packet


# Common Network Services & Test Scenarios
PACKET_TEMPLATES = [
    # 1. Normal Web Traffic (HTTP)
    {
        "service": "HTTP (Web Browsing)",
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "dst_ip": "93.184.216.34",
        "dst_port": 80
    },
    # 2. Secure Web Traffic (HTTPS)
    {
        "service": "HTTPS (Secure Web)",
        "protocol": "TCP",
        "src_ip": "192.168.1.45",
        "dst_ip": "142.250.190.46",
        "dst_port": 443
    },
    # 3. DNS Query (Google DNS)
    {
        "service": "DNS Lookup (Google DNS)",
        "protocol": "UDP",
        "src_ip": "192.168.1.45",
        "dst_ip": "8.8.8.8",
        "dst_port": 53
    },
    # 4. DNS Query (Cloudflare DNS)
    {
        "service": "DNS Lookup (Cloudflare)",
        "protocol": "UDP",
        "src_ip": "192.168.1.12",
        "dst_ip": "1.1.1.1",
        "dst_port": 53
    },
    # 5. Authorized Internal SSH
    {
        "service": "Internal SSH (Admin)",
        "protocol": "TCP",
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.100",
        "dst_port": 22
    },
    # 6. Unauthorized External SSH Attempt (Hacker scanning port 22)
    {
        "service": "External SSH Attempt (Suspicious)",
        "protocol": "TCP",
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.1.100",
        "dst_port": 22
    },
    # 7. Unencrypted Telnet (Insecure legacy protocol)
    {
        "service": "Telnet (Insecure)",
        "protocol": "TCP",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "dst_port": 23
    },
    # 8. Malicious C2 / Metasploit Reverse Shell Port
    {
        "service": "Metasploit / C2 Beacon Port",
        "protocol": "TCP",
        "src_ip": "192.168.1.77",
        "dst_ip": "185.220.101.5",
        "dst_port": 4444
    },
    # 9. Unauthorized Windows RDP
    {
        "service": "RDP Remote Desktop",
        "protocol": "TCP",
        "src_ip": "192.168.1.80",
        "dst_ip": "192.168.1.200",
        "dst_port": 3389
    },
    # 10. Database Connection attempt directly from outside
    {
        "service": "MySQL Database Port",
        "protocol": "TCP",
        "src_ip": "198.51.100.22",
        "dst_ip": "192.168.1.150",
        "dst_port": 3306
    }
]


def generate_random_packet():
    """Ek realistic simulated packet generate karta hai with random source port."""
    template = random.choice(PACKET_TEMPLATES)
    
    # Client machines random high port (ephemeral port range: 49152 - 65535) use karti hain
    client_port = random.randint(49152, 65535)

    packet = {
        "service": template["service"],
        "protocol": template["protocol"],
        "src_ip": template["src_ip"],
        "src_port": client_port,
        "dst_ip": template["dst_ip"],
        "dst_port": template["dst_port"]
    }
    return packet


def run_single_burst(count=8):
    """Specific number of packets simulate karta hai (useful for Web UI or quick test)."""
    results = []
    for _ in range(count):
        pkt = generate_random_packet()
        result = inspect_packet(pkt)
        results.append({
            "service": pkt["service"],
            "packet": pkt,
            "action": result["action"],
            "reason": result["reason"]
        })
    return results


def start_live_simulation(interval=1.0):
    """
    Continuous live traffic simulator. Terminal me real-time packets feed karega.
    Rukne ke liye Ctrl+C dabayein.
    """
    print("=" * 65)
    print("🛡️  PYTHON FIREWALL TRAFFIC SIMULATOR STARTED")
    print(f"⏱️  Generating 1 packet every {interval}s... Press Ctrl+C to stop.")
    print("=" * 65)

    try:
        packet_count = 0
        while True:
            packet_count += 1
            pkt = generate_random_packet()
            res = inspect_packet(pkt)

            action = res["action"]
            color_tag = "[ALLOW]" if action == "ALLOW" else "[BLOCK]"
            
            print(f"#{packet_count:03d} | {color_tag:<7} | {pkt['protocol']:<3} | "
                  f"{pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']} "
                  f"({pkt['service']}) | Reason: {res['reason']}")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Traffic simulation stopped by user.")


if __name__ == "__main__":
    import sys
    if "--live" in sys.argv:
        # Real-time continuous stream
        start_live_simulation(interval=1.0)
    else:
        # Default: Quick 5-packet burst
        print("--- Running Quick 5-Packet Burst Simulation ---")
        burst_results = run_single_burst(5)
        for r in burst_results:
            print(f"[{r['action']}] {r['packet']['protocol']} -> {r['packet']['dst_ip']}:{r['packet']['dst_port']} ({r['service']}) | {r['reason']}")
        print("\n💡 Tip: Real-time continuous packets stream dekhne ke liye yeh run karein:")
        print("   python traffic_simulator.py --live")
