# 🛡️ PyWall - Simple Python Network Firewall

Ek lightweight, educational Python packet-filtering firewall jo networking aur cybersecurity ke core concepts sikhane ke liye design kiya gaya hai.

---

## 📂 Project Structure

```text
NitinPython/
├── database.py             # SQLite setup, rules storage aur audit logs
├── firewall_core.py        # 5-tuple evaluation engine & Strict Default-Deny policy
├── traffic_simulator.py    # Safe synthetic packet generator (HTTP, DNS, SSH, Scans)
├── app.py                  # Flask Web Dashboard backend
├── templates/
│   └── index.html          # Sleek cybersecurity dark-mode UI
├── firewall.db             # Auto-generated SQLite database
└── requirements.txt        # Python dependencies (Flask)
```

---

## 🧠 Core Networking & Cybersecurity Concepts

1. **Packet 5-Tuple (Packet ki Identity):**
   - **Source IP**: Kis machine se packet generate hua.
   - **Destination IP**: Kis target computer ya server tak jana hai.
   - **Source Port**: Sender ka temporary ephemeral port (e.g. 52410).
   - **Destination Port**: Server ki service (e.g. `80`=HTTP, `443`=HTTPS, `22`=SSH, `53`=DNS, `3306`=MySQL).
   - **Protocol**: Layer 4 protocol (`TCP` reliable streams ke liye, `UDP` fast queries ke liye).

2. **Strict Default-Deny (Zero Trust Architecture):**
   - Firewall ka golden rule: *"Block everything unless explicitly permitted."*
   - Agar packet kisi ALLOW rule se match nahi hota, toh packet turant DROP/BLOCK ho jata hai.

3. **Safe Simulation (No Root / No Hardware Drivers Needed):**
   - Real firewalls (jaise Linux iptables, pfSense) real Network Interface Cards (NICs) se raw packets sniff karte hain.
   - Humara simulator realistic packet objects create karta hai taaki aap safely bina network disrupt kiye test kar sakein.

---

## 🚀 How to Run

### Step 1: Virtual Environment Activate karein (Windows PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 2: Option A - Web Dashboard Run karein (Recommended)
```powershell
python app.py
```
Browser open karein: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**
- Real-time allowed/blocked packet counters dekhein.
- Button dabakar simulated packets bhejein.
- Web UI se direct new firewall rules add/delete karein.

---

### Step 3: Option B - Live Terminal Traffic Simulator
Agar aapko continuous live packets console me stream hote huye dekhne hain:
```powershell
python traffic_simulator.py
```
*(Rokne ke liye `Ctrl + C` dabayein)*
