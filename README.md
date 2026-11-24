<div align="center">

# Personal Network Intrusion Detection System (NIDS)

**A lightweight, rule-based NIDS that captures live traffic, flags suspicious patterns, and shows alerts on a web dashboard.**

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Capture-2b5b84)
![Flask](https://img.shields.io/badge/Flask-Dashboard-black?logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Alert_Store-003b57?logo=sqlite)
![Status](https://img.shields.io/badge/status-learning_project-yellow)

</div>

---

## Why I built this

I wanted to understand intrusion detection from the packet up rather than only through tools like Snort or Splunk. This project captures raw traffic with Scapy, applies simple detection rules, stores alerts in SQLite, and serves them through a Flask dashboard. The full path from **capture → detect → store → visualize** is in a few readable files.

## What it detects

| Rule | Protocol | Trigger |
| --- | --- | --- |
| **IP flood** | TCP | A single source IP sends more than 10 packets |
| **Port scan** | TCP | A single source IP touches more than 10 distinct destination ports |
| **Uncommon UDP port** | UDP | Traffic to a port outside the known-services list (HTTP, HTTPS, SSH, Telnet, FTP, DNS, SMB) |
| **ICMP flood** | ICMP | A single source IP sends more than 10 ICMP packets |

Thresholds are intentionally simple and count for the whole session. They are not time-windowed, so this is a learning tool, not a production IDS.

## Architecture

```text
  Network interface
        │  (Scapy sniff, filter="ip")
        ▼
  sniffer.py ── detection rules ──► alerts.db (SQLite)
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
              read_alerts.py                         dashboard.py
            (CLI alert report)                 (Flask web dashboard)
```

| File | Purpose |
| --- | --- |
| `make_database.py` | Creates the `alerts` table in `alerts.db` |
| `sniffer.py` | Captures packets and writes alerts for TCP, UDP, and ICMP rules |
| `read_alerts.py` | Prints stored alerts in the terminal |
| `dashboard.py` + `templates/dashboard.html` | Serves alerts as a web table at `http://127.0.0.1:5000` |
| `seed_sample_alerts.py` | Resets the database with sample alerts for a demo without live capture |

## Quick start

```bash
git clone https://github.com/dware11/Personal-NIDS-Project.git
cd Personal-NIDS-Project
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python make_database.py        # create the database
sudo python sniffer.py         # live capture (needs admin/root; Ctrl+C to stop)
python dashboard.py            # open http://127.0.0.1:5000
```

No traffic to test with? Run `python seed_sample_alerts.py`, then `python dashboard.py`.

> On Windows, live capture needs [Npcap](https://npcap.com/) and an Administrator terminal. Only capture traffic on networks you own or have permission to monitor.

## What I learned

- How TCP, UDP, and ICMP headers are parsed at the packet level with Scapy
- How port scans and floods look in raw traffic, and why fixed thresholds cause false positives
- Storing and querying security events with SQLite and parameterized queries
- Connecting a capture pipeline to a simple Flask front end

## Next steps

- [ ] Time-windowed thresholds (e.g., packets per source per 10 seconds) to cut false positives
- [ ] One alert per incident instead of one per packet after the threshold
- [ ] SYN-scan detection using TCP flags
- [ ] Auto-refreshing dashboard with filters by alert type and source
- [ ] Map alerts to MITRE ATT&CK techniques (T1046 Network Service Discovery, T1498 Network DoS)
