# CodeAlpha Network Intrusion Detection System

**Task 4 — CodeAlpha Cyber Security Internship**

A network-based intrusion detection system built with **Suricata**, running on an Ubuntu 24.04 LTS virtual machine, with custom detection rules and alert visualization through the **Wazuh** dashboard.

---

## 📋 Overview

This project sets up a fully functional Network Intrusion Detection System (NIDS) that:

- Captures and inspects live network traffic on a virtual machine
- Detects common reconnaissance and exploitation patterns (ping sweeps, port scans, reverse shell connections, suspicious HTTP clients) using custom Suricata rules
- Logs alerts in real time to `fast.log` and `eve.json`
- Forwards those alerts into Wazuh for centralized, searchable, dashboard-based visualization

---

## 🖥 Environment

| Component | Detail |
|---|---|
| Hypervisor | UTM (Apple Silicon / M1 Mac) |
| Guest OS | Ubuntu 24.04.4 LTS (arm64) |
| VM Memory | 6 GB (bumped from 4 GB to support Wazuh's indexer) |
| Network Interface | `enp0s1` |
| VM IP | `192.168.64.3` (DHCP, consistent) |
| Access | SSH (`ssh jerry@192.168.64.3`) |
| IDS Engine | Suricata 7.0.3 |
| Ruleset | Emerging Threats Open (68,538 rules, 52,592 enabled) + 4 custom rules |
| Visualization | Wazuh 4.14.4 (manager + indexer + dashboard, single-node) |

---

## 🗺 Topology

```
┌─────────────────┐         ┌──────────────────────────────────────┐
│   Attacker /     │  traffic │        Ubuntu VM (192.168.64.3)      │
│   Mac Host       │ ───────▶│  ┌────────────┐                       │
│ (ping, nmap,      │        │  │  Suricata   │──▶ fast.log           │
│  curl, netcat)    │        │  │ (enp0s1)    │──▶ eve.json ──┐        │
└─────────────────┘         │  └────────────┘              │        │
                              │                               ▼        │
                              │                    ┌────────────────┐ │
                              │                    │  Wazuh Manager  │ │
                              │                    │  (localfile     │ │
                              │                    │   reads eve.json)│ │
                              │                    └───────┬────────┘ │
                              │                            ▼          │
                              │                  ┌────────────────┐   │
                              │                  │ Wazuh Indexer   │   │
                              │                  └───────┬────────┘   │
                              │                          ▼            │
                              │                ┌────────────────┐     │
                              │                │ Wazuh Dashboard │     │
                              │                │ (https://VM_IP) │     │
                              │                └────────────────┘     │
                              └──────────────────────────────────────┘
```

---

## ⚙️ Setup Steps

### 1. Install Suricata
```bash
sudo apt install suricata -y
sudo suricata-update
```
Pulled the Emerging Threats Open ruleset — 68,538 rules, 52,592 enabled by default.

### 2. Fix the network interface
Suricata's default config listened on `eth0`, which doesn't exist on this VM (interface is actually `enp0s1`). Edited `/etc/suricata/suricata.yaml`:
```yaml
af-packet:
  - interface: enp0s1   # was eth0
```
Without this fix, Suricata reported as "running" but wasn't capturing any packets.

### 3. Write custom detection rules
Created `/var/lib/suricata/rules/local.rules` (Suricata's actual `default-rule-path` — note this differs from `/etc/suricata/rules/`, which is not scanned by default) with 4 custom signatures:

```
alert icmp any any -> $HOME_NET any (msg:"CUSTOM ICMP Ping Detected"; sid:1000001; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"CUSTOM Possible Nmap SYN Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 5; sid:1000002; rev:1;)

alert tcp any any -> $HOME_NET 4444 (msg:"CUSTOM Possible Metasploit Reverse Shell Port Access"; sid:1000003; rev:1;)

alert http any any -> $HOME_NET any (msg:"CUSTOM Suspicious User-Agent - curl"; http.user_agent; content:"curl"; sid:1000004; rev:1;)
```

Full file: [`rules/local.rules`](rules/local.rules)

| SID | Rule | Detects | Key logic |
|---|---|---|---|
| 1000001 | ICMP Ping Detected | Any ICMP echo request/reply to `$HOME_NET` | No qualifiers — fires on any ICMP traffic |
| 1000002 | Possible Nmap SYN Scan Detected | Rapid port scanning | `flags:S` (SYN packets only) + `threshold` — fires once 20+ SYNs are seen from one source within 5 seconds |
| 1000003 | Possible Metasploit Reverse Shell Port Access | Connection attempts to TCP port 4444, a well-known default Metasploit listener port | Scoped to destination port `4444` only |
| 1000004 | Suspicious User-Agent - curl | HTTP requests where the `User-Agent` header contains "curl" | Uses the `http.user_agent` sticky buffer with a `content` match |

Registered the ruleset in `suricata.yaml`:
```yaml
rule-files:
  - suricata.rules
  - local.rules
```

### 4. Verify and start
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
# → 2 rule files processed, 52596 rules successfully loaded, 0 failed

sudo systemctl restart suricata
sudo systemctl status suricata
# → active (running)
```

### 5. Set up Wazuh for visualization
Installed Wazuh 4.14.4 in single-node (all-in-one) mode — manager, indexer, and dashboard all on the same VM.

Wired Suricata's alert feed into Wazuh by adding a `<localfile>` block to `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
Restarted the manager to apply:
```bash
sudo systemctl restart wazuh-manager
```

---

## 🧪 Testing & Evidence

Each custom rule was individually triggered and confirmed at three levels: **traffic generated → Suricata alert → Wazuh dashboard visualization.**

### Test 1 — ICMP Ping (sid:1000001)
```bash
ping -c 3 192.168.64.3
```
**Result:** 2 alerts fired (echo request inbound + echo reply outbound).

### Test 2 — Nmap SYN Scan (sid:1000002)
```bash
sudo nmap -sS 192.168.64.3
```
**Result:** Default scan swept ~1,000 ports, including port 4444 — tripped both the general SYN-scan rule *and* the Metasploit port rule in a single scan.
> 📸 `screenshots/01-ping-and-nmap-traffic.png`

### Test 3 — Metasploit Reverse Shell Port (sid:1000003)
Confirmed via the same nmap scan above (port 4444 was included in the swept range).

### Test 4 — Suspicious curl User-Agent (sid:1000004)
Required a listener on the target port so the TCP handshake and HTTP request could complete:
```bash
# On the VM:
sudo python3 -m http.server 80

# From the attacker machine:
curl -A "curl-suspicious-agent-test" http://192.168.64.3/
```
**Result:** Alert fired on the flagged User-Agent string.
> 📸 `screenshots/02-full-test-sequence-traffic.png`

### Clean, isolated re-test
To capture clean evidence without background network noise, the Suricata log was stopped, truncated, and restarted, then all 4 tests were re-run back to back:
```bash
sudo systemctl stop suricata
sudo truncate -s 0 /var/log/suricata/fast.log
sudo systemctl start suricata
```
```bash
grep "CUSTOM" /var/log/suricata/fast.log
```
> 📸 `screenshots/03-all-custom-rules-fastlog.png` — filtered output showing all 4 custom rules firing across multiple test runs
> 📸 `screenshots/06-clean-log-reset-and-retest.png` — the full stop/truncate/restart/retest sequence
> 📸 `screenshots/07-live-tail-with-truncation-marker.png` — live `tail -f` output, including the `file truncated` marker confirming the clean reset

---

## 📊 Dashboard Visualization (Wazuh)

All Suricata alerts — including all 4 custom rules — are searchable and visualized in the Wazuh **Threat Hunting** module:

- **Search query:** `suricata`
- **Fields shown:** timestamp, agent name, rule description, severity level, rule ID
- Custom alerts appear under a unified Wazuh rule ID (`86601`) with the original Suricata rule description preserved (e.g. *"Suricata: Alert - CUSTOM ICMP Ping Detected"*)

> 📸 `screenshots/04-dashboard-table-all-alerts.png` — events table showing all 4 custom alerts alongside system-level PAM/sudo audit events
> 📸 `screenshots/05-dashboard-histogram-and-table.png` — full view with the alert-frequency histogram above the table

This satisfies the optional bonus objective of visualizing detected attacks via a dashboard.

---

## 🚨 Response Steps (Manual)

On receiving an alert, the following manual response workflow was followed and documented:

1. **Identify** — cross-reference `fast.log` timestamp + rule ID against the Wazuh dashboard event
2. **Classify severity** — Wazuh auto-assigns a rule level (all custom alerts registered at level 3 / low-moderate) alongside Suricata's own priority field
3. **Investigate source** — check source IP against known/expected hosts on the local network
4. **Contain (if malicious)** — for real intrusions, next steps would include blocking the source IP (`iptables`/`ufw`), isolating the affected host, and reviewing `eve.json` for full packet context
5. **Document** — record the incident, rule triggered, and response taken (this README serves as that documentation for the test scenarios above)

---

## 📁 Repository Structure

```
CodeAlpha_NetworkIntrusionDetection/
├── README.md
├── rules/
│   └── local.rules
├── config/
│   ├── suricata.yaml.diff       # interface fix
│   └── ossec.conf.snippet       # Wazuh localfile block
└── screenshots/
    ├── 01-ping-and-nmap-traffic.png
    ├── 02-full-test-sequence-traffic.png
    ├── 03-all-custom-rules-fastlog.png
    ├── 04-dashboard-table-all-alerts.png
    ├── 05-dashboard-histogram-and-table.png
    ├── 06-clean-log-reset-and-retest.png
    └── 07-live-tail-with-truncation-marker.png
```

---

## 🛠 Tools Used

- [Suricata](https://suricata.io/) — network IDS/IPS engine
- [Emerging Threats Open](https://rules.emergingthreats.net/) — community ruleset
- [Wazuh](https://wazuh.com/) — SIEM / log analysis and dashboard visualization
- Ubuntu 24.04 LTS, UTM, nmap, curl — testing and virtualization tooling

---

## 🎓 About

Completed as part of the **CodeAlpha Cyber Security Internship** — Task 4: Network Intrusion Detection System.

Other tasks completed as part of this internship: *(update as applicable)*
- [ ] Task 1 — Basic Network Sniffer
- [ ] Task 2 — Phishing Awareness Training

---

*This project is for educational purposes as part of an internship program.*
