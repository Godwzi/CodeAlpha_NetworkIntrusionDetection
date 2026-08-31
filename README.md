# CodeAlpha Network Intrusion Detection System

A working network intrusion detection setup built with Suricata on an Ubuntu VM, with custom detection rules and alerts visualized through Wazuh.

I wanted to actually go through the process of standing up an IDS end-to-end rather than just reading about how one works — getting the interface config right, writing rules that actually match traffic, and wiring the alerts into a dashboard I could search through. Built as part of the CodeAlpha Cyber Security Internship.

## What it does

- Captures and inspects live network traffic on a VM
- Detects a handful of common recon/exploitation patterns (ping sweeps, port scans, reverse shell connections, suspicious HTTP clients) using rules I wrote myself
- Logs alerts in real time to `fast.log` and `eve.json`
- Forwards those alerts into Wazuh so they're searchable and visible on a dashboard, not just buried in a log file

---

## Environment

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

## Topology

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

## Setup

### 1. Install Suricata
```bash
sudo apt install suricata -y
sudo suricata-update
```
This pulled the Emerging Threats Open ruleset — 68,538 rules, 52,592 enabled by default.

### 2. Fix the network interface
First thing that tripped me up: Suricata's default config listens on `eth0`, which doesn't exist on this VM — the interface here is actually `enp0s1`. Suricata will happily report as "running" via systemd even with the wrong interface, it just silently captures nothing. Took a bit to notice the log was empty despite the service being "active." Fixed it in `/etc/suricata/suricata.yaml`:
```yaml
af-packet:
  - interface: enp0s1   # was eth0
```

### 3. Write custom detection rules
Created `/var/lib/suricata/rules/local.rules` — worth noting this is Suricata's actual `default-rule-path`, which is *not* the same as `/etc/suricata/rules/` (that folder looks like the obvious place to put rules but isn't scanned by default, which cost me some debugging time too). Wrote 4 custom signatures:

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

### 5. Add Wazuh for visualization
I already had Wazuh (manager + indexer + dashboard, single-node) set up on the same VM from earlier work, so this was mostly about wiring Suricata's alerts into it rather than a from-scratch install. Added a `<localfile>` block to `/var/ossec/etc/ossec.conf` so the manager reads Suricata's JSON alert log directly:
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

## Testing & evidence

I tested each rule individually and traced it through three levels: traffic generated → Suricata alert → Wazuh dashboard.

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
Screenshot: `screenshots/01-ping-and-nmap-traffic.png`

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
Screenshot: `screenshots/02-full-test-sequence-traffic.png`

### Cleaning up for a clear test run
The log had picked up a fair amount of background noise by this point (mostly Spotify's P2P broadcast traffic on the LAN), so to get a clean, readable capture I stopped Suricata, truncated the log, and restarted it before re-running all 4 tests back to back:
```bash
sudo systemctl stop suricata
sudo truncate -s 0 /var/log/suricata/fast.log
sudo systemctl start suricata
```
```bash
grep "CUSTOM" /var/log/suricata/fast.log
```
Screenshots:
- `screenshots/03-all-custom-rules-fastlog.png` — filtered output showing all 4 custom rules firing across multiple test runs
- `screenshots/06-clean-log-reset-and-retest.png` — the full stop/truncate/restart/retest sequence
- `screenshots/07-live-tail-with-truncation-marker.png` — live `tail -f` output, including the `file truncated` marker confirming the clean reset

---

## Dashboard visualization (Wazuh)

All Suricata alerts, including all 4 custom rules, show up in Wazuh's **Threat Hunting** module and are searchable:

- **Search query:** `suricata`
- **Fields shown:** timestamp, agent name, rule description, severity level, rule ID
- Custom alerts land under a unified Wazuh rule ID (`86601`) but keep the original Suricata message intact — e.g. *"Suricata: Alert - CUSTOM ICMP Ping Detected"*

Screenshots:
- `screenshots/04-dashboard-table-all-alerts.png` — events table showing all 4 custom alerts alongside system-level PAM/sudo audit events
- `screenshots/05-dashboard-histogram-and-table.png` — full view with the alert-frequency histogram above the table

This covers the optional bonus objective in the task brief — visualizing detected attacks via a dashboard.

---

## Response steps

If this were a real intrusion rather than a test, here's the workflow I'd follow after an alert fires:

1. **Identify** — cross-reference the `fast.log` timestamp and rule ID against the matching Wazuh dashboard event
2. **Classify severity** — Wazuh assigns a rule level automatically (all 4 custom alerts came in at level 3, low-moderate) alongside Suricata's own priority field
3. **Investigate the source** — check the source IP against expected hosts on the local network
4. **Contain, if it's actually malicious** — block the source IP (`iptables`/`ufw`), isolate the affected host, dig into `eve.json` for full packet context
5. **Document it** — this README is effectively that documentation for the test scenarios above

---

## Repository structure

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

## Tools used

- [Suricata](https://suricata.io/) — the IDS/IPS engine doing the actual detection
- [Emerging Threats Open](https://rules.emergingthreats.net/) — the community ruleset it ships with
- [Wazuh](https://wazuh.com/) — log analysis and dashboard visualization
- Ubuntu 24.04 LTS, UTM, nmap, curl — everything else needed to build and test this

## About

Part of the CodeAlpha Cyber Security Internship — I'm completing 2-3 of the 4 available tasks. Check my other repos for the rest.
