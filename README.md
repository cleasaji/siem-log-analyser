# SIEM Log Analyser & Alert Correlator

A lightweight SIEM (Security Information and Event Management) prototype that ingests Windows Event Logs and syslog streams, applies Sigma detection rules, and generates prioritised alerts tagged with MITRE ATT&CK techniques.

## What it does

- Parses Windows Event Logs (.evtx) and Linux syslog files
- Applies Sigma detection rules to identify suspicious patterns
- Tags each alert with the corresponding MITRE ATT&CK Tactic and Technique ID
- Correlates related events across a time window to reduce alert fatigue
- Outputs prioritised alerts (Critical / High / Medium / Low)
- Includes a Kibana dashboard template for visual monitoring

## Tech Stack

| Component | Technology |
|---|---|
| Log parsing | Python 3, python-evtx, re |
| Detection rules | Sigma (YAML rule format) |
| Alert correlation | Python (time-window grouping) |
| Storage | Elasticsearch (ELK Stack) |
| Visualisation | Kibana dashboard |
| Output | JSON, CSV, terminal |

## Project Structure

```
siem-log-analyser/
├── ingest/
│   ├── evtx_parser.py       # Windows Event Log parser
│   └── syslog_parser.py     # Linux syslog parser
├── detection/
│   ├── sigma_engine.py      # Sigma rule loader and matcher
│   └── rules/               # Sigma YAML detection rules
│       ├── brute_force.yml
│       ├── lateral_movement.yml
│       └── privilege_escalation.yml
├── correlator.py            # Time-window event correlation
├── attck_mapper.py          # MITRE ATT&CK technique tagger
├── alerter.py               # Alert prioritisation and output
├── kibana_dashboard.json    # Import this into Kibana
├── requirements.txt
└── README.md
```

## How to Run

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/siem-log-analyser.git
cd siem-log-analyser

# 2. Install dependencies
pip install -r requirements.txt

# 3. Analyse a Windows Event Log file
python alerter.py --input logs/security.evtx --type evtx

# 4. Analyse a syslog file
python alerter.py --input logs/auth.log --type syslog

# 5. Output to JSON
python alerter.py --input logs/security.evtx --output alerts.json
```

## Example Alert Output

```
[CRITICAL] Brute Force Login Attempt Detected
  ATT&CK Technique : T1110.001 - Password Guessing
  Tactic           : Credential Access
  Source IP        : 10.0.0.44
  Target Account   : Administrator
  Event Count      : 47 failed logins in 60 seconds
  Time Window      : 2026-06-15 14:32:10 → 14:33:10
  Recommended Action: Block IP, force password reset

[HIGH] Suspicious PowerShell Execution
  ATT&CK Technique : T1059.001 - PowerShell
  Tactic           : Execution
  Host             : DESKTOP-AB12CD
  Command          : powershell -enc JABjAGwAaQBlA...
  Event ID         : 4104
```

## Sigma Rule Example

```yaml
title: Brute Force Login Attempt
status: stable
description: Detects multiple failed login attempts within a short time window
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 1m
  condition: selection | count() > 10
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
```

## Kibana Dashboard

Import `kibana_dashboard.json` into your Kibana instance to get:
- Alert volume over time
- Top source IPs by alert count
- ATT&CK technique heatmap
- Critical alerts feed

## Requirements

```
python-evtx
pyyaml
elasticsearch
requests
pandas
```
