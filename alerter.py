import re
import json
import argparse
from datetime import datetime
from collections import defaultdict

# --- SIGMA-style detection rules ---
RULES = [
    {
        "title": "Brute Force Login Attempt",
        "pattern": r"Failed password|authentication failure|FAILED LOGIN",
        "threshold": 5,
        "window_seconds": 60,
        "level": "CRITICAL",
        "attck_technique": "T1110.001",
        "attck_tactic": "Credential Access",
        "recommendation": "Block source IP, force password reset on targeted account"
    },
    {
        "title": "Suspicious PowerShell Execution",
        "pattern": r"powershell.*-enc|-EncodedCommand|Invoke-Expression|IEX\(",
        "threshold": 1,
        "window_seconds": 300,
        "level": "HIGH",
        "attck_technique": "T1059.001",
        "attck_tactic": "Execution",
        "recommendation": "Investigate PowerShell history, check for malware"
    },
    {
        "title": "Privilege Escalation Attempt",
        "pattern": r"sudo|su root|privilege escalation|UAC bypass",
        "threshold": 3,
        "window_seconds": 120,
        "level": "HIGH",
        "attck_technique": "T1068",
        "attck_tactic": "Privilege Escalation",
        "recommendation": "Review user privileges, check for exploits"
    },
    {
        "title": "Port Scanning Detected",
        "pattern": r"SYN_RECV|port scan|nmap|masscan",
        "threshold": 10,
        "window_seconds": 30,
        "level": "MEDIUM",
        "attck_technique": "T1046",
        "attck_tactic": "Discovery",
        "recommendation": "Block scanning IP, review firewall rules"
    },
    {
        "title": "Malware / Suspicious Process",
        "pattern": r"mimikatz|meterpreter|nc\.exe|netcat|reverse shell",
        "threshold": 1,
        "window_seconds": 300,
        "level": "CRITICAL",
        "attck_technique": "T1003",
        "attck_tactic": "Credential Dumping",
        "recommendation": "Isolate host immediately, initiate incident response"
    },
]

LEVEL_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m"
}


def parse_log_file(filepath):
    lines = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append({"raw": line, "timestamp": datetime.utcnow().isoformat()})
    return lines


def analyse_logs(log_entries):
    alerts = []
    matches = defaultdict(list)

    for entry in log_entries:
        raw = entry["raw"]
        for rule in RULES:
            if re.search(rule["pattern"], raw, re.IGNORECASE):
                matches[rule["title"]].append(entry)

    for rule in RULES:
        matched = matches[rule["title"]]
        if len(matched) >= rule["threshold"]:
            alerts.append({
                "level":             rule["level"],
                "title":             rule["title"],
                "attck_technique":   rule["attck_technique"],
                "attck_tactic":      rule["attck_tactic"],
                "match_count":       len(matched),
                "recommendation":    rule["recommendation"],
                "sample_log":        matched[0]["raw"][:200]
            })

    alerts.sort(key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["level"]))
    return alerts


def print_alerts(alerts):
    if not alerts:
        print("\n[✓] No threats detected.\n")
        return

    print(f"\n{'='*60}")
    print(f"  SIEM ALERT REPORT — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}\n")

    for a in alerts:
        c = LEVEL_COLORS.get(a["level"], "")
        r = LEVEL_COLORS["RESET"]
        print(f"{c}[{a['level']}]{r} {a['title']}")
        print(f"  ATT&CK : {a['attck_technique']} — {a['attck_tactic']}")
        print(f"  Matches: {a['match_count']} log entries")
        print(f"  Action : {a['recommendation']}")
        print(f"  Sample : {a['sample_log'][:100]}")
        print()


def save_json(alerts, output):
    with open(output, "w") as f:
        json.dump({"generated": datetime.utcnow().isoformat(), "alerts": alerts}, f, indent=2)
    print(f"[*] Alerts saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIEM Log Analyser")
    parser.add_argument("--input",  required=True, help="Path to log file")
    parser.add_argument("--output", default=None,  help="Save alerts to JSON file")
    args = parser.parse_args()

    print(f"[*] Loading logs from {args.input} ...")
    entries = parse_log_file(args.input)
    print(f"[*] {len(entries)} log lines loaded. Running detection rules...")

    alerts = analyse_logs(entries)
    print_alerts(alerts)

    if args.output:
        save_json(alerts, args.output)
