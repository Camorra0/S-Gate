import json
import sys
import os

REPORTS_DIR = "/home/server/devsecops-project/reports"
BLOCKING_LEVELS = ["High", "Critical"]

def get_latest_report():
    files = sorted([
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith("zap_report") and f.endswith(".json")
    ])
    if not files:
        print("[!] No reports found.")
        sys.exit(1)
    latest = os.path.join(REPORTS_DIR, files[-1])
    print(f"[*] Checking report: {latest}")
    return latest

def check_policy(report_path):
    with open(report_path) as f:
        data = json.load(f)

    findings = {"Critical": [], "High": [], "Medium": [], "Low": [], "Informational": []}

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0]
            name = alert.get("name", "Unknown")
            if risk in findings:
                findings[risk].append(name)

    print("\n========== POLICY CHECK ==========")
    for level, items in findings.items():
        icon = "🔴" if level in ("Critical", "High") else "🟡" if level == "Medium" else "🟢"
        print(f"{icon} {level}: {len(items)}")
        for item in items:
            print(f"     - {item}")

    blocking = []
    for level in BLOCKING_LEVELS:
        blocking.extend(findings[level])

    print("\n========== DECISION ==========")
    if blocking:
        print(f"❌ DEPLOYMENT BLOCKED — {len(blocking)} critical issue(s) found!")
        for item in blocking:
            print(f"   → {item}")
        sys.exit(1)
    else:
        print("✅ DEPLOYMENT ALLOWED — No critical issues found.")
        sys.exit(0)

if __name__ == "__main__":
    report = get_latest_report()
    check_policy(report)
