import json
import os
import sys
from datetime import datetime

REPORTS_DIR = "/home/server/devsecops-project/reports"

def get_all_reports():
    files = sorted([
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith("zap_report") and f.endswith(".json")
    ])
    return files

def parse_vulnerabilities(report_path):
    with open(report_path) as f:
        data = json.load(f)
    vulns = set()
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            name = alert.get("name", "Unknown")
            risk = alert.get("riskdesc", "").split(" ")[0]
            vulns.add(f"[{risk}] {name}")
    return vulns

def compare_reports(old_vulns, new_vulns):
    new_found = new_vulns - old_vulns
    fixed     = old_vulns - new_vulns
    remaining = old_vulns & new_vulns
    return new_found, fixed, remaining

def run_history():
    files = get_all_reports()

    if len(files) == 0:
        print("[!] No reports found.")
        sys.exit(1)

    if len(files) == 1:
        print("[*] Only one report found — no history to compare yet.")
        print(f"[*] First scan: {files[0]}")
        sys.exit(0)

    old_report = os.path.join(REPORTS_DIR, files[-2])
    new_report = os.path.join(REPORTS_DIR, files[-1])

    print(f"\n{'='*55}")
    print("       VULNERABILITY HISTORY COMPARISON")
    print(f"{'='*55}")
    print(f"  Old scan: {files[-2]}")
    print(f"  New scan: {files[-1]}")
    print(f"{'='*55}\n")

    old_vulns = parse_vulnerabilities(old_report)
    new_vulns = parse_vulnerabilities(new_report)

    new_found, fixed, remaining = compare_reports(old_vulns, new_vulns)

    print(f"🔴 NEW vulnerabilities appeared: {len(new_found)}")
    if new_found:
        for v in new_found:
            print(f"     + {v}")
    else:
        print("     None — great job!")

    print()

    print(f"✅ Vulnerabilities FIXED: {len(fixed)}")
    if fixed:
        for v in fixed:
            print(f"     - {v}")
    else:
        print("     None fixed yet")

    print()

    print(f"⚠️  Still present: {len(remaining)}")
    for v in remaining:
        print(f"     = {v}")

    print(f"\n{'='*55}")
    print(f"  Total before: {len(old_vulns)}")
    print(f"  Total now:    {len(new_vulns)}")
    trend = len(new_vulns) - len(old_vulns)
    if trend > 0:
        print(f"  Trend:        ⬆️  +{trend} (getting worse)")
    elif trend < 0:
        print(f"  Trend:        ⬇️  {trend} (getting better)")
    else:
        print(f"  Trend:        ➡️  No change")
    print(f"{'='*55}\n")

    log_path = os.path.join(REPORTS_DIR, f"history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_path, "w") as f:
        f.write(f"History Comparison\n")
        f.write(f"Old: {files[-2]}\n")
        f.write(f"New: {files[-1]}\n\n")
        f.write(f"New vulnerabilities: {len(new_found)}\n")
        for v in new_found:
            f.write(f"  + {v}\n")
        f.write(f"\nFixed: {len(fixed)}\n")
        for v in fixed:
            f.write(f"  - {v}\n")
        f.write(f"\nStill present: {len(remaining)}\n")
        for v in remaining:
            f.write(f"  = {v}\n")
    print(f"[*] History log saved: {log_path}")

if __name__ == "__main__":
    run_history()
