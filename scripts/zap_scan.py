import subprocess
import os
import sys
from datetime import datetime

TARGET_URL  = "http://localhost:9000"
ZAP_IMAGE   = "ghcr.io/zaproxy/zaproxy:stable"
REPORTS_DIR = "/home/server/devsecops-project/reports"
TIMESTAMP   = datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_FILE = f"zap_report_{TIMESTAMP}.json"

def run_scan():
    print(f"[*] Starting ZAP scan against {TARGET_URL} ...")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.chmod(REPORTS_DIR, 0o777)
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{REPORTS_DIR}:/zap/wrk/:rw",
        "--user", "root",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t", TARGET_URL,
        "-J", REPORT_FILE,
        "-I",
        "-d"
    ]
    result = subprocess.run(cmd)
    print(f"[*] Scan done. Exit code: {result.returncode}")

if __name__ == "__main__":
    os.makedirs(REPORTS_DIR, exist_ok=True)
    run_scan()
    report_path = os.path.join(REPORTS_DIR, REPORT_FILE)
    if os.path.exists(report_path):
        print(f"[+] Report saved: {report_path}")
    else:
        print("[!] Report not found — something went wrong.")
        sys.exit(1)
