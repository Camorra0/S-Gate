import os
import sys
from minio import Minio
from minio.error import S3Error

MINIO_ENDPOINT  = "localhost:9001"
MINIO_ACCESS    = "admin"
MINIO_SECRET    = "password123"
BUCKET_NAME     = "zap-reports"
REPORTS_DIR     = os.path.expanduser("~/devsecops-project/reports")

def get_latest_report():
    files = sorted([
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith("zap_report") and f.endswith(".json")
    ])
    if not files:
        print("[!] No reports found.")
        sys.exit(1)
    return os.path.join(REPORTS_DIR, files[-1]), files[-1]

def upload_report():
    client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS,
        secret_key=MINIO_SECRET,
        secure=False
    )
    report_path, report_name = get_latest_report()
    print(f"[*] Uploading: {report_name}")
    client.fput_object(
        BUCKET_NAME,
        report_name,
        report_path,
        content_type="application/json"
    )
    print(f"[+] ✅ Report uploaded to MinIO bucket '{BUCKET_NAME}'")
    print(f"[+] File: {report_name}")

if __name__ == "__main__":
    try:
        upload_report()
    except S3Error as e:
        print(f"[!] MinIO error: {e}")
        sys.exit(1)
