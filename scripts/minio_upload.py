import os
import sys
from minio import Minio
from minio.error import S3Error

MINIO_ENDPOINT  = "localhost:9001"
MINIO_ACCESS    = "admin"
MINIO_SECRET    = "password123"
BUCKET_NAME     = "zap-reports"
REPORTS_DIR     = "/home/server/devsecops-project/reports"

def get_latest_files():
    all_files = os.listdir(REPORTS_DIR)
    
    # Get latest JSON report
    json_files = sorted([f for f in all_files 
                        if f.startswith("zap_report") and f.endswith(".json")])
    
    # Get latest HTML report
    html_files = sorted([f for f in all_files 
                        if f.startswith("report") and f.endswith(".html")])
    
    result = []
    if json_files:
        result.append((os.path.join(REPORTS_DIR, json_files[-1]), json_files[-1], "application/json"))
    if html_files:
        result.append((os.path.join(REPORTS_DIR, html_files[-1]), html_files[-1], "text/html"))
    
    return result

def upload_reports():
    client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS,
        secret_key=MINIO_SECRET,
        secure=False
    )

    files = get_latest_files()
    if not files:
        print("[!] No reports found.")
        sys.exit(1)

    for file_path, file_name, content_type in files:
        print(f"[*] Uploading: {file_name}")
        client.fput_object(
            BUCKET_NAME,
            file_name,
            file_path,
            content_type=content_type
        )
        print(f"[+] ✅ Uploaded: {file_name}")

if __name__ == "__main__":
    try:
        upload_reports()
    except S3Error as e:
        print(f"[!] MinIO error: {e}")
        sys.exit(1)
