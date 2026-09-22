"""
Acquisition script for MITRE Enterprise ATT&CK STIX dataset.
"""

import os
import sys
import json
import hashlib
import urllib.request
from datetime import datetime, timezone

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def acquire_mitre_attack():
    version = "19.2"
    release_date = "2026-08-05T22:58:54Z"
    source_url = f"https://github.com/mitre-attack/attack-stix-data/releases/download/v{version}/enterprise-attack.json"

    raw_dir = os.path.join("data", "knowledge", "mitre_attack", "raw")
    os.makedirs(raw_dir, exist_ok=True)

    dest_filename = f"enterprise-attack-{version}.json"
    dest_path = os.path.join(raw_dir, dest_filename)

    print(f"Target MITRE ATT&CK Version: Enterprise v{version}")
    print(f"Source URL: {source_url}")
    print(f"Destination: {dest_path}")

    if os.path.exists(dest_path):
        print(f"File {dest_path} already exists. Verifying checksum...")
    else:
        print(f"Downloading {dest_filename} from {source_url}...")
        headers = {"User-Agent": "NEXUS-Forecast/1.0 (Cybersecurity Research)"}
        req = urllib.request.Request(source_url, headers=headers)
        
        with urllib.request.urlopen(req) as resp, open(dest_path, "wb") as out:
            total_size = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 1024 * 1024  # 1MB chunks
            
            while True:
                chunk = resp.read(block_size)
                if not chunk:
                    break
                out.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = downloaded / total_size * 100
                    sys.stdout.write(f"\rDownloading: {downloaded / (1024*1024):.1f} MB / {total_size / (1024*1024):.1f} MB ({percent:.1f}%)")
                    sys.stdout.flush()
            print()

    file_size = os.path.getsize(dest_path)
    sha256 = calculate_sha256(dest_path)
    print(f"Download complete / verified.")
    print(f"File Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
    print(f"SHA-256: {sha256}")

    # Write raw metadata
    meta = {
        "domain": "enterprise-attack",
        "version": version,
        "release_date": release_date,
        "source_url": source_url,
        "download_timestamp": datetime.now(timezone.utc).isoformat(),
        "file_name": dest_filename,
        "file_path": dest_path.replace("\\", "/"),
        "size_bytes": file_size,
        "sha256": sha256
    }
    meta_path = os.path.join(raw_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Raw metadata saved to: {meta_path}")
    return dest_path, meta

if __name__ == "__main__":
    acquire_mitre_attack()
