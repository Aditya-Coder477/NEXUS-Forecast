"""
Script to generate pre-cleanup and post-cleanup dataset inventories for NEXUS-Forecast.
"""

import os
import json
import csv
import argparse

def generate_inventory(output_prefix="data_inventory_before_cleanup"):
    root_dir = "data"
    inventory = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Do not include the inventory files themselves if regenerating
        for f in filenames:
            if f.startswith("data_inventory_") or f.startswith("ctu13_"):
                continue
            fp = os.path.join(dirpath, f)
            rel_path = os.path.relpath(fp, ".").replace("\\", "/")
            size_bytes = os.path.getsize(fp)
            size_gb = round(size_bytes / (1024**3), 6)
            ext = os.path.splitext(f)[1].lower()

            # Dataset identification
            if "CIC-IDS2017" in rel_path:
                dataset = "CIC-IDS2017"
            elif "CIC-IDS2018" in rel_path:
                dataset = "CIC-IDS2018"
            elif "CTU-13" in rel_path:
                dataset = "CTU-13"
            elif "UNSW-NB15" in rel_path:
                dataset = "UNSW-NB15"
            elif "capec" in rel_path:
                dataset = "CAPEC"
            elif "mitre_attack" in rel_path:
                dataset = "MITRE-ATTACK"
            else:
                dataset = "OTHER"

            # File type and estimated role
            if ext == ".pcap":
                file_type = "PCAP"
                if dataset == "CTU-13":
                    estimated_role = "Raw packet capture (redundant with Binetflow for flow modeling)"
                    action_candidate = "DELETE_CANDIDATE"
                else:
                    estimated_role = "Raw packet capture (evaluation / benchmark reference)"
                    action_candidate = "KEEP"
            elif ext == ".binetflow":
                file_type = "Binetflow"
                estimated_role = "Bidirectional NetFlow records with ground-truth botnet labels"
                action_candidate = "KEEP"
            elif ext == ".csv":
                file_type = "CSV"
                estimated_role = "Extracted flow features and ground truth labels"
                action_candidate = "KEEP"
            elif ext == ".md5":
                file_type = "MD5 Checksum"
                estimated_role = "Dataset integrity verification"
                action_candidate = "KEEP"
            elif ext in [".txt", ".html"] or f.upper().startswith("README"):
                file_type = "Documentation / Metadata"
                estimated_role = "Scenario description, setup details, and protocol documentation"
                action_candidate = "KEEP"
            elif ext == ".exe":
                file_type = "Binary Executable"
                estimated_role = "Original malware sample executable (sandboxed artifact)"
                action_candidate = "REVIEW_REQUIRED"
            elif ext == ".json":
                file_type = "JSON"
                estimated_role = "Structured knowledge or metadata artifact"
                action_candidate = "KEEP"
            elif ext == ".zip":
                file_type = "ZIP Archive"
                estimated_role = "Compressed raw dataset/source"
                action_candidate = "KEEP"
            else:
                file_type = "Other"
                estimated_role = "Ancillary data file"
                action_candidate = "REVIEW_REQUIRED"

            inventory.append({
                "dataset": dataset,
                "relative_path": rel_path,
                "file_name": f,
                "extension": ext if ext else "(none)",
                "size_bytes": size_bytes,
                "size_gb": size_gb,
                "file_type": file_type,
                "estimated_role": estimated_role,
                "action_candidate": action_candidate
            })

    # Sort inventory by relative_path
    inventory.sort(key=lambda x: x["relative_path"])

    # Write CSV
    csv_path = os.path.join(root_dir, f"{output_prefix}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "dataset", "relative_path", "file_name", "extension", 
            "size_bytes", "size_gb", "file_type", "estimated_role", "action_candidate"
        ])
        writer.writeheader()
        writer.writerows(inventory)

    # Write JSON
    json_path = os.path.join(root_dir, f"{output_prefix}.json")
    summary = {
        "total_files": len(inventory),
        "total_size_bytes": sum(item["size_bytes"] for item in inventory),
        "total_size_gb": round(sum(item["size_bytes"] for item in inventory) / (1024**3), 2),
        "datasets": {}
    }
    for item in inventory:
        d = item["dataset"]
        if d not in summary["datasets"]:
            summary["datasets"][d] = {"file_count": 0, "total_bytes": 0, "total_gb": 0}
        summary["datasets"][d]["file_count"] += 1
        summary["datasets"][d]["total_bytes"] += item["size_bytes"]

    for d in summary["datasets"]:
        summary["datasets"][d]["total_gb"] = round(summary["datasets"][d]["total_bytes"] / (1024**3), 2)

    summary["files"] = inventory

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Inventory saved to {csv_path} and {json_path}")
    print(f"Total files: {summary['total_files']}, Total size: {summary['total_size_gb']} GB")
    for d, s in summary["datasets"].items():
        print(f"  {d}: {s['file_count']} files, {s['total_gb']} GB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default="data_inventory_before_cleanup", help="Output file prefix")
    args = parser.parse_args()
    generate_inventory(args.prefix)
