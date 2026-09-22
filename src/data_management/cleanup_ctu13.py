"""
CTU-13 Safe Cleanup Script for NEXUS-Forecast.

Safely removes raw PCAP files that are redundant with verified flow-level
Binetflow representations, reclaiming ~71.72 GB of storage.

Safety rules:
1. Default mode is ALWAYS --dry-run.
2. Only operates on files with decision == 'DELETE' in data/ctu13_deletion_plan.csv.
3. NEVER deletes files marked 'KEEP' or 'REVIEW_REQUIRED'.
4. Verifies the corresponding replacement .binetflow exists and is readable.
5. Emits detailed progress and writes structured log to data/ctu13_cleanup_log.json.
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone

def run_cleanup(mode="dry-run", plan_path="data/ctu13_deletion_plan.csv", log_path="data/ctu13_cleanup_log.json"):
    print("=" * 70)
    print(f"NEXUS-Forecast CTU-13 Safe Cleanup Utility")
    print(f"Mode: {'DRY RUN (No files will be deleted)' if mode == 'dry-run' else 'REAL EXECUTION (Files marked DELETE will be permanently removed)'}")
    print(f"Plan File: {plan_path}")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    if not os.path.exists(plan_path):
        print(f"ERROR: Plan file not found: {plan_path}")
        sys.exit(1)

    with open(plan_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        plan_rows = list(reader)

    total_candidates = 0
    total_candidate_bytes = 0
    actions_taken = []
    skipped_items = []
    failed_items = []

    print("\nEvaluating Plan Records...")
    print("-" * 70)

    for r in plan_rows:
        file_path = r["file_path"].replace("/", os.sep)
        decision = r["decision"].strip()
        expected_size = int(r["file_size"])
        replacement_file = r["replacement_file"].replace("/", os.sep)

        if decision != "DELETE":
            skipped_items.append({
                "file_path": r["file_path"],
                "decision": decision,
                "reason": f"Decision is {decision} (non-delete)"
            })
            continue

        # File is marked DELETE. Perform strict provenance checks.
        total_candidates += 1
        total_candidate_bytes += expected_size

        # Check 1: Does the target file exist?
        if not os.path.exists(file_path):
            print(f"[ERROR] Target file missing: {file_path}")
            failed_items.append({
                "file_path": r["file_path"],
                "error": "Target file missing on disk"
            })
            continue

        # Check 2: Does replacement Binetflow exist and is non-empty?
        if not os.path.exists(replacement_file):
            print(f"[REJECT] Replacement Binetflow missing: {replacement_file}. Skipping {file_path}!")
            failed_items.append({
                "file_path": r["file_path"],
                "error": f"Replacement {replacement_file} does not exist"
            })
            continue

        if os.path.getsize(replacement_file) == 0:
            print(f"[REJECT] Replacement Binetflow is empty (0 bytes): {replacement_file}. Skipping {file_path}!")
            failed_items.append({
                "file_path": r["file_path"],
                "error": f"Replacement {replacement_file} is 0 bytes"
            })
            continue

        actual_size = os.path.getsize(file_path)
        size_gb = actual_size / (1024**3)

        if mode == "dry-run":
            print(f"[DRY-RUN WOULD DELETE] {file_path}")
            print(f"       Size: {actual_size:,} bytes ({size_gb:.2f} GB) | Scenario: {r['scenario']}")
            print(f"       Verified Replacement: {replacement_file} ({os.path.getsize(replacement_file):,} bytes)")
            actions_taken.append({
                "file_path": r["file_path"],
                "size_bytes": actual_size,
                "size_gb": round(size_gb, 4),
                "action": "WOULD_DELETE",
                "replacement_file": r["replacement_file"],
                "status": "SIMULATED"
            })
        elif mode == "execute":
            try:
                print(f"[DELETING] {file_path} ({size_gb:.2f} GB)...")
                os.remove(file_path)
                print(f"[DELETED] Successfully removed: {file_path}")
                actions_taken.append({
                    "file_path": r["file_path"],
                    "size_bytes": actual_size,
                    "size_gb": round(size_gb, 4),
                    "action": "DELETED",
                    "replacement_file": r["replacement_file"],
                    "status": "SUCCESS"
                })
            except Exception as e:
                print(f"[FAIL] Error deleting {file_path}: {e}")
                failed_items.append({
                    "file_path": r["file_path"],
                    "error": str(e)
                })

    print("-" * 70)
    print("\nSummary:")
    print(f"Total files in plan: {len(plan_rows)}")
    print(f"Files marked DELETE: {total_candidates}")
    print(f"Total space to reclaim: {total_candidate_bytes:,} bytes ({total_candidate_bytes / (1024**3):.2f} GB)")
    print(f"Actions processed: {len(actions_taken)}")
    print(f"Non-delete files preserved: {len(skipped_items)}")
    print(f"Errors / Rejections: {len(failed_items)}")

    # Write log
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "plan_file": plan_path,
        "total_candidates": total_candidates,
        "total_candidate_bytes": total_candidate_bytes,
        "total_candidate_gb": round(total_candidate_bytes / (1024**3), 2),
        "actions_taken": actions_taken,
        "skipped_non_delete_count": len(skipped_items),
        "failed_items": failed_items,
        "status": "COMPLETED" if len(failed_items) == 0 else "COMPLETED_WITH_ERRORS"
    }

    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        json.dump(log_data, lf, indent=2)

    print(f"Audit log written to: {log_path}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS-Forecast CTU-13 Safe Cleanup Utility")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", default=True, help="Simulate deletion and verify safety (default)")
    group.add_argument("--execute", action="store_true", help="Execute permanent deletion of files marked DELETE")
    parser.add_argument("--plan", default="data/ctu13_deletion_plan.csv", help="Path to deletion plan CSV")
    parser.add_argument("--log", default="data/ctu13_cleanup_log.json", help="Path to write cleanup log JSON")

    args = parser.parse_args()
    exec_mode = "execute" if args.execute else "dry-run"
    run_cleanup(mode=exec_mode, plan_path=args.plan, log_path=args.log)
