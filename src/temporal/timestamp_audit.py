"""
Comprehensive timestamp audit across CIC-IDS2017, UNSW-NB15, and CTU-13.
Analyzes format, timezone assumptions, parsing success, duplicate timestamps,
and monotonicity before windowing.
"""

import os
import glob
import json
import pandas as pd
from datetime import datetime, timezone

def audit_timestamps():
    print("=" * 70, flush=True)
    print("RUNNING DATASET TIMESTAMP AUDIT", flush=True)
    print("=" * 70, flush=True)

    results = {}

    # 1. CIC-IDS2017
    print("\nAuditing CIC-IDS2017...", flush=True)
    cic_files = sorted(glob.glob("data/CIC-IDS2017/CSV/GeneratedLabelledFlows/TrafficLabelling/*.csv"))
    cic_audits = []

    for cf in cic_files:
        fname = os.path.basename(cf)
        scenario_id = fname.replace(".pcap_ISCX.csv", "").replace(".csv", "")
        
        with open(cf, "r", encoding="latin1") as f:
            hdr = [c.strip() for c in f.readline().split(",")]
        ts_idx = hdr.index("Timestamp")

        df = pd.read_csv(cf, usecols=[ts_idx], encoding="latin1", on_bad_lines="skip", low_memory=False)
        col_name = df.columns[0]
        raw_series = df[col_name].dropna().astype(str)
        total_rows = len(raw_series)

        # Parse with flexible format
        parsed = pd.to_datetime(raw_series, format="mixed", errors="coerce")
        valid_count = int(parsed.notna().sum())
        invalid_count = total_rows - valid_count
        success_rate = (valid_count / total_rows) * 100 if total_rows > 0 else 0

        valid_ts = parsed.dropna().sort_values()
        min_ts = valid_ts.iloc[0].isoformat() if len(valid_ts) > 0 else None
        max_ts = valid_ts.iloc[-1].isoformat() if len(valid_ts) > 0 else None
        duration_hrs = (valid_ts.iloc[-1] - valid_ts.iloc[0]).total_seconds() / 3600 if len(valid_ts) > 0 else 0

        is_monotonic = bool(parsed.is_monotonic_increasing)
        dup_count = int(parsed.duplicated().sum())

        cic_audits.append({
            "scenario_id": scenario_id,
            "source_file": fname,
            "source_timestamp_column": col_name.strip(),
            "total_rows": int(total_rows),
            "minimum_timestamp": min_ts,
            "maximum_timestamp": max_ts,
            "timezone_assumption": "EST / UTC-3 (Dataset capture local time)",
            "parse_success_rate": round(success_rate, 4),
            "invalid_timestamp_count": int(invalid_count),
            "duplicate_timestamp_count": dup_count,
            "timestamp_monotonicity": is_monotonic,
            "estimated_duration_hours": round(duration_hrs, 2)
        })
        print(f"  [{scenario_id}] {valid_count:,} valid timestamps ({success_rate:.1f}%), Span: {min_ts} -> {max_ts}", flush=True)

    results["CIC-IDS2017"] = cic_audits

    # 2. UNSW-NB15
    print("\nAuditing UNSW-NB15...", flush=True)
    unsw_cf = "data/UNSW-NB15/CICFlowMeter_out.csv"
    if os.path.exists(unsw_cf):
        with open(unsw_cf, "r", encoding="latin1") as f:
            hdr = [c.strip() for c in f.readline().split(",")]
        ts_idx = hdr.index("Timestamp")

        total_rows = 0
        valid_count = 0
        min_ts = None
        max_ts = None
        is_monotonic = True
        dup_count = 0

        # Process in chunks using exact format string for speed
        for chunk in pd.read_csv(unsw_cf, usecols=[ts_idx], chunksize=1000000, encoding="latin1", on_bad_lines="skip"):
            raw_s = chunk[chunk.columns[0]].dropna().astype(str)
            total_rows += len(raw_s)
            p = pd.to_datetime(raw_s, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
            # fallback for any irregular formats
            na_mask = p.isna()
            if na_mask.any():
                p[na_mask] = pd.to_datetime(raw_s[na_mask], format="mixed", errors="coerce")
            valid_p = p.dropna()
            valid_count += len(valid_p)
            dup_count += int(valid_p.duplicated().sum())

            if len(valid_p) > 0:
                cur_min = valid_p.min().isoformat()
                cur_max = valid_p.max().isoformat()
                min_ts = cur_min if min_ts is None or cur_min < min_ts else min_ts
                max_ts = cur_max if max_ts is None or cur_max > max_ts else max_ts

        invalid_count = total_rows - valid_count
        success_rate = (valid_count / total_rows) * 100 if total_rows > 0 else 0

        results["UNSW-NB15"] = [{
            "scenario_id": "full_capture",
            "source_file": os.path.basename(unsw_cf),
            "source_timestamp_column": "Timestamp",
            "total_rows": int(total_rows),
            "minimum_timestamp": min_ts,
            "maximum_timestamp": max_ts,
            "timezone_assumption": "AEST / UTC+10 (Sydney capture local time)",
            "parse_success_rate": round(success_rate, 4),
            "invalid_timestamp_count": int(invalid_count),
            "duplicate_timestamp_count": dup_count,
            "timestamp_monotonicity": False,
            "estimated_duration_hours": round((pd.to_datetime(max_ts) - pd.to_datetime(min_ts)).total_seconds() / 3600, 2) if min_ts and max_ts else 0
        }]
        print(f"  [UNSW-NB15] {valid_count:,} valid timestamps ({success_rate:.1f}%), Span: {min_ts} -> {max_ts}", flush=True)

    # 3. CTU-13
    print("\nAuditing CTU-13...", flush=True)
    ctu_files = sorted(glob.glob("data/CTU-13-Dataset/*/*.binetflow"), key=lambda x: int(os.path.basename(os.path.dirname(x))))
    ctu_audits = []

    for ctu_f in ctu_files:
        scen_id = f"scenario_{int(os.path.basename(os.path.dirname(ctu_f))):02d}"
        with open(ctu_f, "r", encoding="latin1") as f:
            hdr = [c.strip() for c in f.readline().split(",")]
        ts_idx = hdr.index("StartTime")

        df_c = pd.read_csv(ctu_f, usecols=[ts_idx], encoding="latin1", on_bad_lines="skip", low_memory=False)
        col_name = df_c.columns[0]
        raw_series = df_c[col_name].dropna().astype(str)
        total_rows = len(raw_series)

        parsed_c = pd.to_datetime(raw_series, format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
        valid_count = int(parsed_c.notna().sum())
        invalid_count = total_rows - valid_count
        success_rate = (valid_count / total_rows) * 100 if total_rows > 0 else 0

        valid_ts = parsed_c.dropna()
        min_ts = valid_ts.min().isoformat() if len(valid_ts) > 0 else None
        max_ts = valid_ts.max().isoformat() if len(valid_ts) > 0 else None
        duration_hrs = (valid_ts.max() - valid_ts.min()).total_seconds() / 3600 if len(valid_ts) > 0 else 0

        ctu_audits.append({
            "scenario_id": scen_id,
            "source_file": os.path.basename(ctu_f),
            "source_timestamp_column": "StartTime",
            "total_rows": int(total_rows),
            "minimum_timestamp": min_ts,
            "maximum_timestamp": max_ts,
            "timezone_assumption": "CEST / UTC+2 (Prague capture local time)",
            "parse_success_rate": round(success_rate, 4),
            "invalid_timestamp_count": int(invalid_count),
            "duplicate_timestamp_count": int(parsed_c.duplicated().sum()),
            "timestamp_monotonicity": bool(parsed_c.is_monotonic_increasing),
            "estimated_duration_hours": round(duration_hrs, 2)
        })
        print(f"  [{scen_id}] {valid_count:,} valid timestamps ({success_rate:.1f}%), Span: {min_ts} -> {max_ts}", flush=True)

    results["CTU-13"] = ctu_audits

    out_path = "data/processed/timestamp_audit_report.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nTimestamp audit complete. Results saved to: {out_path}", flush=True)

if __name__ == "__main__":
    audit_timestamps()
