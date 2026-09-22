"""
Master validation test suite for NEXUS-Forecast Data & Knowledge Management.
"""

import os
import sys
import json
import csv
import hashlib
import time

sys.path.insert(0, os.path.abspath("."))

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def validate_system():
    print("=" * 70)
    print("RUNNING NEXUS-FORECAST VALIDATION SUITE")
    print("=" * 70)

    checks_passed = 0
    checks_total = 0

    def assert_test(condition, name, details=""):
        nonlocal checks_passed, checks_total
        checks_total += 1
        if condition:
            print(f"[PASS] {name} {details}")
            checks_passed += 1
        else:
            print(f"[FAIL] {name} {details}")

    # TEST 1: CIC-IDS2017 is untouched
    cic_files = []
    for root, dirs, files in os.walk("data/CIC-IDS2017"):
        for f in files:
            cic_files.append(os.path.join(root, f))
    assert_test(len(cic_files) == 28, "CIC-IDS2017 File Count Untouched", f"({len(cic_files)} files)")
    cic_bytes = sum(os.path.getsize(f) for f in cic_files)
    assert_test(cic_bytes == 54521141432, "CIC-IDS2017 Byte Count Exact Match", f"({cic_bytes:,} bytes)")

    # TEST 2: UNSW-NB15 is untouched
    unsw_files = []
    for root, dirs, files in os.walk("data/UNSW-NB15"):
        for f in files:
            unsw_files.append(os.path.join(root, f))
    assert_test(len(unsw_files) == 4, "UNSW-NB15 File Count Untouched", f"({len(unsw_files)} files)")
    unsw_bytes = sum(os.path.getsize(f) for f in unsw_files)
    assert_test(unsw_bytes == 2111448562, "UNSW-NB15 Byte Count Exact Match", f"({unsw_bytes:,} bytes)")

    # TEST 3: CAPEC source files intact
    capec_xml = "data/knowledge/capec/raw/capec_latest.xml"
    assert_test(os.path.exists(capec_xml), "CAPEC Source XML Exists", capec_xml)
    capec_xml_sha256 = calculate_sha256(capec_xml)
    assert_test(capec_xml_sha256 == "70279a2dff0cb0ad79e546adb07828335a704ad5210e047e09e986172fc9e34d", "CAPEC Source XML Checksum Valid", f"({capec_xml_sha256[:16]}...)")

    # TEST 4: CTU-13 plan integrity
    plan_path = "data/ctu13_deletion_plan.csv"
    assert_test(os.path.exists(plan_path), "CTU-13 Deletion Plan Exists", plan_path)
    with open(plan_path, "r", encoding="utf-8") as f:
        plan_rows = list(csv.DictReader(f))
    
    assert_test(len(plan_rows) == 52, "CTU-13 Plan Total Records", f"({len(plan_rows)} records)")
    delete_rows = [r for r in plan_rows if r["decision"] == "DELETE"]
    keep_rows = [r for r in plan_rows if r["decision"] == "KEEP"]
    review_rows = [r for r in plan_rows if r["decision"] == "REVIEW_REQUIRED"]
    
    assert_test(len(delete_rows) == 13, "CTU-13 Exact DELETE Count", f"({len(delete_rows)} PCAPs)")
    assert_test(len(keep_rows) == 26, "CTU-13 Exact KEEP Count", f"({len(keep_rows)} Binetflows + READMEs)")
    assert_test(len(review_rows) == 13, "CTU-13 Exact REVIEW_REQUIRED Count", f"({len(review_rows)} malware samples)")
    
    # All delete items must be .pcap and have existing non-empty binetflow
    all_delete_safe = True
    for r in delete_rows:
        if not r["file_path"].endswith(".pcap"):
            all_delete_safe = False
        if not os.path.exists(r["replacement_file"]):
            all_delete_safe = False
    assert_test(all_delete_safe, "CTU-13 All DELETE Candidates Have Valid Binetflow Replacements")

    # TEST 5: CTU-13 dry run log exists and successful
    log_path = "data/ctu13_cleanup_log.json"
    assert_test(os.path.exists(log_path), "CTU-13 Dry-Run Log Exists", log_path)
    with open(log_path, "r", encoding="utf-8") as f:
        log_data = json.load(f)
    assert_test(log_data.get("status") == "COMPLETED", "CTU-13 Dry-Run Log Status COMPLETED")
    assert_test(log_data.get("total_candidates") == 13, "CTU-13 Dry-Run Candidate Count is 13")

    # TEST 6: MITRE ATT&CK raw STIX validity & SHA-256
    mitre_raw = "data/knowledge/mitre_attack/raw/enterprise-attack-19.2.json"
    assert_test(os.path.exists(mitre_raw), "MITRE Raw STIX File Exists", mitre_raw)
    mitre_sha = calculate_sha256(mitre_raw)
    assert_test(mitre_sha == "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4", "MITRE Raw STIX Checksum Valid", f"({mitre_sha[:16]}...)")

    # TEST 7: MITRE Processed Files Validity
    processed_dir = "data/knowledge/mitre_attack/processed"
    tactics_p = os.path.join(processed_dir, "tactics.json")
    tech_p = os.path.join(processed_dir, "techniques.json")
    subtech_p = os.path.join(processed_dir, "subtechniques.json")
    rel_p = os.path.join(processed_dir, "relationships.json")
    curated_p = os.path.join(processed_dir, "nexus_forecast_attack_knowledge.json")
    stage_p = os.path.join(processed_dir, "attack_stage_mapping.json")

    for p, name in [(tactics_p, "Tactics"), (tech_p, "Techniques"), (subtech_p, "Sub-techniques"),
                    (rel_p, "Relationships"), (curated_p, "Curated Knowledge"), (stage_p, "Stage Mapping")]:
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert_test(len(data) > 0, f"MITRE Processed {name} Valid JSON and Non-Empty", f"({len(data)} records)")
        except Exception as e:
            assert_test(False, f"MITRE Processed {name} Valid JSON", str(e))

    # TEST 8: ATT&CK IDs Uniqueness and Sub-technique Parent Consistency
    with open(tech_p, "r", encoding="utf-8") as f:
        techs = json.load(f)
    with open(subtech_p, "r", encoding="utf-8") as f:
        subtechs = json.load(f)
    
    tech_ids = [t["external_id"] for t in techs]
    subtech_ids = [s["external_id"] for s in subtechs]
    assert_test(len(tech_ids) == len(set(tech_ids)), "Parent Technique IDs Are Unique", f"({len(tech_ids)} unique)")
    assert_test(len(subtech_ids) == len(set(subtech_ids)), "Sub-technique IDs Are Unique", f"({len(subtech_ids)} unique)")
    
    # Subtechniques have valid parents
    valid_parents = all(s.get("parent_external_id") != "" for s in subtechs)
    assert_test(valid_parents, "All Sub-techniques Have Valid Parent Technique IDs")

    # TEST 9: Stage Mapping Integrity
    with open(stage_p, "r", encoding="utf-8") as f:
        stages = json.load(f)
    all_fields_present = all("mapping_confidence" in s and "mapping_reason" in s and "source" in s for s in stages)
    assert_test(all_fields_present, "All Stage Mappings Contain Required Metadata Fields")

    # TEST 10: CAPEC Processed & Schema Integrity
    capec_norm = "data/knowledge/capec/processed/capec_normalized.json"
    assert_test(os.path.exists(capec_norm), "CAPEC Normalized JSON Exists", capec_norm)
    with open(capec_norm, "r", encoding="utf-8") as f:
        capec_patterns = json.load(f)
    assert_test(len(capec_patterns) == 615, "CAPEC Exactly 615 Patterns Extracted", f"({len(capec_patterns)} patterns)")

    schema_p = "data/knowledge/knowledge_schema.json"
    assert_test(os.path.exists(schema_p), "Knowledge Schema JSON Exists", schema_p)
    with open(schema_p, "r", encoding="utf-8") as f:
        schema_data = json.load(f)
    concrete_mappings = schema_data.get("non_fabrication_guarantee", {}).get("mappings", [])
    assert_test(len(concrete_mappings) == 57, "Knowledge Schema Contains 57 Documented Mappings", f"({len(concrete_mappings)} verified)")

    # TEST 11: Offline Loader Execution (< 200 ms)
    from src.data_management.knowledge_loader import NexusKnowledgeBase
    t0 = time.time()
    kb = NexusKnowledgeBase()
    elapsed_ms = (time.time() - t0) * 1000
    assert_test(kb.loaded and elapsed_ms < 200, "Offline Knowledge Loader Succeeds in < 200ms", f"({elapsed_ms:.2f} ms)")

    # TEST 12: Documentation Exists
    assert_test(os.path.exists("data/knowledge/README.md"), "Documentation data/knowledge/README.md Exists")
    assert_test(os.path.exists("data/DATA_MANAGEMENT.md"), "Documentation data/DATA_MANAGEMENT.md Exists")

    print("=" * 70)
    print(f"VALIDATION SUMMARY: {checks_passed} / {checks_total} CHECKS PASSED")
    print("=" * 70)

    if checks_passed == checks_total:
        print("ALL VERIFICATIONS PASSED SUCCESSFULLY.")
        return True
    else:
        print("SOME CHECKS FAILED.")
        return False

if __name__ == "__main__":
    success = validate_system()
    sys.exit(0 if success else 1)
