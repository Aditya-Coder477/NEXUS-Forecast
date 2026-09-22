"""
Script to copy raw CAPEC sources, parse capec_latest.xml, extract normalized attack patterns,
document MITRE ATT&CK taxonomy mappings, and generate metadata.json.
"""

import os
import shutil
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_text_or_empty(elem, xpath, ns):
    found = elem.find(xpath, ns)
    if found is not None and found.text:
        return found.text.strip()
    return ""

def process_capec():
    raw_dir = os.path.join("data", "knowledge", "capec", "raw")
    proc_dir = os.path.join("data", "knowledge", "capec", "processed")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(proc_dir, exist_ok=True)

    # 1. Copy zip sources from Downloads to raw if present
    downloads_dir = r"c:\Users\ADRAJ\Downloads"
    for zip_name in ["333.csv.zip", "658.csv.zip", "659.csv.zip"]:
        src_zip = os.path.join(downloads_dir, zip_name)
        dst_zip = os.path.join(raw_dir, zip_name)
        if os.path.exists(src_zip) and not os.path.exists(dst_zip):
            shutil.copy2(src_zip, dst_zip)
            print(f"Copied {src_zip} -> {dst_zip}")

    xml_path = os.path.join(raw_dir, "capec_latest.xml")
    if not os.path.exists(xml_path):
        raise FileNotFoundError(f"CAPEC raw XML not found at {xml_path}")

    # 2. Parse capec_latest.xml
    print(f"Parsing {xml_path}...")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    capec_name = root.attrib.get("Name", "CAPEC")
    capec_version = root.attrib.get("Version", "3.9")
    capec_date = root.attrib.get("Date", "2023-01-24")

    patterns = root.findall(".//capec:Attack_Pattern", ns)
    print(f"Found {len(patterns)} Attack_Pattern elements in CAPEC v{capec_version} (Date: {capec_date})")

    normalized_patterns = []
    attck_mapping_count = 0

    for p in patterns:
        cid = p.attrib.get("ID", "")
        cname = p.attrib.get("Name", "")
        abstraction = p.attrib.get("Abstraction", "")
        status = p.attrib.get("Status", "")

        # Description
        desc_elem = p.find("capec:Description", ns)
        description = ""
        if desc_elem is not None:
            description = "".join(desc_elem.itertext()).strip()

        # Typical severity & likelihood
        severity = get_text_or_empty(p, "capec:Typical_Severity", ns)
        likelihood = get_text_or_empty(p, "capec:Likelihood_Of_Attack", ns)

        # Prerequisites
        prereqs = []
        for pr in p.findall(".//capec:Prerequisites/capec:Prerequisite", ns):
            text = "".join(pr.itertext()).strip()
            if text:
                prereqs.append(text)

        # Consequences
        consequences = []
        for c in p.findall(".//capec:Consequences/capec:Consequence", ns):
            scopes = [s.text.strip() for s in c.findall("capec:Scope", ns) if s.text]
            impacts = [i.text.strip() for i in c.findall("capec:Impact", ns) if i.text]
            consequences.append({
                "scopes": scopes,
                "impacts": impacts
            })

        # Related attack patterns
        related_aps = []
        for rap in p.findall(".//capec:Related_Attack_Patterns/capec:Related_Attack_Pattern", ns):
            related_aps.append({
                "capec_id": f"CAPEC-{rap.attrib.get('CAPEC_ID', '')}",
                "nature": rap.attrib.get("Nature", "")
            })

        # Related weaknesses (CWE)
        related_cwes = []
        for rw in p.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", ns):
            cwe_id = rw.attrib.get("CWE_ID", "")
            if cwe_id:
                related_cwes.append(f"CWE-{cwe_id}")

        # Taxonomy mappings (especially ATT&CK)
        taxonomy_mappings = []
        for tm in p.findall(".//capec:Taxonomy_Mappings/capec:Taxonomy_Mapping", ns):
            tax_name = tm.attrib.get("Taxonomy_Name", "")
            entry_id = get_text_or_empty(tm, "capec:Entry_ID", ns)
            entry_name = get_text_or_empty(tm, "capec:Entry_Name", ns)
            mapping_dict = {
                "taxonomy_name": tax_name,
                "entry_id": entry_id,
                "entry_name": entry_name
            }
            if tax_name == "ATTACK":
                attck_mapping_count += 1
                # Format standardized T-prefix if numeric
                std_attck_id = f"T{entry_id}" if not entry_id.startswith("T") else entry_id
                mapping_dict["standard_attack_id"] = std_attck_id

            taxonomy_mappings.append(mapping_dict)

        # References
        references = []
        for ref in p.findall(".//capec:References/capec:Reference", ns):
            ref_id = ref.attrib.get("Reference_ID", "")
            section = ref.attrib.get("Section", "")
            references.append({
                "reference_id": ref_id,
                "section": section
            })

        normalized_patterns.append({
            "capec_id": f"CAPEC-{cid}",
            "numeric_id": int(cid) if cid.isdigit() else cid,
            "name": cname,
            "abstraction_level": abstraction,
            "status": status,
            "description": description,
            "typical_severity": severity,
            "likelihood_of_attack": likelihood,
            "prerequisites": prereqs,
            "consequences": consequences,
            "related_attack_patterns": related_aps,
            "related_weaknesses": related_cwes,
            "taxonomy_mappings": taxonomy_mappings,
            "references": references
        })

    # Sort normalized patterns by numeric_id
    normalized_patterns.sort(key=lambda x: x["numeric_id"] if isinstance(x["numeric_id"], int) else 999999)

    # Write normalized JSON
    norm_json_path = os.path.join(proc_dir, "capec_normalized.json")
    with open(norm_json_path, "w", encoding="utf-8") as f:
        json.dump(normalized_patterns, f, indent=2)

    # 3. Inventory raw files in capec/raw
    raw_files_info = []
    for root, dirs, files in os.walk(raw_dir):
        for f in files:
            fp = os.path.join(root, f)
            rel = os.path.relpath(fp, "data/knowledge/capec").replace("\\", "/")
            raw_files_info.append({
                "file_name": f,
                "relative_path": rel,
                "size_bytes": os.path.getsize(fp),
                "sha256": calculate_sha256(fp),
                "format": os.path.splitext(f)[1].replace(".", "").upper()
            })

    # 4. Generate data/knowledge/capec/metadata.json
    metadata = {
        "catalog_name": capec_name,
        "capec_version": capec_version,
        "release_date": capec_date,
        "source_url": "https://capec.mitre.org/data/xml/views/3000.xml",
        "acquisition_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "raw_files": raw_files_info,
        "number_of_attack_patterns": len(normalized_patterns),
        "number_of_documented_attck_mappings": attck_mapping_count,
        "nvd_status": "EXCLUDED_BY_DESIGN",
        "status": "OFFLINE_LOCAL_NORMALIZED"
    }

    metadata_path = os.path.join("data", "knowledge", "capec", "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("CAPEC processing complete.")
    print(f"Normalized patterns: {len(normalized_patterns)} saved to {norm_json_path}")
    print(f"Documented ATT&CK mappings: {attck_mapping_count}")
    print(f"Metadata saved to {metadata_path}")

if __name__ == "__main__":
    process_capec()
