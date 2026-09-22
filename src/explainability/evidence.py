"""
Network Evidence Attribution and Source-Flow Traceability for Phase 17.
Enforces strict anti-causality principles:
- Evidence is framed as 'supporting observations' or 'influential observations'.
- Never claims 'Flow X caused the attack' or 'Feature X proves an attack'.
- Distinguishes: Model Attribution -> Observed Network Evidence -> Analyst Interpretation.

Features:
1. Canonical feature-to-flow field traceability mapping.
2. Evidence Taxonomy (Traffic Volume, Host Diversity, Port Diversity, Protocol Behavior,
   Connection Behavior, Directionality, Temporal Persistence).
3. Baseline deviation evaluator.
4. Flow-level evidence ranking and aggregate evidence reporting.
5. Optional IP identifier redaction for security/privacy.
"""

import os
import re
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple

from src.world_model.dataset import STATE_FEATURE_NAMES
from src.explainability.baseline import BaselineManager

# Authoritative Traceability Specification
FEATURE_TRACEABILITY_SPEC = {
    "total_flows": {
        "category": "TRAFFIC_VOLUME",
        "source_fields": ["flow_id / row index"],
        "traceable": "YES",
        "evidence_method": "Record cardinality count in window",
        "decomposable": False
    },
    "unique_src_hosts": {
        "category": "HOST_DIVERSITY",
        "source_fields": ["src_ip"],
        "traceable": "YES",
        "evidence_method": "Distinct source IP cardinality",
        "decomposable": True,
        "ranking_field": "src_ip"
    },
    "unique_dst_hosts": {
        "category": "HOST_DIVERSITY",
        "source_fields": ["dst_ip"],
        "traceable": "YES",
        "evidence_method": "Distinct destination IP cardinality",
        "decomposable": True,
        "ranking_field": "dst_ip"
    },
    "unique_dst_ports": {
        "category": "PORT_DIVERSITY",
        "source_fields": ["dst_port"],
        "traceable": "YES",
        "evidence_method": "Distinct destination port cardinality",
        "decomposable": True,
        "ranking_field": "dst_port"
    },
    "unique_protocols": {
        "category": "PROTOCOL_BEHAVIOR",
        "source_fields": ["protocol"],
        "traceable": "YES",
        "evidence_method": "Distinct transport/network protocol count",
        "decomposable": False
    },
    "total_packets": {
        "category": "TRAFFIC_VOLUME",
        "source_fields": ["packets_forward", "packets_backward"],
        "traceable": "YES",
        "evidence_method": "Sum of bidirectional flow packets",
        "decomposable": True,
        "ranking_field": "total_packets"
    },
    "total_bytes": {
        "category": "TRAFFIC_VOLUME",
        "source_fields": ["bytes_forward", "bytes_backward"],
        "traceable": "YES",
        "evidence_method": "Sum of bidirectional flow bytes",
        "decomposable": True,
        "ranking_field": "total_bytes"
    },
    "inbound_bytes": {
        "category": "DIRECTIONALITY",
        "source_fields": ["bytes_forward", "bytes_backward", "is_inbound"],
        "traceable": "YES",
        "evidence_method": "Summed byte volume for inbound flows",
        "decomposable": True,
        "ranking_field": "total_bytes"
    },
    "outbound_bytes": {
        "category": "DIRECTIONALITY",
        "source_fields": ["bytes_forward", "bytes_backward", "is_outbound"],
        "traceable": "YES",
        "evidence_method": "Summed byte volume for outbound flows",
        "decomposable": True,
        "ranking_field": "total_bytes"
    },
    "inbound_outbound_ratio": {
        "category": "DIRECTIONALITY",
        "source_fields": ["is_inbound", "is_outbound", "bytes"],
        "traceable": "YES",
        "evidence_method": "Ratio: (inbound_bytes + 1) / (outbound_bytes + 1)",
        "decomposable": False
    },
    "mean_flow_duration": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["duration"],
        "traceable": "YES",
        "evidence_method": "Arithmetic mean of terminating flow durations",
        "decomposable": True,
        "ranking_field": "duration"
    },
    "mean_packet_rate": {
        "category": "TRAFFIC_VOLUME",
        "source_fields": ["packet_rate"],
        "traceable": "YES",
        "evidence_method": "Mean packet transfer rate across flows",
        "decomposable": True,
        "ranking_field": "packet_rate"
    },
    "mean_byte_rate": {
        "category": "TRAFFIC_VOLUME",
        "source_fields": ["byte_rate"],
        "traceable": "YES",
        "evidence_method": "Mean byte transfer rate across flows",
        "decomposable": True,
        "ranking_field": "byte_rate"
    },
    "mean_iat": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["iat_mean"],
        "traceable": "PARTIAL",
        "evidence_method": "Mean inter-arrival time (valid entries; -1 sentinel if uncalculated)",
        "decomposable": False
    },
    "std_iat": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["iat_std"],
        "traceable": "PARTIAL",
        "evidence_method": "Standard deviation of inter-arrival time",
        "decomposable": False
    },
    "syn_count": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["tcp_syn"],
        "traceable": "YES",
        "evidence_method": "Aggregated count of TCP SYN packets",
        "decomposable": True,
        "ranking_field": "tcp_syn"
    },
    "ack_count": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["tcp_ack"],
        "traceable": "YES",
        "evidence_method": "Aggregated count of TCP ACK packets",
        "decomposable": True,
        "ranking_field": "tcp_ack"
    },
    "rst_count": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["tcp_rst"],
        "traceable": "YES",
        "evidence_method": "Aggregated count of TCP RST packets",
        "decomposable": True,
        "ranking_field": "tcp_rst"
    },
    "fin_count": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["tcp_fin"],
        "traceable": "YES",
        "evidence_method": "Aggregated count of TCP FIN packets",
        "decomposable": True,
        "ranking_field": "tcp_fin"
    },
    "connection_failure_rate": {
        "category": "CONNECTION_BEHAVIOR",
        "source_fields": ["tcp_rst", "tcp_syn"],
        "traceable": "YES",
        "evidence_method": "Ratio of session aborts to attempts: (rst + 1) / (syn + 1)",
        "decomposable": False
    },
    "unique_host_pair_count": {
        "category": "HOST_DIVERSITY",
        "source_fields": ["src_ip", "dst_ip"],
        "traceable": "YES",
        "evidence_method": "Count of distinct directed communication edges",
        "decomposable": True,
        "ranking_field": "host_pair"
    },
    "fan_out_ratio": {
        "category": "HOST_DIVERSITY",
        "source_fields": ["src_ip", "dst_ip"],
        "traceable": "YES",
        "evidence_method": "Ratio: unique_dst_hosts / (unique_src_hosts + 1e-4)",
        "decomposable": False
    }
}


class EvidenceAttributor:
    def __init__(self, baseline_manager: BaselineManager, redact_identifiers: bool = False):
        self.baseline_manager = baseline_manager
        self.redact_identifiers = redact_identifiers

    def redact_ip(self, ip_str: str) -> str:
        """Masks the host portion of IP addresses for security/privacy."""
        if not self.redact_identifiers:
            return ip_str
        # IPv4 masking: e.g. 192.168.1.50 -> 192.168.1.***
        parts = str(ip_str).split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        return str(ip_str)

    def extract_evidence_for_sequence(
        self,
        sequence_row: pd.Series,
        top_features: List[Dict[str, Any]],
        top_timesteps: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Produces supporting evidence items for the top influential features and timesteps.
        """
        supporting_observations = []
        baseline_deviations = []

        # 1. Evaluate baseline deviations on the most recent state S_t
        for feat_item in top_features[:5]:
            feat = feat_item["feature"]
            val_col = f"S_t_{feat}"
            if val_col in sequence_row:
                current_val = float(sequence_row[val_col])
                dev = self.baseline_manager.compute_deviation(feat, current_val)
                baseline_deviations.append(dev)

                # Supporting observation text (strict non-causal language)
                spec = FEATURE_TRACEABILITY_SPEC.get(feat, {})
                cat = spec.get("category", "GENERAL")
                p95_txt = " (P95 exceeded)" if dev["p95_exceeded"] else ""
                direction_txt = "elevated" if dev["iqr_deviation"] > 0 else "suppressed"

                obs_text = (
                    f"Observation in category [{cat}]: Feature '{feat}' was observed at {dev['current_value']:,} "
                    f"({direction_txt}, baseline median: {dev['baseline_median']:,}, IQR deviation: {dev['iqr_deviation']:.2f}{p95_txt}). "
                    f"Attribution direction: {feat_item['direction']}."
                )
                supporting_observations.append({
                    "feature": feat,
                    "category": cat,
                    "direction": feat_item["direction"],
                    "observation_text": obs_text,
                    "deviation_details": dev
                })

        # 2. Traceability metadata
        traceability_summary = []
        for feat_item in top_features[:5]:
            feat = feat_item["feature"]
            spec = FEATURE_TRACEABILITY_SPEC.get(feat, {})
            traceability_summary.append({
                "feature": feat,
                "category": spec.get("category", "UNKNOWN"),
                "source_fields": spec.get("source_fields", []),
                "flow_level_traceable": spec.get("traceable", "NO"),
                "evidence_method": spec.get("evidence_method", "N/A")
            })

        return {
            "supporting_observations": supporting_observations,
            "baseline_deviations": baseline_deviations,
            "feature_traceability": traceability_summary
        }

    @staticmethod
    def get_traceability_table() -> pd.DataFrame:
        """Returns the complete 22-feature traceability specification table."""
        rows = []
        for feat, spec in FEATURE_TRACEABILITY_SPEC.items():
            rows.append({
                "State Feature": feat,
                "Category": spec["category"],
                "Source Fields": ", ".join(spec["source_fields"]),
                "Flow-Level Traceable": spec["traceable"],
                "Evidence Method": spec["evidence_method"]
            })
        return pd.DataFrame(rows)
