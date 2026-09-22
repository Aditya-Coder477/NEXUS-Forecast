# PHASE 17: EVIDENCE TRACEABILITY REPORT

**Execution Timestamp**: 2026-09-21T19:44:35.300413+00:00

## 1. Traceability Mapping Framework

NEXUS-Forecast enforces a strict distinction between **Model Attribution**, **Observed Network Evidence**, and **Analyst Interpretation**.

Under no circumstances does Phase 17 manufacture unsupported flow attribution. The 22 canonical network state features map to flow fields as follows:

| State Feature | Category | Source Fields | Flow-Level Traceable | Evidence Method |
| :--- | :--- | :--- | :--- | :--- |
| total_flows | TRAFFIC_VOLUME | flow_id / row index | YES | Record cardinality count in window |
| unique_src_hosts | HOST_DIVERSITY | src_ip | YES | Distinct source IP cardinality |
| unique_dst_hosts | HOST_DIVERSITY | dst_ip | YES | Distinct destination IP cardinality |
| unique_dst_ports | PORT_DIVERSITY | dst_port | YES | Distinct destination port cardinality |
| unique_protocols | PROTOCOL_BEHAVIOR | protocol | YES | Distinct transport/network protocol count |
| total_packets | TRAFFIC_VOLUME | packets_forward, packets_backward | YES | Sum of bidirectional flow packets |
| total_bytes | TRAFFIC_VOLUME | bytes_forward, bytes_backward | YES | Sum of bidirectional flow bytes |
| inbound_bytes | DIRECTIONALITY | bytes_forward, bytes_backward, is_inbound | YES | Summed byte volume for inbound flows |
| outbound_bytes | DIRECTIONALITY | bytes_forward, bytes_backward, is_outbound | YES | Summed byte volume for outbound flows |
| inbound_outbound_ratio | DIRECTIONALITY | is_inbound, is_outbound, bytes | YES | Ratio: (inbound_bytes + 1) / (outbound_bytes + 1) |
| mean_flow_duration | CONNECTION_BEHAVIOR | duration | YES | Arithmetic mean of terminating flow durations |
| mean_packet_rate | TRAFFIC_VOLUME | packet_rate | YES | Mean packet transfer rate across flows |
| mean_byte_rate | TRAFFIC_VOLUME | byte_rate | YES | Mean byte transfer rate across flows |
| mean_iat | CONNECTION_BEHAVIOR | iat_mean | PARTIAL | Mean inter-arrival time (valid entries; -1 sentinel if uncalculated) |
| std_iat | CONNECTION_BEHAVIOR | iat_std | PARTIAL | Standard deviation of inter-arrival time |
| syn_count | CONNECTION_BEHAVIOR | tcp_syn | YES | Aggregated count of TCP SYN packets |
| ack_count | CONNECTION_BEHAVIOR | tcp_ack | YES | Aggregated count of TCP ACK packets |
| rst_count | CONNECTION_BEHAVIOR | tcp_rst | YES | Aggregated count of TCP RST packets |
| fin_count | CONNECTION_BEHAVIOR | tcp_fin | YES | Aggregated count of TCP FIN packets |
| connection_failure_rate | CONNECTION_BEHAVIOR | tcp_rst, tcp_syn | YES | Ratio of session aborts to attempts: (rst + 1) / (syn + 1) |
| unique_host_pair_count | HOST_DIVERSITY | src_ip, dst_ip | YES | Count of distinct directed communication edges |
| fan_out_ratio | HOST_DIVERSITY | src_ip, dst_ip | YES | Ratio: unique_dst_hosts / (unique_src_hosts + 1e-4) |

## 2. Traceability Limitations
1. **Aggregate Aggregation**: Features such as `connection_failure_rate` and `inbound_outbound_ratio` are non-linear aggregations and cannot be decomposed into single-flow credits.
2. **Sentinels**: Inter-arrival times (`mean_iat`, `std_iat`) use -1.0 sentinel values where flow packets are insufficient, limiting micro-timing flow attribution in CTU-13.
