# Phase 18: ATT&CK and CAPEC Forecast Enrichment Documentation

## Overview
Phase 18 enriches NEXUS-Forecast predictions with contextual threat intelligence from MITRE ATT&CK (v19.2) and CAPEC (v3.9).

## Operational Workflow
```text
Forecasted State & Probabilities
               ↓
     Predicted Attack Stage
               ↓
    MitreEnricher (attack_stage_mapping.json)
               ↓
    EvidenceKnowledgeMapper (Phase 17 Features)
               ↓
    CapecEnricher (capec_normalized.json)
               ↓
       EnrichedForecastResult
```

## Relevance Levels
- `EVIDENCE_SUPPORTED`: Active telemetry anomalies support technique mechanics.
- `CONTEXTUALLY_RELEVANT`: Technically mapped to the predicted stage.
- `REVIEW_REQUIRED`: Human review necessary due to cross-stage ambiguity.
- `NOT_RELEVANT`: Inactive for current stage.
