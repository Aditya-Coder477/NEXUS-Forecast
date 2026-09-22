"""
CLI Runner for NEXUS-Forecast Phase 19 Offline Inference Pipeline.
Accepts sequence files (.parquet, .csv), runs deterministic inference with
optional explainability and knowledge enrichment, and exports standard reports.
"""

import os
import sys
import argparse
import logging
import json

from src.inference.config import InferenceConfig
from src.inference.pipeline import OfflineInferencePipeline
from src.inference.output import OutputFormatter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="NEXUS-Forecast Phase 19 Air-Gapped Offline Inference CLI"
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to input sequence file (.parquet or .csv) or directory.",
    )
    parser.add_argument(
        "--input-type",
        type=str,
        choices=["sequence", "flows"],
        default="sequence",
        help="Input format type (sequence or flows).",
    )
    parser.add_argument(
        "--explain",
        type=str,
        choices=["none", "lightweight", "full"],
        default="lightweight",
        help="Model explainability mode.",
    )
    parser.add_argument(
        "--enrich",
        type=str,
        choices=["none", "attack", "full"],
        default="full",
        help="MITRE ATT&CK & CAPEC knowledge enrichment mode.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/forecast_output.json",
        help="Target output file path.",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "jsonl", "markdown"],
        default="json",
        help="Output serialisation format.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.45,
        help="Operational attack decision threshold theta* (default: 0.45).",
    )
    parser.add_argument(
        "--device",
        type=str,
        default="cpu",
        help="Inference compute device (cpu or cuda).",
    )

    args = parser.parse_args()

    # Build config
    config = InferenceConfig(
        operational_threshold=args.threshold,
        explain_mode=args.explain,
        enrich_mode=args.enrich,
        device=args.device,
    )

    logger.info(f"Initializing Offline Inference Pipeline (device={args.device}, threshold={args.threshold})...")
    pipeline = OfflineInferencePipeline(config)

    logger.info(f"Executing inference on input: {args.input} (type={args.input_type})...")
    results = pipeline.predict(
        input_data=args.input,
        explain_mode=args.explain,
        enrich_mode=args.enrich,
    )

    logger.info(f"Inference completed for {len(results)} sample(s).")

    # Format and save output
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    if args.format == "json":
        OutputFormatter.save_json(results, args.output)
        logger.info(f"Saved canonical JSON output to: {args.output}")
    elif args.format == "jsonl":
        OutputFormatter.save_jsonl(results, args.output)
        logger.info(f"Saved JSONL output to: {args.output}")
    elif args.format == "markdown":
        md_text = "\n\n".join([OutputFormatter.to_soc_markdown(r) for r in results])
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md_text)
        logger.info(f"Saved SOC Markdown report to: {args.output}")

    # Print summary to console
    print(f"\n================ NEXUS-Forecast Summary ================")
    for idx, r in enumerate(results):
        fid = r.get("forecast_id")
        attack = r.get("summary", {}).get("overall_attack_forecasted")
        max_p = r.get("summary", {}).get("max_attack_prob")
        traj = " -> ".join(r.get("summary", {}).get("predicted_trajectory", []))
        print(f"Sample {idx+1} [{fid}]: Attack={attack} (Max Prob: {max_p:.1%}) | Trajectory: {traj}")
    print("========================================================\n")


if __name__ == "__main__":
    main()
