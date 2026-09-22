"""
CLI Launcher for the NEXUS-Forecast Offline Analyst Workstation.
Starts the local air-gapped web server on http://127.0.0.1:8000.
"""

import os
import sys
from pathlib import Path
import argparse
import uvicorn
import logging

# Ensure project root is always present on sys.path regardless of execution directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Launch NEXUS-Forecast Analyst Dashboard")
    default_host = os.environ.get("HOST", "127.0.0.1")
    default_port = int(os.environ.get("PORT", "8000"))
    parser.add_argument("--host", type=str, default=default_host, help="Host address (default: 127.0.0.1 or $HOST)")
    parser.add_argument("--port", type=int, default=default_port, help="Port number (default: 8000 or $PORT)")
    parser.add_argument("--reload", action="store_true", help="Enable automatic code reloading")
    args = parser.parse_args()

    print("\n" + "=" * 65)
    print("  NEXUS-FORECAST: AIR-GAPPED ANALYST WORKSTATION")
    print(f"  Access Dashboard: http://{args.host}:{args.port}")
    print("  Mode: OFFLINE LOCAL INFERENCE (Zero external connections)")
    print("=" * 65 + "\n")

    uvicorn.run(
        "backend.app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        app_dir=str(PROJECT_ROOT),
    )


if __name__ == "__main__":
    main()
