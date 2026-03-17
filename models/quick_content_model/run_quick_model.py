"""CLI runner for QuickContentThreatModel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.quick_content_model.model import QuickContentThreatModel


def main() -> None:
    parser = argparse.ArgumentParser(description="Run quick content threat analysis for a URL")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    args = parser.parse_args()

    model = QuickContentThreatModel(timeout=args.timeout)
    report = model.analyze_url(args.url)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
