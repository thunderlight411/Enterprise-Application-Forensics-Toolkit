import argparse
import json
from pathlib import Path

from .analysis import ForensicsToolkit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enterprise Application Forensics Toolkit"
    )
    parser.add_argument(
        "--installer",
        required=True,
        help="Pad naar de installer die geanalyseerd moet worden.",
    )
    parser.add_argument(
        "--output",
        default="report.json",
        help="Pad naar het outputrapport (JSON).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Toon extra informatie tijdens analyse.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    toolkit = ForensicsToolkit(
        installer_path=Path(args.installer),
        verbose=args.verbose,
    )

    report = toolkit.run_analysis()
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"Analyse voltooid: {output_path}")
