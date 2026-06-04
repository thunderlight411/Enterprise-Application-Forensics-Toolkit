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
        help="Pad naar de installer die geanalyseerd moet worden.",
    )
    parser.add_argument(
        "--procmon",
        help="Pad naar een ProcMon CSV-bestand voor trace-analyse.",
    )
    parser.add_argument(
        "--procdump",
        help="Pad naar een ProcDump .dmp-bestand voor dump-analyse.",
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

    if not args.installer and not args.procmon and not args.procdump:
        parser.error("Provide at least one of --installer, --procmon, or --procdump")

    toolkit = ForensicsToolkit(
        installer_path=Path(args.installer) if args.installer else None,
        procmon_path=Path(args.procmon) if args.procmon else None,
        procdump_path=Path(args.procdump) if args.procdump else None,
        verbose=args.verbose,
    )

    report = toolkit.run_analysis()
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"Analyse voltooid: {output_path}")
