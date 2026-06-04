import csv
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ChangeSummary:
    description: str
    items: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "description": self.description,
            "items": self.items,
        }


@dataclass
class AnalysisReport:
    installer: str
    changes: Dict[str, ChangeSummary] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    required_rights: List[str] = field(default_factory=list)
    intune_msix_recommendation: str = "unknown"

    def to_dict(self) -> Dict:
        return {
            "installer": self.installer,
            "changes": {k: v.to_dict() for k, v in self.changes.items()},
            "dependencies": self.dependencies,
            "required_rights": self.required_rights,
            "intune_msix_recommendation": self.intune_msix_recommendation,
        }


class ForensicsToolkit:
    def __init__(
        self,
        installer_path: Optional[Path] = None,
        procmon_path: Optional[Path] = None,
        procdump_path: Optional[Path] = None,
        verbose: bool = False,
    ):
        self.installer_path = installer_path
        self.procmon_path = procmon_path
        self.procdump_path = procdump_path
        self.verbose = verbose

    def run_analysis(self) -> Dict:
        installer = str(self.installer_path or "")
        report = AnalysisReport(installer=installer)

        if self.procmon_path:
            report.changes["procmon"] = self._analyze_procmon_file(self.procmon_path)
        else:
            report.changes["procmon"] = self._analyze_procmon()

        if self.procdump_path:
            report.changes["procdump"] = self._analyze_procdump_file(self.procdump_path)

        report.changes["registry"] = self._snapshot_registry()
        report.changes["files"] = self._snapshot_files()
        report.dependencies = self._scan_dependencies()
        report.required_rights = self._evaluate_required_rights()
        report.intune_msix_recommendation = self._evaluate_intune_msix()

        return report.to_dict()

    def _analyze_procmon(self) -> ChangeSummary:
        if self.verbose:
            print("Running ProcMon-style installation trace analysis...")
        return ChangeSummary(
            description="ProcMon-installatieanalyse",
            items=["placeholder: importeer en parse ProcMon CSV of ETL"],
        )

    def _analyze_procmon_file(self, procmon_path: Path) -> ChangeSummary:
        if self.verbose:
            print(f"Parsing ProcMon CSV: {procmon_path}")

        if not procmon_path.exists():
            return ChangeSummary(
                description="ProcMon-analyse",
                items=[f"Bestand niet gevonden: {procmon_path}"],
            )

        operations, top_paths, registry_ops = self._parse_procmon_csv(procmon_path)
        items: List[str] = []

        if operations:
            top_operations = operations.most_common(5)
            items.append("Top ProcMon-operaties:")
            items.extend([f"{op}: {count}" for op, count in top_operations])

        if registry_ops:
            items.append("Top registerbewerkingen:")
            items.extend([f"{op}: {count}" for op, count in registry_ops.most_common(5)])

        if top_paths:
            items.append("Top paden opgenomen in ProcMon:")
            items.extend([f"{path}: {count}" for path, count in top_paths.most_common(5)])

        if not items:
            items.append("Geen ProcMon-gegevens gevonden in CSV.")

        return ChangeSummary(
            description=f"ProcMon-analyse van {procmon_path.name}",
            items=items,
        )

    def _parse_procmon_csv(self, procmon_path: Path) -> Tuple[Counter, Counter, Counter]:
        operations: Counter[str] = Counter()
        top_paths: Counter[str] = Counter()
        registry_ops: Counter[str] = Counter()

        with procmon_path.open(newline="", encoding="utf-8-sig") as fp:
            reader = csv.DictReader(fp)
            if reader.fieldnames is None:
                return operations, top_paths, registry_ops

            for row in reader:
                operation = (row.get("Operation") or "").strip()
                path_value = (row.get("Path") or "").strip()
                operations[operation] += 1

                if path_value:
                    top_paths[path_value] += 1

                if "Reg" in operation or "Registry" in operation:
                    registry_ops[operation] += 1

        return operations, top_paths, registry_ops

    def _analyze_procdump_file(self, procdump_path: Path) -> ChangeSummary:
        if self.verbose:
            print(f"Analyzing ProcDump file: {procdump_path}")

        if not procdump_path.exists():
            return ChangeSummary(
                description="ProcDump-analyse",
                items=[f"Bestand niet gevonden: {procdump_path}"],
            )

        signature = "unknown"
        try:
            header = procdump_path.read_bytes()[:4]
            signature = header.decode("ascii", errors="replace")
        except Exception:
            signature = "onleesbaar"

        items = [
            f"ProcDump-bestand: {procdump_path.name}",
            f"Grootte: {procdump_path.stat().st_size} bytes",
            f"Signatuur: {signature}",
        ]

        if signature == "MDMP":
            items.append("Herkenning: Windows minidump-formaat")
        elif procdump_path.suffix.lower() == ".dmp":
            items.append("Herkenning: mogelijk ProcDump dumpbestand")

        return ChangeSummary(
            description=f"ProcDump-analyse van {procdump_path.name}",
            items=items,
        )

    def _snapshot_registry(self) -> ChangeSummary:
        if self.verbose:
            print("Capturing registry snapshot changes...")
        return ChangeSummary(
            description="Registry snapshot en wijzigingen",
            items=["placeholder: vergelijk voor/na registry snapshots"],
        )

    def _snapshot_files(self) -> ChangeSummary:
        if self.verbose:
            print("Capturing filesystem snapshot changes...")
        return ChangeSummary(
            description="Bestandssnapshot en wijzigingen",
            items=["placeholder: vergelijk file system snapshots"],
        )

    def _scan_dependencies(self) -> List[str]:
        if self.verbose:
            print("Scanning dependencies...")
        return ["placeholder: dependency scanning op PE/manifest/installer"]

    def _evaluate_required_rights(self) -> List[str]:
        if self.verbose:
            print("Evaluating required rights...")
        return ["placeholder: analyseer administrator of systeemrechten"]

    def _evaluate_intune_msix(self) -> str:
        if self.verbose:
            print("Assessing Intune/MSIX suitability...")
        return "placeholder: nog te implementeren"
