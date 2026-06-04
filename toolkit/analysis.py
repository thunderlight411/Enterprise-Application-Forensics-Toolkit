from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List


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
    def __init__(self, installer_path: Path, verbose: bool = False):
        self.installer_path = installer_path
        self.verbose = verbose

    def run_analysis(self) -> Dict:
        installer = str(self.installer_path)
        report = AnalysisReport(installer=installer)

        report.changes["procmon"] = self._analyze_procmon()
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
