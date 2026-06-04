import json
from pathlib import Path

from toolkit.analysis import ForensicsToolkit


def test_run_analysis_creates_report(tmp_path):
    installer = tmp_path / "dummy-installer.exe"
    installer.write_text("dummy")

    toolkit = ForensicsToolkit(installer_path=installer, verbose=False)
    report = toolkit.run_analysis()

    assert report["installer"] == str(installer)
    assert "procmon" in report["changes"]
    assert "registry" in report["changes"]
    assert report["intune_msix_recommendation"] == "placeholder: nog te implementeren"
