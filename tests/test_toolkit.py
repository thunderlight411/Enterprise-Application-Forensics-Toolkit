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


def test_procmon_csv_analysis(tmp_path):
    procmon_file = tmp_path / "trace.csv"
    procmon_file.write_text(
        "Time,Process Name,PID,Operation,Path,Result,Detail\n"
        "0,setup.exe,1234,File Create,C:\\Program Files\\app\\app.exe,SUCCESS,\n"
        "1,setup.exe,1234,RegSetValue,HKEY_LOCAL_MACHINE\\Software\\App,SUCCESS,\n"
        "2,setup.exe,1234,File Create,C:\\Program Files\\app\\config.xml,SUCCESS,\n"
    )

    toolkit = ForensicsToolkit(
        procmon_path=procmon_file,
        verbose=False,
    )
    report = toolkit.run_analysis()
    procmon_change = report["changes"]["procmon"]

    assert "ProcMon-analyse" in procmon_change["description"]
    assert any("File Create" in item for item in procmon_change["items"])
    assert any("HKEY_LOCAL_MACHINE" in item for item in procmon_change["items"])


def test_procdump_analysis(tmp_path):
    procdump_file = tmp_path / "memory.dmp"
    procdump_file.write_bytes(b"MDMP" + b"\x00" * 32)

    toolkit = ForensicsToolkit(
        procdump_path=procdump_file,
        verbose=False,
    )
    report = toolkit.run_analysis()
    procdump_change = report["changes"]["procdump"]

    assert "ProcDump-analyse" in procdump_change["description"]
    assert any("MDMP" in item for item in procdump_change["items"])
