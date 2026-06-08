# Enterprise Application Forensics Toolkit

Een startpunt voor een toolkit die een package engineer helpt analyseren wat een installer doet en of een applicatie geschikt is voor Intune/MSIX.

## Kernfunctionaliteit

- `procmon`-achtige installatiesporenanalyse
- Registry snapshot / wijzigingen
- Bestandssnapshots en file system changes
- Dependency scanning voor runtime en installatie
- Installer / package analyse en evaluatie
- Snelle rapportage voor rechten, noodzakelijke dependencies en Intune/MSIX-geschiktheid

## Doel

Eén tool waarmee een packager binnen 5 minuten ziet:
- wat een installer heeft gewijzigd
- welke dependencies nodig zijn
- welke rechten vereist zijn
- of de applicatie geschikt is voor Intune/MSIX

## Starten

```powershell
python -m toolkit --installer "C:\path\to\installer.exe" --output report.json
python -m toolkit --procmon "C:\path\to\trace.csv" --output report.json
python -m toolkit --procdump "C:\path\to\memory.dmp" --output report.json
```

## Structuur

- `toolkit/cli.py` - commandline interface
- `toolkit/analysis.py` - analyse- en evaluatiemodules
- `toolkit/__main__.py` - package entrypoint


## C++-onderzoek en proof-of-concept

Deze repository bevat naast de Python-toolkit nu ook een onderzoek naar een C++-herimplementatie in `docs/cpp-port-investigation.md`. Een parallelle C++ proof-of-concept staat in `cpp/` en behoudt de bestaande commandline-opties en JSON-rapportstructuur voor de huidige functionaliteiten.

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
./cpp/build/eaftoolkit --procmon trace.csv --procdump memory.dmp --output report.json
```

## Volgende stappen

- implementeren van live ProcMon-log parsing of capture
- opname van snapshot-vergelijking voor register en bestanden
- dependency scanning via PE/manifest/nuget/npm modules
- MSIX/Intune-evaluatie op basis van installatiekenmerken en rechten
