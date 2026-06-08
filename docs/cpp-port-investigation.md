# Onderzoek: C++-herimplementatie van de Enterprise Application Forensics Toolkit

## Conclusie

De huidige toolkit kan functioneel naar C++ worden overgezet zonder verlies van de bestaande functionaliteit. De huidige Python-code bevat vooral commandline-parsing, rapportopbouw, ProcMon-CSV-samenvatting, ProcDump-headerherkenning en placeholders voor toekomstige registry-, filesystem-, dependency- en Intune/MSIX-analyses. Deze onderdelen zijn direct in moderne C++ te modelleren met `std::filesystem`, standaard I/O, kleine datastructuren en een JSON-serializer.

Een C++-variant is vooral interessant zodra de toolkit meer Windows-native functionaliteit krijgt, zoals registry snapshots, file system monitoring, ETW/ProcMon-achtige capture, PE-inspectie en dumpanalyse. Voor snelle prototyping blijft Python eenvoudiger, maar voor een forensische Windows-agent of zelfstandige binary is C++ een goede keuze.

## Functionaliteitsmatrix

| Functionaliteit | Huidige Python-status | C++-haalbaarheid | Aanpak in C++ |
| --- | --- | --- | --- |
| CLI met `--installer`, `--procmon`, `--procdump`, `--output`, `--verbose` | Geïmplementeerd | Hoog | Handmatige argumentparser of CLI-library zoals CLI11. |
| JSON-rapport | Geïmplementeerd | Hoog | Eigen serializer voor huidige structuur of `nlohmann/json`. |
| ProcMon CSV-analyse | Geïmplementeerd | Hoog | CSV-parser met header mapping en tellers voor operation/path/registry operations. |
| ProcDump `.dmp`-herkenning | Geïmplementeerd | Hoog | Eerste vier bytes lezen en `MDMP` herkennen. |
| Registry snapshot/wijzigingen | Placeholder | Hoog op Windows | Windows Registry API (`RegOpenKeyEx`, `RegEnumKeyEx`, `RegQueryValueEx`) of PowerShell-export als fallback. |
| File system snapshots | Placeholder | Hoog | `std::filesystem` voor snapshots; Windows USN Journal of ReadDirectoryChangesW voor live wijzigingen. |
| Dependency scanning | Placeholder | Hoog | PE import table, manifest parsing, MSI metadata, NuGet/npm manifests. |
| Rechtenanalyse | Placeholder | Hoog | Installer metadata, manifest requestedExecutionLevel, registry/file targets en service/install acties. |
| Intune/MSIX-geschiktheid | Placeholder | Hoog | Regels engine op basis van privileges, services/drivers, HKLM/HKCU, Program Files-writes en dependencies. |

## Aanbevolen migratiestrategie

1. **Bevries het rapportcontract.** Houd de JSON-velden `installer`, `changes`, `dependencies`, `required_rights` en `intune_msix_recommendation` stabiel zodat bestaande gebruikers of scripts niet breken.
2. **Maak eerst een parallelle C++ CLI.** Laat Python en C++ tijdelijk naast elkaar bestaan. De C++ proof-of-concept in `cpp/` volgt dezelfde opties en rapportstructuur.
3. **Voeg golden-output tests toe.** Vergelijk Python- en C++-rapporten voor dezelfde ProcMon CSV en ProcDump-bestanden.
4. **Migreer Windows-native functies eerst.** Registry-, filesystem-, PE- en dumpanalyse leveren in C++ waarschijnlijk de meeste winst op.
5. **Behoud Python eventueel als orchestration-laag.** Als snelle automatisering belangrijk blijft, kan Python de C++ binary aanroepen of bindings gebruiken.

## Risico's en aandachtspunten

- **CSV-compatibiliteit:** ProcMon CSV-bestanden kunnen quotes, komma's en BOM bevatten. De C++ parser moet dit expliciet ondersteunen.
- **JSON escaping:** Rapportvelden bevatten Windows-paden met backslashes en mogelijk Unicode; de serializer moet correct escapen.
- **Windows API-complexiteit:** Registry- en ETW-integratie vragen meer foutafhandeling dan de huidige placeholders.
- **Build/distributie:** C++ vraagt CMake/toolchainbeheer, maar levert een zelfstandige binary op.
- **Gedragspariteit:** De volgorde en tekst van rapportitems moeten bewust worden getest als gebruikers rapporten vergelijken.

## Proof-of-concept in deze branch

Deze branch bevat een C++ proof-of-concept onder `cpp/` met:

- dezelfde CLI-opties als de Python-toolkit;
- dezelfde hoofdstructuur van het JSON-rapport;
- ProcMon CSV-telling van operaties, registerbewerkingen en paden;
- ProcDump-signatuurherkenning;
- dezelfde placeholderteksten voor nog te implementeren analyses.

De C++ proof-of-concept is bedoeld als migratiebasis en niet als vervanging van de Python-entrypoint in deze stap.
