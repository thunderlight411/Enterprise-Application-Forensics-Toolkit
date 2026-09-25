# Onvolledige snapshots

Bestands- en registermetingen bewaren naast ingelezen waarden ook leesfouten.
Elke fout bevat de locatie, de mislukte bewerking en de foutcode. De GUI toont
een onvolledige voor-snapshot direct met de bijbehorende fouten.

Een vergelijking wordt per onderdeel alleen uitgevoerd wanneer beide metingen
zonder geregistreerde leesfouten zijn afgerond. Bij een onvolledig onderdeel
wordt de vergelijking geheel overgeslagen: er verschijnen geen aantallen of
paden voor toegevoegd, gewijzigd of verwijderd. Dit voorkomt dat ontbrekende
metingen als echte wijzigingen worden gepresenteerd. Een volledige
bestandsmeting blijft bruikbaar als alleen de registermeting onvolledig is.

In JSON krijgen snapshotvergelijkingen het aanvullende veld `complete`:

```json
{
  "description": "Registervergelijking: HKLM (onvolledig)",
  "complete": false,
  "items": [
    "Vergelijking overgeslagen: onvolledige snapshot; wijzigingen zijn niet betrouwbaar vast te stellen.",
    "Na-snapshot: HKLM\\SOFTWARE\\Example [RegOpenKeyExW]: Windows error 5"
  ]
}
```

Volledige vergelijkingen hebben `complete: true` en behouden de bestaande
tellingen. Andere analyses krijgen dit veld niet. Ingelezen deelresultaten
blijven intern beschikbaar, maar worden niet als bevestigde verschillen getoond.

## Collectie

- Bestanden: fouten bij het openen en uitlezen van mappen en bij het lezen van
  status, grootte en wijzigingstijd worden geregistreerd. Een onleesbare
  submap verhindert niet dat al ontdekte andere mappen worden verwerkt.
- Register: bij `ERROR_MORE_DATA` worden buffers vergroot en wordt dezelfde
  waarde opnieuw gelezen. Na maximaal acht pogingen wordt een fout vastgelegd,
  zodat een voortdurend veranderende waarde de scan niet eindeloos blokkeert.
- Andere enumeratiefouten stoppen de betreffende enumeratie met een foutmelding;
  er wordt niet eindeloos naar volgende indices doorgelopen. Geopende
  registerhandles worden ook bij exceptions vrijgegeven.

## Tests

Gebruik de bestaande CMake/CTest-commando's uit registry-value-comparison.md.
De nieuwe suite controleert 128 KiB-registerwaarden, kleine naam- en databuffers,
lege waarden, een ontbrekende sleutel, toegang geweigerd, ontbrekende mappen,
een bestand als doelmap en de volledigheidsstatus in het JSON-rapport.

De integratietests gebruiken uitsluitend een unieke tijdelijke map en een
unieke vluchtige HKCU-testsleutel. De ACL-test herstelt de rechten voordat de
testsleutel wordt verwijderd; productiesleutels worden niet gewijzigd.

## Grenzen

`complete` betekent dat binnen de gekozen scope geen leesfouten zijn gemeld.
Het is geen atomische momentopname: bestanden en registerwaarden kunnen tijdens
de scan veranderen. De productiescope blijft HKLM SOFTWARE en SYSTEM in de
standaard registerweergave en de gekozen bestandsmap; directory-symlinks worden
niet gevolgd. HKCU, lege registersleutels en inhoudshashes zijn geen onderdeel
van deze wijziging. Fouten en volledige registerwaarden kosten extra geheugen.
