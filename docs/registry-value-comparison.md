# Voorstel: betrouwbare vergelijking van registerwaarden

Registerwaarden worden intern opgeslagen als het oorspronkelijke Windows-type
en de volledige ingelezen byte-array. De vergelijking gebruikt beide velden.
De bestaande rapportvelden, tellingen en lijsten met gewijzigde paden blijven gelijk.

Dit herkent wijzigingen na de eerste 16 bytes, lengtewijzigingen,
typewijzigingen en verschillen tussen REG_MULTI_SZ-elementen die dezelfde
weergavetekst opleveren. reg_value_repr blijft uitsluitend een weergavefunctie;
de ingekorte uitvoer bepaalt niet meer of een waarde gewijzigd is.

## Verificatie

Op Windows met Visual Studio C++ Build Tools en CMake:

```powershell
cmake -S cpp/tests -B cpp/test-build -A x64
cmake --build cpp/test-build --config Release
ctest --test-dir cpp/test-build -C Release --output-on-failure
```

De tests werken met in-memory fixtures en wijzigen het Windows-register niet.
Ze gebruiken expliciete controles, zodat ze ook in Release-builds actief blijven.
De afzonderlijke testworkflow bouwt tevens de CLI en GUI.

## Afbakening

Dit voorstel verbetert de vergelijking van succesvol ingelezen waarden.
Buffergroei en zichtbare leesfouten zijn inmiddels uitgewerkt in
[Onvolledige snapshots](snapshot-completeness.md). Ontbrekende HKCU-dekking en
detectie van lege registersleutels vragen nog afzonderlijke wijzigingen.
Volledige byte-arrays gebruiken meer geheugen dan de eerdere ingekorte tekst.
