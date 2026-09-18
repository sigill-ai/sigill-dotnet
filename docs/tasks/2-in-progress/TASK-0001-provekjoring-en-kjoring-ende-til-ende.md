# TASK-0001: Prøvekjøring — én kjøring ende til ende

EPIC-0001, ledd 1. Status: In progress 18.09.2026 — bestilt av eier samme dag.
Første ende-til-ende-kjøring mot testmiljøet er grønn (ni artefakter,
platformen bekrefter signaturene, verifikatoren gir run_finalized og bound).
Venter på at eier og Raymond ser kjøringen (akseptanse 4).

## Formål

Svare på ett spørsmål: kan notatets tre bevisklasser signeres blindt,
lenkes med `chain` og bindes til hverandre slik at en verifikator kan
avgjøre «komplett, uendret og bundet» uten hjelp fra platform ut over
signaturkontrollen? Svaret skal komme fra en test mot testmiljøet, ikke
fra et dokument.

## Omfang

1. **Prosjekt** `src/Sigill.Sdk.Agent/` med prosjektreferanse til
   `Sigill.Sdk`, samme målrammeverk som kjernen, lagt inn i
   `Sigill.Sdk.sln`. Ingen pakkemetadata, ingen publisering, ingen
   README ut over én linje. Testprosjekt `tests/Sigill.Sdk.Agent.Tests/`.
2. **Tre tynne byggere** som produserer konvoluttene fra notatet 5.1, 5.2
   og 5.3 som `JsonObject` med feltnavnene som de står, hasher detached
   objects lokalt, kanoniserer med `EnvelopeHashing.Canonicalize` og
   signerer med `SignObjectHashesAsync` og riktig
   `EnvelopeContentType`. Resultatet er artefaktet `{ envelope, signature }`
   etter v2 §6.
3. **Kjøringstilstand** i én klasse: `correlationId`, neste `seq`, forrige
   bindingshash og Control Artifacts bindingshash. `run_start` binder
   Control Artifact, hver hendelse setter `prev`, `run_end` setter
   `finalSeq`, `finalPrevSignatureSha256` og `runDisposition`.
4. **Bindingshash** som én funksjon: SHA-256 over den base64url-dekodede
   klassiske signaturverdien (notatet 4.4).
5. **Verifikator** med kontrollrekkefølgen fra notatet 6.2, steg 1 til 7:
   signatur og fullstendighet via `VerifyObjectHashesAsync`, gruppering på
   `correlationId`, kjedekontroll, `run_end`-kontroll, binding til Control
   Artifact, og `subject`-kontroll av evalueringen. Resultatet er en enkel
   post med feltene fra notatet 6.1. Ingen tidslinje, ingen ferdige
   setninger.
6. **Ende-til-ende-test mot testmiljøet**: skjermbildets kjøring bygges
   og signeres, alle ni artefakter lagres som filer i testens utmappe
   sammen med detached objects, og verifikatoren gir `run_finalized`,
   `chain_valid`, `objects_complete`, `binding = bound` og én evaluering
   med `subject_bound = true`. Testen hopper over når testmiljøets
   nøkkel ikke er satt, og sier det høyt.
7. **Tre sabotasjetester på de lagrede filene**, uten nytt platformkall
   for kjede og binding: artefakt seq 3 fjernet gir `chain_valid = false`
   og `run_invalid`; `run_end` fjernet gir `run_open`; Control Artifact
   byttet gir `binding = run_only` og `subject_bound = false`.

## Forenklinger som er valgt bevisst

- Evalueringen signeres med samme klient og sertifikat som agenten (B5
  står åpen). Verifikatoren skiller derfor ikke verifierens identitet fra
  agentens i denne tasken.
- Ingen skjemavalidering. Konvoluttene er JSON-objekter, ikke typer.
- Ingen gjenopptak fra lagret tilstand. Kjøringen lever i én prosess.
- Ingen frakoblet signaturkontroll. Platformkallet er kilden.

## Eksplisitt utenfor

- Spesifikasjon, JSON Schema, testvektorer, pakkemetadata (TASK-0002).
- Alt i backend og frontend.

## Akseptansekriterier

1. `dotnet test` grønn på grenen. Sabotasjetestene kjører uten nettverk.
2. Ende-til-ende-testen er grønn mot testmiljøet, og de lagrede
   artefaktene ligger igjen så eier og Raymond kan åpne dem.
3. `git diff main -- src/Sigill.Sdk tests/Sigill.Sdk.Tests` er tom.
4. Eier og Raymond har sett kjøringen og sagt ja eller nei til å gå
   videre.

## Anslag

Én PR på grenen.
