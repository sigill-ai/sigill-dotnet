# TASK-0002: Gjør det normativt

EPIC-0001, ledd 2. Status: In progress 18.09.2026 — bestilt av eier etter
grønn prøvekjøring; levert på grenen samme dag, venter eierverifisering.
Ingen push før eier sier til.

## Formål

Ta det som virket i prøvekjøringen og gjøre det til noe andre kan bygge
mot: spesifikasjon, skjema, byteidentiske testvektorer og en pakke som
kan publiseres. Innholdet er skrevet fra koden og artefaktene i TASK-0001,
ikke fra notatet alene.

## Beslutninger tatt ved bestillingen (18.09.2026)

Eieren bestilte tasken uten forbehold. Notatets anbefalinger er derfor
lagt til grunn og skrevet inn i spesifikasjonen. Eier bekrefter eller
korrigerer ved verifisering.

| Punkt | Beslutning |
|---|---|
| B1 | Søsterprofiler med tre MIME-typer. Profilen leses fra `sigD.ctys[0]`. |
| B2 | Spesifikasjonen eies av sigill-dotnet i `spec/`, speiles til sigill-python. |
| B5 | Verifieren signerer med eget sertifikat i samme tenant. Signeringskallet tar sertifikat per kall, så det er én konfigurasjonsverdi. Egen tenant dokumentert som produksjonsmønster. |
| B6 | Kjeden bæres i artefaktene. Tenant-global rekkefølge og «ingen kjøring er slettet» bevises ikke i denne fasen. |
| Feltnavn | Engelsk, som resten av konvoluttfamilien. Notatets navn som de står. |
| `activity.name` | Påkrevd i alle tre profilene. |
| Rollesett | Lukket per profil. Produsentprivate data går i `extensions`. |
| `binds` | Påkrevd i `run_start`, valgfritt ellers, identisk om gjentatt. |
| `boundActionHash` | Valgfritt felt i `human_approval`: SHA-256 av `tool-arguments`-objektet godkjenningen dekker. |
| `evidenceId` | `urn:uuid:`-form, siden profilene alltid refererer hverandre med URI. |
| Kjerneavhengighet | Sidepakken refererer den publiserte `Sigill.Sdk` 0.5.0 som pakke, ikke prosjektet. Da bygger den nøyaktig slik en kunde gjør, og kjernen kan ikke endres ved et uhell. |

## Levert

1. **Spesifikasjon** i `spec/`: `agent-profiles-common-v1.md` (familiekjerne,
   bindingsregel, verifikasjonsprosedyre), `agent-control-artifact-v1.md`,
   `agent-execution-evidence-v1.md`, `control-evaluation-v1.md`. Én
   krysshenvisning lagt inn i `ai-evidence-envelope-v2.md` §3.4.
2. **Tre JSON Schema** (draft 2020-12, `additionalProperties: false`), med
   betingede regler for `chain.prevSignatureSha256`, `step`-felter per
   type og rolleantall i `objects[]`.
3. **Testvektor 10** `spec/test-vectors/10-agent-controlled-run/`: den ekte
   kjøringen fra TASK-0001 (ni artefakter signert av testtenanten),
   objektene, kanoniske bytes og hash per konvolutt, forventet
   verifikasjonsresultat, `_generate.py` og `_validate.py`.
4. **Tester**: kanoniseringsvektorer (bytes, hash, `hashV[0]`), intakt sett
   mot forventet resultat, alle åtte sabotasjetester fra notatet 8.3 på
   kopier av vektoren, byggernes regler. 33 tester, kjører uten nettverk.
5. **Pakke** `Sigill.Sdk.Agent` 0.1.0-preview.1 med metadata og README;
   `dotnet pack` gir en nupkg med avhengighet `Sigill.Sdk 0.5.0`.
   Publisering er egen eierbeslutning.
6. **CI**: vektor 10 regenereres og valideres i `spec-vectors`-jobben.
7. **Bestilling av Python-speiling** som TASK-0003 i backlog.

## Ikke levert, med grunn

- Skjemavalidering ved kjøretid i .NET. Krever en ny pakkeavhengighet;
  skjemaene håndheves av `_validate.py` i CI og av testene.
- Frakoblet signaturkontroll, tidsstempelgyldighet som eget felt,
  gjenopptak av pauset kjøring. Ingen test har vist behovet ennå.

## Akseptansekriterier

1. Alle eksempler og alle ni ekte konvolutter validerer mot sitt skjema;
   `_generate.py` reproduserer vektorene byte for byte. **Oppfylt.**
2. Alle åtte sabotasjetester grønne uten nettverk. **Oppfylt.**
3. Omfanget er revidert mot det TASK-0001 faktisk viste. **Oppfylt**, se
   beslutningstabellen.
4. Eieren har verifisert på grenen. **Åpent.**
