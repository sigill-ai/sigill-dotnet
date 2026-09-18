# TASK-0002: Gjør det normativt

EPIC-0001, ledd 2. Status: In progress. Levert og korrigert etter eierens
gjennomgang (tidsrekkefølge, boundActionHash, monotoni, grunnlinje), pushet
etter eiers ja. Eierkorreksjon 19.09: akseptanse 4 (verifisert på grenen)
står åpen; lukkingen 18.09 var utledet, ikke bekreftet.

Endringer etter første levering, alle i sidepakken: preview.2 (SealTime,
baseline-state som rolle), preview.3 (baseline-state i Control Evaluation,
`baselineDigestMatches`, 40 tester). Backend refererer preview.3. Hver
endring har fått nytt versjonsnummer, siden NuGet cacher per versjon i
~/.nuget/packages og en ny nupkg med samme nummer ville blitt ignorert
lokalt mens Docker-bygget fikk den nye.

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
| B2 | Spesifikasjonen eies av sigill-dotnet i `spec/`. Speiling til sigill-python er en senere intensjon, ikke en beslutning (TASK-0003 parkert 18.09). |
| B5 | Verifieren signerer med eget sertifikat i samme tenant. Signeringskallet tar sertifikat per kall, så det er én konfigurasjonsverdi. Egen tenant dokumentert som produksjonsmønster. |
| B6 | Kjeden bæres i artefaktene. Tenant-global rekkefølge og «ingen kjøring er slettet» bevises ikke i denne fasen. |
| Feltnavn | Engelsk, som resten av konvoluttfamilien. Notatets navn som de står. |
| `activity.name` | Påkrevd i alle tre profilene. |
| Rollesett | Lukket per profil. Produsentprivate data går i `extensions`. |
| `binds` | Påkrevd i `run_start`, valgfritt ellers, identisk om gjentatt. |
| `boundActionHash` | **Strøket 18.09 (eierkorreksjon).** Ingen test trengte feltet, og det innførte en ny bindingsregel. Hva godkjenningen dekker er innholdet i `approval-receipt`. |
| Seal-tid | **Lagt til og korrigert 18.09 (eierkorreksjon).** Verifikatoren leser `sigTst` genTime og `accuracy`. Kontrollens TSA-tid skal ikke ligge etter run_start sin, innenfor accuracy og hele sekunder. Bindingen beviser rekkefølgen allerede; et avvik peker på platform eller TSA, rapporteres som avvik og endrer ikke utfallet. Monotoni langs kjeden er fjernet: `prev` beviser rekkefølgen, og TSA-poolen (seks TSA-er i vektor 10) ville gitt falske røde på raske kjøringer. Egen test med testklokke. |
| `baseline-state` | **Lagt til 18.09 (eierkorreksjon).** Én valgfri rolle i Control Artifact for tilstanden før kjøringen. Lagt inn nå fordi rollesettet er lukket; innholdet brukes av verifier-komponenten i backend, ikke av SDK-et. |
| Binding av grunnlinjen | **Lagt til 18.09 (eierbestilling).** Control Evaluation legger ved `baseline-state` på samme måte som `control-set`; verifikatoren rapporterer `baselineDigestMatches`. Test: evaluering med annen grunnlinje avvises. Endringen er i sidepakken, ikke i kjernen. |
| Luken «handling først, segl etterpå» | Verken binding eller tid ser den. Løses i verifier-komponenten: `observed-state` tar med radens endringstidspunkt, og seal-tiden til `tool_call` må ligge før. Hører til backend-leddet (der `observed-state` lages), se spec §4.1. |
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
5. **Pakke** `Sigill.Sdk.Agent` 0.1.0-preview.3 med metadata og README;
   `dotnet pack` gir en nupkg med avhengighet `Sigill.Sdk 0.5.0`.
   Publisering er egen eierbeslutning.
6. **CI**: vektor 10 regenereres og valideres i `spec-vectors`-jobben.
7. **TASK-0003 (Python-speiling)** skrevet og parkert; tas opp etter eiers ja til å gå videre.

## Prinsipp: koden er sannheten (eierkorreksjon 18.09)

Så lenge initiativet kan bli forkastet, er spesifikasjon, skjema, vektor og
CI et øyeblikksbilde av koden, ikke omvendt. Kostnaden ved en justering
holdes nede slik: vektor 10 fornyes fra koden med én kjøring
(`SIGILL_AGENT_WRITE_VECTOR`), skjemaene håndheves kun av `_validate.py`,
og prosaen har et banner som sier at koden gjelder ved avvik. Prosa og
skjema oppdateres når koden har satt seg, ikke ved hver endring.

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
