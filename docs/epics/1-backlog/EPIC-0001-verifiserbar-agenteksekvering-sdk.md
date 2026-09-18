# EPIC-0001: Verifiserbar agenteksekvering — SDK-laget

Status: Backlog — utkast til eiergodkjenning 18.09.2026.

Gren: `initiativ/agenteksekvering` i dette repoet. Eierordre 18.09.2026:
initiativet lever på egne grener i alle berørte repoer, merges ikke til
`main` før Hallvard og Raymond begge sier klart, og kan bli forkastet i sin
helhet. Alt i denne epicen skal derfor kunne slettes uten spor i
`Sigill.Sdk`.

## Grunnlag

- «Realiseringsnotat: Verifiserbar kontroll og eksekvering for AI-agenter»,
  `sigill-harness/docs/design-docs/sigill_verifiable_agent_execution_realisering_v1.md`
  (16.09.2026, heretter *notatet*). Kapittelreferanser under peker dit.
- Eierens fire skjermbilder av FØR / UNDER / ETTER-visningen (18.09.2026):
  kjøringen `customer-address-change`, agent `contract-agent v17`,
  kontrollsett `customer-write-v4`, sju hendelser seq 0 til 6, og
  `overall: FAIL` på `status-unchanged`.
- `spec/ai-evidence-envelope-v2.md` §2 (familiekjerne og søsterprofiler),
  §3.4 (`chain` reservert) og §6 (artefaktet).

## Formål

Finne ut, med minst mulig kode, om notatets tre bevisklasser lar seg
signere, lenke og verifisere over den blinde signeringen platformen har i
dag. Først når det er vist, gjøres det normativt.

## Arbeidsmåte

Eierbeslutning 18.09.2026: prøvekjøring først, spesifikasjon etterpå.
Notatet kap. 11 setter spesifikasjonen først. Den rekkefølgen gjelder for
noe som skal leve; for noe som skal prøves og kanskje kastes, bevises
konseptet ende til ende først, og spesifikasjonen skrives fra koden som
virker. Ende-til-ende-tester mot testmiljøet er styringsverktøyet, og
kursen korrigeres underveis.

## Rammer

1. **Sidepakke, ikke kjerneendring.** Ett prosjekt ved siden av
   `Sigill.Sdk`, bygget på den offentlige flaten:
   `SignObjectHashesAsync` med `ObjectSignOptions.EnvelopeContentType`,
   `EnvelopeHashing.Canonicalize` og `VerifyObjectHashesAsync`.
   `Sigill.Sdk` endres ikke. Mangler kjernen noe, stopper arbeidet og
   spør.
2. **Notatets feltnavn brukes som de står** i prøvekjøringen. De låses
   først i TASK-0002.
3. **Én bindingsmekanisme** (notatet 4.4): SHA-256 over den
   base64url-dekodede klassiske JWS-signaturverdien til målartefaktet.

## Leveranse

| Task | Innhold | Notatet |
|---|---|---|
| TASK-0001 | Prøvekjøring: én kjøring ende til ende, signert, lenket og verifisert | kap. 4, 5, 6.2, 8.2 |
| TASK-0002 | Etter ja: spesifikasjon, skjema, testvektorer, resten av sabotasjetestene, pakkemetadata | kap. 5, 7.2, 8.3 |

TASK-0002 starter ikke før eier og Raymond har sett TASK-0001 virke og
sagt ja til å gå videre.

## Beslutninger

| Punkt | I prøvekjøringen | Avgjøres |
|---|---|---|
| B1 søsterprofiler eller extensions | Søsterprofiler, tre MIME-typer | Bekreftes før TASK-0002 |
| B2 hvem eier spesifikasjonen | Ikke aktuelt før TASK-0002 | Før TASK-0002 |
| B5 verifierens identitet | Samme sertifikat som agenten, notert som forenkling. `SignObjectHashesAsync` tar `certificateId` per kall, så et eget verifier-sertifikat i samme tenant krever kun én konfigurasjonsverdi | Før TASK-0002 |
| B6 kjede uten hovedbok | Kjeden bæres i artefaktene | Bekreftes før TASK-0002 |

## Eksplisitt utenfor

- Endringer i `platform` og i `Sigill.Sdk`-kjernen.
- Backend, frontend, sigill-python og sigill-evidence.
- Vitneattestasjoner, anchoring, sub-kjøringer, gjenopptak av pauset
  kjøring, frakoblet verifisering uten platform. Tas opp når en test viser
  at det trengs.

## Akseptanse for epicen

1. TASK-0001 viser én kjøring som verifikatoren rapporterer som komplett,
   uendret og bundet, og tre manipulasjoner som den avviser.
2. Eier og Raymond har tatt stilling til om initiativet går videre.
3. Sletting av sidepakkens mapper og tilbakestilling av `Sigill.Sdk.sln`
   gir `main` tilbake.
