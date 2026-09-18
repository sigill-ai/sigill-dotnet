# EPIC-0001: Verifiserbar agenteksekvering — SDK-laget

Status: Completed 18.09.2026 — SDK-laget levert på initiativgrenen (TASK-0001 og TASK-0002); TASK-0003 parkert. Backend-leddet fortsetter i sigill-backend EPIC-0025.

Gren: `initiativ/agenteksekvering` i dette repoet. Eierordre 18.09.2026:
initiativet lever på egne grener i alle berørte repoer, merges ikke til
`main` før eieren sier klart, og kan bli forkastet i sin
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

Eierpresisering 18.09 kveld: det som koster ved senere endringer er ikke
gjennomgangene, men at spesifikasjon, skjema, vektor og CI må endres i
takt med koden. Så lenge initiativet kan bli forkastet, er koden sannheten
og spesifikasjonen et øyeblikksbilde av den. Vektoren fornyes fra koden;
prosaen får et banner som sier det. Kjernepåstander, som at kontroll-
grunnlaget var forseglet før kjøringen, hører hjemme i en tidlig test, ikke
i en gjennomgang.

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
| TASK-0002 | Spesifikasjon, skjema, testvektor fra den ekte kjøringen, alle åtte sabotasjetester, pakkemetadata | kap. 5, 7.2, 8.3 |
| TASK-0003 | Speiling til sigill-python — parkert, senere intensjon | kap. 7.2 |

TASK-0002 ble bestilt 18.09 etter grønn prøvekjøring. TASK-0003 er parkert
og tas opp etter eiers ja til å gå videre med initiativet.

## Beslutninger

Tatt 18.09.2026 ved bestillingen av TASK-0002, etter notatets
anbefalinger; detaljene står i TASK-0002. Eier bekrefter eller korrigerer
ved verifisering.

| Punkt | Beslutning |
|---|---|
| B1 søsterprofiler eller extensions | Søsterprofiler, tre MIME-typer |
| B2 hvem eier spesifikasjonen | sigill-dotnet `spec/`; Python-speiling er senere intensjon (TASK-0003 parkert) |
| B5 verifierens identitet | Eget sertifikat i samme tenant; sertifikat per kall finnes i SDK-et |
| B6 kjede uten hovedbok | Kjeden bæres i artefaktene |

## Til backend-leddet

- **CRM-tidskontroll i verifier-komponenten**: `observed-state` inkluderer
  radens endringstidspunkt, og verifieren kontrollerer at seal-tiden til
  `tool_call` ligger før skrivetidspunktet. Det er den ene kontrollen som
  avslører «handling først, segl etterpå» (spec §4.1). Ingen SDK-endring.
- **Baseline-state**: rollen `baseline-state` finnes nå i Control Artifact
  (én rolle, skjema oppdatert). Backend-harnesset leser kunderaden før
  kjøringen og forsegler den der; verifier-komponenten sammenligner
  `observed-state` mot den. Uten dette er «uendret» bare verifierens ord.
- **Demo-hensyn**: raske kjøringer mot en tilfeldig TSA i poolen. Ingen
  tidskontroll i SDK-et påvirker utfallet, så en sporadisk rød foran
  publikum kan ikke komme fra klokkeavvik.

## Eksplisitt utenfor

- Endringer i `platform` og i `Sigill.Sdk`-kjernen.
- Backend, frontend, sigill-python og sigill-evidence.
- Vitneattestasjoner, anchoring, sub-kjøringer, gjenopptak av pauset
  kjøring, frakoblet verifisering uten platform. Tas opp når en test viser
  at det trengs.

## Akseptanse for epicen

1. TASK-0001 viser én kjøring som verifikatoren rapporterer som komplett,
   uendret og bundet, og tre manipulasjoner som den avviser.
2. Eieren har tatt stilling til om initiativet går videre. Kravspesifikasjonen
   er utarbeidet av eieren sammen med Raymond; demonstrasjon for Raymond
   skjer når en MCP-løsning er på plass fra frontend og nedover, ikke per task.
3. Sletting av sidepakkens mapper og tilbakestilling av `Sigill.Sdk.sln`
   gir `main` tilbake.
