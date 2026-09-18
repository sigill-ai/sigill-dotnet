# TASK-0003: Speiling av agentprofilene til sigill-python

EPIC-0001, ledd 3. Status: Backlog — bestilles i sigill-python når eier
og Raymond har godkjent TASK-0002. Gjøres på en initiativgren der også.

## Formål

Samme tre profiler i Python, byteidentisk med .NET, slik CONTRIBUTING.md
krever for alt i `spec/`.

## Omfang

1. Kopier `spec/` fra denne grenen inn i sigill-python (vendoring, byte
   for byte), inkludert `test-vectors/10-agent-controlled-run/`.
2. Pakke `sigill-agent` (arbeidsnavn) over `sigill` med samme fire
   byggeklosser: Control Artifact, kjøring med kjede og avslutning,
   Control Evaluation, verifikator med resultatflaten fra
   `agent-profiles-common-v1.md` §4.
3. Tester som leser vektor 10: kanoniske bytes, `hashV[0]`, intakt sett
   mot `expected-result.json`, de åtte sabotasjetestene.

## Akseptanse

Begge SDK-er gir identiske kanoniske bytes for alle ni konvolutter og
identisk verifikasjonsresultat for det intakte settet.
